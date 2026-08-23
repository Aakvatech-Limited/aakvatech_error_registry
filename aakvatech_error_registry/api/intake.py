import hashlib
import json

import frappe
from frappe.utils import get_datetime, now_datetime

from aakvatech_error_registry.api.security import verify_signed_request


def _fingerprint(error):
    parts = [
        (error.get("app") or "").strip(),
        (error.get("file_path") or "").strip(),
        (error.get("function") or "").strip(),
        str(error.get("line_number") or ""),
        (error.get("exception_type") or "").strip(),
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def _logical_fingerprint(error):
    parts = [
        (error.get("app") or "").strip(),
        (error.get("file_path") or "").strip(),
        (error.get("function") or "").strip(),
        (error.get("exception_type") or "").strip(),
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def _site_error_key(error_name, managed_site):
    return hashlib.sha256((error_name + "|" + managed_site).encode("utf-8")).hexdigest()


def _upsert_error(site, observation):
    canonical = _fingerprint(observation)
    error_name = frappe.db.exists("Application Error", {"canonical_fingerprint": canonical})
    now = now_datetime()
    first_seen = get_datetime(observation.get("first_seen")) if observation.get("first_seen") else now
    last_seen = get_datetime(observation.get("last_seen")) if observation.get("last_seen") else now
    count = max(int(observation.get("occurrence_count") or 1), 1)

    if error_name:
        app_error = frappe.get_doc("Application Error", error_name)
        app_error.last_seen = max(get_datetime(app_error.last_seen) if app_error.last_seen else last_seen, last_seen)
        app_error.occurrence_count = int(app_error.occurrence_count or 0) + count
        if observation.get("traceback"):
            app_error.representative_traceback = observation.get("traceback")
        if observation.get("source_context"):
            app_error.source_context = observation.get("source_context")
        app_error.save(ignore_permissions=True)
    else:
        app_error = frappe.get_doc({
            "doctype": "Application Error",
            "status": "New",
            "canonical_fingerprint": canonical,
            "logical_fingerprint": _logical_fingerprint(observation),
            "app_name": observation.get("app"),
            "module_name": observation.get("module"),
            "component_type": observation.get("component_type") or "Unknown",
            "component_name": observation.get("component"),
            "file_path": observation.get("file_path"),
            "function_name": observation.get("function"),
            "line_number": observation.get("line_number"),
            "exception_type": observation.get("exception_type"),
            "exception_message": observation.get("exception_message"),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "occurrence_count": count,
            "affected_site_count": 0,
            "representative_traceback": observation.get("traceback"),
            "source_context": observation.get("source_context"),
        }).insert(ignore_permissions=True)

    key = _site_error_key(app_error.name, site.name)
    site_row_name = frappe.db.exists("Application Error Site", {"site_error_key": key})
    is_new_site = not site_row_name
    if site_row_name:
        site_row = frappe.get_doc("Application Error Site", site_row_name)
        site_row.last_seen = max(get_datetime(site_row.last_seen) if site_row.last_seen else last_seen, last_seen)
        site_row.occurrence_count = int(site_row.occurrence_count or 0) + count
        site_row.latest_local_error_log = observation.get("latest_local_error_log")
        site_row.app_version = observation.get("app_version")
        site_row.git_commit_sha = observation.get("git_commit_sha")
        site_row.save(ignore_permissions=True)
    else:
        frappe.get_doc({
            "doctype": "Application Error Site",
            "site_error_key": key,
            "application_error": app_error.name,
            "managed_site": site.name,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "occurrence_count": count,
            "latest_local_error_log": observation.get("latest_local_error_log"),
            "app_version": observation.get("app_version"),
            "git_commit_sha": observation.get("git_commit_sha"),
        }).insert(ignore_permissions=True)

    if is_new_site:
        app_error.db_set("affected_site_count", int(app_error.affected_site_count or 0) + 1, update_modified=False)

    return app_error.name, canonical, count


@frappe.whitelist(allow_guest=True, methods=["POST"])
def report_errors():
    body_bytes = frappe.request.get_data(cache=True) or b""
    site = verify_signed_request(body_bytes)
    try:
        payload = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
    except Exception:
        frappe.throw("Invalid JSON payload", frappe.ValidationError)

    batch_id = (payload.get("batch_id") or "").strip()
    errors = payload.get("errors") or []
    if not batch_id or not isinstance(errors, list):
        frappe.throw("batch_id and errors[] are required", frappe.ValidationError)

    batch_key = hashlib.sha256((site.site_uuid + "|" + batch_id).encode("utf-8")).hexdigest()
    existing = frappe.db.exists("Error Intake Batch", {"batch_key": batch_key})
    if existing:
        return {"accepted": True, "duplicate": True, "batch": existing}

    batch = frappe.get_doc({
        "doctype": "Error Intake Batch",
        "batch_key": batch_key,
        "batch_id": batch_id,
        "managed_site": site.name,
        "site_uuid": site.site_uuid,
        "received_on": now_datetime(),
        "reporting_date": payload.get("reporting_date"),
        "status": "Processing",
        "observation_count": 0,
        "occurrence_count": 0,
    }).insert(ignore_permissions=True)

    total_occurrences = 0
    results = []
    for observation in errors:
        if not observation.get("app") or not observation.get("file_path") or not observation.get("exception_type"):
            frappe.throw("Each error requires app, file_path and exception_type", frappe.ValidationError)
        error_name, fingerprint, count = _upsert_error(site, observation)
        total_occurrences += count
        results.append({"application_error": error_name, "fingerprint": fingerprint})

    batch.db_set("observation_count", len(errors), update_modified=False)
    batch.db_set("occurrence_count", total_occurrences, update_modified=False)
    batch.db_set("status", "Processed", update_modified=False)
    frappe.db.commit()
    return {
        "accepted": True,
        "duplicate": False,
        "batch": batch.name,
        "observations": len(errors),
        "occurrences": total_occurrences,
        "results": results,
    }
