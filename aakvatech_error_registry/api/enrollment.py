import hashlib

import frappe
from frappe.utils import now_datetime


def _get_source_ip():
    request = getattr(frappe.local, "request", None)
    return getattr(request, "remote_addr", None) if request else None


def _public_key_fingerprint(public_key):
    return hashlib.sha256((public_key or "").encode("utf-8")).hexdigest()


@frappe.whitelist(allow_guest=True, methods=["POST"])
def register():
    """Register exactly one first-contact enrollment for a site UUID.

    A newly seen UUID is quarantined as Pending Approval. Repeated enrollment
    attempts never create a second record and cannot activate the site.
    """
    payload = frappe.request.get_json(silent=True) or {}
    site_uuid = (payload.get("site_uuid") or "").strip()
    site_name = (payload.get("site_name") or "").strip()
    public_key = (payload.get("public_key") or "").strip()

    if not site_uuid or not site_name or not public_key:
        frappe.throw("site_uuid, site_name and public_key are required", frappe.ValidationError)

    existing = frappe.db.exists("Managed Site", {"site_uuid": site_uuid})
    if existing:
        status = frappe.db.get_value("Managed Site", existing, "status")
        frappe.local.response.http_status_code = 403
        return {
            "accepted": False,
            "site_uuid": site_uuid,
            "status": status,
            "message": "Site UUID is already enrolled; further enrollment is blocked pending central authorization.",
        }

    now = now_datetime()
    source_ip = _get_source_ip()
    doc = frappe.get_doc(
        {
            "doctype": "Managed Site",
            "site_uuid": site_uuid,
            "site_name": site_name,
            "site_url": payload.get("site_url"),
            "status": "Pending Approval",
            "first_seen": now,
            "last_seen": now,
            "public_key": public_key,
            "public_key_fingerprint": _public_key_fingerprint(public_key),
            "frappe_version": payload.get("frappe_version"),
            "erpnext_version": payload.get("erpnext_version"),
            "av_tools_version": payload.get("av_tools_version"),
        }
    )
    if source_ip:
        doc.append(
            "ip_addresses",
            {
                "ip_address": source_ip,
                "status": "Pending",
                "first_seen": now,
                "last_seen": now,
            },
        )
    doc.insert(ignore_permissions=True)
    frappe.db.commit()

    frappe.local.response.http_status_code = 202
    return {
        "accepted": True,
        "site_uuid": site_uuid,
        "status": "Pending Approval",
        "message": "First contact recorded. Error transmissions remain blocked until the site and source IP are approved.",
    }
