import base64
import hashlib
import time

import frappe
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_CLOCK_SKEW_SECONDS = 300


def get_source_ip():
    request = getattr(frappe.local, "request", None)
    return getattr(request, "remote_addr", None) if request else None


def canonical_message(site_uuid, timestamp, nonce, body_bytes):
    body_hash = hashlib.sha256(body_bytes or b"").hexdigest()
    return (site_uuid + "\n" + timestamp + "\n" + nonce + "\n" + body_hash).encode("utf-8")


def verify_signed_request(body_bytes):
    site_uuid = (frappe.get_request_header("X-Aakva-Site-ID") or "").strip()
    timestamp = (frappe.get_request_header("X-Aakva-Timestamp") or "").strip()
    nonce = (frappe.get_request_header("X-Aakva-Nonce") or "").strip()
    signature = (frappe.get_request_header("X-Aakva-Signature") or "").strip()

    if not site_uuid or not timestamp or not nonce or not signature:
        frappe.throw("Missing signed-request headers", frappe.AuthenticationError)

    try:
        request_ts = int(timestamp)
    except (TypeError, ValueError):
        frappe.throw("Invalid request timestamp", frappe.AuthenticationError)

    if abs(int(time.time()) - request_ts) > MAX_CLOCK_SKEW_SECONDS:
        frappe.throw("Request timestamp is outside the allowed clock skew", frappe.AuthenticationError)

    site_name = frappe.db.exists("Managed Site", {"site_uuid": site_uuid})
    if not site_name:
        frappe.throw("Unknown site UUID", frappe.AuthenticationError)

    site = frappe.get_doc("Managed Site", site_name)
    if site.status != "Active":
        frappe.throw("Managed Site is not active", frappe.PermissionError)

    source_ip = get_source_ip()
    approved_ips = {row.ip_address for row in site.ip_addresses if row.status == "Approved"}
    if not source_ip or source_ip not in approved_ips:
        _register_unapproved_ip(site, source_ip)
        frappe.throw("Source IP is not approved for this site", frappe.PermissionError)

    nonce_hash = hashlib.sha256((site_uuid + ":" + nonce).encode("utf-8")).hexdigest()
    if frappe.db.exists("Error Request Nonce", {"nonce_hash": nonce_hash}):
        frappe.throw("Request nonce has already been used", frappe.AuthenticationError)

    try:
        public_key = serialization.load_pem_public_key(site.public_key.encode("utf-8"))
        if not isinstance(public_key, Ed25519PublicKey):
            frappe.throw("Managed Site public key must be Ed25519", frappe.AuthenticationError)
        public_key.verify(base64.b64decode(signature), canonical_message(site_uuid, timestamp, nonce, body_bytes))
    except frappe.ValidationError:
        raise
    except Exception:
        frappe.throw("Invalid request signature", frappe.AuthenticationError)

    frappe.get_doc({
        "doctype": "Error Request Nonce",
        "nonce_hash": nonce_hash,
        "site_uuid": site_uuid,
        "nonce": nonce,
        "request_timestamp": request_ts,
    }).insert(ignore_permissions=True)

    site.db_set("last_seen", frappe.utils.now_datetime(), update_modified=False)
    return site


def _register_unapproved_ip(site, source_ip):
    if not source_ip:
        return
    now = frappe.utils.now_datetime()
    existing = None
    for row in site.ip_addresses:
        if row.ip_address == source_ip:
            existing = row
            break
    if existing:
        existing.last_seen = now
    else:
        site.append("ip_addresses", {
            "ip_address": source_ip,
            "status": "Pending",
            "first_seen": now,
            "last_seen": now,
        })
    site.save(ignore_permissions=True)
