import frappe
from frappe.model.document import Document
from frappe.utils import now_datetime


class ManagedSite(Document):
    def approve(self):
        self.status = "Active"
        self.approved_on = now_datetime()
        self.approved_by = frappe.session.user
        for row in self.ip_addresses:
            if row.status == "Pending":
                row.status = "Approved"
                row.approved_on = now_datetime()
                row.approved_by = frappe.session.user
        self.save(ignore_permissions=True)

    def reject(self, reason=None):
        self.status = "Rejected"
        self.rejected_on = now_datetime()
        self.rejected_by = frappe.session.user
        if reason:
            self.rejection_reason = reason
        self.save(ignore_permissions=True)


@frappe.whitelist()
def approve_site(name):
    frappe.only_for("System Manager")
    doc = frappe.get_doc("Managed Site", name)
    doc.approve()
    return {"status": doc.status}


@frappe.whitelist()
def reject_site(name, reason=None):
    frappe.only_for("System Manager")
    doc = frappe.get_doc("Managed Site", name)
    doc.reject(reason)
    return {"status": doc.status}
