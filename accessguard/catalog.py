"""Reference data: privileged directory roles, risky Graph permissions and identity heuristics."""
from __future__ import annotations

import re
from collections.abc import Iterable

MICROSOFT_TENANT_ID = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"  # owner tenant of Microsoft first-party apps
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"

GLOBAL_ADMIN_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10"

# Built-in role template IDs. Display names are also matched, so a role is still
# classified correctly if Microsoft ever renames or a template ID is missing here.
CRITICAL_ROLES: dict[str, str] = {
    GLOBAL_ADMIN_TEMPLATE: "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2": "Hybrid Identity Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
}

PRIVILEGED_ROLES: dict[str, str] = {
    **CRITICAL_ROLES,
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
    "3a2c62db-5318-420d-8d74-23affee5d9d5": "Intune Administrator",
    "fdd7a751-b60b-444a-984c-02652fe8fa1c": "Groups Administrator",
    "966707d0-3269-4727-9be2-8c3a10f19b9d": "Password Administrator",
    "7698a772-787b-4ac8-901f-60d6b08affd2": "Cloud Device Administrator",
}

_EXTRA_PRIVILEGED_NAMES = {
    "Directory Writers",
    "Domain Name Administrator",
    "External Identity Provider Administrator",
    "Authentication Policy Administrator",
    "Partner Tier2 Support",
    "Partner Tier1 Support",
    "Security Operator",
    "Teams Administrator",
    "Lifecycle Workflows Administrator",
}

_CRITICAL_NAMES = {n.lower() for n in CRITICAL_ROLES.values()}
_PRIVILEGED_NAMES = {n.lower() for n in PRIVILEGED_ROLES.values()} | {n.lower() for n in _EXTRA_PRIVILEGED_NAMES}

# Microsoft Graph application permissions that allow tenant takeover or privilege escalation.
CRITICAL_APP_PERMISSIONS = {
    "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All",
    "Directory.ReadWrite.All",
    "PrivilegedAccess.ReadWrite.AzureAD",
    "PrivilegedAccess.ReadWrite.AzureADGroup",
    "Policy.ReadWrite.ConditionalAccess",
    "Policy.ReadWrite.AuthenticationMethod",
    "UserAuthenticationMethod.ReadWrite.All",
    "Domain.ReadWrite.All",
}

# Broad data access or write access that should be justified and owned.
HIGH_APP_PERMISSIONS = {
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
    "GroupMember.ReadWrite.All",
    "Organization.ReadWrite.All",
    "Mail.ReadWrite",
    "Mail.Read",
    "Mail.Send",
    "MailboxSettings.ReadWrite",
    "Files.ReadWrite.All",
    "Files.Read.All",
    "Sites.FullControl.All",
    "Sites.Manage.All",
    "Sites.ReadWrite.All",
    "Sites.Read.All",
    "Chat.Read.All",
    "Chat.ReadWrite.All",
    "ChannelMessage.Read.All",
    "Calendars.ReadWrite",
    "Contacts.ReadWrite",
    "Notes.ReadWrite.All",
    "Device.ReadWrite.All",
    "DeviceManagementConfiguration.ReadWrite.All",
    "DeviceManagementManagedDevices.ReadWrite.All",
    "DeviceManagementRBAC.ReadWrite.All",
}

# Delegated scopes that are risky when consented for every user in the tenant.
HIGH_RISK_DELEGATED = {
    "Mail.ReadWrite",
    "Mail.Read",
    "Mail.Send",
    "Files.ReadWrite.All",
    "Files.Read.All",
    "Sites.ReadWrite.All",
    "Sites.Read.All",
    "Directory.ReadWrite.All",
    "Directory.AccessAsUser.All",
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
    "Contacts.ReadWrite",
    "Calendars.ReadWrite",
    "Chat.ReadWrite",
    "Notes.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All",
    "EWS.AccessAsUser.All",
}

# The only Graph application permissions AccessGuard itself needs (plus a few harmless read scopes).
READ_ONLY_ALLOWED = {
    "User.Read.All",
    "Directory.Read.All",
    "AuditLog.Read.All",
    "RoleManagement.Read.Directory",
    "RoleManagement.Read.All",
    "Application.Read.All",
    "UserAuthenticationMethod.Read.All",
    "Organization.Read.All",
    "Reports.Read.All",
    "Policy.Read.All",
    "Group.Read.All",
    "GroupMember.Read.All",
}

REQUIRED_PERMISSIONS = (
    ("User.Read.All", "Users, account status and hybrid-sync flag"),
    ("Directory.Read.All", "Organisation details, tenant-wide consent grants, directory objects"),
    ("AuditLog.Read.All", "Sign-in activity (dormant accounts) and the MFA registration report"),
    ("RoleManagement.Read.Directory", "Directory role definitions and assignments"),
    ("Application.Read.All", "App registrations, credentials, owners, service principals and app permissions"),
    ("UserAuthenticationMethod.Read.All", "MFA registration details"),
)


def classify_role(template_id: str | None, name: str | None, is_privileged: bool | None = None) -> tuple[bool, bool]:
    """Return (privileged, critical) for a directory role."""
    lname = (name or "").strip().lower()
    critical = (template_id in CRITICAL_ROLES) or lname in _CRITICAL_NAMES
    privileged = critical or bool(is_privileged) or (template_id in PRIVILEGED_ROLES) or lname in _PRIVILEGED_NAMES
    return privileged, critical


def excessive_permissions(granted: Iterable[str]) -> list[str]:
    """Permissions on AccessGuard's own app registration that it does not need."""
    return sorted({p for p in granted if p not in READ_ONLY_ALLOWED})


def looks_like_ai_agent(name: str, tags: Iterable[str], sp_type: str | None, keywords: Iterable[str]) -> bool:
    """Heuristic flag for service principals that appear to be AI agents or bots.

    This is deliberately labelled as a heuristic in the UI — it is a prompt for review,
    not a classification Microsoft provides.
    """
    if sp_type and "agent" in sp_type.lower():
        return True
    tags = list(tags or [])
    if any("agent" in t.lower() for t in tags):
        return True
    words = [k for k in keywords if k]
    if not words:
        return False
    pattern = re.compile(r"\b(" + "|".join(re.escape(k) for k in words) + r")\b", re.IGNORECASE)
    return bool(pattern.search(name or "")) or any(pattern.search(t) for t in tags)
