"""A synthetic tenant for demos and tests. Every name and ID here is fictional.

Dates are generated relative to `now`, so the same risks show up whenever the demo runs.
"""
from __future__ import annotations

import random
import uuid
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone

from .catalog import GLOBAL_ADMIN_TEMPLATE, MICROSOFT_TENANT_ID, classify_role, looks_like_ai_agent
from .config import DEFAULT_AGENT_KEYWORDS
from .models import Application, Credential, RoleAssignment, ServicePrincipal, TenantSnapshot, User

DOMAIN = "contosohealth.example"
ONMS = "contosohealthdemo.onmicrosoft.com"

FIRST = ["Amelia", "Oliver", "Isla", "George", "Ava", "Harry", "Mia", "Noah", "Sophia", "Jack", "Grace", "Leo",
         "Freya", "Arthur", "Lily", "Oscar", "Ella", "Charlie", "Emily", "Theo", "Priya", "Tunde", "Aisha", "Kwame",
         "Chen", "Fatima", "Liam", "Zara", "Ravi", "Nia"]
LAST = ["Smith", "Jones", "Taylor", "Brown", "Williams", "Wilson", "Johnson", "Roberts", "Patel", "Okafor",
        "Wright", "Evans", "Thomas", "Hughes", "Khan", "Walker", "Green", "Adeyemi", "Clarke", "Lewis"]
DEPTS = ["Finance", "Clinical Operations", "HR", "IT", "Sales", "Customer Service", "Operations"]
TITLES = ["Analyst", "Coordinator", "Manager", "Officer", "Administrator", "Specialist", "Advisor"]
METHODS = [["microsoftAuthenticatorPush"], ["microsoftAuthenticatorPush", "mobilePhone"], ["fido2"],
           ["softwareOneTimePasscode"], ["windowsHelloForBusiness", "microsoftAuthenticatorPush"]]

ROLE_IDS = {
    "Global Administrator": GLOBAL_ADMIN_TEMPLATE,
    "Privileged Role Administrator": "e8611ab8-c189-46e8-94e1-60213ab1f814",
    "Exchange Administrator": "29232cdf-9323-42fd-ade2-1d097af3e4de",
    "User Administrator": "fe930be7-5e62-47db-91af-98c3a49a38b1",
    "Helpdesk Administrator": "729827e3-9c14-49f7-bb1b-9608f156bbb8",
    "Security Administrator": "194ae4cb-b126-40b2-bd5b-6091b380977d",
    "Reports Reader": "4a5d8f65-41da-4de4-8968-e035b65339cf",
}


def _id(label: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"accessguard-demo/{label}"))


def demo_snapshot(now: datetime | None = None, keywords: Iterable[str] = DEFAULT_AGENT_KEYWORDS) -> TenantSnapshot:
    now = now or datetime.now(timezone.utc)
    rng = random.Random(2026)
    keywords = tuple(keywords)
    tenant_id = _id("tenant")
    vendor_tenant = _id("vendor-tenant")

    def ago(days: int, hours: int = 0) -> datetime:
        return now - timedelta(days=days, hours=hours)

    users: list[User] = []
    seen_upns: set[str] = set()

    def add_user(label: str, name: str, upn: str, **kw) -> User:
        user = User(id=_id(f"user/{label}"), display_name=name, upn=upn, **kw)
        users.append(user)
        return user

    # Regular staff
    dormant = {7, 19, 26, 38, 51, 64, 77, 90}
    disabled = {12, 45, 83}
    for i in range(110):
        first, last = FIRST[i % len(FIRST)], LAST[(i * 7 + i // len(FIRST)) % len(LAST)]
        local = f"{first}.{last}".lower()
        if local in seen_upns:
            local = f"{local}{i}"
        seen_upns.add(local)
        enabled = i not in disabled
        if not enabled:
            last_sign_in = ago(rng.randint(150, 500))
        elif i in dormant:
            last_sign_in = ago(rng.randint(100, 420))
        else:
            last_sign_in = ago(rng.randint(0, 25), rng.randint(0, 23))
        mfa = rng.random() > 0.06
        add_user(
            f"staff/{i}", f"{first} {last}", f"{local}@{DOMAIN}",
            account_enabled=enabled, created=ago(rng.randint(120, 1600)), last_sign_in=last_sign_in,
            on_prem_synced=rng.random() < 0.7, mfa_registered=mfa, mfa_methods=rng.choice(METHODS) if mfa else [],
            department=rng.choice(DEPTS), job_title=rng.choice(TITLES),
        )

    add_user("new-starter", "Kofi Mensah", f"kofi.mensah@{DOMAIN}", created=ago(200), last_sign_in=None,
             on_prem_synced=True, mfa_registered=False, department="Operations", job_title="Coordinator")

    # Guests
    partners = ["northwind.example", "fabrikam.example", "adatum.example", "tailspin.example"]
    dormant_guests = {1, 4, 6, 9, 11, 13}
    for i in range(14):
        first, last, partner = FIRST[(i * 3) % len(FIRST)], LAST[(i * 5) % len(LAST)], partners[i % 4]
        add_user(
            f"guest/{i}", f"{first} {last} (Guest)", f"{first}.{last}_{partner}#EXT#@{ONMS}".lower(),
            user_type="Guest", created=ago(rng.randint(150, 900)),
            last_sign_in=ago(rng.randint(100, 500)) if i in dormant_guests else ago(rng.randint(1, 60)),
            mfa_registered=rng.random() > 0.3, department=None, job_title="External",
        )

    # Admins and other notable accounts
    jane = add_user("admin-jane", "Jane Okafor (Admin)", f"admin.jane@{ONMS}", created=ago(900), last_sign_in=ago(1),
                    mfa_registered=True, mfa_methods=["fido2", "microsoftAuthenticatorPush"], department="IT", job_title="IT Manager")
    itops = add_user("it-ops", "IT Operations (shared)", f"it.ops@{ONMS}", created=ago(1400), last_sign_in=ago(3),
                     mfa_registered=False, department="IT", job_title="Shared admin account")
    bg1 = add_user("bg1", "Break Glass 01", f"breakglass01@{ONMS}", created=ago(1000), last_sign_in=ago(32),
                   mfa_registered=True, mfa_methods=["fido2"], department="IT", job_title="Emergency access")
    bg2 = add_user("bg2", "Break Glass 02", f"breakglass02@{ONMS}", created=ago(1000), last_sign_in=ago(32),
                   mfa_registered=True, mfa_methods=["fido2"], department="IT", job_title="Emergency access")
    daniel = add_user("daniel", "Daniel Wright", f"daniel.wright@{DOMAIN}", created=ago(700), last_sign_in=ago(0, 5),
                      on_prem_synced=True, mfa_registered=True, mfa_methods=["microsoftAuthenticatorPush"],
                      department="IT", job_title="Infrastructure Engineer")
    vendor = add_user("vendorx", "VendorX Support (Guest)", f"support_vendorx.example#EXT#@{ONMS}", user_type="Guest",
                      created=ago(300), last_sign_in=ago(5), mfa_registered=False, job_title="External support")
    leaver = add_user("leaver", "Mark Davies (leaver)", f"mark.davies@{DOMAIN}", account_enabled=False, created=ago(1200),
                      last_sign_in=ago(140), on_prem_synced=True, mfa_registered=True, mfa_methods=["mobilePhone"],
                      department="IT", job_title="Helpdesk Lead")
    sam = add_user("sam", "Sam Patel", f"sam.patel@{DOMAIN}", created=ago(500), last_sign_in=ago(1), on_prem_synced=True,
                   mfa_registered=True, mfa_methods=["microsoftAuthenticatorPush"], department="IT", job_title="Service Desk Analyst")
    ruth = add_user("ruth", "Ruth Evans", f"ruth.evans@{ONMS}", created=ago(800), last_sign_in=ago(152),
                    mfa_registered=True, mfa_methods=["fido2"], department="IT", job_title="Security Lead")
    finance_lead = add_user("finance-lead", "Grace Hughes", f"grace.hughes@{DOMAIN}", created=ago(600), last_sign_in=ago(2),
                            on_prem_synced=True, mfa_registered=True, mfa_methods=["microsoftAuthenticatorPush"],
                            department="Finance", job_title="Finance Manager")

    # Service principals and app registrations
    sps: list[ServicePrincipal] = []
    apps: list[Application] = []

    def secret(label: str, started_days_ago: int, ends_in_days: int) -> Credential:
        return Credential("secret", _id(f"key/{label}"), label, ago(started_days_ago), now + timedelta(days=ends_in_days))

    def cert(label: str, started_days_ago: int, ends_in_days: int) -> Credential:
        return Credential("certificate", _id(f"key/{label}"), label, ago(started_days_ago), now + timedelta(days=ends_in_days))

    def add_sp(label, name, perms=(), delegated=(), publisher="own", tags=(), owners=(), creds=()) -> ServicePrincipal:
        owner_tenant = {"own": tenant_id, "vendor": vendor_tenant, "microsoft": MICROSOFT_TENANT_ID}[publisher]
        sp = ServicePrincipal(
            id=_id(f"sp/{label}"), app_id=_id(f"app/{label}"), display_name=name, owner_tenant_id=owner_tenant,
            tags=list(tags), created=ago(rng.randint(90, 1200)), app_permissions=sorted(perms),
            delegated_admin_consent=sorted(delegated),
        )
        sp.is_ai_agent = looks_like_ai_agent(sp.display_name, sp.tags, sp.sp_type, keywords)
        sps.append(sp)
        if publisher == "own":
            apps.append(Application(id=_id(f"appobj/{label}"), app_id=sp.app_id, display_name=name, created=sp.created,
                                    credentials=list(creds), owners=[o.display_name for o in owners]))
        return sp

    add_sp("graph", "Microsoft Graph", publisher="microsoft")
    add_sp("exo", "Office 365 Exchange Online", publisher="microsoft")

    add_sp("legacy-hr", "Legacy HR Sync", ["Directory.ReadWrite.All", "User.ReadWrite.All"], owners=[jane],
           creds=[secret("hr-sync-2023", 1105, -10), secret("hr-sync-2025", 400, 330)])
    add_sp("backup", "Backup Connector", ["Mail.ReadWrite", "Files.ReadWrite.All", "Sites.FullControl.All"], publisher="vendor")
    add_sp("copilot-finance", "Copilot Studio - Finance Agent", ["Mail.Send", "Files.Read.All", "Sites.Read.All", "User.Read.All"],
           owners=[], creds=[secret("agent-runtime", 30, 150)])
    add_sp("ai-triage", "AI Ticket Triage Agent", ["RoleManagement.ReadWrite.Directory", "User.Read.All", "Group.ReadWrite.All"],
           owners=[daniel], creds=[cert("triage-cert", 60, 300)])
    runbook = add_sp("runbook", "Automation Runbook - Joiners", ["User.Read.All", "Group.Read.All"], owners=[itops],
                     creds=[secret("runbook", 170, 12)])
    add_sp("intune-reporting", "Intune Reporting", ["DeviceManagementManagedDevices.Read.All"], owners=[daniel],
           creds=[cert("intune-cert", 100, 630)])
    add_sp("payroll", "Payroll Export", ["User.Read.All"], owners=[finance_lead], creds=[secret("payroll", 160, 20)])
    add_sp("marketing", "Marketing Forms", ["User.Read.All"], owners=[], creds=[secret("forms", 90, 90)])
    add_sp("siem", "SIEM Connector", ["AuditLog.Read.All", "Directory.Read.All", "SecurityEvents.Read.All"], owners=[ruth],
           creds=[cert("siem-cert", 200, 500)])
    add_sp("rota-bot", "Teams Rota Bot", ["User.Read.All", "Calendars.Read"], owners=[], creds=[secret("rota", 60, 120)])
    add_sp("service-desk", "Service Desk Integration", ["User.Read.All", "Group.Read.All"], owners=[sam],
           creds=[secret("service-desk", 100, 630)])
    add_sp("contact-sync", "Website Contact Sync", ["User.ReadBasic.All"], owners=[jane], creds=[secret("contacts", 30, 150)])
    add_sp("old-survey", "Old Survey Tool", delegated=["Files.ReadWrite.All", "Mail.ReadWrite", "User.Read"], publisher="vendor")
    add_sp("doc-scanner", "Document Scanner", ["Files.Read.All"], owners=[daniel], creds=[cert("scanner", 50, 315)])
    add_sp("reporting", "Reporting Dashboard", ["Reports.Read.All"], owners=[ruth], creds=[cert("reports", 80, 285)])
    for i, name in enumerate(["Room Booking", "Expense Capture", "Visitor Sign-in", "Learning Portal", "Print Management",
                              "Wi-Fi Onboarding", "Asset Register", "Shift Swap", "Phone System", "HR Portal SSO",
                              "Recruitment Portal", "Benefits Portal"]):
        add_sp(f"sso/{i}", name, publisher="vendor")
    for i, name in enumerate(["Org Chart Viewer", "Directory Lookup", "Training Records", "Fleet Tracker"]):
        add_sp(f"reader/{i}", name, ["User.Read.All"], publisher="vendor")

    # Directory roles
    roles: list[RoleAssignment] = []

    def assign(principal, principal_type: str, role_name: str) -> None:
        template = ROLE_IDS[role_name]
        privileged, critical = classify_role(template, role_name)
        principal_name = principal.upn if principal_type == "user" else principal.display_name
        roles.append(RoleAssignment(principal.id, principal_type, principal_name, template, role_name, template,
                                    privileged, critical))

    for admin in (jane, itops, bg1, bg2, daniel):
        assign(admin, "user", "Global Administrator")
    assign(vendor, "user", "Exchange Administrator")
    assign(leaver, "user", "User Administrator")
    assign(sam, "user", "Helpdesk Administrator")
    assign(ruth, "user", "Security Administrator")
    assign(finance_lead, "user", "Reports Reader")
    assign(runbook, "servicePrincipal", "Privileged Role Administrator")

    caps = {name: True for name in ("organization", "sign_in_activity", "mfa_registration", "app_permissions",
                                     "delegated_grants", "app_owners", "directory_roles")}
    return TenantSnapshot(
        tenant_id=tenant_id,
        tenant_name="Contoso Health (demo)",
        collected_at=now,
        source="demo",
        users=users,
        service_principals=sps,
        applications=apps,
        role_assignments=roles,
        warnings=[],
        capabilities=caps,
    )
