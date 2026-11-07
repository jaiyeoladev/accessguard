"""Risk rules. Each rule inspects a TenantSnapshot and yields Hits; the engine turns them into Findings.

Adding a rule: decorate a generator function with @rule(...). List the snapshot
capabilities it depends on in `requires` so it is skipped (not silently empty) when
that data could not be collected.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from statistics import median
from typing import Any

from .anomaly import privilege_weight, robust_z_scores
from .catalog import (
    CRITICAL_APP_PERMISSIONS,
    GLOBAL_ADMIN_TEMPLATE,
    HIGH_APP_PERMISSIONS,
    HIGH_RISK_DELEGATED,
    MICROSOFT_TENANT_ID,
)
from .config import Settings
from .models import Application, RoleAssignment, ServicePrincipal, TenantSnapshot, User


@dataclass
class Hit:
    object_id: str
    object_type: str
    object_name: str
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)
    severity: str | None = None
    key: str = ""


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    category: str
    why: str
    remediation: str
    requires: tuple[str, ...]
    func: Callable[[Context], Iterator[Hit]]


RULES: list[Rule] = []


def rule(rule_id: str, title: str, severity: str, category: str, why: str, remediation: str, requires: tuple[str, ...] = ()):
    def decorator(fn: Callable[[Context], Iterator[Hit]]):
        RULES.append(Rule(rule_id, title, severity, category, why, remediation, tuple(requires), fn))
        return fn

    return decorator


@dataclass
class Context:
    snap: TenantSnapshot
    settings: Settings
    now: datetime
    roles_by_principal: dict[str, list[RoleAssignment]]
    apps_by_app_id: dict[str, Application]

    @classmethod
    def build(cls, snap: TenantSnapshot, settings: Settings, now: datetime) -> Context:
        roles: dict[str, list[RoleAssignment]] = defaultdict(list)
        for r in snap.role_assignments:
            roles[r.principal_id].append(r)
        return cls(snap, settings, now, dict(roles), {a.app_id: a for a in snap.applications})

    def roles(self, principal_id: str) -> list[RoleAssignment]:
        return self.roles_by_principal.get(principal_id, [])

    def days_since(self, dt: datetime) -> int:
        return (self.now - dt).days

    def is_first_party(self, sp: ServicePrincipal) -> bool:
        return sp.owner_tenant_id == MICROSOFT_TENANT_ID

    def is_third_party(self, sp: ServicePrincipal) -> bool:
        return bool(sp.owner_tenant_id) and sp.owner_tenant_id not in (self.snap.tenant_id, MICROSOFT_TENANT_ID)


def _role_names(roles: list[RoleAssignment]) -> list[str]:
    return sorted({r.role_name for r in roles})


def _user_hit(u: User, summary: str, evidence: dict[str, Any], severity: str | None = None, key: str = "") -> Hit:
    return Hit(u.id, "user", u.display_name, summary, {"UPN": u.upn, **evidence}, severity, key)


# --- Dormant accounts --------------------------------------------------------

def _dormant(ctx: Context, user_type: str) -> Iterator[Hit]:
    label = "guest" if user_type == "Guest" else "member"
    for u in ctx.snap.users:
        if not u.account_enabled or u.user_type != user_type:
            continue
        if u.last_sign_in is None:
            if u.created is None:
                continue
            age = ctx.days_since(u.created)
            if age <= ctx.settings.never_signed_in_grace_days:
                continue
            summary = f"Enabled {label} account has never signed in (created {age} days ago)."
            evidence: dict[str, Any] = {"Last sign-in": "Never", "Created": u.created.date().isoformat()}
        else:
            idle = ctx.days_since(u.last_sign_in)
            if idle <= ctx.settings.dormant_days:
                continue
            summary = f"No sign-in for {idle} days (threshold {ctx.settings.dormant_days})."
            evidence = {"Last sign-in": u.last_sign_in.date().isoformat(), "Days inactive": idle}
        roles = ctx.roles(u.id)
        if roles:
            evidence["Directory roles"] = _role_names(roles)
        yield _user_hit(u, summary, evidence, "high" if any(r.privileged for r in roles) else None)


@rule(
    "AG-001", "Dormant member account", "medium", "Dormant accounts",
    why="Enabled accounts nobody uses are a favourite target: password-spray and phishing attacks against them go "
        "unnoticed because there is no owner to spot unusual activity. Dormant accounts with roles are worse.",
    remediation="Confirm with the line manager or HR whether the person still needs access. Disable the account, "
                "remove group memberships and roles, then delete it after your retention period.",
    requires=("sign_in_activity",),
)
def dormant_members(ctx: Context) -> Iterator[Hit]:
    yield from _dormant(ctx, "Member")


@rule(
    "AG-002", "Dormant guest account", "medium", "Dormant accounts",
    why="Guest accounts often outlive the project or contract they were created for, leaving outsiders with "
        "access to Teams, SharePoint and apps long after the relationship ends.",
    remediation="Ask the inviting team to confirm the guest is still needed. Remove guests that are not, and "
                "consider Entra access reviews for guests on a quarterly cycle.",
    requires=("sign_in_activity",),
)
def dormant_guests(ctx: Context) -> Iterator[Hit]:
    yield from _dormant(ctx, "Guest")


# --- Privileged access -------------------------------------------------------

@rule(
    "AG-003", "Privileged account without MFA", "critical", "Privileged access",
    why="An administrator protected only by a password can be taken over with a single phished or reused credential, "
        "giving an attacker control of the tenant.",
    remediation="Require the user to register phishing-resistant MFA (FIDO2 or Windows Hello for Business) and enforce "
                "it for all admin roles with a Conditional Access policy.",
    requires=("mfa_registration", "directory_roles"),
)
def privileged_without_mfa(ctx: Context) -> Iterator[Hit]:
    for u in ctx.snap.users:
        priv = [r for r in ctx.roles(u.id) if r.privileged]
        if not u.account_enabled or not priv or u.mfa_registered is not False:
            continue
        yield _user_hit(
            u,
            f"Holds {', '.join(_role_names(priv))} but has no MFA method registered.",
            {"Directory roles": _role_names(priv), "Registered methods": u.mfa_methods or "None"},
        )


@rule(
    "AG-004", "Too many Global Administrators", "high", "Privileged access",
    why="Every Global Administrator can do anything in the tenant. Microsoft recommends fewer than five, including "
        "break-glass accounts; each additional one widens the blast radius of a single compromise.",
    remediation="Move day-to-day admins to least-privileged roles (User, Exchange, Intune Administrator and so on) and "
                "use Privileged Identity Management so Global Administrator is activated only when needed.",
    requires=("directory_roles",),
)
def too_many_global_admins(ctx: Context) -> Iterator[Hit]:
    users = {u.id: u for u in ctx.snap.users}
    holders: dict[str, str] = {}
    for r in ctx.snap.role_assignments:
        if r.role_template_id != GLOBAL_ADMIN_TEMPLATE and r.role_name != "Global Administrator":
            continue
        user = users.get(r.principal_id)
        if user is not None and not user.account_enabled:
            continue
        holders[r.principal_id] = r.principal_name
    limit = ctx.settings.max_global_admins
    if len(holders) > limit:
        yield Hit(
            "tenant", "tenant", ctx.snap.tenant_name,
            f"{len(holders)} principals hold Global Administrator (target: {limit} or fewer, including break-glass).",
            {"Count": len(holders), "Global Administrators": sorted(holders.values())},
            key="too-many-global-admins",
        )


@rule(
    "AG-005", "Guest account holds an admin role", "high", "Privileged access",
    why="Guests are managed by another organisation: you cannot see their device posture, offboarding or password "
        "hygiene, yet a privileged role gives them administrative control of your tenant.",
    remediation="Replace the guest's role with a named, cloud-only account in your tenant, or a time-bound PIM "
                "assignment with approval, and remove the standing role.",
    requires=("directory_roles",),
)
def privileged_guest(ctx: Context) -> Iterator[Hit]:
    for u in ctx.snap.users:
        priv = [r for r in ctx.roles(u.id) if r.privileged]
        if u.account_enabled and u.user_type == "Guest" and priv:
            yield _user_hit(u, f"Guest holds {', '.join(_role_names(priv))}.", {"Directory roles": _role_names(priv)},
                            "critical" if any(r.critical for r in priv) else None)


@rule(
    "AG-006", "Admin role on an on-premises synced account", "medium", "Privileged access",
    why="If Active Directory is compromised, an attacker who controls a synced account also controls its cloud "
        "admin role. Microsoft recommends cloud-only accounts for privileged roles.",
    remediation="Create a separate cloud-only admin account (for example admin.name@tenant.onmicrosoft.com) "
                "with phishing-resistant MFA and move the role to it.",
    requires=("directory_roles",),
)
def privileged_synced(ctx: Context) -> Iterator[Hit]:
    for u in ctx.snap.users:
        priv = [r for r in ctx.roles(u.id) if r.privileged]
        if u.account_enabled and u.on_prem_synced and priv:
            yield _user_hit(u, f"Synced from Active Directory and holds {', '.join(_role_names(priv))}.",
                            {"Directory roles": _role_names(priv), "Source": "On-premises AD (synced)"},
                            "high" if any(r.critical for r in priv) else None)


@rule(
    "AG-007", "Disabled account still holds roles", "low", "Privileged access",
    why="Leftover role assignments on disabled accounts become live the moment the account is re-enabled, "
        "and they clutter the evidence you show auditors.",
    remediation="Remove the role assignments as part of the leaver process, then delete the account after "
                "your retention period.",
    requires=("directory_roles",),
)
def disabled_with_roles(ctx: Context) -> Iterator[Hit]:
    for u in ctx.snap.users:
        roles = ctx.roles(u.id)
        if not u.account_enabled and roles:
            yield _user_hit(u, f"Disabled, but still assigned {', '.join(_role_names(roles))}.",
                            {"Directory roles": _role_names(roles), "Account": "Disabled"})


# --- Non-human identities ----------------------------------------------------

def _sp_evidence(ctx: Context, sp: ServicePrincipal) -> dict[str, Any]:
    return {
        "App ID": sp.app_id,
        "Publisher": "Third-party (multi-tenant app)" if ctx.is_third_party(sp) else "This tenant",
        "Possible AI agent": "Yes (heuristic)" if sp.is_ai_agent else "No",
    }


@rule(
    "AG-008", "App with high-risk Microsoft Graph permissions", "critical", "Non-human identities",
    why="Application permissions work without any signed-in user, so whoever holds the app's secret or certificate "
        "has this access around the clock. Some permissions are a direct path to Global Administrator.",
    remediation="Confirm the business need with the app owner. Replace broad permissions with narrower ones "
                "(for example Sites.Selected instead of Sites.Read.All), rotate credentials, and remove the app "
                "if it is no longer used.",
    requires=("app_permissions",),
)
def risky_app_permissions(ctx: Context) -> Iterator[Hit]:
    for sp in ctx.snap.service_principals:
        if ctx.is_first_party(sp):
            continue
        critical = sorted(p for p in sp.app_permissions if p in CRITICAL_APP_PERMISSIONS)
        high = sorted(p for p in sp.app_permissions if p in HIGH_APP_PERMISSIONS)
        if not critical and not high:
            continue
        if critical:
            summary = f"Can escalate privileges via {', '.join(critical)}."
        else:
            summary = f"Has broad data or write access: {', '.join(high)}."
        evidence = {"Critical permissions": critical or "None", "High-risk permissions": high or "None", **_sp_evidence(ctx, sp)}
        yield Hit(sp.id, "servicePrincipal", sp.display_name, summary, evidence, "critical" if critical else "high")


@rule(
    "AG-009", "App holds a directory role", "high", "Non-human identities",
    why="A directory role on a service principal is a standing, credential-based admin that never does MFA and "
        "is rarely reviewed. Privileged roles on apps are a common persistence technique after a breach.",
    remediation="Replace the role with scoped Graph permissions or an administrative unit, and alert on any sign-in "
                "by this service principal from unexpected locations.",
    requires=("directory_roles",),
)
def app_with_directory_role(ctx: Context) -> Iterator[Hit]:
    for sp in ctx.snap.service_principals:
        roles = ctx.roles(sp.id)
        if not roles or ctx.is_first_party(sp):
            continue
        severity = "critical" if any(r.critical for r in roles) else "high" if any(r.privileged for r in roles) else "medium"
        yield Hit(sp.id, "servicePrincipal", sp.display_name,
                  f"Service principal is assigned {', '.join(_role_names(roles))}.",
                  {"Directory roles": _role_names(roles), **_sp_evidence(ctx, sp)}, severity)


@rule(
    "AG-010", "App credential expired or expiring", "medium", "Credential hygiene",
    why="Expiring credentials cause outages when nobody is watching; expired ones left attached show the app is "
        "not actively maintained and clutter the credential inventory.",
    remediation="Rotate expiring credentials before the expiry date and remove expired ones. Prefer certificates or "
                "managed identities / workload identity federation over client secrets.",
)
def credential_expiry(ctx: Context) -> Iterator[Hit]:
    warn = ctx.settings.credential_expiry_warning_days
    for app in ctx.snap.applications:
        for c in app.credentials:
            if c.end is None:
                continue
            kind = "Client secret" if c.kind == "secret" else "Certificate"
            label = c.display_name or "(unnamed)"
            if c.end < ctx.now:
                severity, summary = "low", f"{kind} '{label}' expired {(ctx.now - c.end).days} days ago but is still attached."
            elif (c.end - ctx.now).days <= warn:
                severity, summary = "medium", f"{kind} '{label}' expires in {(c.end - ctx.now).days} days."
            else:
                continue
            yield Hit(app.id, "application", app.display_name, summary,
                      {"Credential": kind, "Name": label, "Key ID": c.key_id, "Expires": c.end.date().isoformat()},
                      severity, key=c.key_id)


@rule(
    "AG-011", "Long-lived client secret", "medium", "Credential hygiene",
    why="A secret that is valid for years gives a leaked credential years of usefulness. Short lifetimes force "
        "rotation and limit how long a stolen secret works.",
    remediation="Replace the secret with a certificate, a managed identity or workload identity federation. If a "
                "secret is unavoidable, set a lifetime of 6–12 months and enforce it with an app management policy.",
)
def long_lived_secret(ctx: Context) -> Iterator[Hit]:
    limit = ctx.settings.max_secret_lifetime_days
    for app in ctx.snap.applications:
        for c in app.credentials:
            if c.kind != "secret" or not c.start or not c.end or c.end < ctx.now:
                continue
            lifetime = (c.end - c.start).days
            if lifetime > limit:
                yield Hit(app.id, "application", app.display_name,
                          f"Client secret '{c.display_name or '(unnamed)'}' is valid for {lifetime} days (limit {limit}).",
                          {"Name": c.display_name or "(unnamed)", "Key ID": c.key_id,
                           "Created": c.start.date().isoformat(), "Expires": c.end.date().isoformat(), "Lifetime (days)": lifetime},
                          key=c.key_id)


@rule(
    "AG-012", "App registration has no owner", "medium", "Ownership",
    why="Without an owner nobody is accountable for rotating credentials, reviewing permissions or retiring the app, "
        "and there is no one to ask when an auditor or incident responder needs answers.",
    remediation="Assign at least two owners (a person and a backup) and record the business owner in your CMDB or "
                "the app's notes field.",
    requires=("app_owners",),
)
def app_without_owner(ctx: Context) -> Iterator[Hit]:
    agent_app_ids = {sp.app_id for sp in ctx.snap.service_principals if sp.is_ai_agent}
    for app in ctx.snap.applications:
        if app.owners == [] and app.app_id not in agent_app_ids:  # agents are covered by AG-014
            yield Hit(app.id, "application", app.display_name, "No owners are assigned to this app registration.",
                      {"App ID": app.app_id, "Credentials": len(app.credentials)})


@rule(
    "AG-013", "Tenant-wide consent to high-risk delegated permissions", "high", "Consent",
    why="Admin consent for all users lets the app act as any user who signs in to it, for example reading every "
        "user's mail or files. Illicit consent grants are a common phishing technique.",
    remediation="Review whether the app is still needed. Revoke the grant (Enterprise applications → Permissions) and "
                "restrict user consent to verified publishers with low-risk permissions.",
    requires=("delegated_grants",),
)
def risky_admin_consent(ctx: Context) -> Iterator[Hit]:
    for sp in ctx.snap.service_principals:
        risky = sorted(s for s in sp.delegated_admin_consent if s in HIGH_RISK_DELEGATED)
        if risky and not ctx.is_first_party(sp):
            yield Hit(sp.id, "servicePrincipal", sp.display_name,
                      f"Admin-consented for all users: {', '.join(risky)}.",
                      {"High-risk scopes": risky, "All consented scopes": sp.delegated_admin_consent, **_sp_evidence(ctx, sp)})


@rule(
    "AG-014", "AI agent with no accountable owner", "high", "AI agent governance",
    why="AI agents act autonomously with the permissions they are given. An agent with no owner has nobody "
        "approving its access, reviewing its activity or switching it off when the use case ends.",
    remediation="Assign a business owner and a technical owner, document the agent's purpose and data access, and "
                "review its permissions against what the agent actually needs.",
    requires=("app_owners",),
)
def agent_without_owner(ctx: Context) -> Iterator[Hit]:
    for sp in ctx.snap.service_principals:
        if not sp.is_ai_agent or ctx.is_first_party(sp):
            continue
        app = ctx.apps_by_app_id.get(sp.app_id)
        if app is None or app.owners != []:
            continue
        yield Hit(sp.id, "servicePrincipal", sp.display_name,
                  "Looks like an AI agent or bot and has no owner assigned.",
                  {"Graph permissions": sp.app_permissions or "None", **_sp_evidence(ctx, sp)})


# --- Anomaly detection -------------------------------------------------------

@rule(
    "AG-100", "Non-human identity is over-privileged compared with its peers", "medium", "Anomaly detection",
    why="Most service principals in a tenant need little access. One whose privilege score sits far above its peers "
        "is either doing something unusual or was granted more than it needs — both deserve a closer look.",
    remediation="Compare the identity's permissions with what it actually calls (sign-in and audit logs), remove "
                "unused permissions, and record the justification for whatever remains.",
    requires=("app_permissions",),
)
def privilege_outlier(ctx: Context) -> Iterator[Hit]:
    peers = [sp for sp in ctx.snap.service_principals if not ctx.is_first_party(sp)]
    weights = {sp.id: privilege_weight(sp, ctx.roles(sp.id)) for sp in peers}
    scores = robust_z_scores(weights)
    if not scores:
        return
    baseline = median(weights.values())
    by_id = {sp.id: sp for sp in peers}
    for sp_id, z in scores.items():
        if z < ctx.settings.anomaly_threshold or weights[sp_id] < 8:
            continue
        sp = by_id[sp_id]
        yield Hit(sp.id, "servicePrincipal", sp.display_name,
                  f"Privilege score {weights[sp_id]:.1f} against a peer median of {baseline:.1f} (robust z = {z:.1f}).",
                  {"Privilege score": round(weights[sp_id], 1), "Peer median": round(baseline, 1),
                   "Robust z-score": round(z, 2), "Peer group size": len(peers),
                   "Graph permissions": sp.app_permissions or "None", **_sp_evidence(ctx, sp)})
