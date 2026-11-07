"""Collect a read-only snapshot of a Microsoft Entra ID tenant through Microsoft Graph.

Every optional data source degrades gracefully: if a permission or licence is missing,
the snapshot records a warning and a capability flag, and the rules that depend on that
data are skipped rather than producing misleading results.
"""
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, Protocol

from .catalog import GRAPH_APP_ID, classify_role, excessive_permissions, looks_like_ai_agent
from .config import Settings
from .graph_client import GraphError
from .models import Application, Credential, RoleAssignment, ServicePrincipal, TenantSnapshot, User, parse_dt

SOFT_FAIL = {400, 403, 404}

USER_FIELDS = [
    "id",
    "displayName",
    "userPrincipalName",
    "userType",
    "accountEnabled",
    "createdDateTime",
    "onPremisesSyncEnabled",
    "department",
    "jobTitle",
]


class GraphReader(Protocol):
    def get(self, path_or_url: str, params: dict[str, str] | None = None) -> dict[str, Any]: ...
    def get_all(self, path: str, params: dict[str, str] | None = None) -> list[dict[str, Any]]: ...
    def granted_app_roles(self) -> list[str]: ...


def _optional(fn: Callable[[], Any], cap: str, caps: dict[str, bool], warnings: list[str], message: str) -> Any:
    try:
        result = fn()
    except GraphError as exc:
        if exc.status not in SOFT_FAIL:
            raise
        caps[cap] = False
        warnings.append(f"{message} (Graph returned {exc.status}: {exc.message})")
        return None
    caps[cap] = True
    return result


def collect(client: GraphReader, settings: Settings, now: datetime | None = None) -> TenantSnapshot:
    now = now or datetime.now(timezone.utc)
    warnings: list[str] = []
    caps: dict[str, bool] = {}

    try:
        extra = excessive_permissions(client.granted_app_roles())
    except Exception:  # the self-check must never block a scan
        extra = []
    if extra:
        warnings.append(
            "AccessGuard only needs read-only permissions, but its app registration also holds: "
            + ", ".join(extra)
            + ". Remove these to keep the scanner least-privilege."
        )

    tenant_id = settings.tenant_id or "unknown"
    tenant_name = tenant_id
    org = _optional(
        lambda: client.get("/organization", {"$select": "id,displayName"}),
        "organization", caps, warnings, "Tenant name unavailable",
    )
    if org and org.get("value"):
        tenant_name = org["value"][0].get("displayName") or tenant_name

    users = _collect_users(client, caps, warnings)
    _apply_mfa(client, users, caps, warnings)
    sps = _collect_service_principals(client, settings, caps, warnings)
    apps = _collect_applications(client, caps, warnings)
    roles = _collect_roles(client, users, sps, caps, warnings)

    return TenantSnapshot(
        tenant_id=tenant_id,
        tenant_name=tenant_name,
        collected_at=now,
        source="graph",
        users=users,
        service_principals=sps,
        applications=apps,
        role_assignments=roles,
        warnings=warnings,
        capabilities=caps,
    )


def _last_sign_in(activity: dict[str, Any]) -> datetime | None:
    successful = parse_dt(activity.get("lastSuccessfulSignInDateTime"))
    if successful:
        return successful
    candidates = [
        parse_dt(activity.get("lastSignInDateTime")),
        parse_dt(activity.get("lastNonInteractiveSignInDateTime")),
    ]
    return max((c for c in candidates if c), default=None)


def _collect_users(client: GraphReader, caps: dict[str, bool], warnings: list[str]) -> list[User]:
    try:
        raw = client.get_all("/users", {"$select": ",".join(USER_FIELDS + ["signInActivity"]), "$top": "500"})
        caps["sign_in_activity"] = True
    except GraphError as exc:
        if exc.status not in SOFT_FAIL:
            raise
        caps["sign_in_activity"] = False
        warnings.append(
            "Sign-in activity is unavailable — it needs the AuditLog.Read.All permission and Entra ID P1/P2. "
            "Dormant-account checks were skipped."
        )
        raw = client.get_all("/users", {"$select": ",".join(USER_FIELDS), "$top": "999"})

    users = []
    for r in raw:
        users.append(
            User(
                id=r["id"],
                display_name=r.get("displayName") or r.get("userPrincipalName") or r["id"],
                upn=r.get("userPrincipalName") or "",
                user_type=r.get("userType") or "Member",
                account_enabled=r.get("accountEnabled") is not False,
                created=parse_dt(r.get("createdDateTime")),
                last_sign_in=_last_sign_in(r.get("signInActivity") or {}),
                on_prem_synced=bool(r.get("onPremisesSyncEnabled")),
                department=r.get("department"),
                job_title=r.get("jobTitle"),
            )
        )
    return users


def _apply_mfa(client: GraphReader, users: list[User], caps: dict[str, bool], warnings: list[str]) -> None:
    rows = _optional(
        lambda: client.get_all("/reports/authenticationMethods/userRegistrationDetails"),
        "mfa_registration", caps, warnings,
        "MFA registration details are unavailable — they need AuditLog.Read.All, "
        "UserAuthenticationMethod.Read.All and Entra ID P1/P2. MFA checks were skipped",
    )
    if not rows:
        return
    by_id = {r.get("id"): r for r in rows}
    for user in users:
        row = by_id.get(user.id)
        if row is not None:
            user.mfa_registered = bool(row.get("isMfaRegistered"))
            user.mfa_methods = list(row.get("methodsRegistered") or [])


def _collect_service_principals(
    client: GraphReader, settings: Settings, caps: dict[str, bool], warnings: list[str]
) -> list[ServicePrincipal]:
    raw = client.get_all(
        "/servicePrincipals",
        {
            "$select": "id,appId,displayName,accountEnabled,servicePrincipalType,appOwnerOrganizationId,tags,createdDateTime",
            "$top": "999",
        },
    )
    sps: dict[str, ServicePrincipal] = {}
    for r in raw:
        sps[r["id"]] = ServicePrincipal(
            id=r["id"],
            app_id=r.get("appId") or "",
            display_name=r.get("displayName") or r.get("appId") or r["id"],
            account_enabled=r.get("accountEnabled") is not False,
            sp_type=r.get("servicePrincipalType") or "Application",
            owner_tenant_id=r.get("appOwnerOrganizationId"),
            tags=list(r.get("tags") or []),
            created=parse_dt(r.get("createdDateTime")),
        )

    graph = next((r for r in raw if r.get("appId") == GRAPH_APP_ID), None)
    if graph is None:
        caps["app_permissions"] = False
        caps["delegated_grants"] = False
        warnings.append("The Microsoft Graph service principal was not found, so app permission checks were skipped.")
    else:
        detail = client.get(f"/servicePrincipals/{graph['id']}", {"$select": "id,appRoles"})
        role_values = {ar.get("id"): ar.get("value") for ar in detail.get("appRoles", [])}
        assigned = _optional(
            lambda: client.get_all(f"/servicePrincipals/{graph['id']}/appRoleAssignedTo", {"$top": "999"}),
            "app_permissions", caps, warnings, "Application permission assignments could not be read",
        )
        for a in assigned or []:
            if a.get("principalType") != "ServicePrincipal":
                continue
            sp = sps.get(a.get("principalId"))
            value = role_values.get(a.get("appRoleId"))
            if sp and value and value not in sp.app_permissions:
                sp.app_permissions.append(value)

        grants = _optional(
            lambda: client.get_all("/oauth2PermissionGrants"),
            "delegated_grants", caps, warnings, "Delegated consent grants could not be read",
        )
        for g in grants or []:
            if g.get("consentType") != "AllPrincipals" or g.get("resourceId") != graph["id"]:
                continue
            sp = sps.get(g.get("clientId"))
            if not sp:
                continue
            for scope in (g.get("scope") or "").split():
                if scope not in sp.delegated_admin_consent:
                    sp.delegated_admin_consent.append(scope)

    for sp in sps.values():
        sp.app_permissions.sort()
        sp.delegated_admin_consent.sort()
        sp.is_ai_agent = looks_like_ai_agent(sp.display_name, sp.tags, sp.sp_type, settings.agent_keywords)
    return list(sps.values())


def _credentials(r: dict[str, Any]) -> list[Credential]:
    creds = []
    for c in r.get("passwordCredentials") or []:
        creds.append(
            Credential("secret", c.get("keyId") or "", c.get("displayName"),
                       parse_dt(c.get("startDateTime")), parse_dt(c.get("endDateTime")))
        )
    for c in r.get("keyCredentials") or []:
        creds.append(
            Credential("certificate", c.get("keyId") or "", c.get("displayName"),
                       parse_dt(c.get("startDateTime")), parse_dt(c.get("endDateTime")))
        )
    return creds


def _collect_applications(client: GraphReader, caps: dict[str, bool], warnings: list[str]) -> list[Application]:
    select = "id,appId,displayName,createdDateTime,passwordCredentials,keyCredentials"
    try:
        raw = client.get_all("/applications", {"$select": select, "$expand": "owners($select=id,displayName)"})
        caps["app_owners"] = True
        with_owners = True
    except GraphError as exc:
        if exc.status not in SOFT_FAIL:
            raise
        caps["app_owners"] = False
        with_owners = False
        warnings.append("Application owners could not be read, so ownership checks were skipped.")
        raw = client.get_all("/applications", {"$select": select, "$top": "999"})

    apps = []
    for r in raw:
        owners = None
        if with_owners:
            owners = [o.get("displayName") or o.get("userPrincipalName") or o.get("id") for o in r.get("owners") or []]
        apps.append(
            Application(
                id=r["id"],
                app_id=r.get("appId") or "",
                display_name=r.get("displayName") or r["id"],
                created=parse_dt(r.get("createdDateTime")),
                credentials=_credentials(r),
                owners=owners,
            )
        )
    return apps


def _collect_roles(
    client: GraphReader, users: list[User], sps: list[ServicePrincipal], caps: dict[str, bool], warnings: list[str]
) -> list[RoleAssignment]:
    message = "Directory roles are unavailable — they need RoleManagement.Read.Directory. Privileged-access checks were skipped"
    definitions = _optional(
        lambda: client.get_all("/roleManagement/directory/roleDefinitions"), "directory_roles", caps, warnings, message
    )
    if definitions is None:
        return []
    def_by_id = {d["id"]: d for d in definitions}

    path = "/roleManagement/directory/roleAssignments"
    try:
        raw = client.get_all(path, {"$select": "id,principalId,roleDefinitionId,directoryScopeId"})
    except GraphError as exc:
        if exc.status == 403:
            caps["directory_roles"] = False
            warnings.append(f"{message} (Graph returned 403: {exc.message})")
            return []
        if exc.status != 400:
            raise
        # Some tenants require a filter when listing assignments — fall back to one call per role.
        raw = []
        for d in definitions:
            raw.extend(client.get_all(path, {"$filter": f"roleDefinitionId eq '{d['id']}'"}))

    users_by_id = {u.id: u for u in users}
    sps_by_id = {s.id: s for s in sps}
    resolved: dict[str, tuple[str, str]] = {}

    def resolve(pid: str) -> tuple[str, str]:
        if pid in users_by_id:
            return "user", users_by_id[pid].upn or users_by_id[pid].display_name
        if pid in sps_by_id:
            return "servicePrincipal", sps_by_id[pid].display_name
        if pid not in resolved:
            try:
                obj = client.get(f"/directoryObjects/{pid}")
                odata_type = (obj.get("@odata.type") or "").rsplit(".", 1)[-1]
                kind = "group" if odata_type == "group" else odata_type or "unknown"
                resolved[pid] = (kind, obj.get("displayName") or pid)
            except GraphError:
                resolved[pid] = ("unknown", pid)
        return resolved[pid]

    assignments = []
    for a in raw:
        pid = a.get("principalId")
        if not pid:
            continue
        definition = def_by_id.get(a.get("roleDefinitionId"), {})
        template = definition.get("templateId") or definition.get("id") or a.get("roleDefinitionId") or ""
        name = definition.get("displayName") or template
        privileged, critical = classify_role(template, name, definition.get("isPrivileged"))
        ptype, pname = resolve(pid)
        assignments.append(
            RoleAssignment(
                principal_id=pid,
                principal_type=ptype,
                principal_name=pname,
                role_id=a.get("roleDefinitionId") or template,
                role_name=name,
                role_template_id=template,
                privileged=privileged,
                critical=critical,
                scope=a.get("directoryScopeId") or "/",
            )
        )
    return assignments
