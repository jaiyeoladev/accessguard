"""Plain data models for a tenant snapshot and the findings produced from it."""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
SEVERITY_WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}

_FRACTION = re.compile(r"\.(\d+)")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_dt(value: Any) -> datetime | None:
    """Parse Graph timestamps (which can carry 7 fractional digits and a trailing Z)."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).strip().replace("Z", "+00:00")
    text = _FRACTION.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), text, count=1)
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    if dt.year < 1900:  # Graph uses 0001-01-01 for "never"
        return None
    return dt


@dataclass
class User:
    id: str
    display_name: str
    upn: str
    user_type: str = "Member"
    account_enabled: bool = True
    created: datetime | None = None
    last_sign_in: datetime | None = None
    on_prem_synced: bool = False
    mfa_registered: bool | None = None  # None = unknown (report not available)
    mfa_methods: list[str] = field(default_factory=list)
    department: str | None = None
    job_title: str | None = None


@dataclass
class ServicePrincipal:
    id: str
    app_id: str
    display_name: str
    account_enabled: bool = True
    sp_type: str = "Application"
    owner_tenant_id: str | None = None
    tags: list[str] = field(default_factory=list)
    created: datetime | None = None
    app_permissions: list[str] = field(default_factory=list)  # Microsoft Graph application permissions
    delegated_admin_consent: list[str] = field(default_factory=list)  # tenant-wide delegated scopes
    is_ai_agent: bool = False


@dataclass
class Credential:
    kind: str  # "secret" | "certificate"
    key_id: str
    display_name: str | None = None
    start: datetime | None = None
    end: datetime | None = None


@dataclass
class Application:
    id: str
    app_id: str
    display_name: str
    created: datetime | None = None
    credentials: list[Credential] = field(default_factory=list)
    owners: list[str] | None = None  # None = owners could not be read


@dataclass
class RoleAssignment:
    principal_id: str
    principal_type: str  # "user" | "servicePrincipal" | "group" | "unknown"
    principal_name: str
    role_id: str
    role_name: str
    role_template_id: str
    privileged: bool = False
    critical: bool = False
    scope: str = "/"


@dataclass
class TenantSnapshot:
    tenant_id: str
    tenant_name: str
    collected_at: datetime
    source: str  # "graph" | "demo" | "test"
    users: list[User] = field(default_factory=list)
    service_principals: list[ServicePrincipal] = field(default_factory=list)
    applications: list[Application] = field(default_factory=list)
    role_assignments: list[RoleAssignment] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    capabilities: dict[str, bool] = field(default_factory=dict)


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    object_id: str
    object_type: str
    object_name: str
    summary: str
    why: str
    remediation: str
    evidence: dict[str, Any] = field(default_factory=dict)
    key: str = ""

    @property
    def fingerprint(self) -> str:
        """Stable id so review decisions carry across scans."""
        raw = f"{self.rule_id}|{self.object_id}|{self.key}".encode()
        return hashlib.sha256(raw).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        data = _jsonable(asdict(self))
        data["fingerprint"] = self.fingerprint
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(**{k: v for k, v in data.items() if k != "fingerprint"})


# --- serialisation ---------------------------------------------------------

def _jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


def snapshot_to_dict(snapshot: TenantSnapshot) -> dict[str, Any]:
    return _jsonable(asdict(snapshot))


def snapshot_from_dict(data: dict[str, Any]) -> TenantSnapshot:
    users = [
        User(**{**u, "created": parse_dt(u.get("created")), "last_sign_in": parse_dt(u.get("last_sign_in"))})
        for u in data.get("users", [])
    ]
    sps = [ServicePrincipal(**{**s, "created": parse_dt(s.get("created"))}) for s in data.get("service_principals", [])]
    apps = []
    for a in data.get("applications", []):
        creds = [
            Credential(**{**c, "start": parse_dt(c.get("start")), "end": parse_dt(c.get("end"))})
            for c in a.get("credentials", [])
        ]
        apps.append(Application(**{**a, "created": parse_dt(a.get("created")), "credentials": creds}))
    roles = [RoleAssignment(**r) for r in data.get("role_assignments", [])]
    return TenantSnapshot(
        tenant_id=data["tenant_id"],
        tenant_name=data["tenant_name"],
        collected_at=parse_dt(data["collected_at"]) or utcnow(),
        source=data.get("source", "graph"),
        users=users,
        service_principals=sps,
        applications=apps,
        role_assignments=roles,
        warnings=list(data.get("warnings", [])),
        capabilities=dict(data.get("capabilities", {})),
    )
