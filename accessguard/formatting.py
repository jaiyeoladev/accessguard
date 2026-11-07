"""Jinja filters shared by the web UI and the exported report."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .models import parse_dt


def _as_dt(value: Any) -> datetime | None:
    return value if isinstance(value, datetime) else parse_dt(value)


def fmt_dt(value: Any) -> str:
    dt = _as_dt(value)
    return dt.astimezone(timezone.utc).strftime("%d %b %Y, %H:%M UTC") if dt else "—"


def fmt_date(value: Any) -> str:
    dt = _as_dt(value)
    return dt.strftime("%d %b %Y") if dt else "—"


def days_ago(value: Any) -> str:
    dt = _as_dt(value)
    if not dt:
        return "Never"
    days = (datetime.now(timezone.utc) - dt).days
    if days <= 0:
        return "Today"
    return f"{days} day{'s' if days != 1 else ''} ago"


def evidence_value(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value) if value else "None"
    return str(value)


TYPE_LABELS = {
    "user": "User",
    "servicePrincipal": "Service principal",
    "application": "App registration",
    "tenant": "Tenant",
    "group": "Group",
}


def register(env) -> None:
    env.filters.update(
        dt=fmt_dt,
        date=fmt_date,
        ago=days_ago,
        ev=evidence_value,
        objtype=lambda v: TYPE_LABELS.get(v, v),
    )
