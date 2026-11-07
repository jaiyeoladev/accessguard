"""Run rules against a snapshot and summarise the results."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from .catalog import MICROSOFT_TENANT_ID
from .config import Settings
from .models import SEVERITIES, SEVERITY_ORDER, SEVERITY_WEIGHT, Finding, TenantSnapshot
from .rules import RULES, Context, Rule


def skipped_rules(snap: TenantSnapshot) -> list[Rule]:
    return [r for r in RULES if any(not snap.capabilities.get(cap, False) for cap in r.requires)]


def evaluate(snap: TenantSnapshot, settings: Settings, now: datetime | None = None) -> list[Finding]:
    ctx = Context.build(snap, settings, now or datetime.now(timezone.utc))
    skipped = {r.id for r in skipped_rules(snap)}
    findings: list[Finding] = []
    seen: set[str] = set()
    for r in RULES:
        if r.id in skipped:
            continue
        for hit in r.func(ctx):
            finding = Finding(
                rule_id=r.id,
                title=r.title,
                severity=hit.severity or r.severity,
                category=r.category,
                object_id=hit.object_id,
                object_type=hit.object_type,
                object_name=hit.object_name,
                summary=hit.summary,
                why=r.why,
                remediation=r.remediation,
                evidence=hit.evidence,
                key=hit.key,
            )
            if finding.fingerprint not in seen:
                seen.add(finding.fingerprint)
                findings.append(finding)
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id, f.object_name.lower()))
    return findings


def run_scan(settings: Settings, demo: bool = False) -> tuple[TenantSnapshot, list[Finding]]:
    if demo:
        from .demo_data import demo_snapshot

        snap = demo_snapshot(keywords=settings.agent_keywords)
    else:
        from .collector import collect
        from .graph_client import GraphClient

        snap = collect(GraphClient(settings), settings)
    return snap, evaluate(snap, settings, snap.collected_at)


def status_of(finding: Finding, reviews: dict[str, dict[str, Any]]) -> str:
    return reviews.get(finding.fingerprint, {}).get("status", "open")


def identity_scores(findings: list[Finding]) -> dict[str, dict[str, Any]]:
    scores: dict[str, dict[str, Any]] = defaultdict(lambda: {"score": 0, "count": 0, "name": "", "type": ""})
    for f in findings:
        if f.object_type == "tenant":
            continue
        entry = scores[f.object_id]
        entry["score"] += SEVERITY_WEIGHT[f.severity]
        entry["count"] += 1
        entry["name"] = f.object_name
        entry["type"] = f.object_type
    return dict(scores)


def summarize(snap: TenantSnapshot, findings: list[Finding], reviews: dict[str, dict[str, Any]]) -> dict[str, Any]:
    open_findings = [f for f in findings if status_of(f, reviews) == "open"]
    nonhuman = [sp for sp in snap.service_principals if sp.owner_tenant_id != MICROSOFT_TENANT_ID]
    severity = {s: sum(1 for f in open_findings if f.severity == s) for s in SEVERITIES}
    return {
        "identities": len(snap.users) + len(nonhuman),
        "users": len(snap.users),
        "guests": sum(1 for u in snap.users if u.user_type == "Guest"),
        "nonhuman": len(nonhuman),
        "ai_agents": sum(1 for sp in nonhuman if sp.is_ai_agent),
        "privileged": len({r.principal_id for r in snap.role_assignments if r.privileged}),
        "dormant": len({f.object_id for f in open_findings if f.rule_id in ("AG-001", "AG-002")}),
        "open": len(open_findings),
        "reviewed": len(findings) - len(open_findings),
        "total": len(findings),
        "severity": severity,
        "status_counts": dict(Counter(status_of(f, reviews) for f in findings)),
        "open_findings": open_findings,
    }
