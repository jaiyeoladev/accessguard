"""Audit evidence exports: a printable HTML evidence pack, CSV and JSON."""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import __version__
from .catalog import REQUIRED_PERMISSIONS
from .engine import skipped_rules, status_of, summarize
from .formatting import register
from .models import SEVERITIES, Finding, TenantSnapshot, utcnow
from .storage import STATUSES, ScanRecord

TEMPLATES = Path(__file__).parent / "web" / "templates"


def _env() -> Environment:
    env = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=select_autoescape(["html"]))
    register(env)
    return env


def render_html(scan: ScanRecord, snap: TenantSnapshot, findings: list[Finding],
                reviews: dict[str, dict[str, Any]], log: list[dict[str, Any]]) -> str:
    grouped = {s: [f for f in findings if f.severity == s] for s in SEVERITIES}
    matrix = {s: {st: sum(1 for f in grouped[s] if status_of(f, reviews) == st) for st in STATUSES} for s in SEVERITIES}
    return _env().get_template("report.html").render(
        scan=scan, snap=snap, findings=findings, grouped=grouped, matrix=matrix, reviews=reviews, log=log,
        summary=summarize(snap, findings, reviews), skipped=skipped_rules(snap),
        permissions=REQUIRED_PERMISSIONS, statuses=STATUSES, severities=SEVERITIES,
        status_of=lambda f: status_of(f, reviews), generated_at=utcnow(), version=__version__,
    )


def _safe_cell(value: Any) -> str:
    """Neutralise spreadsheet formula injection from tenant-controlled names."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


CSV_COLUMNS = ["Fingerprint", "Rule", "Title", "Severity", "Category", "Object type", "Object", "Summary", "Evidence",
               "Status", "Reviewer", "Justification", "Reviewed at"]


def render_csv(findings: list[Finding], reviews: dict[str, dict[str, Any]]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(CSV_COLUMNS)
    for f in findings:
        review = reviews.get(f.fingerprint, {})
        evidence = "; ".join(f"{k}: {', '.join(map(str, v)) if isinstance(v, list) else v}" for k, v in f.evidence.items())
        writer.writerow([_safe_cell(v) for v in (
            f.fingerprint, f.rule_id, f.title, f.severity, f.category, f.object_type, f.object_name, f.summary, evidence,
            STATUSES.get(status_of(f, reviews), "Open"), review.get("reviewer", ""), review.get("justification", ""),
            review.get("updated_at", ""),
        )])
    return out.getvalue()


def render_json(scan: ScanRecord, snap: TenantSnapshot, findings: list[Finding],
                reviews: dict[str, dict[str, Any]], log: list[dict[str, Any]]) -> str:
    summary = summarize(snap, findings, reviews)
    summary.pop("open_findings")
    payload = {
        "generator": f"AccessGuard {__version__}",
        "generated_at": utcnow().isoformat(),
        "scan": {"id": scan.id, "collected_at": scan.collected_at, "tenant_id": scan.tenant_id,
                 "tenant_name": scan.tenant_name, "source": scan.source, "warnings": scan.warnings},
        "summary": summary,
        "skipped_rules": [r.id for r in skipped_rules(snap)],
        "findings": [{**f.to_dict(), "review": reviews.get(f.fingerprint) or {"status": "open"}} for f in findings],
        "review_log": log,
    }
    return json.dumps(payload, indent=2)
