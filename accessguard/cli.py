"""Command-line interface: `accessguard scan | report | serve | rules | check-permissions`."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .catalog import REQUIRED_PERMISSIONS, excessive_permissions
from .config import load_settings
from .engine import run_scan, status_of
from .models import SEVERITIES, SEVERITY_ORDER
from .rules import RULES
from .storage import Store

LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def _cmd_scan(args, settings) -> int:
    if not args.demo and not settings.graph_configured:
        print("No tenant configured. Fill in .env (see docs/entra-setup.md) or run with --demo.", file=sys.stderr)
        return 1
    from .graph_client import AuthError, GraphError

    try:
        snap, findings = run_scan(settings, demo=args.demo)
    except (AuthError, GraphError) as exc:
        print(f"Scan failed: {exc}", file=sys.stderr)
        return 1
    store = Store(settings.data_dir)
    scan_id = store.save_scan(snap, findings)
    reviews = store.reviews()
    open_findings = [f for f in findings if status_of(f, reviews) == "open"]

    print(f"Scan #{scan_id} · {snap.tenant_name} · {len(snap.users)} users, {len(snap.service_principals)} service principals")
    for warning in snap.warnings:
        print(f"  ! {warning}")
    counts = {s: sum(1 for f in open_findings if f.severity == s) for s in SEVERITIES}
    print("  Open findings: " + ", ".join(f"{counts[s]} {s}" for s in SEVERITIES if counts[s]) if open_findings else "  No open findings.")
    for f in open_findings[: args.top]:
        print(f"  [{f.severity.upper():8}] {f.rule_id} {f.object_name}: {f.summary}")
    if len(open_findings) > args.top:
        print(f"  … and {len(open_findings) - args.top} more. Run `accessguard serve` to review them.")

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] <= threshold for f in open_findings):
            return 2
    return 0


def _cmd_report(args, settings) -> int:
    from .report import render_csv, render_html, render_json

    store = Store(settings.data_dir)
    scan = store.latest_scan()
    if scan is None:
        print("No scans yet. Run `accessguard scan` first.", file=sys.stderr)
        return 1
    snap, findings, reviews, log = store.load_snapshot(scan), store.findings_for(scan.id), store.reviews(), store.review_log()
    if args.format == "html":
        body = render_html(scan, snap, findings, reviews, log)
    elif args.format == "csv":
        body = render_csv(findings, reviews)
    else:
        body = render_json(scan, snap, findings, reviews, log)
    out = Path(args.out or f"accessguard-evidence-scan{scan.id}.{args.format}")
    out.write_text(body, encoding="utf-8")
    print(f"Wrote {out}")
    return 0


def _cmd_serve(args, settings) -> int:
    if args.host not in LOOPBACK and not settings.ui_password:
        print("Refusing to listen on a non-local address without a password. "
              "Set ACCESSGUARD_UI_PASSWORD (and ACCESSGUARD_UI_USERNAME) first.", file=sys.stderr)
        return 1
    import uvicorn

    from .web.app import create_app

    store = Store(settings.data_dir)
    if args.demo and store.latest_scan() is None:
        snap, findings = run_scan(settings, demo=True)
        store.save_scan(snap, findings)
    print(f"AccessGuard {__version__} on http://{args.host}:{args.port}")
    uvicorn.run(create_app(settings, store), host=args.host, port=args.port, log_level="info", server_header=False)
    return 0


def _cmd_rules(args, settings) -> int:
    for r in RULES:
        needs = f"  (needs {', '.join(r.requires)})" if r.requires else ""
        print(f"{r.id}  {r.severity:<8}  {r.category:<22}  {r.title}{needs}")
    return 0


def _cmd_check(args, settings) -> int:
    from .graph_client import AuthError, GraphClient

    try:
        granted = sorted(GraphClient(settings).granted_app_roles())
    except AuthError as exc:
        print(exc, file=sys.stderr)
        return 1
    print("Permissions in the token:", ", ".join(granted) or "(none)")
    missing = [p for p, _ in REQUIRED_PERMISSIONS if p not in granted]
    extra = excessive_permissions(granted)
    if missing:
        print("Missing (some checks will be skipped):", ", ".join(missing))
    if extra:
        print("Not needed — remove to stay least-privilege:", ", ".join(extra))
    if not missing and not extra:
        print("Permissions look right.")
    return 1 if extra else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="accessguard", description="Read-only identity security for Microsoft Entra ID.")
    parser.add_argument("--version", action="version", version=f"AccessGuard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", help="Scan the tenant (or a demo tenant) and store the results")
    p.add_argument("--demo", action="store_true", help="Use the built-in fictional tenant")
    p.add_argument("--top", type=int, default=15, help="How many findings to print")
    p.add_argument("--fail-on", choices=SEVERITIES, help="Exit with code 2 if any open finding is at or above this severity")
    p.set_defaults(func=_cmd_scan)

    p = sub.add_parser("report", help="Export the latest scan as an evidence report")
    p.add_argument("--format", choices=("html", "csv", "json"), default="html")
    p.add_argument("--out", help="Output file path")
    p.set_defaults(func=_cmd_report)

    p = sub.add_parser("serve", help="Start the web dashboard")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--demo", action="store_true", help="Load a demo scan if no scans exist yet")
    p.set_defaults(func=_cmd_serve)

    sub.add_parser("rules", help="List the risk rules").set_defaults(func=_cmd_rules)
    sub.add_parser("check-permissions", help="Show which Graph permissions the app registration holds").set_defaults(func=_cmd_check)

    args = parser.parse_args(argv)
    try:
        settings = load_settings()
    except ValueError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 1
    return args.func(args, settings)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
