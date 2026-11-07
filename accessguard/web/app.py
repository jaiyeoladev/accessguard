"""FastAPI web dashboard.

Security posture: binds to localhost by default, optional HTTP Basic auth (required when
exposed beyond localhost), CSRF token on every form, strict Content-Security-Policy and
no third-party assets.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import __version__
from ..catalog import MICROSOFT_TENANT_ID, REQUIRED_PERMISSIONS
from ..config import Settings, load_settings
from ..engine import identity_scores, run_scan, skipped_rules, status_of, summarize
from ..formatting import register
from ..graph_client import AuthError, GraphError
from ..models import SEVERITIES, Finding, TenantSnapshot
from ..report import render_csv, render_html, render_json
from ..rules import RULES
from ..storage import STATUSES, ScanRecord, Store, validate_review

HERE = Path(__file__).parent
CSP = ("default-src 'self'; style-src 'self'; img-src 'self' data:; script-src 'none'; form-action 'self'; "
       "frame-ancestors 'none'; base-uri 'none'")
REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'none'"


@dataclass
class State:
    scan: ScanRecord
    snap: TenantSnapshot
    findings: list[Finding]
    reviews: dict[str, dict[str, Any]]

    def status(self, finding: Finding) -> str:
        return status_of(finding, self.reviews)


def create_app(settings: Settings | None = None, store: Store | None = None) -> FastAPI:
    settings = settings or load_settings()
    store = store or Store(settings.data_dir)
    csrf_token = secrets.token_urlsafe(32)
    basic = HTTPBasic(auto_error=False)

    templates = Jinja2Templates(directory=str(HERE / "templates"))
    register(templates.env)
    templates.env.globals.update(version=__version__, statuses=STATUSES, severities=SEVERITIES)

    def challenge() -> None:
        raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate": 'Basic realm="AccessGuard"'})

    def require_auth(credentials: HTTPBasicCredentials | None = Depends(basic)) -> None:
        if not settings.ui_password:
            return
        if credentials is None:
            challenge()
        user_ok = secrets.compare_digest(credentials.username.encode(), settings.ui_username.encode())
        pass_ok = secrets.compare_digest(credentials.password.encode(), settings.ui_password.encode())
        if not (user_ok and pass_ok):
            challenge()

    def check_csrf(token: str) -> None:
        if not secrets.compare_digest(token.encode(), csrf_token.encode()):
            raise HTTPException(403, "Invalid form token. Reload the page and try again.")

    def load_state() -> State | None:
        scan = store.latest_scan()
        if scan is None:
            return None
        return State(scan, store.load_snapshot(scan), store.findings_for(scan.id), store.reviews())

    def render(request: Request, name: str, status_code: int = 200, **context: Any) -> HTMLResponse:
        base = {"csrf_token": csrf_token, "graph_configured": settings.graph_configured, "latest": store.latest_scan(),
                "nav": name.removesuffix(".html")}
        return templates.TemplateResponse(request, name, {**base, **context}, status_code=status_code)

    app = FastAPI(title="AccessGuard", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", CSP)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if not request.url.path.startswith("/static/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> PlainTextResponse:
        return PlainTextResponse("ok")

    router = APIRouter(dependencies=[Depends(require_auth)])

    @router.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        state = load_state()
        if state is None:
            return render(request, "empty.html", permissions=REQUIRED_PERMISSIONS)
        summary = summarize(state.snap, state.findings, state.reviews)
        scores = identity_scores(summary["open_findings"])
        top_identities = sorted(scores.items(), key=lambda kv: (-kv[1]["score"], kv[1]["name"].lower()))[:8]
        previous = store.previous_scan(state.scan.id)
        delta = None
        if previous:
            now_fps, before = {f.fingerprint for f in state.findings}, store.fingerprints(previous.id)
            delta = {"new": len(now_fps - before), "resolved": len(before - now_fps), "previous": previous}
        categories: dict[str, int] = {}
        for f in summary["open_findings"]:
            categories[f.category] = categories.get(f.category, 0) + 1
        return render(request, "dashboard.html", state=state, summary=summary, top_identities=top_identities,
                      top_findings=summary["open_findings"][:8], delta=delta, skipped=skipped_rules(state.snap),
                      categories=sorted(categories.items(), key=lambda kv: -kv[1]))

    @router.post("/scan")
    def scan(request: Request, csrf: str = Form(...), mode: str = Form("demo")):
        check_csrf(csrf)
        if mode not in ("demo", "live"):
            raise HTTPException(400, "Unknown scan mode.")
        if mode == "live" and not settings.graph_configured:
            return render(request, "error.html", 400, title="Tenant not connected",
                          message="Add your read-only app registration details to .env, then restart AccessGuard.")
        try:
            snap, findings = run_scan(settings, demo=(mode == "demo"))
        except (AuthError, GraphError) as exc:
            return render(request, "error.html", 502, title="Scan failed", message=str(exc))
        store.save_scan(snap, findings)
        return RedirectResponse("/", status_code=303)

    @router.get("/findings", response_class=HTMLResponse)
    def findings_page(request: Request, severity: str = "", category: str = "", state: str = "open", q: str = ""):
        current = load_state()
        if current is None:
            return RedirectResponse("/", status_code=303)
        rows = current.findings
        if severity in SEVERITIES:
            rows = [f for f in rows if f.severity == severity]
        if category:
            rows = [f for f in rows if f.category == category]
        if state in STATUSES:
            rows = [f for f in rows if current.status(f) == state]
        if q.strip():
            needle = q.strip().lower()
            rows = [f for f in rows if needle in f.object_name.lower() or needle in f.title.lower()
                    or needle in f.summary.lower() or needle == f.rule_id.lower()]
        categories = sorted({f.category for f in current.findings})
        return render(request, "findings.html", state_obj=current, rows=rows, categories=categories,
                      filters={"severity": severity, "category": category, "state": state, "q": q})

    def find(current: State | None, fingerprint: str) -> Finding:
        if current is not None:
            for f in current.findings:
                if f.fingerprint == fingerprint:
                    return f
        raise HTTPException(404, "Finding not found in the latest scan.")

    @router.get("/findings/{fingerprint}", response_class=HTMLResponse)
    def finding_detail(request: Request, fingerprint: str):
        current = load_state()
        finding = find(current, fingerprint)
        return render(request, "finding.html", f=finding, review=current.reviews.get(fingerprint),
                      status=current.status(finding), history=store.review_log(fingerprint), error=None, form={})

    @router.post("/findings/{fingerprint}/review")
    def review(request: Request, fingerprint: str, csrf: str = Form(...), decision: str = Form(...),
               reviewer: str = Form(""), justification: str = Form("")):
        check_csrf(csrf)
        current = load_state()
        finding = find(current, fingerprint)
        error = validate_review(decision, justification, reviewer)
        if error:
            return render(request, "finding.html", 400, f=finding, review=current.reviews.get(fingerprint),
                          status=current.status(finding), history=store.review_log(fingerprint), error=error,
                          form={"decision": decision, "reviewer": reviewer, "justification": justification})
        store.set_review(finding, decision, justification, reviewer)
        return RedirectResponse(f"/findings/{fingerprint}", status_code=303)

    @router.get("/identities", response_class=HTMLResponse)
    def identities(request: Request, kind: str = "users", q: str = ""):
        current = load_state()
        if current is None:
            return RedirectResponse("/", status_code=303)
        open_findings = [f for f in current.findings if current.status(f) == "open"]
        scores = identity_scores(open_findings)
        roles: dict[str, list[str]] = {}
        for r in current.snap.role_assignments:
            roles.setdefault(r.principal_id, []).append(r.role_name)
        needle = q.strip().lower()
        if kind == "nonhuman":
            items = [sp for sp in current.snap.service_principals if sp.owner_tenant_id != MICROSOFT_TENANT_ID]
            if needle:
                items = [sp for sp in items if needle in sp.display_name.lower() or needle in sp.app_id.lower()]
            rows = [{"obj": sp, "roles": sorted(set(roles.get(sp.id, []))), "score": scores.get(sp.id, {}).get("score", 0),
                     "count": scores.get(sp.id, {}).get("count", 0),
                     "third_party": sp.owner_tenant_id not in (None, current.snap.tenant_id)} for sp in items]
        else:
            kind = "users"
            items = current.snap.users
            if needle:
                items = [u for u in items if needle in u.display_name.lower() or needle in u.upn.lower()]
            rows = [{"obj": u, "roles": sorted(set(roles.get(u.id, []))), "score": scores.get(u.id, {}).get("score", 0),
                     "count": scores.get(u.id, {}).get("count", 0)} for u in items]
        rows.sort(key=lambda r: (-r["score"], r["obj"].display_name.lower()))
        return render(request, "identities.html", kind=kind, rows=rows, q=q, state_obj=current)

    @router.get("/scans", response_class=HTMLResponse)
    def scans(request: Request):
        return render(request, "scans.html", scans=store.list_scans(), rules=RULES, log=store.review_log(limit=50))

    def export_state() -> State:
        current = load_state()
        if current is None:
            raise HTTPException(404, "Run a scan first.")
        return current

    def filename(current: State, ext: str) -> str:
        stamp = current.scan.collected_at[:10]
        return f"accessguard-evidence-{stamp}-scan{current.scan.id}.{ext}"

    @router.get("/export/report.html")
    def export_html(download: int = 0):
        current = export_state()
        html = render_html(current.scan, current.snap, current.findings, current.reviews, store.review_log())
        headers = {"Content-Security-Policy": REPORT_CSP}
        if download:
            headers["Content-Disposition"] = f'attachment; filename="{filename(current, "html")}"'
        return HTMLResponse(html, headers=headers)

    @router.get("/export/report.csv")
    def export_csv():
        current = export_state()
        return Response(render_csv(current.findings, current.reviews), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="{filename(current, "csv")}"'})

    @router.get("/export/report.json")
    def export_json():
        current = export_state()
        body = render_json(current.scan, current.snap, current.findings, current.reviews, store.review_log())
        return Response(body, media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{filename(current, "json")}"'})

    app.include_router(router)
    return app
