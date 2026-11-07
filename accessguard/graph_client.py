"""A deliberately read-only Microsoft Graph client.

The client exposes GET only — there is no code path in AccessGuard that can change
anything in a tenant. It authenticates with the OAuth 2.0 client-credentials flow via
MSAL, follows @odata.nextLink paging and honours Retry-After on throttling.
"""
from __future__ import annotations

import base64
import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import requests

from .config import Settings

GRAPH_HOST = "https://graph.microsoft.com/"
GRAPH_ROOT = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
RETRY_STATUSES = {429, 500, 502, 503, 504}
MAX_RETRIES = 5


class AuthError(Exception):
    """Could not obtain a token — configuration or credential problem."""


class GraphError(Exception):
    def __init__(self, status: int, message: str, url: str = ""):
        super().__init__(f"Microsoft Graph request failed ({status}): {message}")
        self.status = status
        self.message = message
        self.url = url


def _error_message(resp: requests.Response) -> str:
    try:
        body = resp.json()
        err = body.get("error", {}) if isinstance(body, dict) else {}
        return err.get("message") or err.get("code") or resp.reason or "error"
    except ValueError:
        return (resp.text or "")[:200] or resp.reason or "error"


def _retry_after(resp: requests.Response, attempt: int) -> float:
    header = resp.headers.get("Retry-After")
    try:
        wait = float(header) if header else 2.0 ** attempt
    except ValueError:
        wait = 2.0 ** attempt
    return max(0.0, min(wait, 60.0))


class GraphClient:
    def __init__(
        self,
        settings: Settings,
        session: requests.Session | None = None,
        token_provider: Callable[[], str] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self._session = session or requests.Session()
        self._sleep = sleep
        self._token_provider = token_provider or self._msal_provider(settings)

    @staticmethod
    def _msal_provider(settings: Settings) -> Callable[[], str]:
        if not settings.graph_configured:
            raise AuthError(
                "Microsoft Graph credentials are not configured. Set AZURE_TENANT_ID, AZURE_CLIENT_ID and "
                "AZURE_CLIENT_SECRET (or AZURE_CLIENT_CERT_PATH + AZURE_CLIENT_CERT_THUMBPRINT) in .env."
            )
        import msal

        if settings.uses_certificate:
            credential: Any = {
                "private_key": Path(settings.cert_path).read_text(encoding="utf-8"),  # type: ignore[arg-type]
                "thumbprint": settings.cert_thumbprint,
            }
        else:
            credential = settings.client_secret
        app = msal.ConfidentialClientApplication(
            settings.client_id,
            authority=f"https://login.microsoftonline.com/{settings.tenant_id}",
            client_credential=credential,
        )

        def provider() -> str:
            result = app.acquire_token_for_client(scopes=[GRAPH_SCOPE])  # MSAL caches tokens in memory
            token = result.get("access_token")
            if not token:
                detail = result.get("error_description") or result.get("error") or "unknown error"
                raise AuthError(f"Could not get a Microsoft Graph token: {detail}")
            return token

        return provider

    # -- requests -----------------------------------------------------------

    def get(self, path_or_url: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        url = path_or_url if path_or_url.startswith("https://") else f"{GRAPH_ROOT}{path_or_url}"
        if not url.startswith(GRAPH_HOST):
            # Never send the bearer token anywhere except Microsoft Graph (e.g. a tampered nextLink).
            raise GraphError(0, "Refusing to call a non-Graph URL", url)

        last_error: GraphError | None = None
        for attempt in range(MAX_RETRIES):
            headers = {"Authorization": f"Bearer {self._token_provider()}", "Accept": "application/json"}
            try:
                resp = self._session.get(url, params=params, headers=headers, timeout=60)
            except requests.RequestException as exc:
                last_error = GraphError(0, f"Network error: {exc}", url)
                self._sleep(min(2.0 ** attempt, 30.0))
                continue
            if resp.status_code in RETRY_STATUSES:
                last_error = GraphError(resp.status_code, _error_message(resp), url)
                self._sleep(_retry_after(resp, attempt))
                continue
            if resp.status_code >= 400:
                raise GraphError(resp.status_code, _error_message(resp), url)
            return resp.json()
        raise last_error or GraphError(0, "Request failed", url)

    def get_all(self, path: str, params: dict[str, str] | None = None) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        page = self.get(path, params)
        while True:
            items.extend(page.get("value", []))
            next_link = page.get("@odata.nextLink")
            if not next_link:
                return items
            page = self.get(next_link)  # nextLink already carries the query string

    def granted_app_roles(self) -> list[str]:
        """Application permissions in the current access token (used for the least-privilege self-check)."""
        token = self._token_provider()
        try:
            payload = token.split(".")[1]
            payload += "=" * (-len(payload) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload))
        except (IndexError, ValueError):
            return []
        return list(claims.get("roles", []))
