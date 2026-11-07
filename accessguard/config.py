"""Runtime configuration, loaded from environment variables (and a .env file if present)."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_AGENT_KEYWORDS: tuple[str, ...] = (
    "agent",
    "copilot",
    "gpt",
    "openai",
    "llm",
    "chatbot",
    "bot",
    "ai",
    "claude",
    "gemini",
    "anthropic",
    "assistant",
)


def _str(name: str) -> str | None:
    value = os.getenv(name, "").strip()
    return value or None


def _int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a whole number, got {raw!r}") from exc
    if value < 0:
        raise ValueError(f"{name} must not be negative")
    return value


def _float(name: str, default: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number, got {raw!r}") from exc


@dataclass
class Settings:
    # Microsoft Entra app registration (read-only)
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    cert_path: str | None = None
    cert_thumbprint: str | None = None

    # Storage
    data_dir: Path = Path("data")

    # Rule thresholds
    dormant_days: int = 90
    never_signed_in_grace_days: int = 30
    credential_expiry_warning_days: int = 30
    max_secret_lifetime_days: int = 365
    max_global_admins: int = 4
    anomaly_threshold: float = 3.5

    # Web UI protection
    ui_username: str = "admin"
    ui_password: str | None = None

    # Heuristic keywords used to flag service principals that look like AI agents
    agent_keywords: tuple[str, ...] = DEFAULT_AGENT_KEYWORDS

    @property
    def uses_certificate(self) -> bool:
        return bool(self.cert_path and self.cert_thumbprint)

    @property
    def graph_configured(self) -> bool:
        return bool(self.tenant_id and self.client_id and (self.client_secret or self.uses_certificate))


def load_settings(env_file: str | None = ".env") -> Settings:
    """Build Settings from the environment. Values in a .env file never override real env vars."""
    if env_file:
        try:
            from dotenv import load_dotenv
        except ImportError:  # pragma: no cover - python-dotenv is a declared dependency
            pass
        else:
            load_dotenv(env_file, override=False)

    keywords_raw = _str("ACCESSGUARD_AGENT_KEYWORDS")
    keywords = (
        tuple(k.strip().lower() for k in keywords_raw.split(",") if k.strip())
        if keywords_raw
        else DEFAULT_AGENT_KEYWORDS
    )

    return Settings(
        tenant_id=_str("AZURE_TENANT_ID"),
        client_id=_str("AZURE_CLIENT_ID"),
        client_secret=_str("AZURE_CLIENT_SECRET"),
        cert_path=_str("AZURE_CLIENT_CERT_PATH"),
        cert_thumbprint=_str("AZURE_CLIENT_CERT_THUMBPRINT"),
        data_dir=Path(_str("ACCESSGUARD_DATA_DIR") or "data"),
        dormant_days=_int("ACCESSGUARD_DORMANT_DAYS", 90),
        never_signed_in_grace_days=_int("ACCESSGUARD_NEVER_SIGNED_IN_GRACE_DAYS", 30),
        credential_expiry_warning_days=_int("ACCESSGUARD_CREDENTIAL_EXPIRY_WARNING_DAYS", 30),
        max_secret_lifetime_days=_int("ACCESSGUARD_MAX_SECRET_LIFETIME_DAYS", 365),
        max_global_admins=_int("ACCESSGUARD_MAX_GLOBAL_ADMINS", 4),
        anomaly_threshold=_float("ACCESSGUARD_ANOMALY_THRESHOLD", 3.5),
        ui_username=_str("ACCESSGUARD_UI_USERNAME") or "admin",
        ui_password=_str("ACCESSGUARD_UI_PASSWORD"),
        agent_keywords=keywords,
    )
