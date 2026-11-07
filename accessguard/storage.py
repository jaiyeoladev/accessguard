"""Local storage: scan history and findings in SQLite, raw snapshots as private JSON files,
and an append-only log of every review decision (the audit trail)."""
from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import Finding, TenantSnapshot, snapshot_from_dict, snapshot_to_dict, utcnow

STATUSES: dict[str, str] = {
    "open": "Open",
    "acknowledged": "Acknowledged",
    "remediated": "Remediated",
    "accepted_risk": "Risk accepted",
    "false_positive": "False positive",
}
NEEDS_JUSTIFICATION = {"accepted_risk", "false_positive"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at TEXT NOT NULL,
    tenant_id TEXT,
    tenant_name TEXT,
    source TEXT NOT NULL,
    snapshot_file TEXT NOT NULL,
    finding_count INTEGER NOT NULL,
    warnings TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS findings (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (scan_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS reviews (
    fingerprint TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    justification TEXT,
    reviewer TEXT,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS review_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL,
    rule_id TEXT,
    object_name TEXT,
    status TEXT NOT NULL,
    justification TEXT,
    reviewer TEXT,
    at TEXT NOT NULL
);
"""


@dataclass
class ScanRecord:
    id: int
    collected_at: str
    tenant_id: str | None
    tenant_name: str | None
    source: str
    snapshot_file: str
    finding_count: int
    warnings: list[str]


def validate_review(status: str, justification: str, reviewer: str) -> str | None:
    """Return an error message, or None if the review decision is valid."""
    if status not in STATUSES:
        return "Choose a valid status."
    if not reviewer.strip():
        return "Enter the reviewer's name so the decision is attributable."
    if len(reviewer) > 120:
        return "Reviewer name is too long."
    if len(justification) > 2000:
        return "Justification must be 2,000 characters or fewer."
    if status in NEEDS_JUSTIFICATION and not justification.strip():
        return f"A justification is required when marking a finding as '{STATUSES[status]}'."
    return None


class Store:
    def __init__(self, data_dir: Path | str):
        self.data_dir = Path(data_dir)
        self.snapshot_dir = self.data_dir / "snapshots"
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.data_dir / "accessguard.db"
        with self._conn() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def _write_private(path: Path, text: str) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)

    # -- scans ----------------------------------------------------------------

    def save_scan(self, snap: TenantSnapshot, findings: list[Finding]) -> int:
        now = utcnow().isoformat()
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO scans (collected_at, tenant_id, tenant_name, source, snapshot_file, finding_count, warnings)"
                " VALUES (?, ?, ?, ?, '', ?, ?)",
                (snap.collected_at.isoformat(), snap.tenant_id, snap.tenant_name, snap.source, len(findings),
                 json.dumps(snap.warnings)),
            )
            scan_id = int(cur.lastrowid)
            filename = f"scan-{scan_id}.json"
            conn.execute("UPDATE scans SET snapshot_file = ? WHERE id = ?", (filename, scan_id))
            conn.executemany(
                "INSERT OR IGNORE INTO findings (scan_id, fingerprint, rule_id, severity, data) VALUES (?, ?, ?, ?, ?)",
                [(scan_id, f.fingerprint, f.rule_id, f.severity, json.dumps(f.to_dict())) for f in findings],
            )
            # A finding marked remediated that is still detected is reopened, with a log entry.
            for f in findings:
                row = conn.execute("SELECT status FROM reviews WHERE fingerprint = ?", (f.fingerprint,)).fetchone()
                if row and row["status"] == "remediated":
                    note = f"Reopened automatically: still detected in scan #{scan_id}."
                    conn.execute(
                        "UPDATE reviews SET status = 'open', justification = ?, reviewer = 'AccessGuard', updated_at = ?"
                        " WHERE fingerprint = ?", (note, now, f.fingerprint))
                    conn.execute(
                        "INSERT INTO review_log (fingerprint, rule_id, object_name, status, justification, reviewer, at)"
                        " VALUES (?, ?, ?, 'open', ?, 'AccessGuard', ?)", (f.fingerprint, f.rule_id, f.object_name, note, now))
        self._write_private(self.snapshot_dir / filename, json.dumps(snapshot_to_dict(snap)))
        return scan_id

    @staticmethod
    def _record(row: sqlite3.Row) -> ScanRecord:
        return ScanRecord(
            id=row["id"], collected_at=row["collected_at"], tenant_id=row["tenant_id"], tenant_name=row["tenant_name"],
            source=row["source"], snapshot_file=row["snapshot_file"], finding_count=row["finding_count"],
            warnings=json.loads(row["warnings"] or "[]"),
        )

    def list_scans(self, limit: int = 100) -> list[ScanRecord]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [self._record(r) for r in rows]

    def latest_scan(self) -> ScanRecord | None:
        scans = self.list_scans(1)
        return scans[0] if scans else None

    def previous_scan(self, scan_id: int) -> ScanRecord | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id < ? ORDER BY id DESC LIMIT 1", (scan_id,)).fetchone()
        return self._record(row) if row else None

    def load_snapshot(self, scan: ScanRecord) -> TenantSnapshot:
        path = self.snapshot_dir / Path(scan.snapshot_file).name
        return snapshot_from_dict(json.loads(path.read_text(encoding="utf-8")))

    def findings_for(self, scan_id: int) -> list[Finding]:
        with self._conn() as conn:
            rows = conn.execute("SELECT data FROM findings WHERE scan_id = ? ORDER BY rowid", (scan_id,)).fetchall()
        return [Finding.from_dict(json.loads(r["data"])) for r in rows]

    def fingerprints(self, scan_id: int) -> set[str]:
        with self._conn() as conn:
            rows = conn.execute("SELECT fingerprint FROM findings WHERE scan_id = ?", (scan_id,)).fetchall()
        return {r["fingerprint"] for r in rows}

    # -- reviews --------------------------------------------------------------

    def reviews(self) -> dict[str, dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM reviews").fetchall()
        return {r["fingerprint"]: dict(r) for r in rows}

    def set_review(self, finding: Finding, status: str, justification: str, reviewer: str) -> None:
        error = validate_review(status, justification, reviewer)
        if error:
            raise ValueError(error)
        now = utcnow().isoformat()
        justification, reviewer = justification.strip(), reviewer.strip()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO reviews (fingerprint, status, justification, reviewer, updated_at) VALUES (?, ?, ?, ?, ?)"
                " ON CONFLICT(fingerprint) DO UPDATE SET status = excluded.status,"
                " justification = excluded.justification, reviewer = excluded.reviewer, updated_at = excluded.updated_at",
                (finding.fingerprint, status, justification, reviewer, now),
            )
            conn.execute(
                "INSERT INTO review_log (fingerprint, rule_id, object_name, status, justification, reviewer, at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (finding.fingerprint, finding.rule_id, finding.object_name, status, justification, reviewer, now),
            )

    def review_log(self, fingerprint: str | None = None, limit: int = 1000) -> list[dict[str, Any]]:
        with self._conn() as conn:
            if fingerprint:
                rows = conn.execute("SELECT * FROM review_log WHERE fingerprint = ? ORDER BY id DESC LIMIT ?",
                                    (fingerprint, limit)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM review_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]
