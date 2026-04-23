"""Async SQLite database access layer."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

import os

import aiosqlite

from backend.db.models import CREATE_TABLES

DB_PATH = Path(os.environ.get("HAST_DB_PATH", str(Path(__file__).parent.parent.parent / "hast.db")))
_db: Optional[aiosqlite.Connection] = None


async def init_db() -> None:
    global _db
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    _db = await aiosqlite.connect(str(DB_PATH))
    _db.row_factory = aiosqlite.Row
    await _db.executescript(CREATE_TABLES)
    await _db.commit()


async def get_db() -> aiosqlite.Connection:
    if _db is None:
        await init_db()
    return _db


async def close_db() -> None:
    if _db:
        await _db.close()


# ── Scan CRUD ─────────────────────────────────────────────────────────────────

async def create_scan(scan_id: str, target: str, profile: str) -> dict:
    db = await get_db()
    await db.execute(
        "INSERT INTO scans (id, target, profile, status) VALUES (?, ?, ?, 'pending')",
        (scan_id, target, profile),
    )
    await db.commit()
    return {"id": scan_id, "target": target, "profile": profile, "status": "pending"}


async def update_scan(scan_id: str, **kwargs) -> None:
    db = await get_db()
    if not kwargs:
        return
    sets = ", ".join(f"{k} = ?" for k in kwargs)
    await db.execute(
        f"UPDATE scans SET {sets} WHERE id = ?",
        (*kwargs.values(), scan_id),
    )
    await db.commit()


async def get_scan(scan_id: str) -> Optional[dict]:
    db = await get_db()
    async with db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)) as cur:
        row = await cur.fetchone()
    return dict(row) if row else None


async def list_scans(limit: int = 50) -> list[dict]:
    db = await get_db()
    async with db.execute(
        "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
    ) as cur:
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def delete_scan(scan_id: str) -> bool:
    db = await get_db()
    await db.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
    await db.execute("DELETE FROM discovered_urls WHERE scan_id = ?", (scan_id,))
    await db.execute("DELETE FROM scan_checkpoints WHERE scan_id = ?", (scan_id,))
    cur = await db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    await db.commit()
    return cur.rowcount > 0


# ── Finding CRUD ──────────────────────────────────────────────────────────────

async def insert_finding(finding: dict) -> None:
    db = await get_db()
    await db.execute(
        """INSERT OR IGNORE INTO findings
           (id, scan_id, tool, severity, name, url, evidence, remediation,
            cvss_score, risk_score, timestamp, is_new)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            finding["id"], finding["scan_id"], finding["tool"],
            finding["severity"], finding["name"], finding["url"],
            finding.get("evidence", ""), finding.get("remediation", ""),
            finding.get("cvss_score"), finding.get("risk_score", 0),
            finding["timestamp"], int(finding.get("is_new", True)),
        ),
    )
    await db.commit()


async def get_findings(scan_id: str) -> list[dict]:
    db = await get_db()
    async with db.execute(
        "SELECT * FROM findings WHERE scan_id = ? ORDER BY risk_score DESC",
        (scan_id,),
    ) as cur:
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def get_previous_finding_keys(target: str) -> set[str]:
    """Return set of 'url|name' from the most recent completed scan for target."""
    db = await get_db()
    async with db.execute(
        """SELECT f.url, f.name FROM findings f
           JOIN scans s ON s.id = f.scan_id
           WHERE s.target = ? AND s.status = 'completed'
           ORDER BY s.started_at DESC LIMIT 1000""",
        (target,),
    ) as cur:
        rows = await cur.fetchall()
    return {f"{r['url']}|{r['name']}" for r in rows}


# ── URL CRUD ──────────────────────────────────────────────────────────────────

async def insert_urls(scan_id: str, urls: list[str], source: str, is_js: bool = False) -> None:
    db = await get_db()
    data = [(scan_id, url, source, int(is_js)) for url in urls]
    await db.executemany(
        "INSERT OR IGNORE INTO discovered_urls (scan_id, url, source, is_js) VALUES (?, ?, ?, ?)",
        data,
    )
    await db.commit()


async def get_urls(scan_id: str, js_only: bool = False) -> list[str]:
    db = await get_db()
    q = "SELECT url FROM discovered_urls WHERE scan_id = ?"
    params: list[Any] = [scan_id]
    if js_only:
        q += " AND is_js = 1"
    async with db.execute(q, params) as cur:
        rows = await cur.fetchall()
    return [r["url"] for r in rows]


# ── Checkpoint CRUD ───────────────────────────────────────────────────────────

async def save_checkpoint(scan_id: str, phase: str, status: str, data: dict = None) -> None:
    db = await get_db()
    await db.execute(
        """INSERT OR REPLACE INTO scan_checkpoints (scan_id, phase, status, data)
           VALUES (?, ?, ?, ?)""",
        (scan_id, phase, status, json.dumps(data or {})),
    )
    await db.commit()


async def get_checkpoints(scan_id: str) -> dict[str, str]:
    db = await get_db()
    async with db.execute(
        "SELECT phase, status FROM scan_checkpoints WHERE scan_id = ?", (scan_id,)
    ) as cur:
        rows = await cur.fetchall()
    return {r["phase"]: r["status"] for r in rows}
