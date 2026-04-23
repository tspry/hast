"""Phase 4 – Aggregation: dedup, score, diff, persist."""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Callable

from backend.db import database as db
from backend.scanner.tools.base import Finding


async def run_aggregation(
    scan_id: str,
    target: str,
    recon_findings: list[Finding],
    scan_findings: list[Finding],
    emit: Callable,
) -> list[dict]:
    """Merge all findings, deduplicate, score, diff, persist. Returns list of finding dicts."""
    await emit("phase_update", {"phase": "aggregation", "status": "running"})

    all_raw = recon_findings + scan_findings

    # Load previous scan's finding keys for diff
    prev_keys = await db.get_previous_finding_keys(target)

    # Dedup by (url, name) — keep highest-risk version
    dedup: dict[str, dict] = {}
    for f in all_raw:
        key = _dedup_key(f)
        scored = _to_finding_dict(f, scan_id, prev_keys)
        if key not in dedup or scored["risk_score"] > dedup[key]["risk_score"]:
            dedup[key] = scored

    final_findings = list(dedup.values())

    # Sort by risk_score desc
    final_findings.sort(key=lambda x: x["risk_score"], reverse=True)

    # Persist to DB
    for finding in final_findings:
        await db.insert_finding(finding)

    # Compute stats
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    new_count = 0
    for f in final_findings:
        sev = f.get("severity", "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        if f.get("is_new"):
            new_count += 1

    stats = {
        "total": len(final_findings),
        "new": new_count,
        "severity_counts": severity_counts,
    }

    await emit("phase_update", {
        "phase": "aggregation",
        "status": "completed",
        "data": stats,
    })

    return final_findings


def _dedup_key(f: Finding) -> str:
    """Create dedup key from url + name."""
    raw = f"{f.url.lower().rstrip('/')}|{f.name.lower()}"
    return hashlib.md5(raw.encode()).hexdigest()


def _to_finding_dict(f: Finding, scan_id: str, prev_keys: set[str]) -> dict:
    key = f"{f.url}|{f.name}"
    is_new = key not in prev_keys

    # Risk score with bonus for verified/high-context findings
    base_score = f.risk_score()
    cvss_bonus = 0
    if f.cvss_score:
        cvss_bonus = int(f.cvss_score * 2)  # CVSS 9.0 → +18 pts

    risk_score = min(100, base_score + cvss_bonus)

    return {
        "id": str(uuid.uuid4()),
        "scan_id": scan_id,
        "tool": f.tool,
        "severity": f.severity,
        "name": f.name,
        "url": f.url,
        "evidence": f.evidence[:2000],  # cap evidence size
        "remediation": f.remediation,
        "cvss_score": f.cvss_score,
        "risk_score": risk_score,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "is_new": is_new,
    }
