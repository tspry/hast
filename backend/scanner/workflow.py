"""Main scan orchestrator – coordinates all phases with checkpoint/resume support."""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Callable, Optional

from backend.db import database as db
from backend.scanner.phases.aggregation import run_aggregation
from backend.scanner.phases.discovery import run_discovery
from backend.scanner.phases.recon import run_recon
from backend.scanner.phases.scanning import run_scanning
from backend.scanner.tools.base import Finding

PHASES = ["recon", "discovery", "scanning", "aggregation"]

# Global registry of active scans
_active_scans: dict[str, asyncio.Task] = {}
_stop_flags: dict[str, bool] = {}


async def start_scan(
    target: str,
    profile: str,
    emit: Callable,
    scan_id: Optional[str] = None,
    resume: bool = False,
) -> str:
    """Start or resume a scan. Returns scan_id."""
    if not scan_id:
        scan_id = str(uuid.uuid4())

    # Check if a scan is already running
    for sid, task in list(_active_scans.items()):
        if not task.done():
            await emit(
                "scan_error",
                {"error": f"Scan {sid} is already running. Stop it first."},
            )
            return sid

    _stop_flags[scan_id] = False
    task = asyncio.create_task(_run_scan(scan_id, target, profile, emit, resume))
    _active_scans[scan_id] = task
    return scan_id


async def stop_scan(scan_id: str) -> bool:
    """Request scan stop. Returns True if scan was running."""
    if scan_id in _stop_flags:
        _stop_flags[scan_id] = True
    task = _active_scans.get(scan_id)
    if task and not task.done():
        task.cancel()
        return True
    return False


def is_scan_running(scan_id: str) -> bool:
    task = _active_scans.get(scan_id)
    return bool(task and not task.done())


def _should_stop(scan_id: str) -> bool:
    return _stop_flags.get(scan_id, False)


async def _run_scan(
    scan_id: str,
    target: str,
    profile: str,
    emit: Callable,
    resume: bool,
) -> None:
    """Execute full scan workflow."""
    try:
        # Create or update scan record
        existing = await db.get_scan(scan_id)
        if not existing:
            await db.create_scan(scan_id, target, profile)

        await db.update_scan(
            scan_id, status="running", started_at=datetime.now(timezone.utc).isoformat()
        )

        await emit(
            "scan_started",
            {
                "scan_id": scan_id,
                "target": target,
                "profile": profile,
            },
        )

        # Load checkpoints if resuming
        checkpoints = await db.get_checkpoints(scan_id) if resume else {}

        # ── Context carried between phases ────────────────────────────────────
        recon_result = {
            "waf_detected": False,
            "waf_name": None,
            "open_ports": [],
            "technologies": [],
            "findings": [],
        }
        discovery_result = {
            "urls": [target],
            "js_urls": [],
            "open_ports": [],
            "findings": [],
        }
        scan_findings = []

        # ── Phase 1: Recon ────────────────────────────────────────────────────
        if not (resume and checkpoints.get("recon") == "completed"):
            if _should_stop(scan_id):
                await _handle_stop(scan_id, emit)
                return
            await db.update_scan(scan_id, phase="recon")
            try:
                recon_result = await run_recon(target, emit, scan_id)
                # Persist recon findings
                for f in recon_result.get("findings", []):
                    await db.insert_finding(
                        {
                            "id": str(uuid.uuid4()),
                            "scan_id": scan_id,
                            "tool": f.tool,
                            "severity": f.severity,
                            "name": f.name,
                            "url": f.url,
                            "evidence": f.evidence,
                            "remediation": f.remediation,
                            "cvss_score": f.cvss_score,
                            "risk_score": f.risk_score(),
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "is_new": True,
                        }
                    )
                await db.save_checkpoint(
                    scan_id,
                    "recon",
                    "completed",
                    {
                        "waf_detected": recon_result["waf_detected"],
                        "waf_name": recon_result["waf_name"],
                        "open_ports": recon_result["open_ports"],
                        "technologies": recon_result["technologies"],
                    },
                )
            except asyncio.CancelledError:
                await _handle_stop(scan_id, emit)
                return
            except Exception as exc:
                await emit(
                    "log",
                    {
                        "tool": "scanner",
                        "stream": "error",
                        "data": f"[recon] Phase error: {exc}",
                    },
                )
                await db.save_checkpoint(scan_id, "recon", "failed")

        # ── Phase 2: Discovery (skip for quick profile) ───────────────────────
        if profile != "quick":
            if not (resume and checkpoints.get("discovery") == "completed"):
                if _should_stop(scan_id):
                    await _handle_stop(scan_id, emit)
                    return
                await db.update_scan(scan_id, phase="discovery")
                try:
                    discovery_result = await run_discovery(
                        target, profile, emit, scan_id
                    )
                    await db.insert_urls(
                        scan_id, discovery_result["urls"], "crawler", False
                    )
                    await db.insert_urls(
                        scan_id, discovery_result["js_urls"], "crawler", True
                    )
                    for f in discovery_result.get("findings", []):
                        await db.insert_finding(
                            {
                                "id": str(uuid.uuid4()),
                                "scan_id": scan_id,
                                "tool": f.tool,
                                "severity": f.severity,
                                "name": f.name,
                                "url": f.url,
                                "evidence": f.evidence,
                                "remediation": f.remediation,
                                "cvss_score": f.cvss_score,
                                "risk_score": f.risk_score(),
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "is_new": True,
                            }
                        )
                    recon_result["open_ports"].extend(
                        discovery_result.get("open_ports", [])
                    )
                    await db.save_checkpoint(
                        scan_id,
                        "discovery",
                        "completed",
                        {
                            "urls_count": len(discovery_result["urls"]),
                            "js_urls_count": len(discovery_result["js_urls"]),
                            "open_ports_count": len(
                                discovery_result.get("open_ports", [])
                            ),
                        },
                    )
                except asyncio.CancelledError:
                    await _handle_stop(scan_id, emit)
                    return
                except Exception as exc:
                    await emit(
                        "log",
                        {
                            "tool": "scanner",
                            "stream": "error",
                            "data": f"[discovery] Phase error: {exc}",
                        },
                    )
                    await db.save_checkpoint(scan_id, "discovery", "failed")
                    # Use just the target URL if discovery failed
                    discovery_result = {
                        "urls": [target],
                        "js_urls": [],
                        "open_ports": [],
                        "findings": [],
                    }
            else:
                # Load from DB on resume
                discovery_result["urls"] = await db.get_urls(scan_id)
                discovery_result["js_urls"] = await db.get_urls(scan_id, js_only=True)

            # Load persisted findings so discovery results are included in aggregation.
            scan_findings = [
                _row_to_finding(row) for row in await db.get_findings(scan_id)
            ]

        # ── Phase 3: Scanning ─────────────────────────────────────────────────
        if not (resume and checkpoints.get("scanning") == "completed"):
            if _should_stop(scan_id):
                await _handle_stop(scan_id, emit)
                return
            await db.update_scan(scan_id, phase="scanning")
            try:
                new_scan_findings = await run_scanning(
                    target=target,
                    urls=discovery_result["urls"],
                    js_urls=discovery_result["js_urls"],
                    profile=profile,
                    waf_detected=recon_result["waf_detected"],
                    open_ports=recon_result["open_ports"],
                    emit=emit,
                    scan_id=scan_id,
                )
                scan_findings.extend(new_scan_findings)
                await db.save_checkpoint(
                    scan_id,
                    "scanning",
                    "completed",
                    {"findings_count": len(scan_findings)},
                )
            except asyncio.CancelledError:
                await _handle_stop(scan_id, emit)
                return
            except Exception as exc:
                await emit(
                    "log",
                    {
                        "tool": "scanner",
                        "stream": "error",
                        "data": f"[scanning] Phase error: {exc}",
                    },
                )
                await db.save_checkpoint(scan_id, "scanning", "failed")

        # ── Phase 4: Aggregation ──────────────────────────────────────────────
        await db.update_scan(scan_id, phase="aggregation")
        try:
            final_findings = await run_aggregation(
                scan_id=scan_id,
                target=target,
                recon_findings=recon_result.get("findings", []),
                scan_findings=scan_findings,
                emit=emit,
            )
            await db.save_checkpoint(scan_id, "aggregation", "completed")
        except Exception as exc:
            await emit(
                "log",
                {
                    "tool": "scanner",
                    "stream": "error",
                    "data": f"[aggregation] Phase error: {exc}",
                },
            )
            final_findings = []

        # ── Finalize ──────────────────────────────────────────────────────────
        # Compute severity counts
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        new_count = 0
        for f in final_findings:
            sev = f.get("severity", "info").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            if f.get("is_new"):
                new_count += 1

        import json

        stats = {**sev_counts, "total": len(final_findings), "new": new_count}
        await db.update_scan(
            scan_id,
            status="completed",
            finished_at=datetime.now(timezone.utc).isoformat(),
            phase="done",
            waf_detected=int(recon_result["waf_detected"]),
            waf_name=recon_result.get("waf_name"),
            stats=json.dumps(stats),
        )

        await emit(
            "scan_complete",
            {
                "scan_id": scan_id,
                "stats": stats,
                "findings": final_findings[:500],  # cap payload
            },
        )

    except asyncio.CancelledError:
        await _handle_stop(scan_id, emit)
    except Exception as exc:
        await db.update_scan(
            scan_id, status="failed", finished_at=datetime.now(timezone.utc).isoformat()
        )
        await emit("scan_error", {"error": str(exc)})
    finally:
        _active_scans.pop(scan_id, None)


def _row_to_finding(row: dict) -> Finding:
    return Finding(
        tool=row.get("tool", "scanner"),
        severity=row.get("severity", "info"),
        name=row.get("name", ""),
        url=row.get("url", ""),
        evidence=row.get("evidence", ""),
        remediation=row.get("remediation", ""),
        cvss_score=row.get("cvss_score"),
        raw={},
    )


async def _handle_stop(scan_id: str, emit: Callable) -> None:
    await db.update_scan(
        scan_id, status="stopped", finished_at=datetime.now(timezone.utc).isoformat()
    )
    await emit("scan_stopped", {"scan_id": scan_id, "message": "Scan stopped by user."})
