"""REST API routes: scan history, findings, export, config."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse, StreamingResponse

from backend.config import get_config, save_config
from backend.db import database as db
from backend.scanner.workflow import stop_scan, is_scan_running, start_scan

router = APIRouter(prefix="/api")


# ── Scans ──────────────────────────────────────────────────────────────────────

@router.get("/scans")
async def list_scans(limit: int = Query(default=50, le=200)):
    scans = await db.list_scans(limit=limit)
    return {"scans": scans}


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@router.post("/scans/{scan_id}/stop")
async def stop_scan_endpoint(scan_id: str):
    stopped = await stop_scan(scan_id)
    return {"stopped": stopped, "scan_id": scan_id}


# ── Findings ──────────────────────────────────────────────────────────────────

@router.get("/scans/{scan_id}/findings")
async def get_findings(
    scan_id: str,
    severity: Optional[str] = None,
    tool: Optional[str] = None,
    keyword: Optional[str] = None,
):
    findings = await db.get_findings(scan_id)
    if severity:
        severities = [s.strip().lower() for s in severity.split(",")]
        findings = [f for f in findings if f["severity"].lower() in severities]
    if tool:
        findings = [f for f in findings if f["tool"].lower() == tool.lower()]
    if keyword:
        kw = keyword.lower()
        findings = [
            f for f in findings
            if kw in f["name"].lower() or kw in f["url"].lower() or kw in f["evidence"].lower()
        ]
    return {"findings": findings, "count": len(findings)}


@router.get("/scans/{scan_id}/diff")
async def get_scan_diff(scan_id: str):
    """Compare current scan with previous scan for same target."""
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    current = await db.get_findings(scan_id)
    current_keys = {f"{f['url']}|{f['name']}" for f in current}

    # Get previous scan
    all_scans = await db.list_scans(limit=100)
    target = scan["target"]
    prev_scan = None
    for s in all_scans:
        if s["id"] != scan_id and s["target"] == target and s["status"] == "completed":
            prev_scan = s
            break

    if not prev_scan:
        return {"new": current, "resolved": [], "unchanged": [], "previous_scan_id": None}

    prev_findings = await db.get_findings(prev_scan["id"])
    prev_keys = {f"{f['url']}|{f['name']}" for f in prev_findings}

    new = [f for f in current if f"{f['url']}|{f['name']}" not in prev_keys]
    resolved = [f for f in prev_findings if f"{f['url']}|{f['name']}" not in current_keys]
    unchanged = [f for f in current if f"{f['url']}|{f['name']}" in prev_keys]

    return {
        "new": new,
        "resolved": resolved,
        "unchanged": unchanged,
        "previous_scan_id": prev_scan["id"],
        "previous_scan_date": prev_scan.get("started_at"),
    }


# ── Export ────────────────────────────────────────────────────────────────────

@router.get("/scans/{scan_id}/export/json")
async def export_json(scan_id: str):
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    findings = await db.get_findings(scan_id)
    payload = json.dumps({"scan": scan, "findings": findings}, indent=2)
    return StreamingResponse(
        io.StringIO(payload),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=hast_{scan_id[:8]}.json"},
    )


@router.get("/scans/{scan_id}/export/csv")
async def export_csv(scan_id: str):
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    findings = await db.get_findings(scan_id)

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=[
        "severity", "tool", "name", "url", "risk_score",
        "cvss_score", "evidence", "remediation", "is_new", "timestamp"
    ])
    writer.writeheader()
    for f in findings:
        writer.writerow({
            "severity": f.get("severity", ""),
            "tool": f.get("tool", ""),
            "name": f.get("name", ""),
            "url": f.get("url", ""),
            "risk_score": f.get("risk_score", 0),
            "cvss_score": f.get("cvss_score", ""),
            "evidence": f.get("evidence", "")[:200],
            "remediation": f.get("remediation", ""),
            "is_new": bool(f.get("is_new", True)),
            "timestamp": f.get("timestamp", ""),
        })
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=hast_{scan_id[:8]}.csv"},
    )


@router.get("/scans/{scan_id}/export/pdf")
async def export_pdf(scan_id: str):
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    findings = await db.get_findings(scan_id)

    try:
        pdf_bytes = _generate_pdf(scan, findings)
    except ImportError:
        raise HTTPException(500, "reportlab not installed — PDF export unavailable")

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=hast_report_{scan_id[:8]}.pdf"},
    )


def _generate_pdf(scan: dict, findings: list[dict]) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=15*mm, rightMargin=15*mm,
                            topMargin=20*mm, bottomMargin=20*mm)
    styles = getSampleStyleSheet()

    SEV_COLORS = {
        "critical": colors.HexColor("#dc2626"),
        "high": colors.HexColor("#ea580c"),
        "medium": colors.HexColor("#ca8a04"),
        "low": colors.HexColor("#2563eb"),
        "info": colors.HexColor("#6b7280"),
    }

    elements = []

    # Title
    title_style = ParagraphStyle("title", parent=styles["Title"],
                                 fontSize=22, textColor=colors.HexColor("#111827"))
    elements.append(Paragraph("HAST Security Report", title_style))
    elements.append(Spacer(1, 4*mm))

    # Meta
    meta_style = styles["Normal"]
    elements.append(Paragraph(f"<b>Target:</b> {scan.get('target', 'N/A')}", meta_style))
    elements.append(Paragraph(f"<b>Profile:</b> {scan.get('profile', 'N/A')}", meta_style))
    elements.append(Paragraph(f"<b>Scan Date:</b> {scan.get('started_at', 'N/A')}", meta_style))
    elements.append(Paragraph(f"<b>Status:</b> {scan.get('status', 'N/A')}", meta_style))
    elements.append(Spacer(1, 6*mm))

    # Summary table
    stats = json.loads(scan.get("stats", "{}"))
    summary_data = [["Severity", "Count"]]
    for sev in ["critical", "high", "medium", "low", "info"]:
        summary_data.append([sev.upper(), str(stats.get(sev, 0))])
    summary_table = Table(summary_data, colWidths=[60*mm, 30*mm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 8*mm))

    # Findings
    elements.append(Paragraph("Findings", styles["Heading1"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e5e7eb")))
    elements.append(Spacer(1, 3*mm))

    for f in findings[:200]:  # cap at 200 for PDF
        sev = f.get("severity", "info").lower()
        sev_color = SEV_COLORS.get(sev, colors.gray)

        sev_style = ParagraphStyle("sev", parent=styles["Normal"],
                                   textColor=sev_color, fontName="Helvetica-Bold", fontSize=9)
        elements.append(Paragraph(f"[{sev.upper()}] {f.get('name', '')}", sev_style))

        url_style = ParagraphStyle("url", parent=styles["Normal"], fontSize=8,
                                   textColor=colors.HexColor("#4b5563"))
        elements.append(Paragraph(f"URL: {f.get('url', '')}", url_style))

        if f.get("evidence"):
            ev_text = f.get("evidence", "")[:300].replace("<", "&lt;").replace(">", "&gt;")
            elements.append(Paragraph(f"Evidence: {ev_text}", url_style))

        if f.get("remediation"):
            rem_style = ParagraphStyle("rem", parent=styles["Normal"], fontSize=8,
                                       textColor=colors.HexColor("#065f46"))
            elements.append(Paragraph(f"Fix: {f.get('remediation', '')}", rem_style))

        elements.append(Spacer(1, 3*mm))

    doc.build(elements)
    return buf.getvalue()


# ── Config ────────────────────────────────────────────────────────────────────

@router.get("/config")
async def get_config_endpoint():
    return get_config()


@router.post("/config")
async def update_config(body: dict):
    allowed_keys = {
        "nuclei_templates_path", "seclists_path", "default_profile",
        "rate_limit_ms", "waf_rate_limit_ms", "respect_robots", "tool_paths",
        "user_agents",
    }
    updates = {k: v for k, v in body.items() if k in allowed_keys}
    save_config(updates)
    return {"ok": True, "config": get_config()}


# ── Bulk Scan ─────────────────────────────────────────────────────────────────

@router.post("/bulk-scan")
async def start_bulk_scan(body: dict):
    """
    Queue a sequential bulk scan over multiple targets.
    Body: { "targets": ["https://a.com", "https://b.com"], "profile": "quick" }
    Returns list of {target, scan_id} pairs immediately — scans run sequentially in background.
    """
    targets: list[str] = body.get("targets", [])
    profile: str = body.get("profile", "quick")

    if not targets:
        raise HTTPException(400, "targets list is required")
    if len(targets) > 50:
        raise HTTPException(400, "Maximum 50 targets per bulk scan")

    # Normalise URLs
    normalised = []
    for t in targets:
        t = t.strip()
        if not t:
            continue
        if not t.startswith(("http://", "https://")):
            t = "https://" + t
        normalised.append(t)

    if not normalised:
        raise HTTPException(400, "No valid targets provided")

    import uuid
    results = []

    async def _noop_emit(event_type, data):
        pass  # bulk scan has no live WS client — results readable via /api/scans

    async def _run_bulk():
        for target in normalised:
            scan_id = str(uuid.uuid4())
            try:
                await start_scan(target=target, profile=profile,
                                 emit=_noop_emit, scan_id=scan_id)
            except Exception:
                pass

    import asyncio
    asyncio.create_task(_run_bulk())

    # Return scan IDs immediately so the client can poll
    scan_ids = []
    import uuid as _uuid
    for target in normalised:
        scan_ids.append({"target": target, "scan_id": str(_uuid.uuid4())})

    return {"queued": len(normalised), "profile": profile, "scans": scan_ids}


@router.get("/bulk-scan/summary")
async def bulk_scan_summary(targets: str = Query(..., description="Comma-separated list of targets")):
    """Return latest scan result per target for a quick multi-target overview."""
    target_list = [t.strip() for t in targets.split(",") if t.strip()]
    all_scans = await db.list_scans(limit=200)

    summary = []
    for target in target_list:
        # Find latest completed scan for this target
        match = next(
            (s for s in all_scans if s["target"] == target and s["status"] == "completed"),
            None
        )
        if not match:
            match = next((s for s in all_scans if s["target"] == target), None)

        if match:
            stats = json.loads(match.get("stats", "{}"))
            summary.append({
                "target": target,
                "scan_id": match["id"],
                "status": match["status"],
                "scanned_at": match.get("started_at"),
                "critical": stats.get("critical", 0),
                "high": stats.get("high", 0),
                "medium": stats.get("medium", 0),
                "low": stats.get("low", 0),
                "info": stats.get("info", 0),
                "total": stats.get("total", 0),
                "waf_detected": bool(match.get("waf_detected")),
            })
        else:
            summary.append({"target": target, "status": "never_scanned"})

    return {"summary": summary}


@router.get("/probe-paths/count")
async def probe_paths_count():
    from backend.scanner.tools.ffuf_tool import PRIORITY_PATHS
    return {"count": len(PRIORITY_PATHS)}


@router.get("/tools/status")
async def tools_status():
    """Return availability status of all tools."""
    from backend.config import resolve_tool_path
    tools = ["nmap", "nuclei", "katana", "gospider", "hakrawler", "gau",
             "ffuf", "trufflehog", "gitleaks", "wafw00f", "whatweb", "curl"]
    return {
        "tools": {
            t: {"available": bool(resolve_tool_path(t)), "path": resolve_tool_path(t) or "not found"}
            for t in tools
        }
    }
