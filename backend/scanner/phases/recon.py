"""Phase 1 – Recon: wafw00f, nmap, whatweb."""
from __future__ import annotations

import asyncio
from typing import AsyncIterator, Callable

from backend.scanner.tools.base import Finding, ToolEvent
from backend.scanner.tools.wafw00f_tool import Wafw00fTool
from backend.scanner.tools.nmap_tool import NmapTool
from backend.scanner.tools.whatweb_tool import WhatwebTool


async def run_recon(
    target: str,
    emit: Callable,
    scan_id: str,
) -> dict:
    """
    Run Phase 1. Returns dict with:
    - waf_detected: bool
    - waf_name: str
    - open_ports: list[dict]
    - technologies: list[str]
    - findings: list[Finding]
    """
    result = {
        "waf_detected": False,
        "waf_name": None,
        "open_ports": [],
        "technologies": [],
        "findings": [],
    }

    await emit("phase_update", {"phase": "recon", "status": "running"})

    # ── wafw00f ──────────────────────────────────────────────────────────────
    await emit("tool_status", {"tool": "wafw00f", "status": "running"})
    wafw00f = Wafw00fTool()
    if not wafw00f.available:
        await emit("tool_status", {"tool": "wafw00f", "status": "skipped",
                                   "message": "wafw00f not found"})
    else:
        async for item in wafw00f.run(target):
            if isinstance(item, Finding):
                result["findings"].append(item)
                if item.raw.get("waf_detected"):
                    result["waf_detected"] = True
                    result["waf_name"] = item.raw.get("waf_name")
            else:
                await emit("log", {"tool": "wafw00f", "stream": item.stream, "data": item.data})
        await emit("tool_status", {"tool": "wafw00f", "status": "done"})

    await emit("waf_detected", {
        "detected": result["waf_detected"],
        "name": result["waf_name"] or "",
        "message": (
            f"WAF detected: {result['waf_name']} — increasing rate limits"
            if result["waf_detected"] else "No WAF detected"
        ),
    })

    # ── nmap ─────────────────────────────────────────────────────────────────
    await emit("tool_status", {"tool": "nmap", "status": "running"})
    nmap = NmapTool()
    if not nmap.available:
        await emit("tool_status", {"tool": "nmap", "status": "skipped",
                                   "message": "nmap not found"})
    else:
        xml_lines = []
        async for item in nmap.run(target):
            if isinstance(item, Finding):
                result["findings"].append(item)
                if "open port" in item.name.lower():
                    port_info = item.raw
                    if port_info:
                        result["open_ports"].append(port_info)
            else:
                await emit("log", {"tool": "nmap", "stream": item.stream, "data": item.data})
        await emit("tool_status", {"tool": "nmap", "status": "done"})

    # ── whatweb ───────────────────────────────────────────────────────────────
    await emit("tool_status", {"tool": "whatweb", "status": "running"})
    whatweb = WhatwebTool()
    if not whatweb.available:
        await emit("tool_status", {"tool": "whatweb", "status": "skipped",
                                   "message": "whatweb not found"})
    else:
        async for item in whatweb.run(target):
            if isinstance(item, Finding):
                result["findings"].append(item)
                if item.raw.get("technologies"):
                    result["technologies"] = item.raw["technologies"]
            else:
                await emit("log", {"tool": "whatweb", "stream": item.stream, "data": item.data})
        await emit("tool_status", {"tool": "whatweb", "status": "done"})

    await emit("phase_update", {"phase": "recon", "status": "completed",
                                "data": {
                                    "waf_detected": result["waf_detected"],
                                    "waf_name": result["waf_name"],
                                    "ports_count": len(result["open_ports"]),
                                    "tech_count": len(result["technologies"]),
                                }})
    return result
