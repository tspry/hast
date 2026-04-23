"""Phase 3 – Scanning: nuclei, ffuf, secret scanning."""
from __future__ import annotations

import asyncio
from typing import Callable

from backend.config import get_rate_limit_ms
from backend.scanner.tools.base import Finding, ToolEvent
from backend.scanner.tools.nuclei_tool import NucleiTool
from backend.scanner.tools.ffuf_tool import FfufTool
from backend.scanner.tools.secret_tools import (
    TrufflehogTool, GitleaksTool, fetch_js_and_scan
)
from backend.scanner.tools.curl_tool import CurlTool


async def run_scanning(
    target: str,
    urls: list[str],
    js_urls: list[str],
    profile: str,
    waf_detected: bool,
    open_ports: list[dict],
    emit: Callable,
    scan_id: str,
) -> list[Finding]:
    """Run Phase 3. Returns list of all Findings."""
    await emit("phase_update", {"phase": "scanning", "status": "running"})

    all_findings: list[Finding] = []
    rate_ms = get_rate_limit_ms(waf_detected)

    # Expand scan targets with non-standard ports
    extra_targets = []
    for port_info in open_ports:
        port = port_info.get("port", "")
        svc = port_info.get("service", "")
        if port not in ("80", "443", "8080", "8443") and svc in ("http", "https", "http-proxy"):
            from urllib.parse import urlparse
            parsed = urlparse(target)
            scheme = "https" if svc == "https" or port == "443" else "http"
            extra_target = f"{scheme}://{parsed.hostname}:{port}"
            extra_targets.append(extra_target)
            await emit("log", {"tool": "scanner",
                               "stream": "info",
                               "data": f"[scanning] Adding non-standard port target: {extra_target}"})

    all_scan_urls = list(set(urls + extra_targets))

    # ── nuclei ────────────────────────────────────────────────────────────────
    await emit("tool_status", {"tool": "nuclei", "status": "running"})
    nuclei = NucleiTool()
    if not nuclei.available:
        await emit("tool_status", {"tool": "nuclei", "status": "skipped",
                                   "message": "nuclei not found"})
    else:
        headless = profile == "deep"
        # Convert ms delay to approximate rate limit for nuclei
        nuclei_rate = max(1, 1000 // max(rate_ms, 50))
        finding_count = 0
        async for item in nuclei.run(
            all_scan_urls,
            rate_limit=rate_ms,
            headless=headless,
        ):
            if isinstance(item, Finding):
                all_findings.append(item)
                finding_count += 1
                await emit("finding", {"finding": _finding_to_dict(item)})
            else:
                await emit("log", {"tool": "nuclei", "stream": item.stream, "data": item.data})
        await emit("tool_status", {"tool": "nuclei", "status": "done",
                                   "message": f"{finding_count} findings"})

    # ── ffuf ──────────────────────────────────────────────────────────────────
    await emit("tool_status", {"tool": "ffuf", "status": "running"})
    ffuf = FfufTool()
    if not ffuf.available:
        # Fall back to curl probing
        await emit("tool_status", {"tool": "ffuf", "status": "skipped",
                                   "message": "ffuf not found — using curl fallback"})
        await emit("tool_status", {"tool": "curl", "status": "running"})
        curl = CurlTool()
        if curl.available:
            finding_count = 0
            async for item in curl.probe_paths(target, rate_ms=rate_ms):
                if isinstance(item, Finding):
                    all_findings.append(item)
                    finding_count += 1
                    await emit("finding", {"finding": _finding_to_dict(item)})
                else:
                    await emit("log", {"tool": "curl", "stream": item.stream, "data": item.data})
            await emit("tool_status", {"tool": "curl", "status": "done",
                                       "message": f"{finding_count} findings"})
        else:
            await emit("tool_status", {"tool": "curl", "status": "skipped",
                                       "message": "curl not found"})
    else:
        use_full = profile == "deep"
        finding_count = 0
        async for item in ffuf.run(target, use_full_wordlist=use_full):
            if isinstance(item, Finding):
                all_findings.append(item)
                finding_count += 1
                await emit("finding", {"finding": _finding_to_dict(item)})
            else:
                await emit("log", {"tool": "ffuf", "stream": item.stream, "data": item.data})
        await emit("tool_status", {"tool": "ffuf", "status": "done",
                                   "message": f"{finding_count} findings"})

    # ── JS secret scanning ────────────────────────────────────────────────────
    if js_urls:
        await emit("log", {"tool": "scanner", "stream": "info",
                           "data": f"[scanning] Scanning {len(js_urls)} JS files for secrets..."})

        gitleaks = GitleaksTool()
        trufflehog = TrufflehogTool()

        js_finding_count = 0
        for js_url in js_urls[:100]:  # cap at 100 JS files
            await emit("log", {"tool": "scanner", "stream": "stdout",
                               "data": f"[js-scan] {js_url}"})
            findings_from_js, content = await fetch_js_and_scan(js_url)
            for f in findings_from_js:
                all_findings.append(f)
                js_finding_count += 1
                await emit("finding", {"finding": _finding_to_dict(f)})

            # gitleaks on content
            if content and gitleaks.available:
                async for item in gitleaks.run_on_content(content, js_url):
                    if isinstance(item, Finding):
                        all_findings.append(item)
                        js_finding_count += 1
                        await emit("finding", {"finding": _finding_to_dict(item)})
                    else:
                        await emit("log", {"tool": "gitleaks", "stream": item.stream, "data": item.data})

            await asyncio.sleep(rate_ms / 1000)

        if js_finding_count > 0:
            await emit("log", {"tool": "scanner", "stream": "info",
                               "data": f"[js-scan] Found {js_finding_count} secrets in JS files"})

    await emit("phase_update", {"phase": "scanning", "status": "completed",
                                "data": {"findings_count": len(all_findings)}})
    return all_findings


def _finding_to_dict(f: Finding) -> dict:
    return {
        "tool": f.tool,
        "severity": f.severity,
        "name": f.name,
        "url": f.url,
        "evidence": f.evidence,
        "remediation": f.remediation,
        "cvss_score": f.cvss_score,
        "risk_score": f.risk_score(),
    }
