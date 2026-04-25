"""Phase 2 – Discovery: ProjectDiscovery probing + crawlers + gau + JS extraction."""

from __future__ import annotations

import asyncio
from typing import Callable
from urllib.parse import urlparse

from backend.scanner.tools.base import Finding, ToolEvent
from backend.scanner.tools.crawler_tools import (
    GauTool,
    GospiderTool,
    HakrawlerTool,
    KatanaTool,
    extract_urls_from_line,
    is_js_url,
)
from backend.scanner.tools.projectdiscovery_tools import (
    DnsxTool,
    HttpxTool,
    NaabuTool,
    SubfinderTool,
    parse_dnsx_record,
    parse_httpx_record,
    parse_subfinder_record,
)


async def run_discovery(
    target: str,
    profile: str,
    emit: Callable,
    scan_id: str,
) -> dict:
    """
    Run Phase 2. Returns dict with:
    - urls: list[str]       (all discovered URLs, deduped)
    - js_urls: list[str]    (JS file URLs)
    - open_ports: list[dict]
    - findings: list[Finding]
    """
    await emit("phase_update", {"phase": "discovery", "status": "running"})

    all_urls: set[str] = set()
    subdomains: set[str] = set()
    resolved_hosts: set[str] = set()
    open_ports: list[dict] = []
    findings: list[Finding] = []
    target_host = urlparse(target).hostname or ""

    if target_host and ":" in target_host:
        target_host = target_host.split(":", 1)[0]

    # ── subfinder ───────────────────────────────────────────────────────────
    await emit("tool_status", {"tool": "subfinder", "status": "running"})
    subfinder = SubfinderTool()
    if not subfinder.available:
        await emit(
            "tool_status",
            {
                "tool": "subfinder",
                "status": "skipped",
                "message": "subfinder not found",
            },
        )
    else:
        async for item in subfinder.discover(target_host or target):
            if isinstance(item, ToolEvent):
                await emit(
                    "log",
                    {"tool": "subfinder", "stream": item.stream, "data": item.data},
                )
                if item.stream == "stdout":
                    host = parse_subfinder_record(item.data)
                    if host:
                        subdomains.add(host)
            else:
                await emit("finding", {"finding": _finding_to_dict(item)})
        if subdomains:
            findings.append(
                Finding(
                    tool="subfinder",
                    severity="info",
                    name="Subdomains Discovered",
                    url=target,
                    evidence=f"Found {len(subdomains)} subdomains: {', '.join(sorted(subdomains)[:10])}",
                    remediation="Review exposed subdomains and retire unused hosts.",
                    raw={"subdomains": sorted(subdomains)},
                )
            )
            await emit(
                "tool_status",
                {
                    "tool": "subfinder",
                    "status": "done",
                    "message": f"{len(subdomains)} subdomains",
                },
            )
        else:
            await emit(
                "tool_status",
                {"tool": "subfinder", "status": "done", "message": "0 subdomains"},
            )

    # ── dnsx ────────────────────────────────────────────────────────────────
    dns_inputs_set = set(subdomains)
    if target_host:
        dns_inputs_set.add(target_host)
    dns_inputs = sorted(dns_inputs_set)
    if dns_inputs:
        await emit("tool_status", {"tool": "dnsx", "status": "running"})
        dnsx = DnsxTool()
        if not dnsx.available:
            await emit(
                "tool_status",
                {"tool": "dnsx", "status": "skipped", "message": "dnsx not found"},
            )
        else:
            async for item in dnsx.resolve(dns_inputs):
                if isinstance(item, ToolEvent):
                    await emit(
                        "log",
                        {"tool": "dnsx", "stream": item.stream, "data": item.data},
                    )
                    if item.stream == "stdout":
                        host = parse_dnsx_record(item.data)
                        if host:
                            resolved_hosts.add(host)
                else:
                    await emit("finding", {"finding": _finding_to_dict(item)})
            if resolved_hosts:
                findings.append(
                    Finding(
                        tool="dnsx",
                        severity="info",
                        name="DNS Resolutions",
                        url=target,
                        evidence=f"Resolved {len(resolved_hosts)} hosts from {len(dns_inputs)} inputs",
                        remediation="Confirm only intended subdomains resolve and point to live services.",
                        raw={"resolved_hosts": sorted(resolved_hosts)},
                    )
                )
            await emit(
                "tool_status",
                {
                    "tool": "dnsx",
                    "status": "done",
                    "message": f"{len(resolved_hosts)} resolved hosts",
                },
            )

    if not resolved_hosts and target_host:
        resolved_hosts.add(target_host)

    # ── naabu ───────────────────────────────────────────────────────────────
    naabu_hosts = sorted(
        host for host in resolved_hosts if host and host != target_host
    )
    if naabu_hosts:
        await emit("tool_status", {"tool": "naabu", "status": "running"})
        naabu = NaabuTool()
        if not naabu.available:
            await emit(
                "tool_status",
                {"tool": "naabu", "status": "skipped", "message": "naabu not found"},
            )
        else:
            naabu_count = 0
            async for item in naabu.scan(naabu_hosts, top_ports="100"):
                if isinstance(item, Finding):
                    findings.append(item)
                    open_ports.append(item.raw)
                    naabu_count += 1
                    await emit("finding", {"finding": _finding_to_dict(item)})
                else:
                    await emit(
                        "log",
                        {"tool": "naabu", "stream": item.stream, "data": item.data},
                    )
            await emit(
                "tool_status",
                {
                    "tool": "naabu",
                    "status": "done",
                    "message": f"{naabu_count} open ports",
                },
            )

    # Determine which crawlers to run per profile
    run_gospider = profile in ("standard", "deep")
    run_hakrawler = profile == "deep"
    run_gau = profile in ("standard", "deep")

    # ── Parallel crawlers ─────────────────────────────────────────────────────
    crawl_tasks = []

    async def run_crawler(tool_name, coro_gen):
        """Drain a crawler coroutine, collect URLs."""
        tool_urls = set()
        tool = None
        try:
            async for item in coro_gen:
                if isinstance(item, ToolEvent):
                    if item.stream == "warning":
                        await emit(
                            "tool_status",
                            {
                                "tool": tool_name,
                                "status": "skipped",
                                "message": item.data,
                            },
                        )
                        return tool_urls
                    await emit(
                        "log",
                        {"tool": tool_name, "stream": item.stream, "data": item.data},
                    )
                    # Extract URLs from output line
                    for url in extract_urls_from_line(item.data):
                        tool_urls.add(url)
        except Exception as exc:
            await emit(
                "log",
                {
                    "tool": tool_name,
                    "stream": "error",
                    "data": f"[{tool_name}] error: {exc}",
                },
            )
        return tool_urls

    # katana (always for standard/deep, skip for quick)
    if profile != "quick":
        await emit("tool_status", {"tool": "katana", "status": "running"})
        katana = KatanaTool()
        depth = 3 if profile == "standard" else 4
        katana_urls = await run_crawler("katana", katana.crawl(target, depth=depth))
        all_urls.update(katana_urls)
        await emit(
            "tool_status",
            {"tool": "katana", "status": "done", "message": f"{len(katana_urls)} URLs"},
        )

    # gospider (standard + deep, parallel)
    gospider_task = None
    if run_gospider:
        await emit("tool_status", {"tool": "gospider", "status": "running"})
        gospider = GospiderTool()
        gospider_task = asyncio.create_task(
            run_crawler("gospider", gospider.crawl(target))
        )

    # hakrawler (deep only, parallel)
    hakrawler_task = None
    if run_hakrawler:
        await emit("tool_status", {"tool": "hakrawler", "status": "running"})
        hakrawler = HakrawlerTool()
        hakrawler_task = asyncio.create_task(
            run_crawler("hakrawler", hakrawler.crawl(target))
        )

    # Wait for parallel crawlers
    if gospider_task:
        gs_urls = await gospider_task
        all_urls.update(gs_urls)
        await emit(
            "tool_status",
            {"tool": "gospider", "status": "done", "message": f"{len(gs_urls)} URLs"},
        )

    if hakrawler_task:
        hk_urls = await hakrawler_task
        all_urls.update(hk_urls)
        await emit(
            "tool_status",
            {"tool": "hakrawler", "status": "done", "message": f"{len(hk_urls)} URLs"},
        )

    # ── gau ───────────────────────────────────────────────────────────────────
    if run_gau:
        await emit("tool_status", {"tool": "gau", "status": "running"})
        gau = GauTool()
        gau_urls = await run_crawler("gau", gau.fetch(target))
        all_urls.update(gau_urls)
        await emit(
            "tool_status",
            {"tool": "gau", "status": "done", "message": f"{len(gau_urls)} URLs"},
        )

    # ── httpx ────────────────────────────────────────────────────────────────
    probe_targets_set = set(all_urls)
    probe_targets_set.add(target)
    probe_targets_set.update(resolved_hosts)
    probe_targets = sorted(probe_targets_set)
    if probe_targets:
        await emit("tool_status", {"tool": "httpx", "status": "running"})
        httpx = HttpxTool()
        live_urls: set[str] = set()
        if not httpx.available:
            await emit(
                "tool_status",
                {"tool": "httpx", "status": "skipped", "message": "httpx not found"},
            )
        else:
            async for item in httpx.probe(probe_targets):
                if isinstance(item, ToolEvent):
                    await emit(
                        "log",
                        {"tool": "httpx", "stream": item.stream, "data": item.data},
                    )
                    if item.stream == "stdout":
                        url = parse_httpx_record(item.data)
                        if url:
                            live_urls.add(url)
                else:
                    await emit("finding", {"finding": _finding_to_dict(item)})
            if live_urls:
                all_urls.update(live_urls)
                findings.append(
                    Finding(
                        tool="httpx",
                        severity="info",
                        name="Live HTTP Endpoints",
                        url=target,
                        evidence=f"Confirmed {len(live_urls)} live URLs",
                        remediation="Review live endpoints and restrict any unintended exposure.",
                        raw={"live_urls": sorted(live_urls)},
                    )
                )
            await emit(
                "tool_status",
                {
                    "tool": "httpx",
                    "status": "done",
                    "message": f"{len(live_urls)} live URLs",
                },
            )

    # ── Filter to same host (and subdomains) ──────────────────────────────────
    if target_host:
        filtered = set()
        for url in all_urls:
            try:
                h = urlparse(url).hostname or ""
                if h == target_host or h.endswith(f".{target_host}"):
                    filtered.add(url)
            except Exception:
                pass
        all_urls = filtered

    # Always include target itself
    all_urls.add(target)

    url_list = sorted(all_urls)
    js_urls = [u for u in url_list if is_js_url(u)]

    await emit(
        "phase_update",
        {
            "phase": "discovery",
            "status": "completed",
            "data": {
                "urls_count": len(url_list),
                "js_urls_count": len(js_urls),
            },
        },
    )

    return {
        "urls": url_list,
        "js_urls": js_urls,
        "open_ports": open_ports,
        "findings": findings,
    }


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
