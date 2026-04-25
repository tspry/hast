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
    AlterxTool,
    ShuffleDnsTool,
    UrlffinderTool,
    parse_dnsx_record,
    parse_dnsx_host_ip,
    parse_httpx_record,
    parse_subfinder_record,
)
from backend.config import get_config


async def run_discovery(
    target: str,
    profile: str,
    emit: Callable,
    scan_id: str,
    parallel: bool = False,
) -> dict:
    """
    Run Phase 2. Returns dict with:
    - urls: list[str]         (all discovered URLs, deduped)
    - js_urls: list[str]      (JS file URLs)
    - open_ports: list[dict]
    - findings: list[Finding]
    - subdomains: list[str]   (subdomains from subfinder)
    """
    await emit("phase_update", {"phase": "discovery", "status": "running"})

    all_urls: set[str] = set()
    subdomains: set[str] = set()
    subdomain_ips: dict[str, str] = {}   # host → first resolved IP
    resolved_hosts: set[str] = set()
    open_ports: list[dict] = []
    findings: list[Finding] = []
    target_host = urlparse(target).hostname or ""

    if target_host and ":" in target_host:
        target_host = target_host.split(":", 1)[0]

    # ── Crawlers helper (defined early so parallel mode can start tasks before subfinder) ─
    run_gospider = profile in ("standard", "deep")
    run_hakrawler = profile == "deep"
    run_gau = profile in ("standard", "deep")
    run_urlfinder = profile in ("standard", "deep")

    async def run_crawler(tool_name, coro_gen):
        """Drain a crawler coroutine, emit status, collect URLs."""
        tool_urls: set[str] = set()
        await emit("tool_status", {"tool": tool_name, "status": "running"})
        try:
            async for item in coro_gen:
                if isinstance(item, ToolEvent):
                    if item.stream == "warning":
                        await emit("tool_status", {"tool": tool_name, "status": "skipped",
                                                   "message": item.data})
                        return tool_urls
                    await emit("log", {"tool": tool_name, "stream": item.stream, "data": item.data})
                    for url in extract_urls_from_line(item.data):
                        tool_urls.add(url)
        except Exception as exc:
            await emit("log", {"tool": tool_name, "stream": "error",
                               "data": f"[{tool_name}] error: {exc}"})
        await emit("tool_status", {"tool": tool_name, "status": "done",
                                   "message": f"{len(tool_urls)} URLs"})
        return tool_urls

    # In parallel mode, launch crawlers NOW as background tasks so they run
    # concurrently while the subfinder → dnsx → naabu chain runs below.
    pending_crawler_tasks: list[asyncio.Task] = []
    if parallel and profile != "quick":
        depth = 3 if profile == "standard" else 4
        pending_crawler_tasks.append(asyncio.create_task(
            run_crawler("katana", KatanaTool().crawl(target, depth=depth))
        ))
        if run_gospider:
            pending_crawler_tasks.append(asyncio.create_task(
                run_crawler("gospider", GospiderTool().crawl(target))
            ))
        if run_hakrawler:
            pending_crawler_tasks.append(asyncio.create_task(
                run_crawler("hakrawler", HakrawlerTool().crawl(target))
            ))
        if run_gau:
            pending_crawler_tasks.append(asyncio.create_task(
                run_crawler("gau", GauTool().fetch(target))
            ))
        if run_urlfinder:
            _uf = UrlffinderTool()
            if not _uf.available:
                await emit("tool_status", {"tool": "urlfinder", "status": "skipped",
                                           "message": "urlfinder not found"})
            else:
                pending_crawler_tasks.append(asyncio.create_task(
                    run_crawler("urlfinder", _uf.find(target))
                ))

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
                        host, ip = parse_dnsx_host_ip(item.data)
                        if host:
                            resolved_hosts.add(host)
                            if ip and host not in subdomain_ips:
                                subdomain_ips[host] = ip
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

    # Emit subdomains_found now — after dnsx so IPs are populated
    subdomain_list = [
        {"host": h, "ip": subdomain_ips.get(h, "")}
        for h in sorted(subdomains)
    ]
    await emit("subdomains_found", {
        "subdomains": subdomain_list,
        "count": len(subdomain_list),
    })

    # ── alterx + shuffledns (deep only) ──────────────────────────────────────
    if profile == "deep" and subdomains:
        await emit("tool_status", {"tool": "alterx", "status": "running"})
        alterx = AlterxTool()
        permuted: set[str] = set()
        if not alterx.available:
            await emit("tool_status", {"tool": "alterx", "status": "skipped",
                                       "message": "alterx not found"})
        else:
            async for item in alterx.permute(sorted(subdomains)):
                if isinstance(item, ToolEvent) and item.stream == "stdout":
                    h = item.data.strip()
                    if h:
                        permuted.add(h)
                elif isinstance(item, ToolEvent):
                    await emit("log", {"tool": "alterx", "stream": item.stream, "data": item.data})
            await emit("tool_status", {"tool": "alterx", "status": "done",
                                       "message": f"{len(permuted)} permutations"})

        await emit("tool_status", {"tool": "shuffledns", "status": "running"})
        shuffledns = ShuffleDnsTool()
        if not shuffledns.available:
            await emit("tool_status", {"tool": "shuffledns", "status": "skipped",
                                       "message": "shuffledns not found"})
        elif not permuted:
            await emit("tool_status", {"tool": "shuffledns", "status": "skipped",
                                       "message": "no permutations to resolve"})
        else:
            cfg = get_config()
            seclists = cfg.get("seclists_path", "")
            import os
            resolvers_candidates = [
                os.path.join(seclists, "Miscellaneous", "dns-resolvers.txt"),
                "/usr/share/seclists/Miscellaneous/dns-resolvers.txt",
                "/app/resolvers.txt",
            ]
            resolvers_file = next((p for p in resolvers_candidates if os.path.isfile(p)), "")
            wordlist_candidates = [
                os.path.join(seclists, "Discovery", "DNS", "subdomains-top1million-5000.txt"),
                "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            ]
            wordlist_file = next((p for p in wordlist_candidates if os.path.isfile(p)), "")

            if not resolvers_file or not wordlist_file:
                await emit("tool_status", {"tool": "shuffledns", "status": "skipped",
                                           "message": "resolvers/wordlist not found"})
            else:
                bruteforced: set[str] = set()
                async for item in shuffledns.bruteforce(target_host, wordlist_file, resolvers_file):
                    if isinstance(item, ToolEvent) and item.stream == "stdout":
                        h = parse_dnsx_record(item.data) or item.data.strip()
                        if h:
                            bruteforced.add(h)
                    elif isinstance(item, ToolEvent):
                        await emit("log", {"tool": "shuffledns", "stream": item.stream, "data": item.data})
                resolved_hosts.update(bruteforced)
                subdomains.update(bruteforced)
                await emit("tool_status", {"tool": "shuffledns", "status": "done",
                                           "message": f"{len(bruteforced)} new hosts"})

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

    if pending_crawler_tasks:
        # Parallel mode: collect all crawler results now (they ran concurrently
        # with the subfinder → dnsx → naabu chain above).
        results = await asyncio.gather(*pending_crawler_tasks)
        for urls in results:
            all_urls.update(urls)
    elif profile != "quick":
        # Sequential mode: run crawlers one by one.
        depth = 3 if profile == "standard" else 4
        all_urls.update(await run_crawler("katana", KatanaTool().crawl(target, depth=depth)))

        if run_gospider:
            all_urls.update(await run_crawler("gospider", GospiderTool().crawl(target)))
        if run_hakrawler:
            all_urls.update(await run_crawler("hakrawler", HakrawlerTool().crawl(target)))
        if run_gau:
            all_urls.update(await run_crawler("gau", GauTool().fetch(target)))
        if run_urlfinder:
            urlfinder = UrlffinderTool()
            if not urlfinder.available:
                await emit("tool_status", {"tool": "urlfinder", "status": "skipped",
                                           "message": "urlfinder not found"})
            else:
                all_urls.update(await run_crawler("urlfinder", urlfinder.find(target)))

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
        "subdomains": sorted(subdomains),
        "subdomain_ips": subdomain_ips,
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
