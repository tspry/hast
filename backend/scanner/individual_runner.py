"""Individual tool runner for the Tools tab — runs one tool in isolation."""
from __future__ import annotations

import asyncio
import uuid
from typing import Callable, Optional
from urllib.parse import urlparse

from backend.scanner.tools.base import Finding, ToolEvent


# Tracks active individual tool runs: run_id -> Task
_active_runs: dict[str, asyncio.Task] = {}


async def run_tool(tool_name: str, params: dict, emit: Callable) -> str:
    """Dispatch a single tool run. Returns run_id."""
    run_id = str(uuid.uuid4())[:8]
    task = asyncio.create_task(_execute(tool_name, params, emit, run_id))
    _active_runs[run_id] = task
    return run_id


async def stop_tool_run(run_id: str) -> bool:
    """Cancel an active tool run by run_id. Returns True if it was running."""
    task = _active_runs.get(run_id)
    if task and not task.done():
        task.cancel()
        return True
    return False


async def stop_all_runs(run_ids: set[str]) -> None:
    """Cancel all runs in the given set (called on WS disconnect)."""
    for run_id in run_ids:
        await stop_tool_run(run_id)


async def _execute(tool_name: str, params: dict, emit: Callable, run_id: str) -> None:
    target = params.get("target", "").strip()

    try:
        await emit("tool_run_started", {"tool": tool_name, "run_id": run_id})

        gen = _build_runner(tool_name, params, target)
        if gen is None:
            await emit("log", {
                "tool": tool_name, "stream": "error",
                "data": f"[{tool_name}] Tool not supported for individual runs",
            })
            return

        async for item in gen:
            if isinstance(item, Finding):
                await emit("finding", {"finding": _finding_dict(item)})
            elif isinstance(item, ToolEvent):
                await emit("log", {
                    "tool": tool_name, "stream": item.stream, "data": item.data,
                })

    except asyncio.CancelledError:
        await emit("log", {
            "tool": tool_name, "stream": "warning",
            "data": f"[{tool_name}] Run {run_id} stopped.",
        })
    except Exception as exc:
        await emit("log", {
            "tool": tool_name, "stream": "error",
            "data": f"[{tool_name}] Error: {exc}",
        })
    finally:
        _active_runs.pop(run_id, None)
        await emit("tool_run_done", {"tool": tool_name, "run_id": run_id})


def _build_runner(tool_name: str, params: dict, target: str):
    """Return an async iterator for the given tool, or None if unsupported."""
    parsed = urlparse(target) if target.startswith(("http://", "https://")) else None
    domain = (parsed.hostname if parsed else None) or target

    if tool_name == "wafw00f":
        from backend.scanner.tools.wafw00f_tool import Wafw00fTool
        return Wafw00fTool().run(target)

    if tool_name == "nmap":
        from backend.scanner.tools.nmap_tool import NmapTool
        return NmapTool().run(target)

    if tool_name == "whatweb":
        from backend.scanner.tools.whatweb_tool import WhatwebTool
        return WhatwebTool().run(target)

    if tool_name == "subfinder":
        from backend.scanner.tools.projectdiscovery_tools import SubfinderTool
        return SubfinderTool().discover(domain)

    if tool_name == "dnsx":
        from backend.scanner.tools.projectdiscovery_tools import DnsxTool
        raw = params.get("hosts", target)
        hosts = [h.strip() for h in raw.replace(",", "\n").splitlines() if h.strip()]
        return DnsxTool().resolve(hosts or [domain])

    if tool_name == "naabu":
        from backend.scanner.tools.projectdiscovery_tools import NaabuTool
        raw = params.get("hosts", domain)
        hosts = [h.strip() for h in raw.replace(",", "\n").splitlines() if h.strip()]
        top_ports = str(params.get("top_ports", "100"))
        return NaabuTool().scan(hosts or [domain], top_ports=top_ports)

    if tool_name == "httpx":
        from backend.scanner.tools.projectdiscovery_tools import HttpxTool
        raw = params.get("targets", target)
        targets = [h.strip() for h in raw.replace(",", "\n").splitlines() if h.strip()]
        return HttpxTool().probe(targets or [target])

    if tool_name == "katana":
        from backend.scanner.tools.crawler_tools import KatanaTool
        depth = int(params.get("depth", 2))
        return KatanaTool().crawl(target, depth=depth)

    if tool_name == "gospider":
        from backend.scanner.tools.crawler_tools import GospiderTool
        return GospiderTool().crawl(target)

    if tool_name == "hakrawler":
        from backend.scanner.tools.crawler_tools import HakrawlerTool
        return HakrawlerTool().crawl(target)

    if tool_name == "gau":
        from backend.scanner.tools.crawler_tools import GauTool
        return GauTool().fetch(target)

    if tool_name == "nuclei":
        from backend.scanner.tools.nuclei_tool import NucleiTool
        return NucleiTool().run([target], rate_limit=300, headless=False)

    if tool_name == "ffuf":
        from backend.scanner.tools.ffuf_tool import FfufTool
        full = params.get("full_wordlist", False)
        return FfufTool().run(target, use_full_wordlist=bool(full))

    if tool_name == "gitleaks":
        from backend.scanner.tools.secret_tools import GitleaksTool
        tool = GitleaksTool()
        js_url = params.get("js_url", target)
        return _gitleaks_on_url(tool, js_url)

    if tool_name == "tlsx":
        from backend.scanner.tools.projectdiscovery_tools import TlsxTool
        return TlsxTool().scan(target)

    if tool_name == "cdncheck":
        from backend.scanner.tools.projectdiscovery_tools import CdncheckTool
        return CdncheckTool().check(target)

    if tool_name == "asnmap":
        from backend.scanner.tools.projectdiscovery_tools import AsnmapTool
        return AsnmapTool().lookup(target)

    if tool_name == "alterx":
        from backend.scanner.tools.projectdiscovery_tools import AlterxTool
        raw = params.get("subdomains", domain)
        hosts = [h.strip() for h in raw.replace(",", "\n").splitlines() if h.strip()]
        return AlterxTool().permute(hosts or [domain])

    if tool_name == "shuffledns":
        from backend.scanner.tools.projectdiscovery_tools import ShuffleDnsTool
        wordlist = params.get("wordlist", "")
        resolvers = params.get("resolvers", "")
        if not wordlist or not resolvers:
            return None
        return ShuffleDnsTool().bruteforce(domain, wordlist, resolvers)

    if tool_name == "urlfinder":
        from backend.scanner.tools.projectdiscovery_tools import UrlffinderTool
        return UrlffinderTool().find(target)

    return None


async def _gitleaks_on_url(tool, url: str):
    """Fetch a URL and run gitleaks on its content."""
    from backend.scanner.tools.secret_tools import fetch_js_and_scan
    findings, content = await fetch_js_and_scan(url)
    for f in findings:
        yield f
    if content and tool.available:
        async for item in tool.run_on_content(content, url):
            yield item


def _finding_dict(f: Finding) -> dict:
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
