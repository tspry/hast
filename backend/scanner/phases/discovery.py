"""Phase 2 – Discovery: parallel crawlers + gau + JS extraction."""
from __future__ import annotations

import asyncio
from typing import Callable
from urllib.parse import urlparse

from backend.scanner.tools.crawler_tools import (
    KatanaTool, GospiderTool, HakrawlerTool, GauTool,
    extract_urls_from_line, is_js_url,
)
from backend.scanner.tools.base import ToolEvent


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
    """
    await emit("phase_update", {"phase": "discovery", "status": "running"})

    all_urls: set[str] = set()
    target_host = urlparse(target).hostname or ""

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
                        await emit("tool_status", {"tool": tool_name, "status": "skipped",
                                                   "message": item.data})
                        return tool_urls
                    await emit("log", {"tool": tool_name, "stream": item.stream, "data": item.data})
                    # Extract URLs from output line
                    for url in extract_urls_from_line(item.data):
                        tool_urls.add(url)
        except Exception as exc:
            await emit("log", {"tool": tool_name, "stream": "error",
                               "data": f"[{tool_name}] error: {exc}"})
        return tool_urls

    # katana (always for standard/deep, skip for quick)
    if profile != "quick":
        await emit("tool_status", {"tool": "katana", "status": "running"})
        katana = KatanaTool()
        depth = 3 if profile == "standard" else 4
        katana_urls = await run_crawler("katana", katana.crawl(target, depth=depth))
        all_urls.update(katana_urls)
        await emit("tool_status", {"tool": "katana", "status": "done",
                                   "message": f"{len(katana_urls)} URLs"})

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
        await emit("tool_status", {"tool": "gospider", "status": "done",
                                   "message": f"{len(gs_urls)} URLs"})

    if hakrawler_task:
        hk_urls = await hakrawler_task
        all_urls.update(hk_urls)
        await emit("tool_status", {"tool": "hakrawler", "status": "done",
                                   "message": f"{len(hk_urls)} URLs"})

    # ── gau ───────────────────────────────────────────────────────────────────
    if run_gau:
        await emit("tool_status", {"tool": "gau", "status": "running"})
        gau = GauTool()
        gau_urls = await run_crawler("gau", gau.fetch(target))
        all_urls.update(gau_urls)
        await emit("tool_status", {"tool": "gau", "status": "done",
                                   "message": f"{len(gau_urls)} URLs"})

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

    await emit("phase_update", {
        "phase": "discovery",
        "status": "completed",
        "data": {
            "urls_count": len(url_list),
            "js_urls_count": len(js_urls),
        },
    })

    return {"urls": url_list, "js_urls": js_urls}
