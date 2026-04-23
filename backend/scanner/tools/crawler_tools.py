"""katana, gospider, hakrawler, gau – URL discovery tools."""
from __future__ import annotations

import re
from typing import AsyncIterator
from urllib.parse import urlparse

from backend.scanner.tools.base import SimpleToolRunner, ToolEvent


class KatanaTool(SimpleToolRunner):
    name = "katana"
    binary = "katana"

    async def crawl(self, target: str, depth: int = 3) -> AsyncIterator[ToolEvent]:
        if not self.available:
            yield self._unavailable_event()
            return
        args = ["-u", target, "-d", str(depth), "-jc", "-kf", "all",
                "-c", "10", "-p", "10", "-silent", "-o", "/dev/stdout"]
        async for ev in self.run_raw(args, timeout=300):
            yield ev


class GospiderTool(SimpleToolRunner):
    name = "gospider"
    binary = "gospider"

    async def crawl(self, target: str) -> AsyncIterator[ToolEvent]:
        if not self.available:
            yield self._unavailable_event()
            return
        args = ["-s", target, "-c", "10", "-d", "3", "--other-source",
                "--include-subs", "-q"]
        async for ev in self.run_raw(args, timeout=300):
            yield ev


class HakrawlerTool(SimpleToolRunner):
    name = "hakrawler"
    binary = "hakrawler"

    async def crawl(self, target: str) -> AsyncIterator[ToolEvent]:
        if not self.available:
            yield self._unavailable_event()
            return
        # hakrawler reads from stdin
        try:
            import asyncio
            proc = await asyncio.create_subprocess_exec(
                self.path, "-d", "3", "-t", "8",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=target.encode()), timeout=300
            )
            for line in stdout.decode(errors="replace").splitlines():
                line = line.strip()
                if line:
                    yield ToolEvent(stream="stdout", data=line, tool=self.name)
            for line in stderr.decode(errors="replace").splitlines():
                if line.strip():
                    yield ToolEvent(stream="stderr", data=line.strip(), tool=self.name)
        except Exception as exc:
            yield ToolEvent(stream="error", data=f"[{self.name}] {exc}", tool=self.name)


class GauTool(SimpleToolRunner):
    name = "gau"
    binary = "gau"

    async def fetch(self, domain: str) -> AsyncIterator[ToolEvent]:
        if not self.available:
            yield self._unavailable_event()
            return
        # gau takes domain (no scheme)
        parsed = urlparse(domain)
        host = parsed.hostname or domain.replace("https://", "").replace("http://", "").split("/")[0]
        args = [host, "--providers", "wayback,commoncrawl,otx", "--subs"]
        async for ev in self.run_raw(args, timeout=300):
            yield ev


def extract_urls_from_line(line: str) -> list[str]:
    """Extract valid HTTP URLs from a tool output line."""
    urls = re.findall(r'https?://[^\s\'"<>]+', line)
    valid = []
    for u in urls:
        u = u.rstrip(".,;)")
        try:
            parsed = urlparse(u)
            if parsed.scheme in ("http", "https") and parsed.netloc:
                valid.append(u)
        except Exception:
            pass
    return valid


def is_js_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    return path.endswith(".js") or path.endswith(".mjs")
