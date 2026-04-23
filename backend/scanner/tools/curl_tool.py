"""curl – manual path probe fallback for priority paths."""
from __future__ import annotations

import asyncio
from typing import AsyncIterator
from urllib.parse import urljoin

from backend.scanner.tools.base import Finding, ToolRunner, ToolEvent
from backend.scanner.tools.ffuf_tool import PRIORITY_PATHS, REMEDIATION_FOR


class CurlTool(ToolRunner):
    name = "curl"
    binary = "curl"

    async def probe_paths(
        self,
        target: str,
        paths: list[str] = None,
        rate_ms: int = 200,
    ) -> AsyncIterator[ToolEvent | Finding]:
        if not self.available:
            yield self._unavailable_event()
            return

        probe_list = paths or PRIORITY_PATHS
        base = target.rstrip("/")

        for path in probe_list:
            url = f"{base}/{path}"
            async for item in self._probe_single(url):
                yield item
            await asyncio.sleep(rate_ms / 1000)

    async def _probe_single(self, url: str) -> AsyncIterator[ToolEvent | Finding]:
        args = [
            "-s", "-o", "/dev/null",
            "-w", "%{http_code}|%{size_download}|%{url_effective}",
            "-L", "--max-redirs", "3",
            "-m", "10",
            "--user-agent", "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            url,
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                self.path, *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
            output = stdout.decode().strip()
            if "|" in output:
                parts = output.split("|")
                status = int(parts[0]) if parts[0].isdigit() else 0
                size = int(parts[1]) if parts[1].isdigit() else 0
                effective_url = parts[2] if len(parts) > 2 else url

                yield ToolEvent(stream="stdout", data=f"[curl] {status} {url} ({size} bytes)", tool=self.name)

                if status in (200, 301, 302, 307, 308) and status != 403:
                    path = url.split("/", 3)[-1] if "/" in url else ""
                    path_lower = path.lower()
                    severity = "medium"
                    remediation = "Review and restrict access to this file."
                    for keyword, remed in REMEDIATION_FOR.items():
                        if keyword in path_lower:
                            remediation = remed
                            if keyword in (".env", "wp-config", ".git", "backup", "appsettings"):
                                severity = "high" if status != 200 else "critical"
                            break

                    yield Finding(
                        tool="curl",
                        severity=severity,
                        name=f"Exposed Path: {path}",
                        url=effective_url,
                        evidence=f"HTTP {status} — {size} bytes",
                        remediation=remediation,
                    )
        except asyncio.TimeoutError:
            yield ToolEvent(stream="warning", data=f"[curl] timeout: {url}", tool=self.name)
        except Exception as exc:
            yield ToolEvent(stream="error", data=f"[curl] {exc}", tool=self.name)
