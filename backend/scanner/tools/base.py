"""Base async tool runner with streaming stdout/stderr."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import AsyncIterator, Optional


@dataclass
class ToolEvent:
    stream: str          # stdout | stderr | info | warning | error
    data: str
    tool: str = ""


@dataclass
class Finding:
    tool: str
    severity: str        # critical | high | medium | low | info
    name: str
    url: str
    evidence: str = ""
    remediation: str = ""
    cvss_score: Optional[float] = None
    raw: dict = field(default_factory=dict)

    def risk_score(self) -> int:
        base = {"critical": 92, "high": 75, "medium": 50, "low": 25, "info": 5}
        return base.get(self.severity.lower(), 5)


class ToolRunner:
    """Async subprocess runner that streams lines as ToolEvents."""

    name: str = "base"
    binary: str = ""

    def __init__(self):
        self.path: Optional[str] = None
        self.available: bool = False
        self._detect()

    def _detect(self) -> None:
        from backend.config import resolve_tool_path
        p = resolve_tool_path(self.binary or self.name)
        if p:
            self.path = p
            self.available = True

    def _unavailable_event(self) -> ToolEvent:
        return ToolEvent(
            stream="warning",
            data=f"[{self.name}] not found in PATH — skipping",
            tool=self.name,
        )

    async def _run_subprocess(
        self,
        args: list[str],
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
        timeout: int = 600,
    ) -> AsyncIterator[ToolEvent]:
        """Run binary with args, yield ToolEvents for each output line.

        Uses a single async task per stream (stdout/stderr) feeding a shared
        queue. A deadline cancels both tasks if the total wall-clock time is
        exceeded, avoiding the broken asyncio.wait-on-queue-get pattern.
        """
        cmd = [self.path] + args
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=env,
            )
        except FileNotFoundError:
            yield ToolEvent(stream="error",
                            data=f"[{self.name}] binary not found: {self.path}",
                            tool=self.name)
            return
        except Exception as exc:
            yield ToolEvent(stream="error",
                            data=f"[{self.name}] failed to start: {exc}",
                            tool=self.name)
            return

        queue: asyncio.Queue = asyncio.Queue()
        _DONE = object()  # sentinel

        async def _drain(stream, stream_name: str) -> None:
            try:
                async for raw_line in stream:
                    line = raw_line.decode(errors="replace").rstrip()
                    if line:
                        await queue.put(ToolEvent(stream=stream_name,
                                                  data=line, tool=self.name))
            except Exception:
                pass
            finally:
                await queue.put(_DONE)

        t_out = asyncio.create_task(_drain(proc.stdout, "stdout"))
        t_err = asyncio.create_task(_drain(proc.stderr, "stderr"))
        done_count = 0

        try:
            deadline = asyncio.get_event_loop().time() + timeout
            while done_count < 2:
                remaining = deadline - asyncio.get_event_loop().time()
                if remaining <= 0:
                    proc.terminate()
                    yield ToolEvent(stream="warning",
                                    data=f"[{self.name}] timed out after {timeout}s",
                                    tool=self.name)
                    break
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=min(remaining, 5))
                except asyncio.TimeoutError:
                    continue
                if item is _DONE:
                    done_count += 1
                else:
                    yield item
        finally:
            t_out.cancel()
            t_err.cancel()
            try:
                await asyncio.wait_for(proc.wait(), timeout=10)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()


class SimpleToolRunner(ToolRunner):
    """Run tool with given args, stream every line as a ToolEvent."""

    async def run_raw(self, args: list[str], timeout: int = 600) -> AsyncIterator[ToolEvent]:
        if not self.available:
            yield self._unavailable_event()
            return
        async for ev in self._run_subprocess(args, timeout=timeout):
            yield ev
