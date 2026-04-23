"""Base async tool runner with streaming stdout/stderr."""
from __future__ import annotations

import asyncio
import shutil
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
        """Run binary with args, yield ToolEvents for each output line."""
        cmd = [self.path] + args
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=env,
            )

            async def read_stream(stream, stream_name: str):
                while True:
                    try:
                        line = await asyncio.wait_for(stream.readline(), timeout=30)
                    except asyncio.TimeoutError:
                        continue
                    if not line:
                        break
                    yield ToolEvent(stream=stream_name, data=line.decode(errors="replace").rstrip(), tool=self.name)

            stdout_q: asyncio.Queue = asyncio.Queue()
            stderr_q: asyncio.Queue = asyncio.Queue()

            async def drain_stdout():
                async for ev in read_stream(proc.stdout, "stdout"):
                    await stdout_q.put(ev)
                await stdout_q.put(None)

            async def drain_stderr():
                async for ev in read_stream(proc.stderr, "stderr"):
                    await stderr_q.put(ev)
                await stderr_q.put(None)

            tasks = [
                asyncio.create_task(drain_stdout()),
                asyncio.create_task(drain_stderr()),
            ]

            stdout_done = stderr_done = False
            try:
                while not (stdout_done and stderr_done):
                    done, _ = await asyncio.wait(
                        [asyncio.ensure_future(stdout_q.get()), asyncio.ensure_future(stderr_q.get())],
                        return_when=asyncio.FIRST_COMPLETED,
                        timeout=timeout,
                    )
                    # drain queues
                    for item in [stdout_q, stderr_q]:
                        while not item.empty():
                            ev = item.get_nowait()
                            if ev is None:
                                if item is stdout_q:
                                    stdout_done = True
                                else:
                                    stderr_done = True
                            else:
                                yield ev
            except asyncio.TimeoutError:
                proc.terminate()
                yield ToolEvent(stream="warning", data=f"[{self.name}] timed out after {timeout}s", tool=self.name)
            finally:
                for t in tasks:
                    t.cancel()

            try:
                await asyncio.wait_for(proc.wait(), timeout=10)
            except asyncio.TimeoutError:
                proc.kill()

        except FileNotFoundError:
            yield ToolEvent(stream="error", data=f"[{self.name}] binary not found: {self.path}", tool=self.name)
        except Exception as exc:
            yield ToolEvent(stream="error", data=f"[{self.name}] unexpected error: {exc}", tool=self.name)

    async def stream(self, *args, **kwargs) -> AsyncIterator[ToolEvent]:
        """Override in subclass. Yields ToolEvents and Finding objects."""
        if not self.available:
            yield self._unavailable_event()
            return
        async for ev in self._run_subprocess(list(args)):
            yield ev


# ── Simple line-by-line runner (used by most tools) ──────────────────────────

class SimpleToolRunner(ToolRunner):
    """Run tool with given args, stream every line as stdout event."""

    async def run_raw(self, args: list[str], timeout: int = 600) -> AsyncIterator[ToolEvent]:
        if not self.available:
            yield self._unavailable_event()
            return
        async for ev in self._run_subprocess(args, timeout=timeout):
            yield ev
