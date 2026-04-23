"""wafw00f – WAF detection."""
from __future__ import annotations

import re
from typing import AsyncIterator

from backend.scanner.tools.base import Finding, SimpleToolRunner, ToolEvent


class Wafw00fTool(SimpleToolRunner):
    name = "wafw00f"
    binary = "wafw00f"

    async def run(self, target: str) -> AsyncIterator[ToolEvent | Finding]:
        if not self.available:
            yield self._unavailable_event()
            return

        waf_name = None
        waf_detected = False

        async for ev in self.run_raw([target, "-a", "--format", "json"], timeout=120):
            yield ev
            line = ev.data.lower()
            # Parse plain text output as well
            if "is behind" in line or "protected by" in line:
                waf_detected = True
                m = re.search(r"behind (.+?)(?:\s+waf|$)", ev.data, re.I)
                if m:
                    waf_name = m.group(1).strip()
            elif "no waf detected" in line or "generic detection" in line:
                waf_detected = False

        if waf_detected:
            yield Finding(
                tool=self.name,
                severity="info",
                name="WAF Detected",
                url=target,
                evidence=f"WAF identified: {waf_name or 'unknown'}",
                remediation="WAF presence noted. Scan aggressiveness reduced.",
                raw={"waf_name": waf_name, "waf_detected": True},
            )
        else:
            yield Finding(
                tool=self.name,
                severity="info",
                name="No WAF Detected",
                url=target,
                evidence="No WAF or CDN protection detected.",
                remediation="Consider deploying a WAF for production environments.",
                raw={"waf_detected": False},
            )
