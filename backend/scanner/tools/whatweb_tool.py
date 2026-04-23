"""whatweb – technology stack fingerprinting."""
from __future__ import annotations

import json
import re
from typing import AsyncIterator

from backend.scanner.tools.base import Finding, SimpleToolRunner, ToolEvent


class WhatwebTool(SimpleToolRunner):
    name = "whatweb"
    binary = "whatweb"

    async def run(self, target: str) -> AsyncIterator[ToolEvent | Finding]:
        if not self.available:
            yield self._unavailable_event()
            return

        json_lines: list[str] = []
        args = [target, "--log-json=/dev/stdout", "-a", "3", "--quiet"]

        async for ev in self.run_raw(args, timeout=120):
            yield ev
            if ev.stream == "stdout" and ev.data.strip().startswith("["):
                json_lines.append(ev.data.strip())

        # Parse
        text = "".join(json_lines)
        findings = _parse_whatweb(text, target)
        for f in findings:
            yield f


def _parse_whatweb(text: str, target: str) -> list[Finding]:
    findings = []
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        # Try line by line
        entries = []
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("{") or line.startswith("["):
                try:
                    entries.append(json.loads(line))
                except Exception:
                    pass
        if not entries:
            return findings
        data = entries[0] if len(entries) == 1 else entries

    if isinstance(data, list):
        entries = data
    else:
        entries = [data]

    tech_list = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        plugins = entry.get("plugins", {})
        for tech, details in plugins.items():
            version = ""
            if isinstance(details, dict):
                ver_list = details.get("version", [])
                if ver_list:
                    version = ver_list[0] if isinstance(ver_list, list) else str(ver_list)
            tech_list.append(f"{tech}" + (f" {version}" if version else ""))

    if tech_list:
        findings.append(Finding(
            tool="whatweb",
            severity="info",
            name="Technology Stack Fingerprint",
            url=target,
            evidence=", ".join(tech_list[:30]),
            remediation="Ensure version numbers are not disclosed in HTTP headers or meta tags to reduce attack surface.",
            raw={"technologies": tech_list},
        ))

        # Flag outdated/risky tech
        risky_keywords = {
            "php/5": ("medium", "PHP 5.x is end-of-life. Upgrade to PHP 8.x."),
            "php/7.0": ("medium", "PHP 7.0 is end-of-life. Upgrade to PHP 8.x."),
            "php/7.1": ("medium", "PHP 7.1 is end-of-life. Upgrade to PHP 8.x."),
            "php/7.2": ("medium", "PHP 7.2 is end-of-life. Upgrade to PHP 8.x."),
            "wordpress/3": ("high", "WordPress 3.x is severely outdated. Update immediately."),
            "wordpress/4": ("medium", "WordPress 4.x is outdated. Update to latest."),
            "iis/6": ("critical", "IIS 6.0 is end-of-life and has critical vulnerabilities."),
            "iis/7": ("high", "IIS 7.x is end-of-life. Upgrade to IIS 10+."),
            "apache/2.2": ("medium", "Apache 2.2 is end-of-life. Upgrade to 2.4+."),
            "jquery/1": ("low", "jQuery 1.x has known XSS vulnerabilities. Upgrade to 3.x."),
            "jquery/2": ("low", "jQuery 2.x has known vulnerabilities. Upgrade to 3.x."),
        }
        for ev_lower in [t.lower() for t in tech_list]:
            for keyword, (sev, remed) in risky_keywords.items():
                if keyword in ev_lower:
                    findings.append(Finding(
                        tool="whatweb",
                        severity=sev,
                        name=f"Outdated Technology: {keyword.split('/')[0].title()}",
                        url=target,
                        evidence=f"Detected: {ev_lower}",
                        remediation=remed,
                    ))
                    break

    return findings
