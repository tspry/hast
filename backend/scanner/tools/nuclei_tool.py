"""nuclei – vulnerability and exposure scanner."""

from __future__ import annotations

import json
from pathlib import Path
from typing import AsyncIterator, Optional

from backend.config import get_config
from backend.scanner.tools.base import Finding, SimpleToolRunner, ToolEvent

TEMPLATE_PATHS = [
    "http/exposures/configs/",
    "http/exposures/files/",
    "http/exposures/tokens/",
    "http/exposures/logs/",
    "network/",
]

TAGS = [
    "env,dotenv,config,appsettings,exposure,backup",
    "misconfig,default-login,panel",
    "ssl,tls,http-missing-headers,csp,cors,clickjacking,takeover",
    "tech",
]

SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}

REMEDIATION_MAP = {
    "env": "Remove .env files from web root. Add to .gitignore and rotate any exposed secrets.",
    "dotenv": "Remove .env files from web root. Add to .gitignore and rotate any exposed secrets.",
    "config": "Move configuration files outside the web root or block via server rules.",
    "appsettings": "Remove appsettings.json from web root. Use environment variables for secrets.",
    "backup": "Remove backup files from web root. Implement access controls.",
    "ssl": "Update SSL/TLS configuration. Disable weak protocols (SSLv3, TLS 1.0/1.1).",
    "tls": "Update TLS configuration to TLS 1.2+ with strong cipher suites.",
    "http-missing-headers": "Add missing security headers (HSTS, CSP, X-Frame-Options, etc.).",
    "cors": "Restrict CORS origin to trusted domains only.",
    "csp": "Implement a strict Content Security Policy.",
    "clickjacking": "Add X-Frame-Options: DENY or SAMEORIGIN header.",
    "takeover": "Claim or remove the dangling DNS record to prevent subdomain takeover.",
    "exposure": "Restrict access to exposed files/endpoints via authentication or server rules.",
    "misconfig": "Review and correct the misconfiguration per the evidence provided.",
    "default-login": "Change default credentials immediately.",
    "panel": "Restrict admin panel access to trusted IP ranges.",
}


class NucleiTool(SimpleToolRunner):
    name = "nuclei"
    binary = "nuclei"

    async def run(
        self,
        urls: list[str],
        extra_tags: Optional[list[str]] = None,
        rate_limit: int = 150,
        headless: bool = False,
        custom_templates: Optional[list[str]] = None,
    ) -> AsyncIterator[ToolEvent | Finding]:
        if not self.available:
            yield self._unavailable_event()
            return

        cfg = get_config()
        templates_path = cfg.get("nuclei_templates_path", "")

        # Build URL list file
        import os
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(urls))
            url_file = tf.name

        try:
            args = self._build_args(
                url_file,
                templates_path,
                extra_tags or [],
                rate_limit,
                headless,
                custom_templates or [],
            )
            async for ev in self.run_raw(args, timeout=1800):
                yield ev
                if ev.stream == "stdout":
                    finding = _parse_nuclei_line(ev.data)
                    if finding:
                        yield finding
        finally:
            try:
                os.unlink(url_file)
            except Exception:
                pass

    def _build_args(
        self,
        url_file: str,
        templates_path: str,
        extra_tags: list[str],
        rate_limit: int,
        headless: bool,
        custom_templates: list[str],
    ) -> list[str]:
        args = [
            "-l",
            url_file,
            "-jsonl",
            "-silent",
            "-rate-limit",
            str(max(1, 1000 // max(rate_limit, 1))),
            "-severity",
            "low,medium,high,critical,info",
            "-retries",
            "1",
            "-timeout",
            "10",
        ]

        # ── Community templates ────────────────────────────────────────────────
        if templates_path and Path(templates_path).is_dir():
            for tp in TEMPLATE_PATHS:
                full = Path(templates_path) / tp
                if full.exists():
                    args += ["-t", str(full)]
        all_tags = list(TAGS) + extra_tags
        args += ["-tags", ",".join(all_tags)]

        # ── HAST custom templates (always included) ────────────────────────────
        hast_templates = (
            Path(__file__).parent.parent.parent.parent / "nuclei-templates" / "hast"
        )
        if hast_templates.is_dir():
            args += ["-t", str(hast_templates)]

        # ── Caller-supplied extra templates ────────────────────────────────────
        for ct in custom_templates:
            args += ["-t", ct]

        if headless:
            args.append("-headless")

        return args


def _parse_nuclei_line(line: str) -> Optional[Finding]:
    """Parse a nuclei JSON output line into a Finding."""
    line = line.strip()
    if not line or not line.startswith("{"):
        return None
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None

    info = data.get("info", {})
    severity = SEVERITY_MAP.get(info.get("severity", "info").lower(), "info")
    name = info.get("name", data.get("template-id", "Unknown"))
    url = data.get("matched-at", data.get("host", ""))
    evidence = data.get("extracted-results", "")
    if isinstance(evidence, list):
        evidence = "\n".join(str(e) for e in evidence)
    if not evidence:
        evidence = data.get("curl-command", "")
    if not evidence:
        evidence = f"Template: {data.get('template-id', 'N/A')}"

    # Find best remediation
    tags = info.get("tags", [])
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    remediation = "Review and address the identified issue."
    for tag in tags:
        if tag in REMEDIATION_MAP:
            remediation = REMEDIATION_MAP[tag]
            break
    if info.get("remediation"):
        remediation = info["remediation"]

    cvss = None
    classification = info.get("classification", {})
    if isinstance(classification, dict):
        cvss = classification.get("cvss-score") or classification.get("cvss-metrics")
        if cvss and not isinstance(cvss, (int, float)):
            # Extract first number from CVSS string
            import re

            m = re.search(r"(\d+\.?\d*)", str(cvss))
            cvss = float(m.group(1)) if m else None

    return Finding(
        tool="nuclei",
        severity=severity,
        name=name,
        url=url,
        evidence=evidence,
        remediation=remediation,
        cvss_score=float(cvss) if cvss else None,
        raw=data,
    )
