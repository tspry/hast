"""trufflehog, gitleaks, and regex fallback for secret scanning."""

from __future__ import annotations

import json
import os
import re
import tempfile
from typing import AsyncIterator

import httpx

from backend.scanner.tools.base import Finding, SimpleToolRunner, ToolEvent

# Regex patterns for secret detection in JS/text content
SECRET_PATTERNS = {
    "AWS Access Key": (
        r"AKIA[0-9A-Z]{16}",
        "high",
        "Rotate this AWS key immediately via IAM console.",
    ),
    "AWS Secret Key": (
        r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
        "critical",
        "Rotate this AWS secret key immediately.",
    ),
    "Google API Key": (
        r"AIza[0-9A-Za-z\-_]{35}",
        "high",
        "Restrict or rotate this Google API key in the GCP console.",
    ),
    "GitHub Token": (
        r"ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|ghs_[0-9a-zA-Z]{36}",
        "critical",
        "Revoke this GitHub token immediately at github.com/settings/tokens.",
    ),
    "Slack Token": (
        r"xox[baprs]-[0-9a-zA-Z\-]+",
        "high",
        "Revoke this Slack token at api.slack.com/apps.",
    ),
    "Private Key": (
        r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "critical",
        "Remove and rotate this private key. Never commit keys to source.",
    ),
    "JWT Token": (
        r"eyJ[A-Za-z0-9_/+\-]{10,}={0,2}\.[A-Za-z0-9_/+\-]{10,}={0,2}\.[A-Za-z0-9_/+\-]{10,}={0,2}",
        "medium",
        "Review if this JWT is intentionally exposed. Ensure short TTL.",
    ),
    "Database Connection String": (
        r"(?i)(mongodb|mysql|postgresql|mssql|redis|amqp)://[^\s'\"`]+",
        "critical",
        "Remove database connection strings from source. Use environment variables.",
    ),
    "SendGrid API Key": (
        r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}",
        "high",
        "Rotate this SendGrid API key.",
    ),
    "Stripe Secret Key": (
        r"sk_live_[0-9a-zA-Z]{24}",
        "critical",
        "Rotate this Stripe secret key immediately.",
    ),
    "Stripe Publishable Key": (
        r"pk_live_[0-9a-zA-Z]{24}",
        "low",
        "Stripe publishable keys are semi-public but confirm this is intentional.",
    ),
    "Generic Secret": (
        r"(?i)(api_key|apikey|api_secret|secret_key|access_token|auth_token|password|passwd|pwd|authorization)\s*[=:]\s*['\"]?[a-zA-Z0-9_\-/+\.]{16,}['\"]?",
        "medium",
        "Review and rotate if this is a real credential. Use secrets management.",
    ),
    "Connection String (MSSQL)": (
        r"(?i)(server|data source)=[^;]+;.{0,100}password=[^;]+",
        "critical",
        "Remove connection strings from source code. Use environment variables.",
    ),
}


class TrufflehogTool(SimpleToolRunner):
    name = "trufflehog"
    binary = "trufflehog"

    async def run(self, url_list_file: str) -> AsyncIterator[ToolEvent | Finding]:
        if not self.available:
            yield self._unavailable_event()
            return

        args = [
            "filesystem",
            "--directory",
            "/dev/stdin",
            "--json",
            "--no-update",
        ]
        # trufflehog v3 works differently — use git or filesystem mode
        # For web URLs, use the url-based scanning
        args = ["url", url_list_file, "--json", "--no-update"]

        async for ev in self.run_raw(args, timeout=600):
            yield ev
            if ev.stream == "stdout":
                finding = _parse_trufflehog_line(ev.data)
                if finding:
                    yield finding


class GitleaksTool(SimpleToolRunner):
    name = "gitleaks"
    binary = "gitleaks"

    async def run_on_content(
        self, content: str, source_url: str
    ) -> AsyncIterator[ToolEvent | Finding]:
        """Scan a string of content (JS file contents) for secrets."""
        if not self.available:
            yield self._unavailable_event()
            return

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write(content)
            tmp_file = tf.name

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as out_tf:
            out_file = out_tf.name
        try:
            args = [
                "detect",
                "--source",
                tmp_file,
                "--report-format",
                "json",
                "--report-path",
                out_file,
                "--no-git",
                "--exit-code",
                "0",
            ]
            async for ev in self.run_raw(args, timeout=120):
                yield ev

            findings = _parse_gitleaks_output(out_file, source_url)
            for f in findings:
                yield f
        finally:
            for p in [tmp_file, out_file]:
                try:
                    os.unlink(p)
                except Exception:
                    pass


async def scan_js_content_regex(js_url: str, content: str) -> list[Finding]:
    """Apply regex patterns directly to JS file content."""
    findings = []
    for pattern_name, (pattern, severity, remediation) in SECRET_PATTERNS.items():
        matches = re.findall(pattern, content)
        for match in matches:
            # Truncate long matches
            evidence = match[:200] if len(match) > 200 else match
            # Skip likely false positives (placeholder values)
            if any(
                fp in evidence.lower()
                for fp in [
                    "your_",
                    "xxx",
                    "placeholder",
                    "example",
                    "dummy",
                    "changeme",
                ]
            ):
                continue
            findings.append(
                Finding(
                    tool="regex-secret-scan",
                    severity=severity,
                    name=f"Secret Pattern: {pattern_name}",
                    url=js_url,
                    evidence=f"Pattern match in JS: {evidence}",
                    remediation=remediation,
                )
            )
    return findings


async def fetch_js_and_scan(
    js_url: str, timeout: int = 30
) -> tuple[list[Finding], str]:
    """Fetch a JS URL and return (findings, content)."""
    from backend.config import get_config

    # verify=False is intentional: we scan targets that may have self-signed or
    # misconfigured TLS — that's exactly what we're looking for.
    # Set verify_tls: true in config.yaml to enforce cert validation.
    verify_tls = get_config().get("verify_tls", False)
    try:
        async with httpx.AsyncClient(
            timeout=timeout, verify=verify_tls, follow_redirects=True
        ) as client:
            resp = await client.get(
                js_url,
                headers={
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
                },
            )
            content = resp.text
    except Exception:
        return [], ""

    findings = await scan_js_content_regex(js_url, content)
    return findings, content


def _parse_trufflehog_line(line: str) -> Finding | None:
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None

    detector = data.get("DetectorName", data.get("detector_name", "Unknown"))
    verified = data.get("Verified", data.get("verified", False))
    raw = data.get("Raw", data.get("raw", ""))
    source_url = (
        data.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("file", "")
    )
    if not source_url:
        source_url = str(data.get("SourceMetadata", ""))

    severity = "critical" if verified else "high"
    return Finding(
        tool="trufflehog",
        severity=severity,
        name=f"Secret Detected: {detector}",
        url=source_url or "unknown",
        evidence=f"{'[VERIFIED] ' if verified else ''}{raw[:200]}",
        remediation="Rotate this credential immediately and audit access logs.",
        raw=data,
    )


def _parse_gitleaks_output(output_file: str, source_url: str) -> list[Finding]:
    findings = []
    try:
        with open(output_file) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return findings

    if not isinstance(data, list):
        data = [data]

    for leak in data:
        if not isinstance(leak, dict):
            continue
        rule = leak.get("RuleID", leak.get("ruleId", "unknown"))
        secret = leak.get("Secret", leak.get("secret", ""))
        match = leak.get("Match", leak.get("match", ""))
        findings.append(
            Finding(
                tool="gitleaks",
                severity="high",
                name=f"Secret Detected: {rule}",
                url=source_url,
                evidence=f"{match[:200]}",
                remediation="Rotate this credential immediately and audit access logs.",
                raw=leak,
            )
        )
    return findings
