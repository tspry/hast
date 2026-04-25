"""ProjectDiscovery tools used by HAST: subfinder, dnsx, httpx, naabu."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import AsyncIterator, Iterable, Optional

from backend.scanner.tools.base import Finding, SimpleToolRunner, ToolEvent


def _write_temp_lines(lines: Iterable[str], suffix: str = ".txt") -> str:
    with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False) as tf:
        for line in lines:
            line = str(line).strip()
            if line:
                tf.write(line + "\n")
        return tf.name


def _json_or_text(line: str) -> dict | str | None:
    text = (line or "").strip()
    if not text:
        return None
    if text.startswith("{") or text.startswith("["):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None
    return text


def _tool_value(data: dict | str | None, *keys: str) -> Optional[str]:
    if isinstance(data, str):
        return data.strip() or None
    if not isinstance(data, dict):
        return None
    for key in keys:
        value = data.get(key)
        if value:
            return str(value).strip()
    return None


def _port_severity(port: str, service: str) -> tuple[str, str]:
    risky = {
        "21": ("high", "FTP should not be exposed publicly. Restrict or disable it."),
        "23": ("high", "Telnet should not be exposed publicly. Use SSH instead."),
        "3389": ("high", "RDP should be restricted to VPN or trusted IPs."),
        "5900": ("high", "VNC should be restricted to VPN or trusted IPs."),
        "445": ("medium", "SMB should not be exposed publicly."),
        "3306": ("medium", "Database service should be restricted to trusted hosts."),
        "5432": ("medium", "Database service should be restricted to trusted hosts."),
        "1433": ("medium", "Database service should be restricted to trusted hosts."),
        "6379": ("medium", "Redis should be restricted to trusted hosts."),
        "27017": ("medium", "MongoDB should be restricted to trusted hosts."),
        "9200": ("medium", "Elasticsearch should be restricted to trusted hosts."),
    }
    if port in risky:
        return risky[port]
    if service in {"http", "https", "http-proxy"}:
        return (
            "info",
            "Web service port discovered by naabu. Verify it should be reachable.",
        )
    return "low", "Review whether this port should be exposed externally."


class SubfinderTool(SimpleToolRunner):
    name = "subfinder"
    binary = "subfinder"

    async def discover(self, domain: str) -> AsyncIterator[ToolEvent]:
        if not self.available:
            yield self._unavailable_event()
            return
        args = ["-d", domain, "-all", "-silent", "-json"]
        async for ev in self.run_raw(args, timeout=900):
            yield ev


class DnsxTool(SimpleToolRunner):
    name = "dnsx"
    binary = "dnsx"

    async def resolve(self, hosts: list[str]) -> AsyncIterator[ToolEvent]:
        if not self.available:
            yield self._unavailable_event()
            return
        host_file = _write_temp_lines(hosts)
        try:
            args = ["-l", host_file, "-json", "-silent"]
            async for ev in self.run_raw(args, timeout=600):
                yield ev
        finally:
            Path(host_file).unlink(missing_ok=True)


class HttpxTool(SimpleToolRunner):
    name = "httpx"
    binary = "httpx"

    async def probe(self, targets: list[str]) -> AsyncIterator[ToolEvent]:
        if not self.available:
            yield self._unavailable_event()
            return
        target_file = _write_temp_lines(targets)
        try:
            args = [
                "-l",
                target_file,
                "-j",
                "-silent",
                "-sc",
                "-title",
                "-td",
                "-location",
                "-server",
            ]
            async for ev in self.run_raw(args, timeout=900):
                yield ev
        finally:
            Path(target_file).unlink(missing_ok=True)


class NaabuTool(SimpleToolRunner):
    name = "naabu"
    binary = "naabu"

    async def scan(
        self, hosts: list[str], top_ports: str = "100"
    ) -> AsyncIterator[ToolEvent | Finding]:
        if not self.available:
            yield self._unavailable_event()
            return
        host_file = _write_temp_lines(hosts)
        try:
            args = [
                "-l",
                host_file,
                "-j",
                "-silent",
                "-s",
                "c",
                "-tp",
                top_ports,
            ]
            async for ev in self.run_raw(args, timeout=900):
                yield ev
                if ev.stream != "stdout":
                    continue
                record = _json_or_text(ev.data)
                if not isinstance(record, dict):
                    continue
                finding = _parse_naabu_record(record)
                if finding:
                    yield finding
        finally:
            Path(host_file).unlink(missing_ok=True)


class TlsxTool(SimpleToolRunner):
    name = "tlsx"
    binary = "tlsx"

    async def scan(self, target: str) -> AsyncIterator[ToolEvent | Finding]:
        if not self.available:
            yield self._unavailable_event()
            return
        # Strip scheme — tlsx wants host[:port]
        from urllib.parse import urlparse
        parsed = urlparse(target)
        host = parsed.netloc or parsed.path
        args = ["-u", host, "-json", "-silent", "-expired", "-self-signed", "-mismatched", "-ro"]
        async for ev in self.run_raw(args, timeout=60):
            yield ev
            if ev.stream == "stdout":
                f = _parse_tlsx_line(ev.data, target)
                if f:
                    yield f


class CdncheckTool(SimpleToolRunner):
    name = "cdncheck"
    binary = "cdncheck"

    async def check(self, target: str) -> AsyncIterator[ToolEvent | Finding]:
        if not self.available:
            yield self._unavailable_event()
            return
        from urllib.parse import urlparse
        host = urlparse(target).hostname or target
        args = ["-i", host, "-resp", "-json", "-silent"]
        async for ev in self.run_raw(args, timeout=30):
            yield ev
            if ev.stream == "stdout":
                f = _parse_cdncheck_line(ev.data, target)
                if f:
                    yield f


class AsnmapTool(SimpleToolRunner):
    name = "asnmap"
    binary = "asnmap"

    async def lookup(self, target: str) -> AsyncIterator[ToolEvent | Finding]:
        if not self.available:
            yield self._unavailable_event()
            return
        from urllib.parse import urlparse
        host = urlparse(target).hostname or target
        args = ["-i", host, "-json", "-silent"]
        async for ev in self.run_raw(args, timeout=60):
            yield ev
            if ev.stream == "stdout":
                f = _parse_asnmap_line(ev.data, target)
                if f:
                    yield f


class AlterxTool(SimpleToolRunner):
    name = "alterx"
    binary = "alterx"

    async def permute(self, subdomains: list[str]) -> AsyncIterator[ToolEvent]:
        if not self.available:
            yield self._unavailable_event()
            return
        sub_file = _write_temp_lines(subdomains)
        try:
            args = ["-l", sub_file, "-silent"]
            async for ev in self.run_raw(args, timeout=120):
                yield ev
        finally:
            Path(sub_file).unlink(missing_ok=True)


class ShuffleDnsTool(SimpleToolRunner):
    name = "shuffledns"
    binary = "shuffledns"

    async def bruteforce(
        self, domain: str, wordlist: str, resolvers: str
    ) -> AsyncIterator[ToolEvent]:
        if not self.available:
            yield self._unavailable_event()
            return
        args = [
            "-d", domain,
            "-w", wordlist,
            "-r", resolvers,
            "-silent",
            "-json",
        ]
        async for ev in self.run_raw(args, timeout=900):
            yield ev


class UrlffinderTool(SimpleToolRunner):
    name = "urlfinder"
    binary = "urlfinder"

    async def find(self, target: str) -> AsyncIterator[ToolEvent]:
        if not self.available:
            yield self._unavailable_event()
            return
        args = ["-u", target, "-silent", "-all"]
        async for ev in self.run_raw(args, timeout=300):
            yield ev


# ── Output parsers ────────────────────────────────────────────────────────────

def _parse_tlsx_line(line: str, target: str) -> Optional[Finding]:
    data = _json_or_text(line)
    if not isinstance(data, dict):
        return None
    host = _tool_value(data, "host", "ip") or target
    expired = data.get("expired", False)
    self_signed = data.get("self_signed", False)
    mismatched = data.get("mismatched", False)
    tls_version = data.get("tls_version", data.get("version", ""))
    subject_cn = data.get("subject_cn", data.get("host", ""))
    not_after = data.get("not_after", "")
    issuer = data.get("issuer_cn", data.get("issuer_org", [""])[0] if isinstance(data.get("issuer_org"), list) else "")

    if expired:
        return Finding(
            tool="tlsx", severity="high",
            name="Expired TLS Certificate",
            url=target,
            evidence=f"Certificate for {subject_cn} expired on {not_after}. Issued by: {issuer}",
            remediation="Renew the TLS certificate immediately. Set up auto-renewal (Let's Encrypt / ACME).",
            raw=data,
        )
    if self_signed:
        return Finding(
            tool="tlsx", severity="medium",
            name="Self-Signed TLS Certificate",
            url=target,
            evidence=f"Certificate for {subject_cn} is self-signed (not trusted by browsers).",
            remediation="Replace with a certificate from a trusted CA (e.g. Let's Encrypt).",
            raw=data,
        )
    if mismatched:
        return Finding(
            tool="tlsx", severity="medium",
            name="TLS Certificate Hostname Mismatch",
            url=target,
            evidence=f"Certificate CN={subject_cn} does not match the host.",
            remediation="Obtain a certificate that covers the correct hostname.",
            raw=data,
        )
    if tls_version and tls_version.lower() in ("tls10", "tls1.0", "tls 1.0", "tls11", "tls1.1", "tls 1.1"):
        return Finding(
            tool="tlsx", severity="medium",
            name=f"Weak TLS Version: {tls_version}",
            url=target,
            evidence=f"Server supports deprecated {tls_version}.",
            remediation="Disable TLS 1.0 and 1.1. Require TLS 1.2+ with strong cipher suites.",
            raw=data,
        )
    # Informational — cert is valid
    return Finding(
        tool="tlsx", severity="info",
        name="TLS Certificate Info",
        url=target,
        evidence=f"CN={subject_cn} | Issuer={issuer} | Expires={not_after} | Version={tls_version}",
        remediation="Monitor certificate expiry and renew before expiration.",
        raw=data,
    )


def _parse_cdncheck_line(line: str, target: str) -> Optional[Finding]:
    data = _json_or_text(line)
    if not isinstance(data, dict):
        return None
    cdn_name = _tool_value(data, "cdn_name", "provider", "name") or ""
    cdn_type = _tool_value(data, "type", "cdn_type") or "cdn"
    ip = _tool_value(data, "ip", "input") or ""
    if not cdn_name:
        return None
    return Finding(
        tool="cdncheck", severity="info",
        name=f"CDN Detected: {cdn_name}",
        url=target,
        evidence=f"IP {ip} is part of {cdn_name} ({cdn_type}). Traffic passes through CDN edge nodes.",
        remediation="Ensure the origin server IP is not exposed. CDN may mask some vulnerabilities — test origin directly if possible.",
        raw=data,
    )


def _parse_asnmap_line(line: str, target: str) -> Optional[Finding]:
    data = _json_or_text(line)
    if not isinstance(data, dict):
        return None
    asn = _tool_value(data, "asn", "as_number") or ""
    org = _tool_value(data, "org", "as_org", "as_name") or ""
    cidrs = data.get("cidr", data.get("routes", []))
    if isinstance(cidrs, str):
        cidrs = [cidrs]
    if not asn and not org:
        return None
    cidr_str = ", ".join(cidrs[:10]) if cidrs else "N/A"
    return Finding(
        tool="asnmap", severity="info",
        name=f"ASN Info: {asn} ({org})",
        url=target,
        evidence=f"ASN: {asn} | Org: {org} | CIDRs: {cidr_str}",
        remediation="Review all IP ranges in the ASN for additional exposed services.",
        raw=data,
    )


def parse_subfinder_record(line: str) -> Optional[str]:
    data = _json_or_text(line)
    return _tool_value(data, "host", "subdomain", "name")


def parse_dnsx_record(line: str) -> Optional[str]:
    data = _json_or_text(line)
    return _tool_value(data, "host", "domain", "name")


def parse_httpx_record(line: str) -> Optional[str]:
    data = _json_or_text(line)
    return _tool_value(data, "url", "input", "host")


def _parse_naabu_record(data: dict) -> Optional[Finding]:
    host = _tool_value(data, "host", "input", "ip", "hostname")
    port = str(data.get("port") or "").strip()
    if not host or not port:
        return None
    service = str(data.get("service") or data.get("service_name") or "").strip()
    protocol = str(data.get("protocol") or "tcp").strip()
    severity, remediation = _port_severity(port, service)
    return Finding(
        tool="naabu",
        severity=severity,
        name=f"Open Port: {port}/{protocol} ({service or 'unknown'})",
        url=f"{host}:{port}",
        evidence=f"Port {port}/{protocol} open on {host} — {service or 'unknown'}",
        remediation=remediation,
        raw={
            "host": host,
            "port": port,
            "protocol": protocol,
            "service": service,
            "ip": data.get("ip", ""),
        },
    )


def parse_naabu_record(line: str) -> Optional[Finding]:
    data = _json_or_text(line)
    if not isinstance(data, dict):
        return None
    return _parse_naabu_record(data)
