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
