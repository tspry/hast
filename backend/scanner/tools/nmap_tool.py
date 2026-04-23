"""nmap – port/service scanning with XML output parsing."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import AsyncIterator
from urllib.parse import urlparse

from backend.scanner.tools.base import Finding, SimpleToolRunner, ToolEvent


class NmapTool(SimpleToolRunner):
    name = "nmap"
    binary = "nmap"

    async def run(self, target: str) -> AsyncIterator[ToolEvent | Finding]:
        if not self.available:
            yield self._unavailable_event()
            return

        host = urlparse(target).hostname or target
        xml_lines: list[str] = []
        collecting_xml = False

        args = ["-sV", "--open", "-T4", "--script=banner,http-title",
                "-oX", "-", host]

        async for ev in self.run_raw(args, timeout=300):
            if ev.stream == "stdout":
                xml_lines.append(ev.data)
                # Still emit progress lines to terminal
                if not ev.data.startswith("<") or "Nmap scan" in ev.data:
                    yield ev
            else:
                yield ev

        # Parse XML
        xml_text = "\n".join(xml_lines)
        findings = _parse_nmap_xml(xml_text, target)
        for f in findings:
            yield f

    def parse_open_ports(self, xml_text: str) -> list[dict]:
        """Return list of {port, protocol, service, version} dicts."""
        return _parse_ports(xml_text)


def _parse_nmap_xml(xml_text: str, target: str) -> list[Finding]:
    findings = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return findings

    for host in root.findall("host"):
        for port_el in host.findall(".//port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = port_el.get("portid", "?")
            proto = port_el.get("protocol", "tcp")
            svc = port_el.find("service")
            svc_name = svc.get("name", "unknown") if svc is not None else "unknown"
            svc_product = svc.get("product", "") if svc is not None else ""
            svc_version = svc.get("version", "") if svc is not None else ""
            full_svc = " ".join(filter(None, [svc_product, svc_version]))

            # Flag interesting services
            severity = "info"
            remediation = "Verify this port should be exposed externally."
            if portid in ("21", "23", "3389", "5900"):
                severity = "high"
                remediation = "This protocol transmits credentials in plaintext or is high-risk. Disable or restrict access."
            elif portid in ("445", "139", "3306", "5432", "1433", "6379", "27017", "9200", "11211"):
                severity = "medium"
                remediation = "Database/internal service exposed. Restrict with firewall rules or VPN."
            elif svc_name in ("http", "https"):
                severity = "info"
                remediation = "Web service port — will be included in nuclei scan targets."

            findings.append(Finding(
                tool="nmap",
                severity=severity,
                name=f"Open Port: {portid}/{proto} ({svc_name})",
                url=f"{target}:{portid}",
                evidence=f"Port {portid}/{proto} open — {full_svc or svc_name}",
                remediation=remediation,
                raw={"port": portid, "protocol": proto, "service": svc_name, "version": full_svc},
            ))
    return findings


def _parse_ports(xml_text: str) -> list[dict]:
    ports = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return ports
    for host in root.findall("host"):
        for port_el in host.findall(".//port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port_el.find("service")
            ports.append({
                "port": port_el.get("portid"),
                "protocol": port_el.get("protocol", "tcp"),
                "service": svc.get("name", "unknown") if svc is not None else "unknown",
                "version": " ".join(filter(None, [
                    svc.get("product", "") if svc is not None else "",
                    svc.get("version", "") if svc is not None else "",
                ])),
            })
    return ports
