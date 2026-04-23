"""Tests for backend/scanner/tools/nmap_tool.py."""
from __future__ import annotations

import pytest

from backend.scanner.tools.nmap_tool import _parse_nmap_xml, _parse_ports
from backend.scanner.tools.base import Finding


# ---------------------------------------------------------------------------
# Minimal valid nmap XML templates
# ---------------------------------------------------------------------------

def _make_nmap_xml(ports: list[tuple[str, str, str, str, str]]) -> str:
    """
    Build a minimal nmap XML document.
    Each port tuple: (portid, protocol, state, service_name, product_version)
    """
    port_elements = []
    for portid, proto, state, svc_name, version in ports:
        product, ver = (version.split(" ", 1) + [""])[:2]
        port_elements.append(f"""
        <port protocol="{proto}" portid="{portid}">
          <state state="{state}" reason="syn-ack" reason_ttl="64"/>
          <service name="{svc_name}" product="{product}" version="{ver}"/>
        </port>""")
    ports_block = "\n".join(port_elements)
    return f"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host starttime="1" endtime="2">
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
{ports_block}
    </ports>
  </host>
</nmaprun>"""


# ---------------------------------------------------------------------------
# _parse_nmap_xml
# ---------------------------------------------------------------------------

class TestParseNmapXml:
    TARGET = "https://example.com"

    def test_open_http_port_returns_info_finding(self):
        xml = _make_nmap_xml([("80", "tcp", "open", "http", "Apache 2.4.51")])
        findings = _parse_nmap_xml(xml, self.TARGET)
        assert len(findings) == 1
        f = findings[0]
        assert isinstance(f, Finding)
        assert f.tool == "nmap"
        assert f.severity == "info"
        assert "80" in f.name
        assert "http" in f.name.lower()

    def test_ftp_port_is_high_severity(self):
        xml = _make_nmap_xml([("21", "tcp", "open", "ftp", "vsftpd 3.0")])
        findings = _parse_nmap_xml(xml, self.TARGET)
        assert findings[0].severity == "high"

    def test_telnet_port_is_high_severity(self):
        xml = _make_nmap_xml([("23", "tcp", "open", "telnet", "")])
        findings = _parse_nmap_xml(xml, self.TARGET)
        assert findings[0].severity == "high"

    def test_rdp_port_is_high_severity(self):
        xml = _make_nmap_xml([("3389", "tcp", "open", "ms-wbt-server", "")])
        findings = _parse_nmap_xml(xml, self.TARGET)
        assert findings[0].severity == "high"

    def test_vnc_port_is_high_severity(self):
        xml = _make_nmap_xml([("5900", "tcp", "open", "vnc", "")])
        findings = _parse_nmap_xml(xml, self.TARGET)
        assert findings[0].severity == "high"

    def test_mysql_port_is_medium_severity(self):
        xml = _make_nmap_xml([("3306", "tcp", "open", "mysql", "MySQL 8.0")])
        findings = _parse_nmap_xml(xml, self.TARGET)
        assert findings[0].severity == "medium"

    def test_postgres_port_is_medium_severity(self):
        xml = _make_nmap_xml([("5432", "tcp", "open", "postgresql", "")])
        findings = _parse_nmap_xml(xml, self.TARGET)
        assert findings[0].severity == "medium"

    def test_redis_port_is_medium_severity(self):
        xml = _make_nmap_xml([("6379", "tcp", "open", "redis", "")])
        findings = _parse_nmap_xml(xml, self.TARGET)
        assert findings[0].severity == "medium"

    def test_mongodb_port_is_medium_severity(self):
        xml = _make_nmap_xml([("27017", "tcp", "open", "mongodb", "")])
        findings = _parse_nmap_xml(xml, self.TARGET)
        assert findings[0].severity == "medium"

    def test_closed_port_not_returned(self):
        xml = _make_nmap_xml([("22", "tcp", "closed", "ssh", "")])
        findings = _parse_nmap_xml(xml, self.TARGET)
        assert findings == []

    def test_multiple_ports_all_returned(self):
        xml = _make_nmap_xml([
            ("80", "tcp", "open", "http", "nginx"),
            ("443", "tcp", "open", "https", "nginx"),
            ("22", "tcp", "open", "ssh", "OpenSSH"),
        ])
        findings = _parse_nmap_xml(xml, self.TARGET)
        assert len(findings) == 3

    def test_url_field_contains_port(self):
        xml = _make_nmap_xml([("8080", "tcp", "open", "http-proxy", "")])
        findings = _parse_nmap_xml(xml, self.TARGET)
        assert "8080" in findings[0].url

    def test_evidence_contains_service_info(self):
        xml = _make_nmap_xml([("80", "tcp", "open", "http", "Apache 2.4")])
        findings = _parse_nmap_xml(xml, self.TARGET)
        assert "Apache" in findings[0].evidence

    def test_invalid_xml_returns_empty_list(self):
        findings = _parse_nmap_xml("not valid xml at all", self.TARGET)
        assert findings == []

    def test_empty_xml_returns_empty_list(self):
        findings = _parse_nmap_xml("", self.TARGET)
        assert findings == []

    def test_smb_port_445_is_medium(self):
        xml = _make_nmap_xml([("445", "tcp", "open", "microsoft-ds", "")])
        findings = _parse_nmap_xml(xml, self.TARGET)
        assert findings[0].severity == "medium"

    def test_raw_field_contains_port_info(self):
        xml = _make_nmap_xml([("3306", "tcp", "open", "mysql", "MySQL 8")])
        f = _parse_nmap_xml(xml, self.TARGET)[0]
        assert f.raw["port"] == "3306"
        assert f.raw["protocol"] == "tcp"
        assert f.raw["service"] == "mysql"


# ---------------------------------------------------------------------------
# _parse_ports
# ---------------------------------------------------------------------------

class TestParsePorts:
    def test_returns_port_dict_list(self):
        xml = _make_nmap_xml([("80", "tcp", "open", "http", "Apache")])
        ports = _parse_ports(xml)
        assert len(ports) == 1
        assert ports[0]["port"] == "80"
        assert ports[0]["protocol"] == "tcp"
        assert ports[0]["service"] == "http"

    def test_closed_ports_excluded(self):
        xml = _make_nmap_xml([("22", "tcp", "closed", "ssh", "")])
        ports = _parse_ports(xml)
        assert ports == []

    def test_multiple_ports(self):
        xml = _make_nmap_xml([
            ("80", "tcp", "open", "http", ""),
            ("443", "tcp", "open", "https", ""),
        ])
        ports = _parse_ports(xml)
        assert len(ports) == 2

    def test_invalid_xml_returns_empty(self):
        assert _parse_ports("garbage") == []

    def test_version_concatenated(self):
        xml = _make_nmap_xml([("80", "tcp", "open", "http", "Apache 2.4.51")])
        ports = _parse_ports(xml)
        assert "Apache" in ports[0]["version"]
