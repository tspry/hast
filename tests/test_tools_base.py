"""Tests for backend/scanner/tools/base.py — Finding, ToolRunner, SimpleToolRunner."""
from __future__ import annotations

import asyncio
from unittest.mock import patch, MagicMock

import pytest
import pytest_asyncio

from backend.scanner.tools.base import Finding, ToolEvent, ToolRunner, SimpleToolRunner


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

class TestFinding:
    def test_risk_score_critical(self):
        f = Finding(tool="test", severity="critical", name="X", url="http://t.com")
        assert f.risk_score() == 92

    def test_risk_score_high(self):
        f = Finding(tool="test", severity="high", name="X", url="http://t.com")
        assert f.risk_score() == 75

    def test_risk_score_medium(self):
        f = Finding(tool="test", severity="medium", name="X", url="http://t.com")
        assert f.risk_score() == 50

    def test_risk_score_low(self):
        f = Finding(tool="test", severity="low", name="X", url="http://t.com")
        assert f.risk_score() == 25

    def test_risk_score_info(self):
        f = Finding(tool="test", severity="info", name="X", url="http://t.com")
        assert f.risk_score() == 5

    def test_risk_score_unknown_severity_defaults_to_info(self):
        f = Finding(tool="test", severity="bogus", name="X", url="http://t.com")
        assert f.risk_score() == 5

    def test_risk_score_case_insensitive(self):
        f = Finding(tool="test", severity="CRITICAL", name="X", url="http://t.com")
        assert f.risk_score() == 92

    def test_default_fields(self):
        f = Finding(tool="nuclei", severity="high", name="Vuln", url="http://example.com")
        assert f.evidence == ""
        assert f.remediation == ""
        assert f.cvss_score is None
        assert f.raw == {}

    def test_raw_field_is_independent_per_instance(self):
        f1 = Finding(tool="t", severity="info", name="A", url="http://a.com")
        f2 = Finding(tool="t", severity="info", name="B", url="http://b.com")
        f1.raw["key"] = "value"
        assert "key" not in f2.raw


# ---------------------------------------------------------------------------
# ToolEvent dataclass
# ---------------------------------------------------------------------------

class TestToolEvent:
    def test_defaults(self):
        ev = ToolEvent(stream="stdout", data="hello")
        assert ev.tool == ""

    def test_with_tool(self):
        ev = ToolEvent(stream="stderr", data="err", tool="nmap")
        assert ev.tool == "nmap"


# ---------------------------------------------------------------------------
# ToolRunner
# ---------------------------------------------------------------------------

class TestToolRunner:
    def test_unavailable_when_binary_not_found(self, monkeypatch):
        """ToolRunner marks itself as unavailable when binary is missing."""
        import backend.config as cfg_module
        monkeypatch.setattr(cfg_module, "_config", {"tool_paths": {}})
        with patch("shutil.which", return_value=None):
            runner = ToolRunner()
        assert runner.available is False
        assert runner.path is None

    def test_available_when_binary_found(self, monkeypatch, tmp_path):
        """ToolRunner marks itself as available when binary exists."""
        import backend.config as cfg_module
        fake = tmp_path / "fake_tool"
        fake.write_text("#!/bin/sh")
        fake.chmod(0o755)
        monkeypatch.setattr(cfg_module, "_config", {"tool_paths": {}})
        with patch("shutil.which", return_value=str(fake)):
            runner = ToolRunner()
            runner.binary = "fake_tool"
        assert runner.available is True

    def test_unavailable_event_format(self, monkeypatch):
        import backend.config as cfg_module
        monkeypatch.setattr(cfg_module, "_config", {"tool_paths": {}})
        with patch("shutil.which", return_value=None):
            runner = ToolRunner()
        runner.name = "mytool"
        ev = runner._unavailable_event()
        assert ev.stream == "warning"
        assert "mytool" in ev.data
        assert "not found" in ev.data


# ---------------------------------------------------------------------------
# SimpleToolRunner.run_raw (unavailable path)
# ---------------------------------------------------------------------------

class TestSimpleToolRunnerUnavailable:
    @pytest.mark.asyncio
    async def test_run_raw_yields_warning_when_unavailable(self, monkeypatch):
        import backend.config as cfg_module
        monkeypatch.setattr(cfg_module, "_config", {"tool_paths": {}})
        with patch("shutil.which", return_value=None):
            runner = SimpleToolRunner()
        runner.name = "ghosttool"

        events = []
        async for ev in runner.run_raw(["--help"]):
            events.append(ev)

        assert len(events) == 1
        assert events[0].stream == "warning"
        assert "ghosttool" in events[0].data


# ---------------------------------------------------------------------------
# ToolRunner._run_subprocess — low-level integration with real echo command
# ---------------------------------------------------------------------------

class TestRunSubprocess:
    @pytest.mark.asyncio
    async def test_streams_stdout_lines(self, monkeypatch, tmp_path):
        """_run_subprocess streams stdout lines from a real subprocess."""
        import backend.config as cfg_module
        echo_path = "/bin/echo"
        monkeypatch.setattr(cfg_module, "_config", {"tool_paths": {}})
        with patch("shutil.which", return_value=echo_path):
            runner = ToolRunner()
        runner.path = echo_path
        runner.name = "echo"
        runner.available = True

        events = []
        async for ev in runner._run_subprocess(["hello world"]):
            events.append(ev)

        stdout_events = [e for e in events if e.stream == "stdout"]
        assert any("hello world" in e.data for e in stdout_events)

    @pytest.mark.asyncio
    async def test_handles_file_not_found(self, monkeypatch):
        """_run_subprocess emits an error event when binary is missing."""
        import backend.config as cfg_module
        monkeypatch.setattr(cfg_module, "_config", {"tool_paths": {}})
        with patch("shutil.which", return_value=None):
            runner = ToolRunner()
        runner.path = "/nonexistent/binary_xyz"
        runner.name = "missingtool"
        runner.available = True

        events = []
        async for ev in runner._run_subprocess([]):
            events.append(ev)

        assert any(e.stream == "error" for e in events)

    @pytest.mark.asyncio
    async def test_timeout_terminates_process(self, monkeypatch):
        """_run_subprocess emits a warning when the process times out."""
        import backend.config as cfg_module
        sleep_path = "/bin/sleep"
        monkeypatch.setattr(cfg_module, "_config", {"tool_paths": {}})
        with patch("shutil.which", return_value=sleep_path):
            runner = ToolRunner()
        runner.path = sleep_path
        runner.name = "sleep"
        runner.available = True

        events = []
        async for ev in runner._run_subprocess(["60"], timeout=1):
            events.append(ev)

        assert any(e.stream == "warning" and "timed out" in e.data for e in events)
