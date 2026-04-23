"""Tests for backend/config.py."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(content: str) -> Path:
    """Write a YAML config file in a temp directory and return its path."""
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
    tmp.write(content)
    tmp.flush()
    tmp.close()
    return Path(tmp.name)


# ---------------------------------------------------------------------------
# load_config
# ---------------------------------------------------------------------------

class TestLoadConfig:
    def test_defaults_applied_when_file_missing(self, tmp_path, monkeypatch):
        """Defaults are applied even when config.yaml does not exist."""
        import backend.config as cfg_module
        missing = tmp_path / "nonexistent.yaml"
        monkeypatch.setattr(cfg_module, "CONFIG_PATH", missing)
        monkeypatch.setattr(cfg_module, "_config", {})
        result = cfg_module.load_config()

        assert result["rate_limit_ms"] == 150
        assert result["waf_rate_limit_ms"] == 500
        assert result["default_profile"] == "standard"
        assert result["respect_robots"] is True
        assert result["server_host"] == "127.0.0.1"
        assert result["server_port"] == 8765
        assert result["open_browser"] is True
        assert isinstance(result["tool_paths"], dict)
        assert isinstance(result["user_agents"], list)

    def test_file_values_override_defaults(self, tmp_path, monkeypatch):
        """Values from config.yaml override built-in defaults."""
        import backend.config as cfg_module
        p = tmp_path / "config.yaml"
        p.write_text("rate_limit_ms: 999\nwaf_rate_limit_ms: 2000\n")
        monkeypatch.setattr(cfg_module, "CONFIG_PATH", p)
        monkeypatch.setattr(cfg_module, "_config", {})
        result = cfg_module.load_config()

        assert result["rate_limit_ms"] == 999
        assert result["waf_rate_limit_ms"] == 2000
        # Defaults that weren't overridden should still be present
        assert result["server_port"] == 8765

    def test_empty_yaml_uses_defaults(self, tmp_path, monkeypatch):
        """An empty YAML file still results in all defaults being present."""
        import backend.config as cfg_module
        p = tmp_path / "config.yaml"
        p.write_text("")
        monkeypatch.setattr(cfg_module, "CONFIG_PATH", p)
        monkeypatch.setattr(cfg_module, "_config", {})
        result = cfg_module.load_config()

        assert result["rate_limit_ms"] == 150


# ---------------------------------------------------------------------------
# get_config
# ---------------------------------------------------------------------------

class TestGetConfig:
    def test_returns_cached_config(self, monkeypatch):
        """get_config() returns the already-loaded config without reloading."""
        import backend.config as cfg_module
        sentinel = {"_loaded": True, "rate_limit_ms": 42}
        monkeypatch.setattr(cfg_module, "_config", sentinel)
        result = cfg_module.get_config()
        assert result is sentinel

    def test_loads_if_empty(self, tmp_path, monkeypatch):
        """get_config() calls load_config() when _config is empty."""
        import backend.config as cfg_module
        p = tmp_path / "config.yaml"
        p.write_text("rate_limit_ms: 77\n")
        monkeypatch.setattr(cfg_module, "CONFIG_PATH", p)
        monkeypatch.setattr(cfg_module, "_config", {})
        result = cfg_module.get_config()
        assert result["rate_limit_ms"] == 77


# ---------------------------------------------------------------------------
# save_config
# ---------------------------------------------------------------------------

class TestSaveConfig:
    def test_persists_and_reloads(self, tmp_path, monkeypatch):
        """save_config writes YAML and the file can be read back."""
        import backend.config as cfg_module
        import yaml
        p = tmp_path / "config.yaml"
        p.write_text("rate_limit_ms: 100\n")
        monkeypatch.setattr(cfg_module, "CONFIG_PATH", p)
        monkeypatch.setattr(cfg_module, "_config", {})
        cfg_module.load_config()

        cfg_module.save_config({"rate_limit_ms": 200})

        saved = yaml.safe_load(p.read_text())
        assert saved["rate_limit_ms"] == 200

    def test_update_does_not_remove_other_keys(self, tmp_path, monkeypatch):
        """Partial updates do not wipe unrelated keys."""
        import backend.config as cfg_module
        p = tmp_path / "config.yaml"
        p.write_text("rate_limit_ms: 100\nwaf_rate_limit_ms: 300\n")
        monkeypatch.setattr(cfg_module, "CONFIG_PATH", p)
        monkeypatch.setattr(cfg_module, "_config", {})
        cfg_module.load_config()

        cfg_module.save_config({"rate_limit_ms": 200})

        import yaml
        saved = yaml.safe_load(p.read_text())
        assert saved["waf_rate_limit_ms"] == 300


# ---------------------------------------------------------------------------
# resolve_tool_path
# ---------------------------------------------------------------------------

class TestResolveToolPath:
    def test_returns_none_when_tool_absent(self, monkeypatch):
        """Returns None for a tool that doesn't exist on PATH or in config."""
        import backend.config as cfg_module
        monkeypatch.setattr(cfg_module, "_config", {"tool_paths": {}})
        with patch("shutil.which", return_value=None):
            result = cfg_module.resolve_tool_path("definitely_not_a_real_tool_xyz")
        assert result is None

    def test_returns_which_result(self, monkeypatch):
        """Falls back to shutil.which when no config override."""
        import backend.config as cfg_module
        monkeypatch.setattr(cfg_module, "_config", {"tool_paths": {}})
        with patch("shutil.which", return_value="/usr/bin/curl"):
            result = cfg_module.resolve_tool_path("curl")
        assert result == "/usr/bin/curl"

    def test_config_override_takes_precedence(self, tmp_path, monkeypatch):
        """A valid path in tool_paths config takes precedence over PATH."""
        import backend.config as cfg_module
        fake_binary = tmp_path / "mynmap"
        fake_binary.write_text("#!/bin/sh")
        fake_binary.chmod(0o755)
        monkeypatch.setattr(cfg_module, "_config", {"tool_paths": {"nmap": str(fake_binary)}})
        result = cfg_module.resolve_tool_path("nmap")
        assert result == str(fake_binary)

    def test_config_override_ignored_if_file_missing(self, tmp_path, monkeypatch):
        """Falls back to PATH when the configured path does not exist."""
        import backend.config as cfg_module
        monkeypatch.setattr(cfg_module, "_config", {
            "tool_paths": {"nmap": str(tmp_path / "ghost")}
        })
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            result = cfg_module.resolve_tool_path("nmap")
        assert result == "/usr/bin/nmap"


# ---------------------------------------------------------------------------
# get_rate_limit_ms
# ---------------------------------------------------------------------------

class TestGetRateLimitMs:
    def test_normal_rate(self, monkeypatch):
        import backend.config as cfg_module
        monkeypatch.setattr(cfg_module, "_config", {
            "rate_limit_ms": 150, "waf_rate_limit_ms": 500
        })
        assert cfg_module.get_rate_limit_ms(waf_detected=False) == 150

    def test_waf_rate(self, monkeypatch):
        import backend.config as cfg_module
        monkeypatch.setattr(cfg_module, "_config", {
            "rate_limit_ms": 150, "waf_rate_limit_ms": 500
        })
        assert cfg_module.get_rate_limit_ms(waf_detected=True) == 500

    def test_custom_waf_rate(self, monkeypatch):
        import backend.config as cfg_module
        monkeypatch.setattr(cfg_module, "_config", {
            "rate_limit_ms": 100, "waf_rate_limit_ms": 1000
        })
        assert cfg_module.get_rate_limit_ms(waf_detected=True) == 1000


# ---------------------------------------------------------------------------
# get_ffuf_wordlist
# ---------------------------------------------------------------------------

class TestGetFfufWordlist:
    def test_returns_none_when_no_seclists(self, monkeypatch):
        import backend.config as cfg_module
        monkeypatch.setattr(cfg_module, "_config", {"seclists_path": ""})
        assert cfg_module.get_ffuf_wordlist() is None

    def test_returns_path_when_wordlist_exists(self, tmp_path, monkeypatch):
        import backend.config as cfg_module
        wordlist_dir = tmp_path / "Discovery" / "Web-Content"
        wordlist_dir.mkdir(parents=True)
        wordlist = wordlist_dir / "raft-medium-files.txt"
        wordlist.write_text("index.php\n")
        monkeypatch.setattr(cfg_module, "_config", {"seclists_path": str(tmp_path)})
        result = cfg_module.get_ffuf_wordlist()
        assert result == str(wordlist)

    def test_returns_none_when_wordlist_file_missing(self, tmp_path, monkeypatch):
        import backend.config as cfg_module
        monkeypatch.setattr(cfg_module, "_config", {"seclists_path": str(tmp_path)})
        assert cfg_module.get_ffuf_wordlist() is None


# ---------------------------------------------------------------------------
# _detect_nuclei_templates / _detect_seclists
# ---------------------------------------------------------------------------

class TestAutoDetection:
    def test_detect_nuclei_templates_env_var(self, tmp_path, monkeypatch):
        """NUCLEI_TEMPLATES env var is used if it points to a real dir."""
        import backend.config as cfg_module
        monkeypatch.setenv("NUCLEI_TEMPLATES", str(tmp_path))
        result = cfg_module._detect_nuclei_templates()
        assert result == str(tmp_path)

    def test_detect_nuclei_templates_returns_empty_if_none_found(self, monkeypatch):
        import backend.config as cfg_module
        monkeypatch.setenv("NUCLEI_TEMPLATES", "$NUCLEI_TEMPLATES")  # unexpanded
        # All candidate paths are non-existent
        with patch("pathlib.Path.is_dir", return_value=False):
            result = cfg_module._detect_nuclei_templates()
        assert result == ""

    def test_detect_seclists_returns_empty_if_not_found(self, monkeypatch):
        import backend.config as cfg_module
        with patch("pathlib.Path.is_dir", return_value=False):
            result = cfg_module._detect_seclists()
        assert result == ""

    def test_detect_seclists_finds_custom_path(self, tmp_path, monkeypatch):
        import backend.config as cfg_module
        # Patch expanduser to return our tmp_path for ~/seclists
        original = os.path.expanduser
        monkeypatch.setattr(os.path, "expanduser",
                            lambda p: str(tmp_path) if p == "~/seclists" else original(p))
        result = cfg_module._detect_seclists()
        assert result == str(tmp_path)
