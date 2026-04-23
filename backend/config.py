"""Configuration loader with auto-detection of tool paths and wordlists."""
from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Optional

import yaml

CONFIG_PATH = Path(__file__).parent.parent / "config.yaml"
_config: dict = {}


def load_config() -> dict:
    global _config
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            _config = yaml.safe_load(f) or {}
    else:
        _config = {}

    # Apply defaults
    _config.setdefault("rate_limit_ms", 150)
    _config.setdefault("waf_rate_limit_ms", 500)
    _config.setdefault("default_profile", "standard")
    _config.setdefault("respect_robots", True)
    _config.setdefault("server_host", "127.0.0.1")
    _config.setdefault("server_port", 8765)
    _config.setdefault("open_browser", True)
    _config.setdefault("tool_paths", {})
    _config.setdefault("user_agents", [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    ])

    # Auto-detect nuclei templates path
    if not _config.get("nuclei_templates_path"):
        _config["nuclei_templates_path"] = _detect_nuclei_templates()

    # Auto-detect seclists path
    if not _config.get("seclists_path"):
        _config["seclists_path"] = _detect_seclists()

    return _config


def get_config() -> dict:
    return _config if _config else load_config()


def save_config(updates: dict) -> None:
    cfg = get_config().copy()
    cfg.update(updates)
    with open(CONFIG_PATH, "w") as f:
        yaml.dump(cfg, f, default_flow_style=False)
    load_config()


def _detect_nuclei_templates() -> str:
    candidates = [
        os.path.expandvars("$NUCLEI_TEMPLATES"),
        os.path.expanduser("~/.local/nuclei-templates"),
        os.path.expanduser("~/nuclei-templates"),
        os.path.expanduser("~/.config/nuclei/templates"),
    ]
    for p in candidates:
        if p and p != "$NUCLEI_TEMPLATES" and Path(p).is_dir():
            return p
    return ""


def _detect_seclists() -> str:
    candidates = [
        "/usr/share/seclists",
        "/usr/share/SecLists",
        os.path.expanduser("~/seclists"),
        os.path.expanduser("~/SecLists"),
        os.path.expanduser("~/tools/seclists"),
    ]
    for p in candidates:
        if Path(p).is_dir():
            return p
    return ""


def resolve_tool_path(tool_name: str) -> Optional[str]:
    """Return binary path for tool, from config override or PATH."""
    cfg = get_config()
    configured = cfg.get("tool_paths", {}).get(tool_name, "")
    if configured and Path(configured).is_file():
        return configured
    return shutil.which(tool_name)


def get_ffuf_wordlist() -> Optional[str]:
    """Return path to raft-medium-files wordlist, or None."""
    seclists = get_config().get("seclists_path", "")
    if seclists:
        candidate = Path(seclists) / "Discovery" / "Web-Content" / "raft-medium-files.txt"
        if candidate.is_file():
            return str(candidate)
    return None


def get_rate_limit_ms(waf_detected: bool = False) -> int:
    cfg = get_config()
    if waf_detected:
        return int(cfg.get("waf_rate_limit_ms", 500))
    return int(cfg.get("rate_limit_ms", 150))
