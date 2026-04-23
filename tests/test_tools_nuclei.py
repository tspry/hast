"""Tests for backend/scanner/tools/nuclei_tool.py."""
from __future__ import annotations

import json

import pytest

from backend.scanner.tools.nuclei_tool import _parse_nuclei_line, SEVERITY_MAP, REMEDIATION_MAP
from backend.scanner.tools.base import Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _nuclei_line(
    template_id: str = "test-template",
    name: str = "Test Finding",
    severity: str = "medium",
    matched_at: str = "https://example.com",
    tags: list[str] | str | None = None,
    extracted: list[str] | str | None = None,
    cvss_score: float | None = None,
    remediation: str | None = None,
) -> str:
    info: dict = {"name": name, "severity": severity}
    if tags is not None:
        info["tags"] = tags
    if remediation:
        info["remediation"] = remediation
    if cvss_score is not None:
        info["classification"] = {"cvss-score": cvss_score}
    data = {
        "template-id": template_id,
        "info": info,
        "matched-at": matched_at,
    }
    if extracted is not None:
        data["extracted-results"] = extracted
    return json.dumps(data)


# ---------------------------------------------------------------------------
# _parse_nuclei_line
# ---------------------------------------------------------------------------

class TestParseNucleiLine:
    def test_basic_finding_returned(self):
        line = _nuclei_line()
        f = _parse_nuclei_line(line)
        assert isinstance(f, Finding)

    def test_name_from_info(self):
        f = _parse_nuclei_line(_nuclei_line(name="Exposed .env File"))
        assert f.name == "Exposed .env File"

    def test_name_falls_back_to_template_id(self):
        data = {
            "template-id": "my-template",
            "info": {"severity": "low"},
            "matched-at": "http://x.com",
        }
        f = _parse_nuclei_line(json.dumps(data))
        assert f.name == "my-template"

    def test_severity_mapped_correctly(self):
        for nuclei_sev, expected in SEVERITY_MAP.items():
            line = _nuclei_line(severity=nuclei_sev)
            f = _parse_nuclei_line(line)
            assert f.severity == expected

    def test_unknown_severity_defaults_to_info(self):
        f = _parse_nuclei_line(_nuclei_line(severity="unknown"))
        assert f.severity == "info"

    def test_url_from_matched_at(self):
        f = _parse_nuclei_line(_nuclei_line(matched_at="https://target.com/path"))
        assert f.url == "https://target.com/path"

    def test_url_falls_back_to_host(self):
        data = {
            "template-id": "t",
            "info": {"name": "T", "severity": "info"},
            "host": "https://fallback.com",
        }
        f = _parse_nuclei_line(json.dumps(data))
        assert f.url == "https://fallback.com"

    def test_extracted_results_list_joined(self):
        f = _parse_nuclei_line(_nuclei_line(extracted=["val1", "val2"]))
        assert "val1" in f.evidence
        assert "val2" in f.evidence

    def test_extracted_results_string_used_directly(self):
        f = _parse_nuclei_line(_nuclei_line(extracted="some evidence"))
        assert "some evidence" in f.evidence

    def test_evidence_falls_back_to_template_id(self):
        line = _nuclei_line()  # no extracted-results
        f = _parse_nuclei_line(line)
        assert "test-template" in f.evidence

    def test_tags_string_triggers_remediation_lookup(self):
        f = _parse_nuclei_line(_nuclei_line(tags="env,dotenv"))
        assert f.remediation == REMEDIATION_MAP["env"]

    def test_tags_list_triggers_remediation_lookup(self):
        f = _parse_nuclei_line(_nuclei_line(tags=["cors", "misconfig"]))
        assert f.remediation == REMEDIATION_MAP["cors"]

    def test_info_remediation_overrides_tag_remediation(self):
        f = _parse_nuclei_line(_nuclei_line(tags="env", remediation="Custom fix."))
        assert f.remediation == "Custom fix."

    def test_unknown_tags_use_default_remediation(self):
        f = _parse_nuclei_line(_nuclei_line(tags=["unknown-tag-xyz"]))
        assert "Review" in f.remediation

    def test_cvss_score_float_parsed(self):
        f = _parse_nuclei_line(_nuclei_line(cvss_score=7.5))
        assert f.cvss_score == 7.5

    def test_cvss_score_none_when_absent(self):
        f = _parse_nuclei_line(_nuclei_line())
        assert f.cvss_score is None

    def test_cvss_from_string_metrics(self):
        data = {
            "template-id": "t",
            "info": {
                "name": "T",
                "severity": "high",
                "classification": {"cvss-metrics": "CVSS:3.1/AV:N/AC:L 8.8 score"},
            },
            "matched-at": "http://x.com",
        }
        f = _parse_nuclei_line(json.dumps(data))
        assert f.cvss_score == 3.1

    def test_non_json_line_returns_none(self):
        assert _parse_nuclei_line("not json") is None

    def test_empty_string_returns_none(self):
        assert _parse_nuclei_line("") is None

    def test_non_object_json_returns_none(self):
        assert _parse_nuclei_line('"just a string"') is None

    def test_tool_is_nuclei(self):
        f = _parse_nuclei_line(_nuclei_line())
        assert f.tool == "nuclei"

    def test_raw_field_contains_original_data(self):
        line = _nuclei_line(template_id="tpl-123")
        f = _parse_nuclei_line(line)
        assert f.raw.get("template-id") == "tpl-123"
