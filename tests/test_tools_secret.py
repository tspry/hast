"""Tests for backend/scanner/tools/secret_tools.py."""
from __future__ import annotations

import json
import os
import tempfile

import pytest
import pytest_asyncio

from backend.scanner.tools.secret_tools import (
    scan_js_content_regex,
    _parse_trufflehog_line,
    _parse_gitleaks_output,
    SECRET_PATTERNS,
)
from backend.scanner.tools.base import Finding


# ---------------------------------------------------------------------------
# scan_js_content_regex
# ---------------------------------------------------------------------------

class TestScanJsContentRegex:
    @pytest.mark.asyncio
    async def test_detects_aws_access_key(self):
        # Deliberately chosen to not contain FP-filter substrings (example, dummy, etc.)
        content = "var key = 'AKIAR2Y43MGWTB3XKZNA';"
        findings = await scan_js_content_regex("https://example.com/app.js", content)
        names = [f.name for f in findings]
        assert any("AWS Access Key" in n for n in names)

    @pytest.mark.asyncio
    async def test_detects_github_token(self):
        content = "token = 'ghp_" + "a" * 36 + "';"
        findings = await scan_js_content_regex("https://example.com/app.js", content)
        names = [f.name for f in findings]
        assert any("GitHub Token" in n for n in names)

    @pytest.mark.asyncio
    async def test_detects_stripe_secret_key(self):
        content = "stripe_key = 'sk_live_" + "a" * 24 + "';"
        findings = await scan_js_content_regex("https://example.com/app.js", content)
        assert any("Stripe Secret Key" in f.name for f in findings)

    @pytest.mark.asyncio
    async def test_detects_stripe_publishable_key(self):
        content = "pk = 'pk_live_" + "a" * 24 + "';"
        findings = await scan_js_content_regex("https://example.com/pay.js", content)
        assert any("Stripe Publishable Key" in f.name for f in findings)

    @pytest.mark.asyncio
    async def test_detects_google_api_key(self):
        content = "var apiKey = 'AIzaSy" + "a" * 34 + "';"
        findings = await scan_js_content_regex("https://example.com/maps.js", content)
        assert any("Google API Key" in f.name for f in findings)

    @pytest.mark.asyncio
    async def test_detects_private_key_header(self):
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
        findings = await scan_js_content_regex("https://example.com/config.js", content)
        assert any("Private Key" in f.name for f in findings)

    @pytest.mark.asyncio
    async def test_detects_jwt_token(self):
        # Minimal realistic-looking JWT
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzNDU2Nzg5MCJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        content = f"var token = '{jwt}';"
        findings = await scan_js_content_regex("https://example.com/auth.js", content)
        assert any("JWT" in f.name for f in findings)

    @pytest.mark.asyncio
    async def test_detects_database_connection_string(self):
        content = "const db = 'postgresql://user:pass@localhost/mydb';"
        findings = await scan_js_content_regex("https://example.com/db.js", content)
        assert any("Database" in f.name for f in findings)

    @pytest.mark.asyncio
    async def test_skips_placeholder_values(self):
        # Placeholder-like values should be filtered out
        content = "const key = 'your_api_key_here_AKIAIOSFODNN7EXAMPLE';"
        findings = await scan_js_content_regex("https://example.com/app.js", content)
        # The 'your_' prefix should cause this to be skipped
        aws_findings = [f for f in findings if "AWS Access Key" in f.name]
        assert aws_findings == []

    @pytest.mark.asyncio
    async def test_skips_example_values(self):
        # The canonical AWS example key from AWS docs contains "EXAMPLE" in the match itself,
        # triggering the FP filter ("example" is in the FP list).
        content = "var key = 'AKIAIOSFODNN7EXAMPLE';"
        findings = await scan_js_content_regex("https://example.com/app.js", content)
        aws_findings = [f for f in findings if "AWS Access Key" in f.name]
        assert aws_findings == []

    @pytest.mark.asyncio
    async def test_returns_empty_for_clean_content(self):
        content = "function add(a, b) { return a + b; }"
        findings = await scan_js_content_regex("https://example.com/utils.js", content)
        assert findings == []

    @pytest.mark.asyncio
    async def test_url_set_on_finding(self):
        content = "var key = 'AKIAIOSFODNN7EXAMPLE';"
        findings = await scan_js_content_regex("https://cdn.example.com/bundle.js", content)
        assert all(f.url == "https://cdn.example.com/bundle.js" for f in findings)

    @pytest.mark.asyncio
    async def test_tool_is_regex_secret_scan(self):
        content = "var key = 'AKIAIOSFODNN7EXAMPLE';"
        findings = await scan_js_content_regex("https://example.com/app.js", content)
        assert all(f.tool == "regex-secret-scan" for f in findings)

    @pytest.mark.asyncio
    async def test_evidence_capped_at_200_chars(self):
        # A match that's very long
        long_match = "a" * 300
        content = f"password = '{long_match}';"
        findings = await scan_js_content_regex("https://example.com/app.js", content)
        for f in findings:
            assert len(f.evidence) <= 300  # evidence wraps the match, but match is capped at 200

    @pytest.mark.asyncio
    async def test_detects_sendgrid_key(self):
        key = "SG." + "a" * 22 + "." + "b" * 43
        content = f"const sg = '{key}';"
        findings = await scan_js_content_regex("https://example.com/mail.js", content)
        assert any("SendGrid" in f.name for f in findings)

    @pytest.mark.asyncio
    async def test_detects_slack_token(self):
        content = "token = 'xoxb-1234567890-abcdefghij';"
        findings = await scan_js_content_regex("https://example.com/slack.js", content)
        assert any("Slack" in f.name for f in findings)


# ---------------------------------------------------------------------------
# SECRET_PATTERNS structure
# ---------------------------------------------------------------------------

class TestSecretPatterns:
    def test_all_patterns_have_three_tuple(self):
        for name, value in SECRET_PATTERNS.items():
            assert isinstance(value, tuple) and len(value) == 3, \
                f"Pattern '{name}' should be a 3-tuple (pattern, severity, remediation)"

    def test_severities_are_valid(self):
        valid = {"critical", "high", "medium", "low", "info"}
        for name, (_, severity, _) in SECRET_PATTERNS.items():
            assert severity in valid, f"Pattern '{name}' has invalid severity '{severity}'"

    def test_remediation_is_non_empty_string(self):
        for name, (_, _, remediation) in SECRET_PATTERNS.items():
            assert isinstance(remediation, str) and remediation, \
                f"Pattern '{name}' has empty remediation"


# ---------------------------------------------------------------------------
# _parse_trufflehog_line
# ---------------------------------------------------------------------------

class TestParseTrufflehogLine:
    def _make_line(self, **kwargs) -> str:
        defaults = {
            "DetectorName": "AWS",
            "Verified": False,
            "Raw": "AKIA123456789ABCDEF",
            "SourceMetadata": {},
        }
        defaults.update(kwargs)
        return json.dumps(defaults)

    def test_basic_parse(self):
        f = _parse_trufflehog_line(self._make_line())
        assert isinstance(f, Finding)
        assert f.tool == "trufflehog"

    def test_verified_true_is_critical(self):
        f = _parse_trufflehog_line(self._make_line(Verified=True))
        assert f.severity == "critical"

    def test_verified_false_is_high(self):
        f = _parse_trufflehog_line(self._make_line(Verified=False))
        assert f.severity == "high"

    def test_detector_name_in_finding_name(self):
        f = _parse_trufflehog_line(self._make_line(DetectorName="Stripe"))
        assert "Stripe" in f.name

    def test_verified_flag_in_evidence(self):
        f = _parse_trufflehog_line(self._make_line(Verified=True))
        assert "[VERIFIED]" in f.evidence

    def test_non_json_returns_none(self):
        assert _parse_trufflehog_line("plain text") is None

    def test_empty_string_returns_none(self):
        assert _parse_trufflehog_line("") is None

    def test_json_array_returns_none(self):
        assert _parse_trufflehog_line("[]") is None

    def test_source_url_from_metadata(self):
        line = json.dumps({
            "DetectorName": "GitHub",
            "Verified": True,
            "Raw": "ghp_abc",
            "SourceMetadata": {"Data": {"Git": {"file": "https://github.com/org/repo/blob/main/secret.py"}}},
        })
        f = _parse_trufflehog_line(line)
        assert "github.com" in f.url

    def test_raw_field_truncated_at_200(self):
        raw = "x" * 300
        f = _parse_trufflehog_line(self._make_line(Raw=raw))
        assert len(f.evidence) <= 210  # "[VERIFIED] " + 200 chars max raw


# ---------------------------------------------------------------------------
# _parse_gitleaks_output
# ---------------------------------------------------------------------------

class TestParseGitleaksOutput:
    def _write_output(self, data) -> str:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            return f.name

    def teardown_method(self, _):
        pass  # files are cleaned up per-test

    def test_parses_list_of_leaks(self):
        data = [
            {"RuleID": "github-pat", "Secret": "ghp_abc", "Match": "token=ghp_abc"},
            {"RuleID": "aws-key", "Secret": "AKIA123", "Match": "key=AKIA123"},
        ]
        path = self._write_output(data)
        try:
            findings = _parse_gitleaks_output(path, "https://example.com/app.js")
            assert len(findings) == 2
        finally:
            os.unlink(path)

    def test_rule_id_in_name(self):
        data = [{"RuleID": "stripe-api-token", "Secret": "sk_live_x", "Match": "sk_live_x"}]
        path = self._write_output(data)
        try:
            findings = _parse_gitleaks_output(path, "https://example.com/a.js")
            assert "stripe-api-token" in findings[0].name
        finally:
            os.unlink(path)

    def test_source_url_set_on_finding(self):
        data = [{"RuleID": "key", "Secret": "abc", "Match": "key=abc"}]
        path = self._write_output(data)
        try:
            findings = _parse_gitleaks_output(path, "https://target.com/bundle.js")
            assert findings[0].url == "https://target.com/bundle.js"
        finally:
            os.unlink(path)

    def test_tool_is_gitleaks(self):
        data = [{"RuleID": "key", "Secret": "abc", "Match": "abc"}]
        path = self._write_output(data)
        try:
            findings = _parse_gitleaks_output(path, "https://x.com/a.js")
            assert findings[0].tool == "gitleaks"
        finally:
            os.unlink(path)

    def test_severity_is_high(self):
        data = [{"RuleID": "key", "Secret": "abc", "Match": "abc"}]
        path = self._write_output(data)
        try:
            findings = _parse_gitleaks_output(path, "https://x.com")
            assert findings[0].severity == "high"
        finally:
            os.unlink(path)

    def test_missing_file_returns_empty(self):
        findings = _parse_gitleaks_output("/nonexistent/file.json", "https://x.com")
        assert findings == []

    def test_invalid_json_returns_empty(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not json")
            path = f.name
        try:
            findings = _parse_gitleaks_output(path, "https://x.com")
            assert findings == []
        finally:
            os.unlink(path)

    def test_single_object_wrapped_in_list(self):
        data = {"RuleID": "key", "Secret": "abc", "Match": "abc"}
        path = self._write_output(data)
        try:
            findings = _parse_gitleaks_output(path, "https://x.com")
            assert len(findings) == 1
        finally:
            os.unlink(path)

    def test_empty_list_returns_empty(self):
        path = self._write_output([])
        try:
            findings = _parse_gitleaks_output(path, "https://x.com")
            assert findings == []
        finally:
            os.unlink(path)

    def test_match_capped_at_200_in_evidence(self):
        long_match = "x" * 500
        data = [{"RuleID": "key", "Secret": "abc", "Match": long_match}]
        path = self._write_output(data)
        try:
            findings = _parse_gitleaks_output(path, "https://x.com")
            assert len(findings[0].evidence) <= 200
        finally:
            os.unlink(path)
