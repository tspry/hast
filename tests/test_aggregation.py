"""Tests for backend/scanner/phases/aggregation.py."""
from __future__ import annotations

import pytest
import pytest_asyncio

from backend.scanner.tools.base import Finding
from backend.scanner.phases.aggregation import (
    run_aggregation,
    _dedup_key,
    _to_finding_dict,
)


# ---------------------------------------------------------------------------
# _dedup_key
# ---------------------------------------------------------------------------

class TestDedupKey:
    def _f(self, url: str, name: str) -> Finding:
        return Finding(tool="test", severity="info", name=name, url=url)

    def test_same_url_name_produces_same_key(self):
        k1 = _dedup_key(self._f("https://example.com/path", "Vuln A"))
        k2 = _dedup_key(self._f("https://example.com/path", "Vuln A"))
        assert k1 == k2

    def test_different_name_produces_different_key(self):
        k1 = _dedup_key(self._f("https://example.com/", "Vuln A"))
        k2 = _dedup_key(self._f("https://example.com/", "Vuln B"))
        assert k1 != k2

    def test_trailing_slash_normalised(self):
        k1 = _dedup_key(self._f("https://example.com/path/", "Vuln"))
        k2 = _dedup_key(self._f("https://example.com/path", "Vuln"))
        assert k1 == k2

    def test_url_lowercased(self):
        k1 = _dedup_key(self._f("HTTPS://EXAMPLE.COM/PATH", "Vuln"))
        k2 = _dedup_key(self._f("https://example.com/path", "Vuln"))
        assert k1 == k2

    def test_name_lowercased(self):
        k1 = _dedup_key(self._f("https://example.com/", "VULN"))
        k2 = _dedup_key(self._f("https://example.com/", "vuln"))
        assert k1 == k2


# ---------------------------------------------------------------------------
# _to_finding_dict
# ---------------------------------------------------------------------------

class TestToFindingDict:
    def _finding(self, **kwargs) -> Finding:
        defaults = dict(tool="nuclei", severity="high", name="Exposed .env",
                        url="https://example.com/.env", evidence="DB_PASS=x",
                        remediation="Remove it", cvss_score=None)
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_basic_structure(self):
        f = self._finding()
        d = _to_finding_dict(f, "scan-1", set())
        assert d["scan_id"] == "scan-1"
        assert d["tool"] == "nuclei"
        assert d["severity"] == "high"
        assert d["name"] == "Exposed .env"
        assert d["url"] == "https://example.com/.env"
        assert "id" in d
        assert "timestamp" in d

    def test_is_new_true_when_not_in_prev_keys(self):
        f = self._finding()
        d = _to_finding_dict(f, "scan-1", set())
        assert d["is_new"] is True

    def test_is_new_false_when_in_prev_keys(self):
        f = self._finding()
        prev = {"https://example.com/.env|Exposed .env"}
        d = _to_finding_dict(f, "scan-1", prev)
        assert d["is_new"] is False

    def test_risk_score_computed(self):
        f = self._finding(severity="high")  # base = 75
        d = _to_finding_dict(f, "scan-1", set())
        assert d["risk_score"] == 75

    def test_cvss_bonus_added(self):
        # Formula: bonus = int(cvss_score * 2); 9.0 * 2 = 18; base 75 + 18 = 93
        f = self._finding(severity="high", cvss_score=9.0)
        d = _to_finding_dict(f, "scan-1", set())
        assert d["risk_score"] == 93

    def test_risk_score_capped_at_100(self):
        # Formula: base 92 (critical) + int(10.0 * 2) = 20 → 112, capped at 100
        f = self._finding(severity="critical", cvss_score=10.0)
        d = _to_finding_dict(f, "scan-1", set())
        assert d["risk_score"] == 100

    def test_evidence_capped_at_2000_chars(self):
        long_evidence = "x" * 3000
        f = self._finding(evidence=long_evidence)
        d = _to_finding_dict(f, "scan-1", set())
        assert len(d["evidence"]) == 2000

    def test_id_is_unique_uuid(self):
        f = self._finding()
        d1 = _to_finding_dict(f, "scan-1", set())
        d2 = _to_finding_dict(f, "scan-1", set())
        assert d1["id"] != d2["id"]


# ---------------------------------------------------------------------------
# run_aggregation (integration with DB)
# ---------------------------------------------------------------------------

class TestRunAggregation:
    @pytest.mark.asyncio
    async def test_empty_findings_returns_empty_list(self, db):
        from backend.db import database as db_module
        await db_module.create_scan("agg-1", "https://example.com", "standard")
        events = []

        async def emit(event_type, data):
            events.append((event_type, data))

        result = await run_aggregation("agg-1", "https://example.com", [], [], emit)
        assert result == []

    @pytest.mark.asyncio
    async def test_findings_persisted_to_db(self, db):
        from backend.db import database as db_module
        await db_module.create_scan("agg-2", "https://example.com", "standard")

        recon = [Finding(tool="nmap", severity="high", name="Open Port: 21/tcp",
                         url="https://example.com:21")]
        scan = [Finding(tool="nuclei", severity="medium", name="Exposed Config",
                        url="https://example.com/config")]

        async def emit(et, d):
            pass

        result = await run_aggregation("agg-2", "https://example.com", recon, scan, emit)
        assert len(result) == 2

        db_findings = await db_module.get_findings("agg-2")
        assert len(db_findings) == 2

    @pytest.mark.asyncio
    async def test_deduplication(self, db):
        from backend.db import database as db_module
        await db_module.create_scan("agg-3", "https://example.com", "standard")

        # Same url+name from two different tools — should be deduped to 1
        f1 = Finding(tool="nuclei", severity="high", name="Exposed .env",
                     url="https://example.com/.env")
        f2 = Finding(tool="ffuf", severity="medium", name="Exposed .env",
                     url="https://example.com/.env")

        async def emit(et, d):
            pass

        result = await run_aggregation("agg-3", "https://example.com", [f1], [f2], emit)
        assert len(result) == 1
        # Should keep the higher risk score (high = 75 > medium = 50)
        assert result[0]["severity"] == "high"

    @pytest.mark.asyncio
    async def test_sorted_by_risk_score_desc(self, db):
        from backend.db import database as db_module
        await db_module.create_scan("agg-4", "https://example.com", "standard")

        findings = [
            Finding(tool="nmap", severity="low", name="Low F", url="https://example.com/l"),
            Finding(tool="nuclei", severity="critical", name="Crit F", url="https://example.com/c"),
            Finding(tool="ffuf", severity="medium", name="Med F", url="https://example.com/m"),
        ]

        async def emit(et, d):
            pass

        result = await run_aggregation("agg-4", "https://example.com", findings, [], emit)
        scores = [r["risk_score"] for r in result]
        assert scores == sorted(scores, reverse=True)

    @pytest.mark.asyncio
    async def test_emits_phase_events(self, db):
        from backend.db import database as db_module
        await db_module.create_scan("agg-5", "https://example.com", "standard")

        events = []

        async def emit(et, d):
            events.append((et, d))

        await run_aggregation("agg-5", "https://example.com", [], [], emit)

        event_types = [e[0] for e in events]
        assert "phase_update" in event_types
        # Should have both 'running' and 'completed' phase_update events
        phase_statuses = [e[1]["status"] for e in events if e[0] == "phase_update"]
        assert "running" in phase_statuses
        assert "completed" in phase_statuses

    @pytest.mark.asyncio
    async def test_is_new_flag_set_correctly(self, db):
        from backend.db import database as db_module

        # Create a previous completed scan with a finding
        await db_module.create_scan("prev-scan", "https://example.com", "standard")
        await db_module.update_scan("prev-scan", status="completed",
                                    started_at="2024-01-01T00:00:00Z")
        await db_module.insert_finding({
            "id": "prev-f-1", "scan_id": "prev-scan", "tool": "nuclei",
            "severity": "high", "name": "Known Vuln", "url": "https://example.com/known",
            "evidence": "", "remediation": "", "cvss_score": None,
            "risk_score": 75, "timestamp": "2024-01-01T00:00:00Z", "is_new": True,
        })

        # Now run aggregation for a new scan on the same target
        await db_module.create_scan("new-scan", "https://example.com", "standard")
        old_f = Finding(tool="nuclei", severity="high", name="Known Vuln",
                        url="https://example.com/known")
        new_f = Finding(tool="nuclei", severity="critical", name="New Critical",
                        url="https://example.com/new")

        async def emit(et, d):
            pass

        result = await run_aggregation("new-scan", "https://example.com", [old_f, new_f], [], emit)

        by_name = {r["name"]: r for r in result}
        assert by_name["Known Vuln"]["is_new"] is False
        assert by_name["New Critical"]["is_new"] is True
