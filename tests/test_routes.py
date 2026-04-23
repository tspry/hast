"""Tests for backend/api/routes.py — REST API endpoints."""
from __future__ import annotations

import json
import uuid
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from backend.main import app


# ---------------------------------------------------------------------------
# Fixture: isolated HTTP client + fresh DB per test
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def client(db):
    """Async HTTP client backed by the FastAPI app with an isolated DB."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


# ---------------------------------------------------------------------------
# /api/scans
# ---------------------------------------------------------------------------

class TestListScans:
    @pytest.mark.asyncio
    async def test_returns_empty_list_initially(self, client):
        resp = await client.get("/api/scans")
        assert resp.status_code == 200
        data = resp.json()
        assert "scans" in data
        assert isinstance(data["scans"], list)

    @pytest.mark.asyncio
    async def test_lists_created_scans(self, client, db):
        from backend.db import database as db_module
        await db_module.create_scan("ls-api-1", "https://a.com", "standard")
        resp = await client.get("/api/scans")
        ids = [s["id"] for s in resp.json()["scans"]]
        assert "ls-api-1" in ids

    @pytest.mark.asyncio
    async def test_limit_param_respected(self, client, db):
        from backend.db import database as db_module
        for i in range(5):
            await db_module.create_scan(f"lim-{i}", f"https://t{i}.com", "standard")
        resp = await client.get("/api/scans?limit=2")
        assert resp.status_code == 200
        assert len(resp.json()["scans"]) <= 2


# ---------------------------------------------------------------------------
# /api/scans/{id}
# ---------------------------------------------------------------------------

class TestGetScan:
    @pytest.mark.asyncio
    async def test_returns_scan(self, client, db):
        from backend.db import database as db_module
        await db_module.create_scan("gs-1", "https://example.com", "quick")
        resp = await client.get("/api/scans/gs-1")
        assert resp.status_code == 200
        assert resp.json()["id"] == "gs-1"

    @pytest.mark.asyncio
    async def test_returns_404_for_missing(self, client):
        resp = await client.get("/api/scans/nonexistent")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# DELETE /api/scans/{id}
# ---------------------------------------------------------------------------

class TestDeleteScan:
    @pytest.mark.asyncio
    async def test_deletes_existing_scan(self, client, db):
        from backend.db import database as db_module
        await db_module.create_scan("del-api-1", "https://example.com", "standard")
        resp = await client.delete("/api/scans/del-api-1")
        assert resp.status_code == 200
        assert resp.json()["deleted"] is True

    @pytest.mark.asyncio
    async def test_returns_404_for_missing(self, client):
        resp = await client.delete("/api/scans/ghost-scan")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_cannot_delete_running_scan(self, client, db):
        from backend.db import database as db_module
        sid = "running-scan-1"
        await db_module.create_scan(sid, "https://example.com", "standard")
        with patch("backend.api.routes.is_scan_running", return_value=True):
            resp = await client.delete(f"/api/scans/{sid}")
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# /api/scans/{id}/findings
# ---------------------------------------------------------------------------

class TestGetFindings:
    @pytest_asyncio.fixture(autouse=True)
    async def setup(self, db):
        from backend.db import database as db_module
        await db_module.create_scan("f-scan-1", "https://example.com", "standard")
        for i, (sev, tool) in enumerate([
            ("critical", "nuclei"),
            ("high", "ffuf"),
            ("medium", "nmap"),
        ]):
            await db_module.insert_finding({
                "id": f"f-{i}", "scan_id": "f-scan-1", "tool": tool,
                "severity": sev, "name": f"Finding {i}",
                "url": f"https://example.com/path{i}",
                "evidence": f"evidence {i}", "remediation": "fix it",
                "cvss_score": None, "risk_score": 50,
                "timestamp": "2024-01-01T00:00:00Z", "is_new": True,
            })

    @pytest.mark.asyncio
    async def test_returns_all_findings(self, client):
        resp = await client.get("/api/scans/f-scan-1/findings")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 3
        assert len(data["findings"]) == 3

    @pytest.mark.asyncio
    async def test_filter_by_severity(self, client):
        resp = await client.get("/api/scans/f-scan-1/findings?severity=critical")
        data = resp.json()
        assert data["count"] == 1
        assert data["findings"][0]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_filter_by_multiple_severities(self, client):
        resp = await client.get("/api/scans/f-scan-1/findings?severity=critical,high")
        data = resp.json()
        assert data["count"] == 2

    @pytest.mark.asyncio
    async def test_filter_by_tool(self, client):
        resp = await client.get("/api/scans/f-scan-1/findings?tool=nuclei")
        data = resp.json()
        assert data["count"] == 1
        assert data["findings"][0]["tool"] == "nuclei"

    @pytest.mark.asyncio
    async def test_filter_by_keyword(self, client):
        resp = await client.get("/api/scans/f-scan-1/findings?keyword=Finding+0")
        data = resp.json()
        assert data["count"] == 1

    @pytest.mark.asyncio
    async def test_filter_combination(self, client):
        resp = await client.get("/api/scans/f-scan-1/findings?severity=high&tool=ffuf")
        data = resp.json()
        assert data["count"] == 1

    @pytest.mark.asyncio
    async def test_no_match_returns_empty(self, client):
        resp = await client.get("/api/scans/f-scan-1/findings?tool=gitleaks")
        data = resp.json()
        assert data["count"] == 0


# ---------------------------------------------------------------------------
# /api/scans/{id}/diff
# ---------------------------------------------------------------------------

class TestGetDiff:
    @pytest.mark.asyncio
    async def test_no_previous_scan_returns_all_as_new(self, client, db):
        from backend.db import database as db_module
        await db_module.create_scan("diff-1", "https://unique-diff-target.com", "standard")
        await db_module.insert_finding({
            "id": "diff-f1", "scan_id": "diff-1", "tool": "nuclei",
            "severity": "high", "name": "Vuln", "url": "https://unique-diff-target.com/v",
            "evidence": "", "remediation": "", "cvss_score": None,
            "risk_score": 75, "timestamp": "2024-01-01T00:00:00Z", "is_new": True,
        })
        resp = await client.get("/api/scans/diff-1/diff")
        assert resp.status_code == 200
        data = resp.json()
        assert data["previous_scan_id"] is None
        assert len(data["new"]) == 1
        assert data["resolved"] == []

    @pytest.mark.asyncio
    async def test_returns_404_for_missing_scan(self, client):
        resp = await client.get("/api/scans/ghost/diff")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_diff_identifies_new_and_resolved(self, client, db):
        from backend.db import database as db_module
        target = "https://diff-two.com"

        # Previous scan
        await db_module.create_scan("prev-diff", target, "standard")
        await db_module.update_scan("prev-diff", status="completed",
                                    started_at="2024-01-01T00:00:00Z")
        await db_module.insert_finding({
            "id": "prev-df1", "scan_id": "prev-diff", "tool": "nuclei",
            "severity": "high", "name": "Old Vuln", "url": f"{target}/old",
            "evidence": "", "remediation": "", "cvss_score": None,
            "risk_score": 75, "timestamp": "2024-01-01T00:00:00Z", "is_new": True,
        })

        # Current scan
        await db_module.create_scan("curr-diff", target, "standard")
        await db_module.update_scan("curr-diff", started_at="2024-06-01T00:00:00Z")
        await db_module.insert_finding({
            "id": "curr-df1", "scan_id": "curr-diff", "tool": "nuclei",
            "severity": "critical", "name": "New Vuln", "url": f"{target}/new",
            "evidence": "", "remediation": "", "cvss_score": None,
            "risk_score": 92, "timestamp": "2024-06-01T00:00:00Z", "is_new": True,
        })

        resp = await client.get("/api/scans/curr-diff/diff")
        assert resp.status_code == 200
        data = resp.json()
        assert data["previous_scan_id"] == "prev-diff"
        new_names = [f["name"] for f in data["new"]]
        resolved_names = [f["name"] for f in data["resolved"]]
        assert "New Vuln" in new_names
        assert "Old Vuln" in resolved_names


# ---------------------------------------------------------------------------
# /api/scans/{id}/export/json
# ---------------------------------------------------------------------------

class TestExportJson:
    @pytest.mark.asyncio
    async def test_json_export_structure(self, client, db):
        from backend.db import database as db_module
        await db_module.create_scan("exp-1", "https://example.com", "standard")
        resp = await client.get("/api/scans/exp-1/export/json")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("application/json")
        data = json.loads(resp.content)
        assert "scan" in data
        assert "findings" in data

    @pytest.mark.asyncio
    async def test_json_export_404_for_missing(self, client):
        resp = await client.get("/api/scans/ghost/export/json")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# /api/scans/{id}/export/csv
# ---------------------------------------------------------------------------

class TestExportCsv:
    @pytest.mark.asyncio
    async def test_csv_export_returns_csv(self, client, db):
        from backend.db import database as db_module
        await db_module.create_scan("csv-1", "https://example.com", "standard")
        resp = await client.get("/api/scans/csv-1/export/csv")
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]
        # Should at least have the header row
        assert "severity" in resp.text

    @pytest.mark.asyncio
    async def test_csv_export_404_for_missing(self, client):
        resp = await client.get("/api/scans/ghost/export/csv")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# /api/config
# ---------------------------------------------------------------------------

class TestConfig:
    @pytest.mark.asyncio
    async def test_get_config_returns_dict(self, client):
        resp = await client.get("/api/config")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)
        assert "rate_limit_ms" in data

    @pytest.mark.asyncio
    async def test_post_config_updates_allowed_key(self, client, tmp_path, monkeypatch):
        import backend.config as cfg_module
        p = tmp_path / "config.yaml"
        p.write_text("rate_limit_ms: 100\n")
        monkeypatch.setattr(cfg_module, "CONFIG_PATH", p)
        monkeypatch.setattr(cfg_module, "_config", {})
        cfg_module.load_config()

        resp = await client.post("/api/config", json={"rate_limit_ms": 300})
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    @pytest.mark.asyncio
    async def test_post_config_ignores_disallowed_keys(self, client, tmp_path, monkeypatch):
        import backend.config as cfg_module
        p = tmp_path / "config.yaml"
        p.write_text("rate_limit_ms: 100\n")
        monkeypatch.setattr(cfg_module, "CONFIG_PATH", p)
        monkeypatch.setattr(cfg_module, "_config", {})
        cfg_module.load_config()

        resp = await client.post("/api/config", json={"server_host": "0.0.0.0",
                                                       "rate_limit_ms": 200})
        assert resp.status_code == 200
        # server_host is not in allowed_keys so it should be ignored
        returned_cfg = resp.json()["config"]
        assert returned_cfg.get("server_host") != "0.0.0.0"


# ---------------------------------------------------------------------------
# /api/tools/status
# ---------------------------------------------------------------------------

class TestToolsStatus:
    @pytest.mark.asyncio
    async def test_returns_all_expected_tools(self, client):
        resp = await client.get("/api/tools/status")
        assert resp.status_code == 200
        tools = resp.json()["tools"]
        for expected in ["nmap", "nuclei", "katana", "ffuf", "wafw00f"]:
            assert expected in tools

    @pytest.mark.asyncio
    async def test_each_tool_has_available_and_path(self, client):
        resp = await client.get("/api/tools/status")
        for tool_name, info in resp.json()["tools"].items():
            assert "available" in info
            assert "path" in info


# ---------------------------------------------------------------------------
# /api/probe-paths/count
# ---------------------------------------------------------------------------

class TestProbePathsCount:
    @pytest.mark.asyncio
    async def test_returns_positive_count(self, client):
        resp = await client.get("/api/probe-paths/count")
        assert resp.status_code == 200
        assert resp.json()["count"] > 0


# ---------------------------------------------------------------------------
# /api/scans/{id}/stop
# ---------------------------------------------------------------------------

class TestStopScan:
    @pytest.mark.asyncio
    async def test_stop_returns_stopped_false_for_idle_scan(self, client, db):
        from backend.db import database as db_module
        await db_module.create_scan("stop-1", "https://example.com", "standard")
        resp = await client.post("/api/scans/stop-1/stop")
        assert resp.status_code == 200
        # Scan isn't running, so stopped should be False
        assert resp.json()["stopped"] is False


# ---------------------------------------------------------------------------
# /api/bulk-scan
# ---------------------------------------------------------------------------

class TestBulkScan:
    @pytest.mark.asyncio
    async def test_queues_multiple_targets(self, client, db):
        with patch("backend.api.routes.start_scan", new_callable=AsyncMock) as mock_start:
            mock_start.return_value = str(uuid.uuid4())
            with patch("backend.api.routes.is_scan_running", return_value=False):
                resp = await client.post("/api/bulk-scan", json={
                    "targets": ["https://a.com", "https://b.com"],
                    "profile": "quick",
                })
        assert resp.status_code == 200
        data = resp.json()
        assert data["queued"] == 2
        assert len(data["scans"]) == 2

    @pytest.mark.asyncio
    async def test_normalises_urls_without_scheme(self, client, db):
        with patch("backend.api.routes.start_scan", new_callable=AsyncMock) as mock_start:
            mock_start.return_value = str(uuid.uuid4())
            with patch("backend.api.routes.is_scan_running", return_value=False):
                resp = await client.post("/api/bulk-scan", json={
                    "targets": ["example.com"],
                    "profile": "quick",
                })
        assert resp.status_code == 200
        scans = resp.json()["scans"]
        assert scans[0]["target"] == "https://example.com"

    @pytest.mark.asyncio
    async def test_rejects_empty_targets(self, client):
        resp = await client.post("/api/bulk-scan", json={"targets": [], "profile": "quick"})
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_rejects_too_many_targets(self, client):
        targets = [f"https://t{i}.com" for i in range(51)]
        resp = await client.post("/api/bulk-scan", json={"targets": targets, "profile": "quick"})
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_rejects_whitespace_only_targets(self, client):
        resp = await client.post("/api/bulk-scan", json={"targets": ["   ", "  "], "profile": "quick"})
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# /api/bulk-scan/summary
# ---------------------------------------------------------------------------

class TestBulkScanSummary:
    @pytest.mark.asyncio
    async def test_returns_never_scanned_for_unknown_targets(self, client, db):
        resp = await client.get("/api/bulk-scan/summary?targets=https://unknown-xyz.com")
        assert resp.status_code == 200
        summary = resp.json()["summary"]
        assert len(summary) == 1
        assert summary[0]["status"] == "never_scanned"

    @pytest.mark.asyncio
    async def test_returns_scan_info_for_known_target(self, client, db):
        from backend.db import database as db_module
        target = "https://known-bulk-target.com"
        await db_module.create_scan("bulk-s1", target, "standard")
        await db_module.update_scan("bulk-s1", status="completed",
                                    started_at="2024-01-01T00:00:00Z",
                                    stats='{"critical":1,"high":2,"total":3}')

        resp = await client.get(f"/api/bulk-scan/summary?targets={target}")
        assert resp.status_code == 200
        summary = resp.json()["summary"]
        assert summary[0]["status"] == "completed"
        assert summary[0]["scan_id"] == "bulk-s1"
