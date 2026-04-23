"""Tests for backend/db/database.py — async CRUD operations."""
from __future__ import annotations

import pytest
import pytest_asyncio

from backend.db import database as db_module


# ---------------------------------------------------------------------------
# Scan CRUD
# ---------------------------------------------------------------------------

class TestScanCRUD:
    @pytest.mark.asyncio
    async def test_create_and_get_scan(self, db):
        await db_module.create_scan("scan-1", "https://example.com", "standard")
        scan = await db_module.get_scan("scan-1")
        assert scan is not None
        assert scan["id"] == "scan-1"
        assert scan["target"] == "https://example.com"
        assert scan["profile"] == "standard"
        assert scan["status"] == "pending"

    @pytest.mark.asyncio
    async def test_get_scan_returns_none_for_missing(self, db):
        result = await db_module.get_scan("nonexistent-id")
        assert result is None

    @pytest.mark.asyncio
    async def test_update_scan_status(self, db):
        await db_module.create_scan("scan-2", "https://example.com", "quick")
        await db_module.update_scan("scan-2", status="running")
        scan = await db_module.get_scan("scan-2")
        assert scan["status"] == "running"

    @pytest.mark.asyncio
    async def test_update_scan_multiple_fields(self, db):
        await db_module.create_scan("scan-3", "https://example.com", "deep")
        await db_module.update_scan("scan-3", status="completed", phase="done",
                                    waf_detected=1, waf_name="Cloudflare")
        scan = await db_module.get_scan("scan-3")
        assert scan["status"] == "completed"
        assert scan["phase"] == "done"
        assert scan["waf_detected"] == 1
        assert scan["waf_name"] == "Cloudflare"

    @pytest.mark.asyncio
    async def test_update_scan_no_kwargs_is_noop(self, db):
        await db_module.create_scan("scan-4", "https://example.com", "standard")
        # Should not raise
        await db_module.update_scan("scan-4")
        scan = await db_module.get_scan("scan-4")
        assert scan["status"] == "pending"

    @pytest.mark.asyncio
    async def test_list_scans_returns_all(self, db):
        await db_module.create_scan("ls-1", "https://a.com", "standard")
        await db_module.create_scan("ls-2", "https://b.com", "quick")
        scans = await db_module.list_scans(limit=50)
        ids = [s["id"] for s in scans]
        assert "ls-1" in ids
        assert "ls-2" in ids

    @pytest.mark.asyncio
    async def test_list_scans_respects_limit(self, db):
        for i in range(5):
            await db_module.create_scan(f"limit-{i}", f"https://t{i}.com", "standard")
        scans = await db_module.list_scans(limit=2)
        assert len(scans) <= 2

    @pytest.mark.asyncio
    async def test_delete_scan_removes_all_data(self, db):
        await db_module.create_scan("del-1", "https://example.com", "standard")
        # Add a finding
        await db_module.insert_finding({
            "id": "f-del-1", "scan_id": "del-1", "tool": "nmap",
            "severity": "info", "name": "Port 80", "url": "https://example.com:80",
            "evidence": "", "remediation": "", "cvss_score": None,
            "risk_score": 5, "timestamp": "2024-01-01T00:00:00Z", "is_new": True,
        })
        # Add a URL
        await db_module.insert_urls("del-1", ["https://example.com/path"], "crawler")
        # Add a checkpoint
        await db_module.save_checkpoint("del-1", "recon", "completed")

        deleted = await db_module.delete_scan("del-1")
        assert deleted is True

        # Verify all related records are gone
        assert await db_module.get_scan("del-1") is None
        assert await db_module.get_findings("del-1") == []
        assert await db_module.get_urls("del-1") == []
        checkpoints = await db_module.get_checkpoints("del-1")
        assert checkpoints == {}

    @pytest.mark.asyncio
    async def test_delete_scan_returns_false_for_missing(self, db):
        result = await db_module.delete_scan("ghost-scan")
        assert result is False


# ---------------------------------------------------------------------------
# Finding CRUD
# ---------------------------------------------------------------------------

class TestFindingCRUD:
    def _make_finding(self, finding_id: str, scan_id: str = "scan-x") -> dict:
        return {
            "id": finding_id,
            "scan_id": scan_id,
            "tool": "nuclei",
            "severity": "high",
            "name": "Exposed .env",
            "url": "https://example.com/.env",
            "evidence": "DB_PASSWORD=secret",
            "remediation": "Remove .env from web root",
            "cvss_score": 7.5,
            "risk_score": 75,
            "timestamp": "2024-01-01T00:00:00Z",
            "is_new": True,
        }

    @pytest.mark.asyncio
    async def test_insert_and_get_finding(self, db):
        await db_module.create_scan("scan-x", "https://example.com", "standard")
        finding = self._make_finding("f-1", "scan-x")
        await db_module.insert_finding(finding)

        results = await db_module.get_findings("scan-x")
        assert len(results) == 1
        f = results[0]
        assert f["id"] == "f-1"
        assert f["severity"] == "high"
        assert f["cvss_score"] == 7.5

    @pytest.mark.asyncio
    async def test_duplicate_finding_ignored(self, db):
        await db_module.create_scan("scan-dup", "https://example.com", "standard")
        finding = self._make_finding("f-dup", "scan-dup")
        await db_module.insert_finding(finding)
        await db_module.insert_finding(finding)  # duplicate — should be silently ignored

        results = await db_module.get_findings("scan-dup")
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_get_findings_returns_empty_for_no_findings(self, db):
        await db_module.create_scan("scan-empty", "https://example.com", "standard")
        results = await db_module.get_findings("scan-empty")
        assert results == []

    @pytest.mark.asyncio
    async def test_findings_sorted_by_risk_score_desc(self, db):
        await db_module.create_scan("scan-sort", "https://example.com", "standard")
        for score, fid in [(25, "f-low"), (92, "f-crit"), (50, "f-med")]:
            finding = self._make_finding(fid, "scan-sort")
            finding["risk_score"] = score
            await db_module.insert_finding(finding)

        results = await db_module.get_findings("scan-sort")
        scores = [r["risk_score"] for r in results]
        assert scores == sorted(scores, reverse=True)

    @pytest.mark.asyncio
    async def test_get_previous_finding_keys(self, db):
        """Returns url|name keys from the most recent completed scan for target."""
        await db_module.create_scan("prev-s1", "https://target.com", "standard")
        await db_module.update_scan("prev-s1", status="completed",
                                    started_at="2024-01-01T00:00:00Z")
        finding = self._make_finding("pf-1", "prev-s1")
        finding["url"] = "https://target.com/.env"
        finding["name"] = "Exposed .env"
        await db_module.insert_finding(finding)

        keys = await db_module.get_previous_finding_keys("https://target.com")
        assert "https://target.com/.env|Exposed .env" in keys

    @pytest.mark.asyncio
    async def test_get_previous_finding_keys_empty_for_no_completed_scan(self, db):
        await db_module.create_scan("prev-s2", "https://new.com", "standard")
        keys = await db_module.get_previous_finding_keys("https://new.com")
        assert keys == set()


# ---------------------------------------------------------------------------
# URL CRUD
# ---------------------------------------------------------------------------

class TestUrlCRUD:
    @pytest.mark.asyncio
    async def test_insert_and_get_urls(self, db):
        await db_module.create_scan("url-s1", "https://example.com", "standard")
        await db_module.insert_urls("url-s1",
                                    ["https://example.com/page1",
                                     "https://example.com/page2"],
                                    "katana")
        urls = await db_module.get_urls("url-s1")
        assert "https://example.com/page1" in urls
        assert "https://example.com/page2" in urls

    @pytest.mark.asyncio
    async def test_duplicate_urls_ignored(self, db):
        await db_module.create_scan("url-s2", "https://example.com", "standard")
        await db_module.insert_urls("url-s2", ["https://example.com/page"], "katana")
        await db_module.insert_urls("url-s2", ["https://example.com/page"], "katana")
        urls = await db_module.get_urls("url-s2")
        assert len(urls) == 1

    @pytest.mark.asyncio
    async def test_js_only_filter(self, db):
        await db_module.create_scan("url-s3", "https://example.com", "standard")
        await db_module.insert_urls("url-s3", ["https://example.com/app.js"], "crawler", is_js=True)
        await db_module.insert_urls("url-s3", ["https://example.com/page"], "crawler", is_js=False)

        all_urls = await db_module.get_urls("url-s3")
        js_urls = await db_module.get_urls("url-s3", js_only=True)

        assert len(all_urls) == 2
        assert len(js_urls) == 1
        assert "https://example.com/app.js" in js_urls


# ---------------------------------------------------------------------------
# Checkpoint CRUD
# ---------------------------------------------------------------------------

class TestCheckpointCRUD:
    @pytest.mark.asyncio
    async def test_save_and_get_checkpoint(self, db):
        await db_module.create_scan("chk-s1", "https://example.com", "standard")
        await db_module.save_checkpoint("chk-s1", "recon", "completed",
                                        {"waf_detected": False})
        checkpoints = await db_module.get_checkpoints("chk-s1")
        assert checkpoints.get("recon") == "completed"

    @pytest.mark.asyncio
    async def test_checkpoint_replace_on_conflict(self, db):
        await db_module.create_scan("chk-s2", "https://example.com", "standard")
        await db_module.save_checkpoint("chk-s2", "recon", "failed")
        await db_module.save_checkpoint("chk-s2", "recon", "completed")
        checkpoints = await db_module.get_checkpoints("chk-s2")
        assert checkpoints["recon"] == "completed"

    @pytest.mark.asyncio
    async def test_get_checkpoints_multiple_phases(self, db):
        await db_module.create_scan("chk-s3", "https://example.com", "standard")
        await db_module.save_checkpoint("chk-s3", "recon", "completed")
        await db_module.save_checkpoint("chk-s3", "discovery", "completed")
        await db_module.save_checkpoint("chk-s3", "scanning", "failed")
        checkpoints = await db_module.get_checkpoints("chk-s3")
        assert checkpoints["recon"] == "completed"
        assert checkpoints["discovery"] == "completed"
        assert checkpoints["scanning"] == "failed"

    @pytest.mark.asyncio
    async def test_get_checkpoints_returns_empty_for_new_scan(self, db):
        await db_module.create_scan("chk-s4", "https://example.com", "standard")
        checkpoints = await db_module.get_checkpoints("chk-s4")
        assert checkpoints == {}
