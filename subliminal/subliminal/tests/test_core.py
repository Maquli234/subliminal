"""
subliminal/tests/test_core.py — Core unit tests
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from subliminal.utils.config import PROFILES, SubliminalConfig


# ─── Config Tests ─────────────────────────────────────────────────────────────

class TestConfig:
    def test_default_config(self):
        cfg = SubliminalConfig(domain="example.com")
        assert cfg.domain == "example.com"
        assert cfg.concurrency == 150
        assert cfg.timeout == 3
        assert cfg.probe is True

    def test_profile_quick(self):
        cfg = SubliminalConfig.from_profile("quick", domain="example.com")
        assert cfg.concurrency == PROFILES["quick"]["concurrency"]
        assert cfg.active == PROFILES["quick"]["active"]
        assert "crtsh" in cfg.sources

    def test_profile_deep(self):
        cfg = SubliminalConfig.from_profile("deep", domain="example.com")
        assert cfg.active is True
        assert len(cfg.sources) >= 4

    def test_profile_stealth(self):
        cfg = SubliminalConfig.from_profile("stealth", domain="example.com")
        assert cfg.concurrency <= 30

    def test_invalid_profile(self):
        with pytest.raises(ValueError):
            SubliminalConfig.from_profile("nonexistent")

    def test_to_dict(self):
        cfg = SubliminalConfig(domain="test.com")
        d = cfg.to_dict()
        assert d["domain"] == "test.com"
        assert "concurrency" in d

    def test_apply_profile(self):
        cfg = SubliminalConfig(domain="example.com")
        cfg.apply_profile("stealth")
        assert cfg.profile == "stealth"


# ─── Passive Source Tests ─────────────────────────────────────────────────────

class TestPassiveSources:
    @pytest.mark.asyncio
    async def test_fetch_crtsh_returns_set(self):
        import json
        mock_response = MagicMock()
        mock_response.text = json.dumps([
            {"name_value": "sub.example.com\nother.example.com"},
            {"name_value": "*.example.com"},   # wildcards should be filtered
        ])

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        from subliminal.modules.passive import fetch_crtsh
        result = await fetch_crtsh(mock_client, "example.com")

        assert "sub.example.com" in result
        assert "other.example.com" in result
        assert not any("*" in s for s in result)

    @pytest.mark.asyncio
    async def test_fetch_crtsh_handles_error(self):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("network error"))

        from subliminal.modules.passive import fetch_crtsh
        result = await fetch_crtsh(mock_client, "example.com")
        assert result == set()

    @pytest.mark.asyncio
    async def test_collect_passive_deduplicates(self):
        duplicate_sub = "www.example.com"

        with patch("subliminal.modules.passive.SOURCES", {
            "src1": AsyncMock(return_value={duplicate_sub, "a.example.com"}),
            "src2": AsyncMock(return_value={duplicate_sub, "b.example.com"}),
        }):
            from subliminal.modules.passive import collect_passive
            mock_client = AsyncMock()
            result = await collect_passive(mock_client, "example.com")

        # Should be de-duplicated
        assert len([s for s in result if s == duplicate_sub]) == 1


# ─── Probe Tests ──────────────────────────────────────────────────────────────

class TestProbe:
    @pytest.mark.asyncio
    async def test_probe_result_alive(self):
        from subliminal.modules.probe import ProbeResult
        r = ProbeResult(host="example.com", url="https://example.com", status=200)
        assert r.is_alive() is True

    @pytest.mark.asyncio
    async def test_probe_result_dead(self):
        from subliminal.modules.probe import ProbeResult
        r = ProbeResult(host="example.com", url="", status=0, error="timeout")
        assert r.is_alive() is False

    @pytest.mark.asyncio
    async def test_probe_empty_set(self):
        from subliminal.modules.probe import probe_all
        results = await probe_all(set(), timeout=1, concurrency=10)
        assert results == []


# ─── Report Tests ─────────────────────────────────────────────────────────────

class TestReport:
    def test_save_txt(self, tmp_path):
        from subliminal.modules.probe import ProbeResult
        from subliminal.modules.report import save_txt
        results = [ProbeResult(host="a.com", url="https://a.com", status=200)]
        out = tmp_path / "out.txt"
        save_txt(results, out)
        assert "https://a.com" in out.read_text()

    def test_save_json(self, tmp_path):
        import json as _json
        from subliminal.modules.probe import ProbeResult
        from subliminal.modules.report import save_json
        results = [ProbeResult(host="a.com", url="https://a.com", status=200)]
        out = tmp_path / "out.json"
        save_json(results, out)
        data = _json.loads(out.read_text())
        assert data[0]["url"] == "https://a.com"

    def test_save_html(self, tmp_path):
        from subliminal.modules.probe import ProbeResult
        from subliminal.modules.report import save_html
        results = [ProbeResult(host="a.com", url="https://a.com", status=200, tls=True)]
        out = tmp_path / "report.html"
        save_html(results, "a.com", out)
        content = out.read_text()
        assert "SUBLIMINAL" in content
        assert "https://a.com" in content

    def test_save_csv(self, tmp_path):
        from subliminal.modules.probe import ProbeResult
        from subliminal.modules.report import save_csv
        results = [ProbeResult(host="a.com", url="https://a.com", status=200)]
        out = tmp_path / "out.csv"
        save_csv(results, out)
        assert "https://a.com" in out.read_text()
