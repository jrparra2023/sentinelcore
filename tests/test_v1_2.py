"""
SentinelCore — tests/test_v1_2.py
pytest suite for v1.2: reputation, geo cache, rule chaining (15 tests).
"""

import sys
import json
import pytest
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from storage.db import Database, NormalizedEvent
from correlation.reputation import (
    update_after_alert, get_reputation_context,
    score_label, get_top_offenders, is_private,
)
from correlation.geo import lookup, enrich_alert
from correlation.chainer import run_chains


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_db(tmp_path):
    return Database(db_path=tmp_path / "test.db")


# ── Reputation tests ──────────────────────────────────────────────────────────

class TestReputation:

    def test_score_label(self):
        assert score_label(0)   == "CLEAN"
        assert score_label(29)  == "CLEAN"
        assert score_label(30)  == "SUSPICIOUS"
        assert score_label(60)  == "MALICIOUS"
        assert score_label(85)  == "KNOWN_BAD"
        assert score_label(100) == "KNOWN_BAD"

    def test_is_private(self):
        assert is_private("192.168.1.1")
        assert is_private("10.0.0.1")
        assert is_private("172.16.0.1")
        assert is_private("127.0.0.1")
        assert not is_private("8.8.8.8")
        assert not is_private("1.1.1.1")

    def test_update_reputation_creates_record(self, tmp_db):
        update_after_alert(tmp_db, "1.2.3.4", "ssh_brute_force", "HIGH")
        rep = tmp_db.get_reputation("1.2.3.4")
        assert rep is not None
        assert rep["score"] > 0
        assert rep["alert_count"] == 1

    def test_score_increases_with_severity(self, tmp_db):
        update_after_alert(tmp_db, "1.2.3.4", "ssh_brute_force", "CRITICAL")
        rep = tmp_db.get_reputation("1.2.3.4")
        assert rep["score"] >= 25

    def test_tag_applied(self, tmp_db):
        update_after_alert(tmp_db, "1.2.3.4", "ssh_brute_force", "HIGH")
        rep = tmp_db.get_reputation("1.2.3.4")
        tags = json.loads(rep["tags"])
        assert "brute_force" in tags

    def test_multiple_alerts_accumulate(self, tmp_db):
        update_after_alert(tmp_db, "5.6.7.8", "ssh_brute_force", "HIGH")
        update_after_alert(tmp_db, "5.6.7.8", "netwatch_port_scan", "HIGH")
        rep = tmp_db.get_reputation("5.6.7.8")
        assert rep["alert_count"] == 2
        assert rep["score"] >= 30

    def test_get_reputation_context_no_record(self, tmp_db):
        ctx = get_reputation_context(tmp_db, "9.9.9.9")
        assert ctx["score"] == 0
        assert ctx["label"] == "CLEAN"

    def test_get_top_offenders(self, tmp_db):
        update_after_alert(tmp_db, "1.1.1.1", "ssh_brute_force", "CRITICAL")
        update_after_alert(tmp_db, "2.2.2.2", "ssh_brute_force", "LOW")
        offenders = get_top_offenders(tmp_db, limit=5)
        assert len(offenders) >= 2
        assert offenders[0]["score"] >= offenders[1]["score"]


# ── Geo cache tests ───────────────────────────────────────────────────────────

class TestGeo:

    def test_private_ip_no_api_call(self, tmp_db):
        result = lookup("192.168.1.1", tmp_db)
        assert result["is_private"] is True
        assert result["country_code"] == "LAN"

    def test_private_ip_cached(self, tmp_db):
        lookup("10.0.0.1", tmp_db)
        cached = tmp_db.get_geo("10.0.0.1")
        assert cached is not None
        assert cached["is_private"] == 1

    def test_enrich_alert_private(self, tmp_db):
        result = enrich_alert("192.168.1.99", tmp_db)
        assert result == "[LAN]"

    def test_enrich_alert_no_ip(self, tmp_db):
        result = enrich_alert("", tmp_db)
        assert result == ""


# ── Rule chaining tests ───────────────────────────────────────────────────────

class TestChainer:

    def _insert_alert(self, db, rule_name, src_ip, severity="HIGH"):
        db.insert_alert(
            rule_name=rule_name,
            severity=severity,
            description=f"test alert {rule_name}",
            event_ids=[1],
            src_ip=src_ip,
        )

    def test_chain_fires_when_both_rules_match(self, tmp_db):
        # Insert a pre-existing `then` rule alert in DB
        self._insert_alert(tmp_db, "netwatch_port_scan", "1.2.3.4", "HIGH")

        # Simulate ssh_brute_force just fired
        fired = [{
            "rule": "ssh_brute_force",
            "severity": "HIGH",
            "group_by": "src_ip",
            "group_value": "1.2.3.4",
            "event_count": 6,
        }]
        chained = run_chains(tmp_db, fired)
        assert len(chained) >= 1
        assert any("chain_ssh_brute_force_then_netwatch_port_scan" in a["rule"]
                   for a in chained)

    def test_chain_does_not_fire_without_trigger(self, tmp_db):
        # Only `then` rule exists, trigger never fired
        fired = [{
            "rule": "netwatch_port_scan",
            "severity": "HIGH",
            "group_by": "src_ip",
            "group_value": "9.9.9.9",
            "event_count": 1,
        }]
        chained = run_chains(tmp_db, fired)
        # No chain should fire because ssh_brute_force didn't trigger
        ssh_chains = [a for a in chained
                      if "ssh_brute_force" in a["rule"]]
        assert len(ssh_chains) == 0

    def test_no_chains_empty_fired(self, tmp_db):
        chained = run_chains(tmp_db, [])
        assert chained == []
