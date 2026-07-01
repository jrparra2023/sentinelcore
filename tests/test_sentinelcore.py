"""
SentinelCore — tests/test_sentinelcore.py
pytest suite: 18 tests covering DB, normalizer, parsers, and correlation engine.
"""

import sys
import json
import pytest
import tempfile
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from storage.db import Database, NormalizedEvent
from ingestion.normalizer import make_event, normalize_timestamp
from ingestion.auth_parser import parse_line as auth_parse_line, parse_file as auth_parse_file
from ingestion.apache_parser import parse_line as apache_parse_line
from ingestion.json_importer import parse_netwatch, parse_homeguard
from correlation.engine import run_all_rules


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_db(tmp_path):
    """Fresh in-memory-like DB for each test."""
    return Database(db_path=tmp_path / "test.db")


def _make_test_event(**kwargs) -> NormalizedEvent:
    defaults = dict(
        timestamp=datetime.now().isoformat(timespec="seconds"),
        source="auth_log",
        event_type="auth_failure",
        severity="LOW",
        message="test event",
        src_ip="192.168.1.99",
    )
    defaults.update(kwargs)
    return NormalizedEvent(**defaults)


# ── Database tests ─────────────────────────────────────────────────────────────

class TestDatabase:

    def test_insert_and_retrieve_event(self, tmp_db):
        event = _make_test_event(message="login failed")
        eid = tmp_db.insert_event(event)
        assert eid == 1
        events = tmp_db.get_events()
        assert len(events) == 1
        assert events[0]["message"] == "login failed"

    def test_bulk_insert(self, tmp_db):
        events = [_make_test_event() for _ in range(5)]
        ids = tmp_db.insert_events(events)
        assert len(ids) == 5
        assert tmp_db.get_events(limit=10).__len__() == 5

    def test_filter_by_event_type(self, tmp_db):
        tmp_db.insert_event(_make_test_event(event_type="auth_failure"))
        tmp_db.insert_event(_make_test_event(event_type="auth_success"))
        results = tmp_db.get_events(event_type="auth_failure")
        assert all(r["event_type"] == "auth_failure" for r in results)

    def test_filter_by_source(self, tmp_db):
        tmp_db.insert_event(_make_test_event(source="auth_log"))
        tmp_db.insert_event(_make_test_event(source="netwatch"))
        results = tmp_db.get_events(source="netwatch")
        assert len(results) == 1

    def test_count_events(self, tmp_db):
        now = datetime.now().isoformat(timespec="seconds")
        for _ in range(3):
            tmp_db.insert_event(_make_test_event(src_ip="10.0.0.1", event_type="auth_failure"))
        count = tmp_db.count_events("10.0.0.1", "auth_failure", "2000-01-01T00:00:00")
        assert count == 3

    def test_insert_and_retrieve_alert(self, tmp_db):
        alert_id = tmp_db.insert_alert(
            rule_name="ssh_brute_force",
            severity="HIGH",
            description="Test alert",
            event_ids=[1, 2, 3],
            src_ip="192.168.1.99",
        )
        alerts = tmp_db.get_alerts()
        assert len(alerts) == 1
        assert alerts[0]["rule_name"] == "ssh_brute_force"

    def test_acknowledge_alert(self, tmp_db):
        aid = tmp_db.insert_alert("rule", "LOW", "desc", [1])
        tmp_db.acknowledge_alert(aid)
        unacked = tmp_db.get_alerts(unacked_only=True)
        assert len(unacked) == 0

    def test_get_stats(self, tmp_db):
        tmp_db.insert_event(_make_test_event())
        tmp_db.insert_alert("r", "HIGH", "d", [1])
        stats = tmp_db.get_stats()
        assert stats["total_events"] == 1
        assert stats["total_alerts"] == 1
        assert stats["unacknowledged_alerts"] == 1


# ── Normalizer tests ──────────────────────────────────────────────────────────

class TestNormalizer:

    def test_make_event_valid(self):
        e = make_event("2026-06-30T14:00:00", "auth_log", "auth_failure",
                       "HIGH", "msg", normalize_ts=False)
        assert e.source == "auth_log"
        assert e.severity == "HIGH"

    def test_invalid_source_coerced(self):
        e = make_event("2026-06-30T14:00:00", "bad_source", "auth_failure",
                       "HIGH", "msg", normalize_ts=False)
        assert e.source == "manual"

    def test_invalid_severity_coerced(self):
        e = make_event("2026-06-30T14:00:00", "auth_log", "auth_failure",
                       "EXTREME", "msg", normalize_ts=False)
        assert e.severity == "LOW"

    def test_normalize_timestamp_syslog(self):
        ts = normalize_timestamp("Jun 30 14:23:01")
        assert "14:23:01" in ts
        assert str(datetime.now().year) in ts

    def test_normalize_timestamp_iso(self):
        ts = normalize_timestamp("2026-06-30T14:23:01")
        assert ts == "2026-06-30T14:23:01"

    def test_normalize_timestamp_apache(self):
        ts = normalize_timestamp("30/Jun/2026:14:23:01 +0000")
        assert "2026-06-30" in ts


# ── Auth parser tests ─────────────────────────────────────────────────────────

class TestAuthParser:

    def test_parse_failed_password(self):
        line = "Jun 30 14:20:01 kali sshd[1234]: Failed password for root from 192.168.1.99 port 22 ssh2"
        e = auth_parse_line(line)
        assert e is not None
        assert e.event_type == "auth_failure"
        assert e.src_ip == "192.168.1.99"
        assert e.user == "root"

    def test_parse_accepted_password(self):
        line = "Jun 30 14:20:10 kali sshd[1235]: Accepted password for kali from 192.168.1.5 port 54321 ssh2"
        e = auth_parse_line(line)
        assert e is not None
        assert e.event_type == "auth_success"
        assert e.user == "kali"

    def test_parse_sudo_command(self):
        line = "Jun 30 14:21:00 kali sudo: kali : TTY=pts/0 ; PWD=/home/kali ; USER=root ; COMMAND=/bin/bash"
        e = auth_parse_line(line)
        assert e is not None
        assert e.event_type == "sudo_command"
        assert e.severity == "MEDIUM"

    def test_parse_unrecognised_line(self):
        assert auth_parse_line("This is not a log line") is None
        assert auth_parse_line("") is None

    def test_parse_file(self, tmp_path):
        log = tmp_path / "auth.log"
        log.write_text(
            "Jun 30 14:20:01 kali sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2\n"
            "Jun 30 14:20:02 kali sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2\n"
        )
        events = list(auth_parse_file(log))
        assert len(events) == 2
        assert all(e.event_type == "auth_failure" for e in events)


# ── JSON importer tests ───────────────────────────────────────────────────────

class TestJsonImporter:

    def test_parse_netwatch(self, tmp_path):
        f = tmp_path / "nw.json"
        f.write_text(json.dumps([
            {"timestamp": "2026-06-30T14:00:00", "type": "PORT_SCAN",
             "severity": "HIGH", "src_ip": "1.2.3.4", "details": "scan"}
        ]))
        events = list(parse_netwatch(f))
        assert len(events) == 1
        assert events[0].event_type == "port_scan"
        assert events[0].source == "netwatch"

    def test_parse_homeguard(self, tmp_path):
        f = tmp_path / "hg.json"
        f.write_text(json.dumps([
            {"timestamp": "2026-06-30T14:00:00", "mac": "aa:bb:cc:dd:ee:ff",
             "ip": "192.168.1.99", "vendor": "Unknown", "alert": "UNKNOWN_DEVICE"}
        ]))
        events = list(parse_homeguard(f))
        assert len(events) == 1
        assert events[0].event_type == "unknown_device"
        assert events[0].severity == "HIGH"


# ── Correlation engine tests ──────────────────────────────────────────────────

class TestCorrelationEngine:

    def _insert_auth_failures(self, db, ip, count):
        now = datetime.now().isoformat(timespec="seconds")
        for _ in range(count):
            db.insert_event(NormalizedEvent(
                timestamp=now, source="auth_log", event_type="auth_failure",
                severity="LOW", message=f"fail from {ip}", src_ip=ip,
            ))

    def test_ssh_brute_force_fires(self, tmp_db):
        self._insert_auth_failures(tmp_db, "192.168.1.50", 6)
        alerts = run_all_rules(tmp_db)
        rule_names = [a["rule"] for a in alerts]
        assert "ssh_brute_force" in rule_names

    def test_no_alert_below_threshold(self, tmp_db):
        self._insert_auth_failures(tmp_db, "192.168.1.51", 3)
        alerts = run_all_rules(tmp_db)
        rule_names = [a["rule"] for a in alerts]
        assert "ssh_brute_force" not in rule_names

    def test_cross_source_critical_alert(self, tmp_db):
        now = datetime.now().isoformat(timespec="seconds")
        tmp_db.insert_event(NormalizedEvent(
            timestamp=now, source="homeguard", event_type="unknown_device",
            severity="HIGH", message="unknown", src_ip="192.168.1.200",
        ))
        tmp_db.insert_event(NormalizedEvent(
            timestamp=now, source="netwatch", event_type="port_scan",
            severity="HIGH", message="scan", src_ip="192.168.1.200",
        ))
        alerts = run_all_rules(tmp_db)
        critical = [a for a in alerts if a.get("severity") == "CRITICAL"]
        assert len(critical) >= 1
