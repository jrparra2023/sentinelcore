"""
SentinelCore — tests/test_v1_1.py
pytest suite for v1.1 parsers: syslog, suricata, nginx (18 tests).
"""

import sys
import json
import pytest
import tempfile
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from ingestion.syslog_parser   import parse_line as syslog_line, parse_file as syslog_file
from ingestion.suricata_parser import parse_line as suricata_line, parse_file as suricata_file
from ingestion.nginx_parser    import parse_line as nginx_line, parse_file as nginx_file


# ── Syslog parser ─────────────────────────────────────────────────────────────

class TestSyslogParser:

    def test_service_started(self):
        line = "Jul  1 14:20:01 kali systemd[1]: Started Daily apt download activities."
        e = syslog_line(line)
        assert e is not None
        assert e.event_type == "service_start"
        assert e.severity == "LOW"
        assert e.source == "syslog"

    def test_service_failed(self):
        line = "Jul  1 14:21:00 kali systemd[1]: Failed to start MySQL Community Server."
        e = syslog_line(line)
        assert e is not None
        assert e.event_type == "service_stop"
        assert e.severity == "HIGH"

    def test_service_stopped(self):
        line = "Jul  1 14:21:30 kali systemd[1]: Stopped OpenSSH Daemon."
        e = syslog_line(line)
        assert e is not None
        assert e.event_type == "service_stop"
        assert e.severity == "LOW"

    def test_oom_killer(self):
        line = "Jul  1 14:22:00 kali kernel: [12345.678] Out of memory: Kill process 1234 (python3) score 500 or sacrifice child"
        e = syslog_line(line)
        assert e is not None
        assert e.event_type == "system_error"
        assert e.severity == "HIGH"
        assert "python3" in e.message

    def test_segfault(self):
        line = "Jul  1 14:22:30 kali kernel: [12346.000] segfault at 00000000 ip 00007f00 sp 00007fff error 4"
        e = syslog_line(line)
        assert e is not None
        assert e.event_type == "system_error"
        assert e.severity == "MEDIUM"

    def test_disk_error(self):
        line = "Jul  1 14:23:00 kali kernel: [12347.000] Buffer I/O error on device sda1, logical block 12345"
        e = syslog_line(line)
        assert e is not None
        assert e.event_type == "system_error"
        assert e.severity == "HIGH"

    def test_pam_failure(self):
        line = "Jul  1 14:23:30 kali pam_unix(sshd:auth)[999]: authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.0.0.1 user=root"
        e = syslog_line(line)
        assert e is not None
        assert e.event_type == "auth_failure"

    def test_unrecognised_returns_none(self):
        assert syslog_line("") is None
        assert syslog_line("This is not a syslog line") is None

    def test_parse_file(self, tmp_path):
        log = tmp_path / "syslog"
        log.write_text(
            "Jul  1 14:20:01 kali systemd[1]: Started Daily apt download activities.\n"
            "Jul  1 14:21:00 kali systemd[1]: Failed to start MySQL Community Server.\n"
            "Jul  1 14:22:00 kali kernel: [12345.678] Out of memory: Kill process 1234 (python3) score 500 or sacrifice child\n"
        )
        events = list(syslog_file(log))
        assert len(events) == 3
        types = {e.event_type for e in events}
        assert "service_start" in types
        assert "service_stop" in types
        assert "system_error" in types


# ── Suricata parser ───────────────────────────────────────────────────────────

class TestSuricataParser:

    def _eve_line(self, signature, category, severity=2, src_ip="1.2.3.4"):
        return json.dumps({
            "timestamp": "2026-07-01T14:20:00.000000+0000",
            "event_type": "alert",
            "src_ip": src_ip,
            "dest_ip": "192.168.1.13",
            "proto": "TCP",
            "alert": {
                "signature": signature,
                "category": category,
                "severity": severity,
                "signature_id": 9999,
            }
        })

    def test_port_scan_alert(self):
        line = self._eve_line("ET SCAN Potential SSH Scan", "Attempted Information Leak", 2)
        e = suricata_line(line)
        assert e is not None
        assert e.event_type == "port_scan"
        assert e.source == "suricata"

    def test_web_attack_high_severity(self):
        line = self._eve_line("ET WEB_SERVER SQL Injection", "Web Application Attack", 1)
        e = suricata_line(line)
        assert e is not None
        assert e.severity == "HIGH"
        assert e.event_type == "web_scan"

    def test_dns_anomaly(self):
        line = self._eve_line("ET DNS Suspicious Query", "DNS", 2)
        e = suricata_line(line)
        assert e is not None
        assert e.event_type == "dns_anomaly"

    def test_non_alert_event_ignored(self):
        line = json.dumps({"timestamp": "2026-07-01T14:00:00+0000", "event_type": "dns"})
        assert suricata_line(line) is None

    def test_invalid_json_returns_none(self):
        assert suricata_line("not json") is None
        assert suricata_line("") is None

    def test_src_ip_captured(self):
        line = self._eve_line("ET SCAN Test", "Network Scan", src_ip="10.10.10.10")
        e = suricata_line(line)
        assert e.src_ip == "10.10.10.10"

    def test_parse_file(self, tmp_path):
        f = tmp_path / "eve.json"
        lines = [
            self._eve_line("ET SCAN SSH", "Attempted Information Leak"),
            self._eve_line("ET WEB_SERVER SQLi", "Web Application Attack", 1),
            json.dumps({"event_type": "dns", "timestamp": "2026-07-01T14:00:00+0000"}),
        ]
        f.write_text("\n".join(lines) + "\n")
        events = list(suricata_file(f))
        assert len(events) == 2  # dns event ignored


# ── Nginx parser ──────────────────────────────────────────────────────────────

class TestNginxParser:

    def test_200_response(self):
        line = '192.168.1.5 - - [01/Jul/2026:14:20:01 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
        e = nginx_line(line)
        assert e is not None
        assert e.event_type == "web_access"
        assert e.severity == "LOW"
        assert e.source == "nginx"

    def test_404_response(self):
        line = '192.168.1.99 - - [01/Jul/2026:14:20:02 +0000] "GET /admin HTTP/1.1" 404 0 "-" "sqlmap/1.0"'
        e = nginx_line(line)
        assert e is not None
        assert e.event_type == "web_error"

    def test_web_scan_detected(self, tmp_path):
        # 20+ 404s from same IP → web_scan
        log = tmp_path / "nginx.log"
        lines = []
        for i in range(22):
            lines.append(
                f'192.168.1.99 - - [01/Jul/2026:14:20:{i:02d} +0000] '
                f'"GET /path{i} HTTP/1.1" 404 0 "-" "scanner/1.0"'
            )
        log.write_text("\n".join(lines) + "\n")
        events = list(nginx_file(log))
        scan_events = [e for e in events if e.event_type == "web_scan"]
        assert len(scan_events) > 0
        assert all(e.severity == "HIGH" for e in scan_events)

    def test_500_response(self):
        line = '192.168.1.5 - - [01/Jul/2026:14:21:01 +0000] "GET /dashboard HTTP/1.1" 500 0 "-" "Mozilla/5.0"'
        e = nginx_line(line)
        assert e is not None
        assert e.event_type == "web_error"
        assert e.severity == "MEDIUM"

    def test_invalid_line_returns_none(self):
        assert nginx_line("") is None
        assert nginx_line("not a log line") is None
