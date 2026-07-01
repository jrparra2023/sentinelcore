"""
SentinelCore — ingestion/syslog_parser.py
Parses /var/log/syslog (general Linux system events).

Detected event types
--------------------
service_start  — systemd service started
service_stop   — systemd service stopped/failed
system_error   — kernel OOM, segfault, disk errors
auth_failure   — PAM authentication failures in syslog
unknown        — everything else (stored for correlation context)
"""

import re
from pathlib import Path
from typing import Generator
from ingestion.normalizer import make_event
from storage.db import NormalizedEvent

# Syslog timestamp: "Jun 30 14:23:01"
_TS   = r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
_HOST = r"\S+"

PATTERNS = {
    "service_start": re.compile(
        rf"^{_TS}\s+{_HOST}\s+systemd\[.*?\]:\s+Started (.+?)\."
    ),
    "service_stop": re.compile(
        rf"^{_TS}\s+{_HOST}\s+systemd\[.*?\]:\s+(Stopped|Failed to start|Stopping) (.+?)\."
    ),
    "oom": re.compile(
        rf"^{_TS}\s+{_HOST}\s+kernel:.*Out of memory.*process\s+\d+\s+\((.+?)\)"
    ),
    "segfault": re.compile(
        rf"^{_TS}\s+{_HOST}\s+kernel:.*segfault at"
    ),
    "disk_error": re.compile(
        rf"^{_TS}\s+{_HOST}\s+kernel:.*(?:I/O error|Buffer I/O error|disk error)"
    ),
    "pam_failure": re.compile(
        rf"^{_TS}\s+{_HOST}\s+\S*pam\S*\[.*?\]:\s+.*(?:authentication failure|AUTH_ERR).*(?:user=(\S+))?"
    ),
}


def parse_line(line: str) -> NormalizedEvent | None:
    line = line.strip()
    if not line:
        return None

    # Service started
    m = PATTERNS["service_start"].match(line)
    if m:
        return make_event(
            timestamp=m.group(1), source="syslog",
            event_type="service_start", severity="LOW",
            message=f"Service started: {m.group(2)}", raw=line,
            extra={"service": m.group(2)},
        )

    # Service stopped/failed
    m = PATTERNS["service_stop"].match(line)
    if m:
        action  = m.group(2)
        service = m.group(3)
        sev     = "HIGH" if "Failed" in action else "LOW"
        return make_event(
            timestamp=m.group(1), source="syslog",
            event_type="service_stop", severity=sev,
            message=f"Service {action.lower()}: {service}", raw=line,
            extra={"service": service, "action": action},
        )

    # OOM killer
    m = PATTERNS["oom"].match(line)
    if m:
        return make_event(
            timestamp=m.group(1), source="syslog",
            event_type="system_error", severity="HIGH",
            message=f"OOM killer invoked — killed process: {m.group(2)}", raw=line,
            extra={"process": m.group(2)},
        )

    # Segfault
    m = PATTERNS["segfault"].match(line)
    if m:
        return make_event(
            timestamp=m.group(1), source="syslog",
            event_type="system_error", severity="MEDIUM",
            message="Kernel segfault detected", raw=line,
        )

    # Disk I/O error
    m = PATTERNS["disk_error"].match(line)
    if m:
        return make_event(
            timestamp=m.group(1), source="syslog",
            event_type="system_error", severity="HIGH",
            message="Disk I/O error detected", raw=line,
        )

    # PAM auth failure
    m = PATTERNS["pam_failure"].match(line)
    if m:
        user = m.group(2) if m.lastindex and m.lastindex >= 2 else None
        return make_event(
            timestamp=m.group(1), source="syslog",
            event_type="auth_failure", severity="MEDIUM",
            message=f"PAM authentication failure{f' for user {user}' if user else ''}",
            user=user, raw=line,
        )

    return None


def parse_file(path: str | Path) -> Generator[NormalizedEvent, None, None]:
    with open(path, "r", errors="replace") as f:
        for line in f:
            event = parse_line(line)
            if event:
                yield event


def ingest(path: str | Path, db) -> int:
    events = list(parse_file(path))
    if events:
        db.insert_events(events)
    return len(events)
