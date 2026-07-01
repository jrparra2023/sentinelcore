"""
SentinelCore — ingestion/auth_parser.py
Parses /var/log/auth.log (Linux SSH, sudo, PAM events).

Detected event types
--------------------
auth_failure  — "Failed password for ..."
auth_success  — "Accepted password/publickey for ..."
sudo_command  — "sudo: ... COMMAND=..."
user_created  — "useradd: new user ..."
user_deleted  — "userdel: delete user ..."
"""

import re
from pathlib import Path
from typing import Generator
from ingestion.normalizer import make_event, infer_auth_severity
from storage.db import NormalizedEvent


# ── Regex patterns ────────────────────────────────────────────────────────────
_TS   = r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"   # "Jun 30 14:23:01"
_HOST = r"\S+"                                         # hostname

PATTERNS = {
    "auth_failure": re.compile(
        rf"^{_TS}\s+{_HOST}\s+\S+:\s+Failed\s+\w+\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)"
    ),
    "auth_success": re.compile(
        rf"^{_TS}\s+{_HOST}\s+\S+:\s+Accepted\s+\w+\s+for\s+(\S+)\s+from\s+(\S+)"
    ),
    "sudo_command": re.compile(
        rf"^{_TS}\s+{_HOST}\s+sudo:\s+(\S+)\s+:.*?COMMAND=(.*?)$"
    ),
    "user_created": re.compile(
        rf"^{_TS}\s+{_HOST}\s+\S+:\s+new user:\s+name=(\S+)"
    ),
    "user_deleted": re.compile(
        rf"^{_TS}\s+{_HOST}\s+\S+:\s+delete user\s+'(\S+)'"
    ),
}


# ── Parser ────────────────────────────────────────────────────────────────────
def parse_line(line: str) -> NormalizedEvent | None:
    """Parse a single auth.log line. Returns None if unrecognised."""
    line = line.strip()
    if not line:
        return None

    # Failed password
    m = PATTERNS["auth_failure"].match(line)
    if m:
        ts, user, src_ip = m.group(1), m.group(2), m.group(3)
        return make_event(
            timestamp=ts,
            source="auth_log",
            event_type="auth_failure",
            severity=infer_auth_severity("auth_failure"),
            message=f"Failed login for user '{user}' from {src_ip}",
            src_ip=src_ip,
            user=user,
            raw=line,
        )

    # Accepted
    m = PATTERNS["auth_success"].match(line)
    if m:
        ts, user, src_ip = m.group(1), m.group(2), m.group(3)
        return make_event(
            timestamp=ts,
            source="auth_log",
            event_type="auth_success",
            severity="LOW",
            message=f"Successful login for user '{user}' from {src_ip}",
            src_ip=src_ip,
            user=user,
            raw=line,
        )

    # sudo
    m = PATTERNS["sudo_command"].match(line)
    if m:
        ts, user, command = m.group(1), m.group(2), m.group(3).strip()
        return make_event(
            timestamp=ts,
            source="auth_log",
            event_type="sudo_command",
            severity="MEDIUM",
            message=f"User '{user}' ran sudo command: {command}",
            user=user,
            raw=line,
            extra={"command": command},
        )

    # useradd
    m = PATTERNS["user_created"].match(line)
    if m:
        ts, user = m.group(1), m.group(2)
        return make_event(
            timestamp=ts,
            source="auth_log",
            event_type="user_created",
            severity="MEDIUM",
            message=f"New user created: '{user}'",
            user=user,
            raw=line,
        )

    # userdel
    m = PATTERNS["user_deleted"].match(line)
    if m:
        ts, user = m.group(1), m.group(2)
        return make_event(
            timestamp=ts,
            source="auth_log",
            event_type="user_deleted",
            severity="HIGH",
            message=f"User deleted: '{user}'",
            user=user,
            raw=line,
        )

    return None


def parse_file(path: str | Path) -> Generator[NormalizedEvent, None, None]:
    """Yield NormalizedEvents from an auth.log file."""
    with open(path, "r", errors="replace") as f:
        for line in f:
            event = parse_line(line)
            if event:
                yield event


def ingest(path: str | Path, db) -> int:
    """Parse auth.log at `path` and bulk-insert into `db`. Returns count."""
    events = list(parse_file(path))
    if events:
        db.insert_events(events)
    return len(events)
