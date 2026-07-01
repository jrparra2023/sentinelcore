"""
SentinelCore — ingestion/normalizer.py
Helpers that every parser uses to build NormalizedEvents consistently.
"""

from datetime import datetime
from typing import Optional
from storage.db import NormalizedEvent


# ── Valid values (guards against typos in parsers) ────────────────────────────
VALID_SOURCES = {
    "auth_log", "syslog", "apache", "nginx",
    "netwatch", "homeguard", "manual",
}

VALID_EVENT_TYPES = {
    # Auth
    "auth_failure",
    "auth_success",
    "sudo_command",
    "user_created",
    "user_deleted",
    # Network
    "port_scan",
    "dns_anomaly",
    "unknown_device",
    "bandwidth_spike",
    # Web
    "web_scan",
    "web_error",
    "web_access",
    # System
    "service_start",
    "service_stop",
    "system_error",
    # Generic
    "unknown",
}

VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


# ── Severity helpers ──────────────────────────────────────────────────────────
def infer_auth_severity(event_type: str, consecutive_failures: int = 1) -> str:
    """
    Infer severity for auth events.
    Single failure → LOW. Repeated failures → escalate.
    """
    if event_type == "auth_success":
        return "LOW"
    if event_type == "sudo_command":
        return "MEDIUM"
    if consecutive_failures >= 10:
        return "HIGH"
    if consecutive_failures >= 3:
        return "MEDIUM"
    return "LOW"


def infer_web_severity(status_code: int, count: int = 1) -> str:
    if status_code == 200:
        return "LOW"
    if status_code in (401, 403):
        return "MEDIUM" if count < 5 else "HIGH"
    if status_code == 404 and count >= 20:
        return "MEDIUM"  # possible web scan
    if status_code >= 500:
        return "MEDIUM"
    return "LOW"


# ── Timestamp normalizer ──────────────────────────────────────────────────────
def normalize_timestamp(raw_ts: str, fmt: str = None) -> str:
    """
    Convert various timestamp formats to ISO-8601.
    Falls back to now() if parsing fails.

    Supported fmts (auto-detected if fmt=None):
      - "Jun 30 14:23:01"          (syslog / auth.log)
      - "30/Jun/2026:14:23:01 +0000"  (Apache combined)
      - "2026-06-30T14:23:01"      (already ISO)
      - "2026-06-30 14:23:01"      (SQLite / HomeGuard JSON)
    """
    formats = [
        "%b %d %H:%M:%S",              # syslog (no year)
        "%d/%b/%Y:%H:%M:%S %z",        # Apache
        "%Y-%m-%dT%H:%M:%S",           # ISO
        "%Y-%m-%d %H:%M:%S",           # SQLite-style
        "%Y-%m-%dT%H:%M:%S.%f",        # ISO with microseconds
    ]

    if fmt:
        formats = [fmt] + formats

    for f in formats:
        try:
            dt = datetime.strptime(raw_ts.strip(), f)
            # syslog has no year — inject current year
            if dt.year == 1900:
                dt = dt.replace(year=datetime.now().year)
            return dt.isoformat(timespec="seconds")
        except ValueError:
            continue

    # last resort
    return datetime.now().isoformat(timespec="seconds")


# ── Factory ───────────────────────────────────────────────────────────────────
def make_event(
    timestamp:  str,
    source:     str,
    event_type: str,
    severity:   str,
    message:    str,
    src_ip:     Optional[str] = None,
    dst_ip:     Optional[str] = None,
    user:       Optional[str] = None,
    raw:        Optional[str] = None,
    extra:      dict          = None,
    normalize_ts: bool        = True,
) -> NormalizedEvent:
    """
    Validated factory for NormalizedEvent.
    Parsers call this instead of constructing NormalizedEvent directly.
    """
    # Validate / coerce
    if source not in VALID_SOURCES:
        source = "manual"
    if event_type not in VALID_EVENT_TYPES:
        event_type = "unknown"
    severity = severity.upper()
    if severity not in VALID_SEVERITIES:
        severity = "LOW"
    if normalize_ts:
        timestamp = normalize_timestamp(timestamp)

    return NormalizedEvent(
        timestamp=timestamp,
        source=source,
        event_type=event_type,
        severity=severity,
        message=message,
        src_ip=src_ip,
        dst_ip=dst_ip,
        user=user,
        raw=raw,
        extra=extra or {},
    )
