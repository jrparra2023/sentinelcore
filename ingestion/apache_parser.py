"""
SentinelCore — ingestion/apache_parser.py
Parses Apache/Nginx combined access log format.

Detected event types
--------------------
web_access  — 2xx responses
web_error   — 4xx/5xx responses
web_scan    — high 404 rate from same IP (flagged at parse time by count)
"""

import re
from pathlib import Path
from collections import defaultdict
from typing import Generator
from ingestion.normalizer import make_event, infer_web_severity
from storage.db import NormalizedEvent

# Combined log format:
# 1.2.3.4 - user [30/Jun/2026:14:23:01 +0000] "GET /path HTTP/1.1" 200 512 "ref" "UA"
_COMBINED = re.compile(
    r'(?P<ip>\S+)\s+'          # client IP
    r'\S+\s+'                   # ident
    r'(?P<user>\S+)\s+'        # auth user
    r'\[(?P<ts>[^\]]+)\]\s+'   # timestamp
    r'"(?P<method>\S+)\s+'     # method
    r'(?P<path>\S+)\s+'        # path
    r'\S+"\s+'                  # protocol
    r'(?P<status>\d{3})\s+'    # status code
    r'(?P<size>\S+)'            # response size
)


def parse_line(line: str, ip_404_counts: dict = None) -> NormalizedEvent | None:
    line = line.strip()
    if not line:
        return None

    m = _COMBINED.match(line)
    if not m:
        return None

    ip     = m.group("ip")
    ts     = m.group("ts")
    method = m.group("method")
    path   = m.group("path")
    status = int(m.group("status"))
    user   = m.group("user") if m.group("user") != "-" else None

    # Track 404s per IP for web scan detection
    if ip_404_counts is not None and status == 404:
        ip_404_counts[ip] += 1

    severity   = infer_web_severity(status)
    event_type = "web_access" if status < 400 else "web_error"

    return make_event(
        timestamp=ts,
        source="apache",
        event_type=event_type,
        severity=severity,
        message=f"{method} {path} → {status} from {ip}",
        src_ip=ip,
        user=user,
        raw=line,
        extra={"method": method, "path": path, "status": status},
    )


def parse_file(path: str | Path) -> Generator[NormalizedEvent, None, None]:
    """
    Yield NormalizedEvents from an Apache access log.
    Upgrades events to web_scan for IPs with 20+ 404s.
    """
    ip_404_counts: dict[str, int] = defaultdict(int)
    events: list[NormalizedEvent] = []

    with open(path, "r", errors="replace") as f:
        for line in f:
            event = parse_line(line, ip_404_counts)
            if event:
                events.append(event)

    # Post-process: flag web_scan IPs
    scan_ips = {ip for ip, cnt in ip_404_counts.items() if cnt >= 20}
    for event in events:
        if event.src_ip in scan_ips and event.event_type == "web_error":
            event.event_type = "web_scan"
            event.severity   = "HIGH"
            event.message    = f"[WEB SCAN] {event.message}"
        yield event


def ingest(path: str | Path, db) -> int:
    events = list(parse_file(path))
    if events:
        db.insert_events(events)
    return len(events)
