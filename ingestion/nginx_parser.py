"""
SentinelCore — ingestion/nginx_parser.py
Parses Nginx combined access log format.
Shares the same detection logic as apache_parser but handles
Nginx's slightly different default timestamp format.

Detected event types
--------------------
web_access  — 2xx responses
web_error   — 4xx/5xx responses
web_scan    — 20+ 404s from same IP (post-processing)
"""

import re
from pathlib import Path
from collections import defaultdict
from typing import Generator
from ingestion.normalizer import make_event, infer_web_severity
from storage.db import NormalizedEvent

# Nginx combined log format (same as Apache combined):
# 1.2.3.4 - user [01/Jul/2026:14:23:01 +0000] "GET /path HTTP/1.1" 200 512 "ref" "UA"
_COMBINED = re.compile(
    r'(?P<ip>\S+)\s+'
    r'\S+\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+'
    r'(?P<path>\S+)\s+'
    r'\S+"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)'
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

    if ip_404_counts is not None and status == 404:
        ip_404_counts[ip] += 1

    severity   = infer_web_severity(status)
    event_type = "web_access" if status < 400 else "web_error"

    return make_event(
        timestamp=ts,
        source="nginx",
        event_type=event_type,
        severity=severity,
        message=f"{method} {path} → {status} from {ip}",
        src_ip=ip,
        user=user,
        raw=line,
        extra={"method": method, "path": path, "status": status},
    )


def parse_file(path: str | Path) -> Generator[NormalizedEvent, None, None]:
    ip_404_counts: dict[str, int] = defaultdict(int)
    events: list[NormalizedEvent] = []

    with open(path, "r", errors="replace") as f:
        for line in f:
            event = parse_line(line, ip_404_counts)
            if event:
                events.append(event)

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
