"""
SentinelCore — ingestion/suricata_parser.py
Parses Suricata EVE JSON log (/var/log/suricata/eve.json).

Suricata writes one JSON object per line (NDJSON format).
We import alert events and map them to NormalizedEvent.

Detected event types
--------------------
port_scan     — ET SCAN signatures
dns_anomaly   — ET DNS signatures
web_scan      — ET WEB_SERVER signatures
system_error  — Suricata engine errors
unknown       — all other alert signatures
"""

import json
from pathlib import Path
from typing import Generator
from ingestion.normalizer import make_event
from storage.db import NormalizedEvent

# Suricata severity: 1=HIGH, 2=MEDIUM, 3=LOW
_SURICATA_SEV = {1: "HIGH", 2: "MEDIUM", 3: "LOW"}

# Map Suricata signature categories → SentinelCore event types
_CATEGORY_MAP = {
    "Attempted Information Leak":     "port_scan",
    "Information Leak":               "port_scan",
    "Network Scan":                   "port_scan",
    "Attempted Denial of Service":    "system_error",
    "Denial of Service Attack":       "system_error",
    "Web Application Attack":         "web_scan",
    "Potentially Bad Traffic":        "unknown",
    "Misc Attack":                    "unknown",
    "DNS":                            "dns_anomaly",
}

def _map_event_type(signature: str, category: str) -> str:
    sig_upper = signature.upper()
    if "SCAN" in sig_upper:
        return "port_scan"
    if "DNS" in sig_upper:
        return "dns_anomaly"
    if "WEB" in sig_upper or "HTTP" in sig_upper:
        return "web_scan"
    return _CATEGORY_MAP.get(category, "unknown")


def parse_line(line: str) -> NormalizedEvent | None:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None

    # Only process alert events
    if obj.get("event_type") != "alert":
        return None

    alert     = obj.get("alert", {})
    signature = alert.get("signature", "Unknown Suricata alert")
    category  = alert.get("category", "")
    sev_int   = alert.get("severity", 2)
    severity  = _SURICATA_SEV.get(sev_int, "MEDIUM")

    src_ip = obj.get("src_ip")
    dst_ip = obj.get("dest_ip")
    ts     = obj.get("timestamp", "")

    event_type = _map_event_type(signature, category)

    return make_event(
        timestamp=ts,
        source="suricata",
        event_type=event_type,
        severity=severity,
        message=f"[Suricata] {signature}",
        src_ip=src_ip,
        dst_ip=dst_ip,
        raw=line,
        extra={
            "signature":  signature,
            "category":   category,
            "sid":        alert.get("signature_id"),
            "proto":      obj.get("proto"),
            "src_port":   obj.get("src_port"),
            "dest_port":  obj.get("dest_port"),
        },
    )


def parse_file(path: str | Path) -> Generator[NormalizedEvent, None, None]:
    """Parse Suricata EVE JSON (NDJSON — one JSON object per line)."""
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
