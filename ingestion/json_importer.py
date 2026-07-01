"""
SentinelCore — ingestion/json_importer.py
Imports JSON output from your existing projects:
  • NetWatch  — logs/alerts.json
  • HomeGuard — logs/alerts.json (intrusion_detector output)

This is what makes SentinelCore a cohesive portfolio: it centralizes
alerts from your two previous tools into a single correlation layer.
"""

import json
from pathlib import Path
from typing import Generator
from ingestion.normalizer import make_event
from storage.db import NormalizedEvent


# ── NetWatch ──────────────────────────────────────────────────────────────────
# Expected NetWatch alert record shape:
# {
#   "timestamp": "2026-06-30T14:23:01",
#   "type": "PORT_SCAN" | "DNS_ANOMALY",
#   "severity": "HIGH" | "MEDIUM",
#   "src_ip": "192.168.1.X",
#   "details": "..."
# }

_NETWATCH_TYPE_MAP = {
    "PORT_SCAN":   "port_scan",
    "DNS_ANOMALY": "dns_anomaly",
}


def _parse_netwatch_record(record: dict) -> NormalizedEvent | None:
    try:
        raw_type  = record.get("type", "UNKNOWN").upper()
        event_type = _NETWATCH_TYPE_MAP.get(raw_type, "unknown")
        return make_event(
            timestamp=record.get("timestamp", ""),
            source="netwatch",
            event_type=event_type,
            severity=record.get("severity", "MEDIUM"),
            message=record.get("details", f"NetWatch alert: {raw_type}"),
            src_ip=record.get("src_ip"),
            raw=json.dumps(record),
            extra=record,
        )
    except Exception:
        return None


def parse_netwatch(path: str | Path) -> Generator[NormalizedEvent, None, None]:
    with open(path, "r") as f:
        data = json.load(f)

    # NetWatch may output a list or a dict with an "alerts" key
    records = data if isinstance(data, list) else data.get("alerts", [])
    for record in records:
        event = _parse_netwatch_record(record)
        if event:
            yield event


# ── HomeGuard ─────────────────────────────────────────────────────────────────
# Expected HomeGuard intrusion alert shape:
# {
#   "timestamp": "2026-06-30T14:23:01",
#   "mac": "aa:bb:cc:dd:ee:ff",
#   "ip": "192.168.1.X",
#   "vendor": "Unknown",
#   "alert": "UNKNOWN_DEVICE"
# }

def _parse_homeguard_record(record: dict) -> NormalizedEvent | None:
    try:
        mac    = record.get("mac", "unknown")
        vendor = record.get("vendor", "Unknown")
        ip     = record.get("ip")
        return make_event(
            timestamp=record.get("timestamp", ""),
            source="homeguard",
            event_type="unknown_device",
            severity="HIGH",
            message=f"Unknown device detected — MAC: {mac} | Vendor: {vendor} | IP: {ip}",
            src_ip=ip,
            raw=json.dumps(record),
            extra={"mac": mac, "vendor": vendor},
        )
    except Exception:
        return None


def parse_homeguard(path: str | Path) -> Generator[NormalizedEvent, None, None]:
    with open(path, "r") as f:
        data = json.load(f)

    records = data if isinstance(data, list) else data.get("alerts", [])
    for record in records:
        event = _parse_homeguard_record(record)
        if event:
            yield event


# ── Generic dispatcher ────────────────────────────────────────────────────────
def ingest_json(path: str | Path, source: str, db) -> int:
    """
    Ingest a JSON alert file from NetWatch or HomeGuard.
    source: "netwatch" | "homeguard"
    """
    path = Path(path)
    if source == "netwatch":
        events = list(parse_netwatch(path))
    elif source == "homeguard":
        events = list(parse_homeguard(path))
    else:
        raise ValueError(f"Unknown JSON source: {source}")

    if events:
        db.insert_events(events)
    return len(events)
