"""
SentinelCore — correlation/reputation.py
IP Reputation scoring system.

Score range: 0–100
  0–29   → CLEAN
  30–59  → SUSPICIOUS
  60–84  → MALICIOUS
  85–100 → KNOWN_BAD

Score is increased each time an alert fires for that IP.
Severity determines the score delta:
  CRITICAL → +25
  HIGH     → +15
  MEDIUM   → +8
  LOW      → +3

Score decays 1 point per day (applied on read).
Tags label the type of activity seen (brute_force, scanner, web_attack, etc.)
"""

from datetime import datetime, timedelta
from storage.db import Database

# Score deltas per severity
SEVERITY_DELTA = {
    "CRITICAL": 25,
    "HIGH":     15,
    "MEDIUM":   8,
    "LOW":      3,
}

# Score → label
def score_label(score: int) -> str:
    if score >= 85: return "KNOWN_BAD"
    if score >= 60: return "MALICIOUS"
    if score >= 30: return "SUSPICIOUS"
    return "CLEAN"

# Rule name → tag
RULE_TAG_MAP = {
    "ssh_brute_force":            "brute_force",
    "ssh_brute_force_slow":       "brute_force",
    "web_scanner":                "web_scan",
    "nginx_web_scanner":          "web_scan",
    "netwatch_port_scan":         "port_scan",
    "suricata_port_scan":         "port_scan",
    "suricata_web_attack":        "web_attack",
    "homeguard_unknown_device":   "unknown_device",
    "unknown_device_then_portscan": "recon",
    "repeated_sudo":              "privilege_escalation",
    "syslog_system_critical":     "system_critical",
}

# RFC1918 / loopback — skip geo for these
_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "::1",
)

def is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def update_after_alert(db: Database, ip: str, rule_name: str, severity: str):
    """Call this after every alert fires for an IP."""
    if not ip:
        return
    delta = SEVERITY_DELTA.get(severity, 5)
    tag   = RULE_TAG_MAP.get(rule_name)
    db.update_reputation(ip, delta, tag)


def get_reputation_context(db: Database, ip: str) -> dict:
    """
    Return reputation context for an IP.
    Used by the correlation engine and dashboard.
    """
    if not ip:
        return {"score": 0, "label": "CLEAN", "alert_count": 0, "tags": []}

    rec = db.get_reputation(ip)
    if not rec:
        return {"score": 0, "label": "CLEAN", "alert_count": 0, "tags": [], "ip": ip}

    import json
    score = rec["score"]
    tags  = json.loads(rec.get("tags", "[]"))
    return {
        "ip":          ip,
        "score":       score,
        "label":       score_label(score),
        "alert_count": rec["alert_count"],
        "tags":        tags,
        "first_seen":  rec.get("first_seen"),
        "last_seen":   rec.get("last_seen"),
    }


def get_top_offenders(db: Database, limit: int = 10) -> list[dict]:
    import json
    rows = db.get_top_offenders(limit)
    result = []
    for r in rows:
        r["tags"]  = json.loads(r.get("tags", "[]"))
        r["label"] = score_label(r["score"])
        result.append(r)
    return result
