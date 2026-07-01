"""
SentinelCore — correlation/engine.py
Evaluates rules.yaml against the events DB and fires alerts.

Design
------
After each ingestion batch, call `run_all_rules(db)`.
The engine looks back `window_secs` for each rule, groups events
by the specified field, and fires an alert when the threshold is met.

For multi-condition rules (cross-source, like unknown_device_then_portscan),
ALL conditions must match the SAME group_by value (e.g. same src_ip).
"""

import yaml
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
from storage.db import Database

RULES_PATH = Path(__file__).parent / "rules.yaml"


def _load_rules() -> list[dict]:
    with open(RULES_PATH) as f:
        data = yaml.safe_load(f)
    return [r for r in data.get("rules", []) if r.get("enabled", True)]


def _window_start(window_secs: int) -> str:
    """ISO-8601 timestamp for `window_secs` ago."""
    return (datetime.now() - timedelta(seconds=window_secs)).isoformat(timespec="seconds")


def _get_groups(db: Database, condition: dict, since: str) -> dict[str, list[int]]:
    """
    Query events matching a condition and group IDs by group_by field.
    Returns {group_value: [event_id, ...]}
    """
    events = db.get_events(
        since=since,
        event_type=condition.get("event_type"),
        source=condition.get("source"),
        limit=10000,
    )
    group_by = condition.get("group_by", "src_ip")
    groups: dict[str, list[int]] = defaultdict(list)
    for e in events:
        key = e.get(group_by)
        if key:
            groups[key].append(e["id"])
    return groups


def _already_alerted(db: Database, rule_name: str, group_value: str, since: str) -> bool:
    """
    Avoid duplicate alerts: check if this rule already fired for this
    group_value in the look-back window.
    """
    alerts = db.get_alerts(limit=500)
    for a in alerts:
        if (
            a["rule_name"] == rule_name
            and (a.get("src_ip") == group_value or a.get("user") == group_value)
            and a["created_at"] >= since
        ):
            return True
    return False


def run_all_rules(db: Database) -> list[dict]:
    """
    Evaluate all enabled rules against the DB.
    Returns list of newly created alert dicts.
    """
    rules  = _load_rules()
    fired: list[dict] = []

    for rule in rules:
        name        = rule["name"]
        severity    = rule["severity"]
        description = rule["description"]
        window_secs = rule.get("window_secs", 300)
        threshold   = rule.get("threshold", 1)
        conditions  = rule.get("conditions", [])
        since       = _window_start(window_secs)

        if not conditions:
            continue

        if len(conditions) == 1:
            # ── Single-condition rule ─────────────────────────────────────────
            cond   = conditions[0]
            groups = _get_groups(db, cond, since)

            for group_val, event_ids in groups.items():
                if len(event_ids) < threshold:
                    continue
                if _already_alerted(db, name, group_val, since):
                    continue

                group_by = cond.get("group_by", "src_ip")
                alert_id = db.insert_alert(
                    rule_name=name,
                    severity=severity,
                    description=f"{description} [{group_by}={group_val}, count={len(event_ids)}]",
                    event_ids=event_ids[:50],  # cap stored IDs
                    src_ip=group_val if group_by == "src_ip" else None,
                    user=group_val   if group_by == "user"   else None,
                )
                alert = {
                    "alert_id": alert_id,
                    "rule": name,
                    "severity": severity,
                    "group_by": group_by,
                    "group_value": group_val,
                    "event_count": len(event_ids),
                }
                fired.append(alert)
                print(f"[ALERT] [{severity}] {name} — {group_by}={group_val} ({len(event_ids)} events)")

        else:
            # ── Multi-condition rule (cross-source) ───────────────────────────
            # All conditions must match the SAME group_by value
            condition_groups: list[dict[str, list[int]]] = []
            for cond in conditions:
                condition_groups.append(_get_groups(db, cond, since))

            # Intersect group keys across all conditions
            common_keys = set(condition_groups[0].keys())
            for g in condition_groups[1:]:
                common_keys &= set(g.keys())

            for group_val in common_keys:
                all_event_ids = []
                for g in condition_groups:
                    all_event_ids.extend(g[group_val])

                if _already_alerted(db, name, group_val, since):
                    continue

                # For multi-condition, each condition needs at least 1 match
                meets_threshold = all(
                    len(g.get(group_val, [])) >= 1 for g in condition_groups
                )
                if not meets_threshold:
                    continue

                alert_id = db.insert_alert(
                    rule_name=name,
                    severity=severity,
                    description=f"[CROSS-SOURCE] {description} [src_ip={group_val}]",
                    event_ids=all_event_ids[:50],
                    src_ip=group_val,
                )
                alert = {
                    "alert_id": alert_id,
                    "rule": name,
                    "severity": severity,
                    "group_by": "src_ip",
                    "group_value": group_val,
                    "event_count": len(all_event_ids),
                    "cross_source": True,
                }
                fired.append(alert)
                print(f"[ALERT] [{severity}] {name} — CROSS-SOURCE src_ip={group_val}")

    return fired


def run_and_report(db: Database):
    """Run all rules and print a summary."""
    fired = run_all_rules(db)
    print(f"\n[SentinelCore] Correlation complete — {len(fired)} alert(s) fired.")
    return fired
