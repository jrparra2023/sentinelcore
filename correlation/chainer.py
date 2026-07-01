"""
SentinelCore — correlation/chainer.py
Rule chaining: when an alert fires, automatically evaluate
dependent rules for the same IP/user.

Chains are defined in rules.yaml under `chains`:

  chains:
    - trigger: ssh_brute_force
      then: escalate_brute_then_scan
      severity: CRITICAL
      description: "SSH brute force followed by port scan — active intrusion attempt"

The chainer runs AFTER the main correlation engine and checks
if any fired alerts match a chain trigger. If the `then` condition
also matches the same group_value, a chained alert fires.
"""

import yaml
from pathlib import Path
from datetime import datetime, timedelta
from storage.db import Database

RULES_PATH = Path(__file__).parent / "rules.yaml"


def _load_chains() -> list[dict]:
    with open(RULES_PATH) as f:
        data = yaml.safe_load(f)
    return data.get("chains", [])


def _window_start(window_secs: int) -> str:
    return (datetime.now() - timedelta(seconds=window_secs)).isoformat(timespec="seconds")


def run_chains(db: Database, fired_alerts: list[dict]) -> list[dict]:
    """
    Evaluate chain rules based on alerts that just fired.
    fired_alerts: list of alert dicts returned by run_all_rules()
    Returns list of new chained alerts.
    """
    chains  = _load_chains()
    chained = []

    if not chains or not fired_alerts:
        return chained

    # Index fired alerts by rule name
    fired_by_rule: dict[str, list[dict]] = {}
    for a in fired_alerts:
        fired_by_rule.setdefault(a["rule"], []).append(a)

    for chain in chains:
        trigger   = chain.get("trigger")
        then_rule = chain.get("then")
        severity  = chain.get("severity", "HIGH")
        desc      = chain.get("description", f"Chain: {trigger} → {then_rule}")
        window    = chain.get("window_secs", 600)

        if trigger not in fired_by_rule:
            continue

        # For each IP that triggered the source rule,
        # check if the `then` rule also has events for same IP
        for trigger_alert in fired_by_rule[trigger]:
            ip = trigger_alert.get("group_value")
            if not ip:
                continue

            # Check if `then` rule already fired for this IP
            then_fired = any(
                a["rule"] == then_rule and a.get("group_value") == ip
                for a in fired_alerts
            )

            # Also check DB for recent `then` alerts for this IP
            if not then_fired:
                since   = _window_start(window)
                db_alerts = db.get_alerts(limit=200)
                then_fired = any(
                    a["rule_name"] == then_rule
                    and a.get("src_ip") == ip
                    and a["created_at"] >= since
                    for a in db_alerts
                )

            if not then_fired:
                continue

            # Avoid duplicate chained alerts
            since = _window_start(window)
            chain_name = f"chain_{trigger}_then_{then_rule}"
            already = any(
                a["rule_name"] == chain_name
                and a.get("src_ip") == ip
                and a["created_at"] >= since
                for a in db.get_alerts(limit=200)
            )
            if already:
                continue

            alert_id = db.insert_alert(
                rule_name=chain_name,
                severity=severity,
                description=f"[CHAIN] {desc} [src_ip={ip}]",
                event_ids=[],
                src_ip=ip,
            )
            chained_alert = {
                "alert_id":   alert_id,
                "rule":       chain_name,
                "severity":   severity,
                "group_by":   "src_ip",
                "group_value": ip,
                "chained":    True,
            }
            chained.append(chained_alert)
            print(f"[CHAIN] [{severity}] {chain_name} — src_ip={ip}")

    return chained
