#!/usr/bin/env python3
"""
SentinelCore — ingest.py
CLI entry point: parse log sources → store → correlate → report

Usage
-----
python3 ingest.py --all-samples
python3 ingest.py --auth /var/log/auth.log
python3 ingest.py --syslog /var/log/syslog
python3 ingest.py --apache /var/log/apache2/access.log
python3 ingest.py --nginx /var/log/nginx/access.log
python3 ingest.py --suricata /var/log/suricata/eve.json
python3 ingest.py --netwatch ~/netwatch/logs/alerts.json
python3 ingest.py --homeguard ~/homeguard/logs/alerts.json
python3 ingest.py --correlate
python3 ingest.py --stats
"""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from storage.db import Database
from ingestion.auth_parser     import ingest as ingest_auth
from ingestion.apache_parser   import ingest as ingest_apache
from ingestion.syslog_parser   import ingest as ingest_syslog
from ingestion.nginx_parser    import ingest as ingest_nginx
from ingestion.suricata_parser import ingest as ingest_suricata
from ingestion.json_importer   import ingest_json
from correlation.engine import run_and_report


def main():
    parser = argparse.ArgumentParser(
        description="SentinelCore — ingest logs and correlate events"
    )
    parser.add_argument("--auth",      metavar="FILE", help="Path to auth.log")
    parser.add_argument("--syslog",    metavar="FILE", help="Path to syslog")
    parser.add_argument("--apache",    metavar="FILE", help="Path to Apache access.log")
    parser.add_argument("--nginx",     metavar="FILE", help="Path to Nginx access.log")
    parser.add_argument("--suricata",  metavar="FILE", help="Path to Suricata eve.json")
    parser.add_argument("--netwatch",  metavar="FILE", help="Path to NetWatch alerts JSON")
    parser.add_argument("--homeguard", metavar="FILE", help="Path to HomeGuard alerts JSON")
    parser.add_argument("--correlate", action="store_true", help="Run correlation engine only")
    parser.add_argument("--all-samples", action="store_true",
                        help="Ingest all files from sample_logs/ and correlate")
    parser.add_argument("--stats", action="store_true", help="Print DB stats and exit")
    args = parser.parse_args()

    db    = Database()
    total = 0

    if args.stats:
        stats = db.get_stats()
        print("\n── SentinelCore DB Stats ─────────────────────────")
        print(f"  Total events  : {stats['total_events']}")
        print(f"  Total alerts  : {stats['total_alerts']}")
        print(f"  Unacknowledged: {stats['unacknowledged_alerts']}")
        print(f"  By source     : {stats['events_by_source']}")
        print(f"  By severity   : {stats['alerts_by_severity']}")
        return

    if args.all_samples:
        sample_dir = Path(__file__).parent / "sample_logs"
        sources = [
            ("auth.log",            "auth",     ingest_auth),
            ("syslog",              "syslog",   ingest_syslog),
            ("nginx_access.log",    "nginx",    ingest_nginx),
            ("suricata_eve.json",   "suricata", ingest_suricata),
            ("netwatch_alerts.json","netwatch", None),
            ("homeguard_alerts.json","homeguard",None),
        ]
        for fname, label, fn in sources:
            p = sample_dir / fname
            if not p.exists():
                continue
            if fn:
                n = fn(p, db)
            else:
                n = ingest_json(p, label, db)
            print(f"[+] {fname:<30} → {n} events")
            total += n

        print(f"\n[SentinelCore] {total} total events ingested.")
        run_and_report(db)
        return

    ingests = [
        (args.auth,      ingest_auth,     "auth"),
        (args.syslog,    ingest_syslog,   "syslog"),
        (args.apache,    ingest_apache,   "apache"),
        (args.nginx,     ingest_nginx,    "nginx"),
        (args.suricata,  ingest_suricata, "suricata"),
        (args.netwatch,  None,            "netwatch"),
        (args.homeguard, None,            "homeguard"),
    ]

    for fpath, fn, label in ingests:
        if not fpath:
            continue
        n = fn(fpath, db) if fn else ingest_json(fpath, label, db)
        print(f"[+] {fpath} → {n} events")
        total += n

    if total > 0:
        print(f"\n[SentinelCore] {total} events ingested.")

    if args.correlate or total > 0:
        run_and_report(db)
    elif not any([args.auth, args.syslog, args.apache, args.nginx,
                  args.suricata, args.netwatch, args.homeguard]):
        parser.print_help()


if __name__ == "__main__":
    main()
