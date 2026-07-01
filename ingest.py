#!/usr/bin/env python3
"""
SentinelCore — ingest.py
CLI entry point: parse log sources → store → correlate → report

Usage
-----
# Ingest all sample logs and run correlation:
python3 ingest.py --all-samples

# Ingest specific sources:
python3 ingest.py --auth sample_logs/auth.log
python3 ingest.py --apache sample_logs/access.log
python3 ingest.py --netwatch sample_logs/netwatch_alerts.json
python3 ingest.py --homeguard sample_logs/homeguard_alerts.json

# Run correlation only (on already-ingested events):
python3 ingest.py --correlate
"""

import sys
import argparse
from pathlib import Path

# Make sure local modules resolve
sys.path.insert(0, str(Path(__file__).parent))

from storage.db import Database
from ingestion.auth_parser import ingest as ingest_auth
from ingestion.apache_parser import ingest as ingest_apache
from ingestion.json_importer import ingest_json
from correlation.engine import run_and_report


def main():
    parser = argparse.ArgumentParser(
        description="SentinelCore — ingest logs and correlate events"
    )
    parser.add_argument("--auth",      metavar="FILE", help="Path to auth.log")
    parser.add_argument("--apache",    metavar="FILE", help="Path to Apache access.log")
    parser.add_argument("--netwatch",  metavar="FILE", help="Path to NetWatch alerts JSON")
    parser.add_argument("--homeguard", metavar="FILE", help="Path to HomeGuard alerts JSON")
    parser.add_argument("--correlate", action="store_true", help="Run correlation engine only")
    parser.add_argument("--all-samples", action="store_true",
                        help="Ingest all files from sample_logs/ and correlate")
    parser.add_argument("--stats",     action="store_true", help="Print DB stats and exit")
    args = parser.parse_args()

    db = Database()
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
        auth_path  = sample_dir / "auth.log"
        nw_path    = sample_dir / "netwatch_alerts.json"
        hg_path    = sample_dir / "homeguard_alerts.json"

        if auth_path.exists():
            n = ingest_auth(auth_path, db)
            print(f"[+] auth.log         → {n} events")
            total += n
        if nw_path.exists():
            n = ingest_json(nw_path, "netwatch", db)
            print(f"[+] netwatch JSON    → {n} events")
            total += n
        if hg_path.exists():
            n = ingest_json(hg_path, "homeguard", db)
            print(f"[+] homeguard JSON   → {n} events")
            total += n

        print(f"\n[SentinelCore] {total} total events ingested.")
        run_and_report(db)
        return

    if args.auth:
        n = ingest_auth(args.auth, db)
        print(f"[+] {args.auth} → {n} events"); total += n
    if args.apache:
        n = ingest_apache(args.apache, db)
        print(f"[+] {args.apache} → {n} events"); total += n
    if args.netwatch:
        n = ingest_json(args.netwatch, "netwatch", db)
        print(f"[+] {args.netwatch} → {n} events"); total += n
    if args.homeguard:
        n = ingest_json(args.homeguard, "homeguard", db)
        print(f"[+] {args.homeguard} → {n} events"); total += n

    if total > 0:
        print(f"\n[SentinelCore] {total} events ingested.")

    if args.correlate or total > 0:
        run_and_report(db)
    elif not any([args.auth, args.apache, args.netwatch, args.homeguard]):
        parser.print_help()


if __name__ == "__main__":
    main()
