"""
SentinelCore — ingestion/watcher.py
Continuous file watcher: monitors log files for changes and
ingests new lines automatically, then runs the correlation engine.

Uses watchdog for filesystem events + tail-style byte offset tracking
so only NEW lines are ingested on each change (not the full file again).

Usage
-----
python3 ingestion/watcher.py                    # watch default paths
python3 ingestion/watcher.py --auth /var/log/auth.log --syslog /var/log/syslog
python3 ingestion/watcher.py --interval 10      # correlate every 10s
"""

import sys
import time
import argparse
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

from storage.db import Database
from ingestion.auth_parser    import parse_file as parse_auth
from ingestion.syslog_parser  import parse_file as parse_syslog
from ingestion.apache_parser  import parse_file as parse_apache
from ingestion.nginx_parser   import parse_file as parse_nginx
from ingestion.suricata_parser import parse_file as parse_suricata
from correlation.engine import run_all_rules


# ── Parser registry ───────────────────────────────────────────────────────────
PARSER_MAP = {
    "auth":     parse_auth,
    "syslog":   parse_syslog,
    "apache":   parse_apache,
    "nginx":    parse_nginx,
    "suricata": parse_suricata,
}


# ── Tail reader (only reads new bytes since last check) ───────────────────────
class TailReader:
    """Tracks file offset and yields only new lines on each read."""
    def __init__(self, path: Path):
        self.path   = path
        self.offset = path.stat().st_size if path.exists() else 0

    def read_new_lines(self) -> list[str]:
        if not self.path.exists():
            return []
        try:
            with open(self.path, "r", errors="replace") as f:
                f.seek(self.offset)
                new_lines  = f.readlines()
                self.offset = f.tell()
            return new_lines
        except OSError:
            return []


# ── Watchdog handler ──────────────────────────────────────────────────────────
class LogFileHandler(FileSystemEventHandler):
    def __init__(self, watched_files: dict, db: Database, lock: threading.Lock):
        """
        watched_files: {Path: (parser_type, TailReader)}
        """
        self.watched_files = watched_files
        self.db            = db
        self.lock          = lock
        self._pending      = set()

    def on_modified(self, event):
        path = Path(event.src_path)
        if path in self.watched_files:
            self._pending.add(path)
            self._flush(path)

    def _flush(self, path: Path):
        parser_type, tail = self.watched_files[path]
        new_lines = tail.read_new_lines()
        if not new_lines:
            return

        parse_fn = PARSER_MAP.get(parser_type)
        if not parse_fn:
            return

        # Write new lines to a temp string and parse
        import io
        buf    = io.StringIO("".join(new_lines))
        events = []
        for line in buf:
            from ingestion.auth_parser    import parse_line as auth_line
            from ingestion.syslog_parser  import parse_line as sys_line
            from ingestion.apache_parser  import parse_line as apache_line
            from ingestion.nginx_parser   import parse_line as nginx_line
            from ingestion.suricata_parser import parse_line as suricata_line

            line_parsers = {
                "auth":     auth_line,
                "syslog":   sys_line,
                "apache":   apache_line,
                "nginx":    nginx_line,
                "suricata": suricata_line,
            }
            parsed = line_parsers[parser_type](line)
            if parsed:
                events.append(parsed)

        if events:
            with self.lock:
                self.db.insert_events(events)
            print(f"[Watcher] {path.name} → {len(events)} new event(s) ingested")


# ── Periodic correlation ──────────────────────────────────────────────────────
def _correlate_loop(db: Database, lock: threading.Lock, interval: int):
    while True:
        time.sleep(interval)
        with lock:
            fired = run_all_rules(db)
        if fired:
            print(f"[Watcher] Correlation — {len(fired)} alert(s) fired")


# ── Polling fallback (when watchdog not available) ────────────────────────────
def _polling_loop(watched_files: dict, db: Database, poll_interval: int, correlate_interval: int):
    """Simple mtime-based polling fallback."""
    mtimes = {p: p.stat().st_mtime if p.exists() else 0 for p in watched_files}
    last_correlate = time.time()
    lock = threading.Lock()

    print(f"[Watcher] Polling mode (watchdog not installed) — checking every {poll_interval}s")

    while True:
        time.sleep(poll_interval)
        for path, (parser_type, tail) in watched_files.items():
            if not path.exists():
                continue
            mtime = path.stat().st_mtime
            if mtime > mtimes[path]:
                mtimes[path] = mtime
                new_lines = tail.read_new_lines()
                if new_lines:
                    from ingestion.auth_parser    import parse_line as auth_line
                    from ingestion.syslog_parser  import parse_line as sys_line
                    from ingestion.apache_parser  import parse_line as apache_line
                    from ingestion.nginx_parser   import parse_line as nginx_line
                    from ingestion.suricata_parser import parse_line as suricata_line
                    line_parsers = {
                        "auth": auth_line, "syslog": sys_line,
                        "apache": apache_line, "nginx": nginx_line,
                        "suricata": suricata_line,
                    }
                    parse_fn = line_parsers.get(parser_type)
                    events = [e for l in new_lines if (e := parse_fn(l))]
                    if events:
                        with lock:
                            db.insert_events(events)
                        print(f"[Watcher] {path.name} → {len(events)} new event(s)")

        if time.time() - last_correlate >= correlate_interval:
            with lock:
                fired = run_all_rules(db)
            if fired:
                print(f"[Watcher] Correlation — {len(fired)} alert(s) fired")
            last_correlate = time.time()


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="SentinelCore — continuous log watcher")
    parser.add_argument("--auth",      metavar="FILE", help="auth.log path")
    parser.add_argument("--syslog",    metavar="FILE", help="syslog path")
    parser.add_argument("--apache",    metavar="FILE", help="Apache access.log path")
    parser.add_argument("--nginx",     metavar="FILE", help="Nginx access.log path")
    parser.add_argument("--suricata",  metavar="FILE", help="Suricata eve.json path")
    parser.add_argument("--interval",  type=int, default=30,
                        help="Correlation interval in seconds (default: 30)")
    parser.add_argument("--poll",      type=int, default=5,
                        help="Poll interval in seconds for fallback mode (default: 5)")
    args = parser.parse_args()

    db = Database()

    # Build watched_files dict: {Path → (type, TailReader)}
    source_args = {
        "auth":     args.auth,
        "syslog":   args.syslog,
        "apache":   args.apache,
        "nginx":    args.nginx,
        "suricata": args.suricata,
    }

    watched_files = {}
    for ptype, fpath in source_args.items():
        if fpath:
            p = Path(fpath)
            watched_files[p] = (ptype, TailReader(p))
            print(f"[Watcher] Watching: {p} [{ptype}]")

    if not watched_files:
        print("[Watcher] No files specified. Use --auth, --syslog, --apache, --nginx, --suricata")
        parser.print_help()
        return

    print(f"[Watcher] Correlation every {args.interval}s")

    if WATCHDOG_AVAILABLE:
        print("[Watcher] Using watchdog (filesystem events)")
        lock    = threading.Lock()
        handler = LogFileHandler(watched_files, db, lock)
        observer = Observer()

        # Watch the parent directories of all files
        watched_dirs = set(p.parent for p in watched_files)
        for d in watched_dirs:
            observer.schedule(handler, str(d), recursive=False)

        observer.start()

        # Correlation in background thread
        corr_thread = threading.Thread(
            target=_correlate_loop, args=(db, lock, args.interval), daemon=True
        )
        corr_thread.start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[Watcher] Stopping...")
            observer.stop()
        observer.join()

    else:
        # Polling fallback
        _polling_loop(watched_files, db, args.poll, args.interval)


if __name__ == "__main__":
    main()
