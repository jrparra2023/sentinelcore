# 🛡 SentinelCore — Lightweight SIEM

A lightweight Security Information and Event Management (SIEM) system built in Python on Kali Linux.  
Centralizes logs from multiple sources, normalizes events into a unified schema, correlates patterns using configurable rules, and surfaces alerts in a real-time Flask dashboard.

Third project in a cybersecurity portfolio: **NetWatch → HomeGuard → SentinelCore**.

---

## Features

- **Multi-source ingestion** — Linux `auth.log`, Apache access logs, NetWatch alerts, HomeGuard alerts
- **Event normalization** — all sources mapped to a unified `NormalizedEvent` schema with ISO-8601 timestamps
- **Correlation engine** — YAML-configurable rules with time-window thresholds and severity escalation
- **Cross-source detection** — correlates events across tools (e.g. unknown device + port scan = CRITICAL)
- **SQLite storage** — persistent event and alert log with indexed queries
- **Live Flask dashboard** — real-time view of events, alerts by severity, sources, and ACK controls
- **24 unit tests** — pytest suite covering DB, normalizer, parsers, and correlation engine

---

## Stack

| Tool | Purpose |
|---|---|
| Python 3.13 | Core language |
| SQLite | Event and alert storage |
| Flask | Web dashboard |
| PyYAML | Rule configuration |
| pytest | Unit testing |

---

## Project Structure

```
sentinelcore/
├── ingestion/
│   ├── normalizer.py        # Validated event factory + timestamp normalization
│   ├── auth_parser.py       # Linux auth.log (SSH failures, sudo, useradd)
│   ├── apache_parser.py     # Apache/Nginx access logs (web scans, errors)
│   └── json_importer.py     # NetWatch + HomeGuard JSON alert files
├── correlation/
│   ├── engine.py            # Rule evaluation engine (single + cross-source)
│   └── rules.yaml           # Configurable detection rules
├── storage/
│   └── db.py                # SQLite handler + NormalizedEvent schema
├── dashboard/
│   ├── app.py               # Flask API server
│   └── templates/
│       └── index.html       # Live web UI
├── sample_logs/             # Test log files
├── tests/
│   └── test_sentinelcore.py # 24 unit tests
├── logs/                    # Auto-generated SQLite DB
└── ingest.py                # CLI entry point
```

---

## Detection Rules

| Rule | Trigger | Severity |
|---|---|---|
| `ssh_brute_force` | 5+ failed SSH logins from same IP in 60s | HIGH |
| `ssh_brute_force_slow` | 20+ failed logins in 10 min | HIGH |
| `web_scanner` | 20+ 404 errors from same IP in 2 min | HIGH |
| `repeated_sudo` | 3+ sudo commands by same user in 5 min | MEDIUM |
| `netwatch_port_scan` | Port scan detected by NetWatch | HIGH |
| `homeguard_unknown_device` | Unknown device detected by HomeGuard | HIGH |
| `unknown_device_then_portscan` | Unknown device + port scan from same IP *(cross-source)* | **CRITICAL** |

Rules are fully configurable in `correlation/rules.yaml` — adjust thresholds, windows, and severity without touching code.

---

## Setup

```bash
git clone https://github.com/jrparra2023/sentinelcore
cd sentinelcore
python3 -m venv venv
source venv/bin/activate
pip install flask pyyaml pytest
```

> Developed and tested on Kali Linux (Python 3.13). Requires bridged adapter mode in VirtualBox to ingest from a real LAN.

---

## Usage

### Ingest sample logs and correlate
```bash
python3 ingest.py --all-samples
```

### Ingest specific sources
```bash
# Linux auth log
python3 ingest.py --auth /var/log/auth.log

# Apache access log
python3 ingest.py --apache /var/log/apache2/access.log

# NetWatch alerts (github.com/jrparra2023/netwatch)
python3 ingest.py --netwatch ~/netwatch/logs/alerts.json

# HomeGuard alerts (github.com/jrparra2023/homeguard)
python3 ingest.py --homeguard ~/homeguard/logs/alerts.json
```

### Run correlation only
```bash
python3 ingest.py --correlate
```

### View DB stats
```bash
python3 ingest.py --stats
```

### Launch dashboard
```bash
python3 dashboard/app.py
# Open http://127.0.0.1:5000
```

### Run tests
```bash
python3 -m pytest tests/ -v
```

---

## Dashboard

Real-time web UI with auto-refresh (30s) showing:
- Total events ingested and active alert count
- Events by source (auth_log, netwatch, homeguard, apache)
- Alerts by severity (CRITICAL / HIGH / MEDIUM / LOW)
- Full alert list with ACK controls
- Event log timeline with source tags and IP attribution

---

## Integration with NetWatch and HomeGuard

SentinelCore is designed to centralize output from the two preceding portfolio projects:

- **[NetWatch](https://github.com/jrparra2023/netwatch)** — real-time network traffic analyzer with port scan and DNS anomaly detection
- **[HomeGuard](https://github.com/jrparra2023/homeguard)** — home network device monitor with MAC whitelist intrusion detection

The `unknown_device_then_portscan` rule demonstrates cross-source correlation: if HomeGuard flags an unknown MAC and NetWatch detects a port scan from the same IP within 10 minutes, SentinelCore fires a **CRITICAL** alert — a pattern a standalone tool would miss.

---

## Roadmap

### v1.0 — Core Pipeline ✅
- [x] Multi-source ingestion (auth.log, Apache, NetWatch, HomeGuard)
- [x] Unified event normalization schema
- [x] SQLite storage with indexed queries
- [x] YAML-driven correlation engine with 7 rules
- [x] Cross-source CRITICAL detection
- [x] Flask live dashboard with ACK controls
- [x] 24 unit tests (pytest)

### v1.1 — Extended Ingestion 🔜
- [ ] Syslog parser (`/var/log/syslog`)
- [ ] Suricata EVE JSON importer
- [ ] Nginx access log support
- [ ] File watcher for continuous ingestion (watchdog)

### v1.2 — Smarter Correlation 🔜
- [ ] IP reputation scoring (repeat offender tracking)
- [ ] Geo-lookup for external IPs
- [ ] Alert deduplication improvements
- [ ] Rule chaining (alert A triggers rule B)

### v1.3 — Production Ready 🔜
- [ ] Docker container
- [ ] Config file (config.yaml) for paths and thresholds
- [ ] Email / desktop notifications on CRITICAL alerts
- [ ] REST API with token authentication

---

## Author

**José Rafael Parra Dugarte**  
Electronics & Telecommunications Engineering — Universidad del Cauca  
Researcher @ GRIAL Wireless Networks Research Group  
[LinkedIn](https://www.linkedin.com/in/josé-rafael-parra-dugarte) · [GitHub](https://github.com/jrparra2023)
