# 🛡 SentinelCore — Lightweight SIEM

A lightweight Security Information and Event Management (SIEM) system built in Python on Kali Linux.  
Centralizes logs from multiple sources, normalizes events into a unified schema, correlates patterns using configurable rules, and surfaces alerts in a real-time Flask dashboard.

Third project in a cybersecurity portfolio: **NetWatch → HomeGuard → SentinelCore**.

---

## Features

- **Multi-source ingestion** — 6 sources: `auth.log`, syslog, Apache, Nginx, Suricata EVE JSON, NetWatch/HomeGuard JSON
- **Event normalization** — all sources mapped to a unified `NormalizedEvent` schema with ISO-8601 timestamps
- **Correlation engine** — YAML-configurable rules with time-window thresholds and severity escalation
- **Cross-source detection** — correlates events across tools (e.g. unknown device + port scan = CRITICAL)
- **IP reputation scoring** — tracks repeat offenders with a 0–100 score and SUSPICIOUS/MALICIOUS/KNOWN_BAD labels
- **Geo-lookup** — external IP enrichment via ip-api.com with SQLite cache
- **Rule chaining** — alert A triggers evaluation of rule B for the same IP
- **SQLite storage** — persistent event, alert, reputation, and geo cache tables with indexed queries
- **Live Flask dashboard** — real-time view of events, alerts by severity, sources, and ACK controls
- **REST API** — Bearer token authenticated `/api/v1/` endpoints
- **Desktop/email notifications** — configurable alerts on HIGH+ severity events
- **Docker** — `Dockerfile` + `docker-compose.yml` with dashboard and watcher services
- **74 unit tests** — pytest suite covering DB, normalizer, parsers, correlation engine, reputation, geo, and API

---

## Stack

| Tool | Purpose |
|---|---|
| Python 3.13 | Core language |
| SQLite | Event, alert, reputation, and geo cache storage |
| Flask | Web dashboard + REST API |
| PyYAML | Rule and config file parsing |
| requests | Geo-lookup via ip-api.com |
| watchdog | File watcher for continuous ingestion |
| pytest | Unit testing (74/74 passing) |
| Docker | Container deployment |

---

## Project Structure
sentinelcore/
├── ingestion/
│   ├── normalizer.py        # Validated event factory + timestamp normalization
│   ├── auth_parser.py       # Linux auth.log (SSH failures, sudo, useradd)
│   ├── apache_parser.py     # Apache access logs (web scans, errors)
│   ├── nginx_parser.py      # Nginx access logs
│   ├── syslog_parser.py     # /var/log/syslog (services, OOM, disk errors)
│   ├── suricata_parser.py   # Suricata EVE JSON alerts
│   ├── json_importer.py     # NetWatch + HomeGuard JSON alert files
│   └── watcher.py           # Continuous file watcher (watchdog)
├── correlation/
│   ├── engine.py            # Rule evaluation engine (single + cross-source + chaining)
│   ├── rules.yaml           # 12 configurable detection rules + 4 chains
│   ├── reputation.py        # IP reputation scoring (0–100)
│   ├── geo.py               # Geo-lookup with SQLite cache
│   └── chainer.py           # Rule chaining engine
├── storage/
│   └── db.py                # SQLite handler + NormalizedEvent schema
├── dashboard/
│   ├── app.py               # Flask API server + REST API v1
│   └── templates/
│       └── index.html       # Live web UI
├── notifications/
│   └── notifier.py          # Desktop (notify-send) + email (SMTP) notifications
├── docker/
│   ├── Dockerfile           # Python 3.13-slim image
│   └── docker-compose.yml   # Dashboard + watcher services
├── sample_logs/             # Test log files (auth, syslog, nginx, suricata)
├── tests/
│   ├── test_sentinelcore.py # 24 core tests (DB, normalizer, parsers, correlation)
│   ├── test_v1_1.py         # 21 tests (syslog, suricata, nginx parsers)
│   ├── test_v1_2.py         # 15 tests (reputation, geo, chaining)
│   └── test_v1_3.py         # 14 tests (config, REST API auth, notifications)
├── config.yaml              # Central configuration file
├── config.py                # Typed config loader
├── requirements.txt         # Python dependencies
├── logs/                    # Auto-generated SQLite DB
└── ingest.py                # CLI entry point
---

## Detection Rules

| Rule | Trigger | Severity |
|---|---|---|
| `ssh_brute_force` | 5+ failed SSH logins from same IP in 60s | HIGH |
| `ssh_brute_force_slow` | 20+ failed logins in 10 min | HIGH |
| `web_scanner` | 20+ 404 errors from same IP in 2 min (Apache) | HIGH |
| `repeated_sudo` | 3+ sudo commands by same user in 5 min | MEDIUM |
| `netwatch_port_scan` | Port scan detected by NetWatch | HIGH |
| `suricata_port_scan` | Port scan detected by Suricata IDS | HIGH |
| `suricata_web_attack` | Web application attack detected by Suricata | HIGH |
| `nginx_web_scanner` | 20+ 404 errors from same IP on Nginx in 2 min | HIGH |
| `homeguard_unknown_device` | Unknown device detected by HomeGuard | HIGH |
| `syslog_service_failure` | Critical service failure in syslog | HIGH |
| `syslog_system_critical` | OOM / disk I/O error in syslog | CRITICAL |
| `unknown_device_then_portscan` | Unknown device + port scan from same IP *(cross-source)* | **CRITICAL** |

Plus 4 rule chains (e.g. SSH brute force + port scan from same IP → CRITICAL escalation).

Rules and chains are fully configurable in `correlation/rules.yaml`.

---

## Setup

```bash
git clone https://github.com/jrparra2023/sentinelcore
cd sentinelcore
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

> Developed and tested on Kali Linux (Python 3.13).

---

## Usage

### Ingest all sample logs and correlate
```bash
python3 ingest.py --all-samples
```

### Ingest specific sources
```bash
python3 ingest.py --auth /var/log/auth.log
python3 ingest.py --syslog /var/log/syslog
python3 ingest.py --nginx /var/log/nginx/access.log
python3 ingest.py --suricata /var/log/suricata/eve.json
python3 ingest.py --netwatch ~/netwatch/logs/alerts.json
python3 ingest.py --homeguard ~/homeguard/logs/alerts.json
```

### Continuous ingestion (file watcher)
```bash
python3 ingestion/watcher.py --auth /var/log/auth.log --syslog /var/log/syslog --interval 30
```

### Launch dashboard
```bash
python3 dashboard/app.py
# Open http://127.0.0.1:5000
```

### REST API (requires Bearer token from config.yaml)
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" http://127.0.0.1:5000/api/v1/stats
curl -H "Authorization: Bearer YOUR_TOKEN" http://127.0.0.1:5000/api/v1/alerts
curl -H "Authorization: Bearer YOUR_TOKEN" http://127.0.0.1:5000/api/v1/reputation/top
```

### Run tests
```bash
python3 -m pytest tests/ -v
```

### Docker
```bash
cd docker
docker-compose up --build
```

---

## Dashboard

Real-time web UI with auto-refresh (30s) showing:
- Total events ingested and active alert count
- Events by source with bar visualization
- Alerts by severity (CRITICAL / HIGH / MEDIUM / LOW)
- Full alert list with ACK controls
- Event log timeline with source tags and IP attribution

---

## Integration with NetWatch and HomeGuard

SentinelCore centralizes output from the two preceding portfolio projects:

- **[NetWatch](https://github.com/jrparra2023/netwatch)** — real-time network traffic analyzer with port scan and DNS anomaly detection
- **[HomeGuard](https://github.com/jrparra2023/homeguard)** — home network device monitor with MAC whitelist intrusion detection

The `unknown_device_then_portscan` rule demonstrates cross-source correlation: if HomeGuard flags an unknown MAC and NetWatch detects a port scan from the same IP within 10 minutes, SentinelCore fires a **CRITICAL** alert — a pattern no single tool would catch.

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

### v1.1 — Extended Ingestion ✅
- [x] Syslog parser (`/var/log/syslog`)
- [x] Suricata EVE JSON importer
- [x] Nginx access log support
- [x] File watcher for continuous ingestion (watchdog)

### v1.2 — Smarter Correlation ✅
- [x] IP reputation scoring (repeat offender tracking)
- [x] Geo-lookup for external IPs
- [x] Alert deduplication improvements
- [x] Rule chaining (alert A triggers rule B)

### v1.3 — Production Ready ✅
- [x] Docker container
- [x] Config file (config.yaml) for paths and thresholds
- [x] Email / desktop notifications on CRITICAL alerts
- [x] REST API with token authentication

---

## Author

**José Rafael Parra Dugarte**  
Electronics & Telecommunications Engineering Student — Universidad del Cauca  
Researcher @ GRIAL Wireless Networks Research Group  
[LinkedIn](https://www.linkedin.com/in/josé-rafael-parra-dugarte) · [GitHub](https://github.com/jrparra2023)
