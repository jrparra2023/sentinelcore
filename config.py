"""
SentinelCore — config.py
Loads and validates config.yaml. Provides a singleton Config object
accessible from anywhere in the project.

Usage
-----
from config import cfg

port     = cfg.dashboard.port
token    = cfg.dashboard.api_token
db_path  = cfg.database.path
"""

import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

CONFIG_PATH = Path(__file__).parent / "config.yaml"


@dataclass
class DatabaseConfig:
    path: str = "logs/sentinelcore.db"


@dataclass
class SourcesConfig:
    auth_log:  str = "/var/log/auth.log"
    syslog:    str = "/var/log/syslog"
    apache:    str = "/var/log/apache2/access.log"
    nginx:     str = "/var/log/nginx/access.log"
    suricata:  str = "/var/log/suricata/eve.json"
    netwatch:  str = ""
    homeguard: str = ""


@dataclass
class WatcherConfig:
    poll_interval_secs:    int = 5
    correlate_every_secs:  int = 30


@dataclass
class DashboardConfig:
    host:         str  = "127.0.0.1"
    port:         int  = 5000
    api_token:    str  = "CHANGE_ME"
    require_auth: bool = True


@dataclass
class DesktopNotifConfig:
    enabled: bool = True


@dataclass
class EmailNotifConfig:
    enabled:       bool = False
    smtp_host:     str  = "smtp.gmail.com"
    smtp_port:     int  = 587
    smtp_user:     str  = ""
    smtp_password: str  = ""
    from_addr:     str  = ""
    to_addr:       str  = ""


@dataclass
class NotificationsConfig:
    min_severity: str                   = "HIGH"
    desktop:      DesktopNotifConfig    = field(default_factory=DesktopNotifConfig)
    email:        EmailNotifConfig      = field(default_factory=EmailNotifConfig)


@dataclass
class GeoConfig:
    enabled:       bool = True
    cache_ttl_days: int = 7
    timeout_secs:   int = 3


@dataclass
class ReputationConfig:
    enabled:              bool = True
    suspicious_threshold: int  = 30
    malicious_threshold:  int  = 60
    known_bad_threshold:  int  = 85


@dataclass
class SentinelConfig:
    database:      DatabaseConfig      = field(default_factory=DatabaseConfig)
    sources:       SourcesConfig       = field(default_factory=SourcesConfig)
    watcher:       WatcherConfig       = field(default_factory=WatcherConfig)
    dashboard:     DashboardConfig     = field(default_factory=DashboardConfig)
    notifications: NotificationsConfig = field(default_factory=NotificationsConfig)
    geo:           GeoConfig           = field(default_factory=GeoConfig)
    reputation:    ReputationConfig    = field(default_factory=ReputationConfig)


def _deep_update(base: dict, override: dict) -> dict:
    """Merge override into base recursively."""
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_update(base[k], v)
        else:
            base[k] = v
    return base


def load_config(path: Path = CONFIG_PATH) -> SentinelConfig:
    """Load config.yaml and return a SentinelConfig object."""
    if not path.exists():
        return SentinelConfig()

    with open(path) as f:
        raw = yaml.safe_load(f) or {}

    db_raw    = raw.get("database", {})
    src_raw   = raw.get("sources", {})
    watch_raw = raw.get("watcher", {})
    dash_raw  = raw.get("dashboard", {})
    notif_raw = raw.get("notifications", {})
    geo_raw   = raw.get("geo", {})
    rep_raw   = raw.get("reputation", {})

    desktop_raw = notif_raw.pop("desktop", {})
    email_raw   = notif_raw.pop("email", {})

    return SentinelConfig(
        database=DatabaseConfig(**{
            k: v for k, v in db_raw.items()
            if k in DatabaseConfig.__dataclass_fields__
        }),
        sources=SourcesConfig(**{
            k: v for k, v in src_raw.items()
            if k in SourcesConfig.__dataclass_fields__
        }),
        watcher=WatcherConfig(**{
            k: v for k, v in watch_raw.items()
            if k in WatcherConfig.__dataclass_fields__
        }),
        dashboard=DashboardConfig(**{
            k: v for k, v in dash_raw.items()
            if k in DashboardConfig.__dataclass_fields__
        }),
        notifications=NotificationsConfig(
            min_severity=notif_raw.get("min_severity", "HIGH"),
            desktop=DesktopNotifConfig(**{
                k: v for k, v in desktop_raw.items()
                if k in DesktopNotifConfig.__dataclass_fields__
            }),
            email=EmailNotifConfig(**{
                k: v for k, v in email_raw.items()
                if k in EmailNotifConfig.__dataclass_fields__
            }),
        ),
        geo=GeoConfig(**{
            k: v for k, v in geo_raw.items()
            if k in GeoConfig.__dataclass_fields__
        }),
        reputation=ReputationConfig(**{
            k: v for k, v in rep_raw.items()
            if k in ReputationConfig.__dataclass_fields__
        }),
    )


# ── Singleton ─────────────────────────────────────────────────────────────────
cfg: SentinelConfig = load_config()
