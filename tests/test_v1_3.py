"""
SentinelCore — tests/test_v1_3.py
pytest suite for v1.3: config loader, REST API token auth,
notification dispatcher (12 tests).
"""

import sys
import json
import pytest
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import load_config, SentinelConfig


# ── Config loader tests ───────────────────────────────────────────────────────

class TestConfig:

    def test_default_config_loads(self):
        cfg = load_config()
        assert isinstance(cfg, SentinelConfig)
        assert cfg.dashboard.port == 5000
        assert cfg.notifications.min_severity == "HIGH"

    def test_config_from_yaml(self, tmp_path):
        yaml_content = """
database:
  path: "custom/path.db"
dashboard:
  port: 8080
  api_token: "mysecrettoken"
  require_auth: true
notifications:
  min_severity: "CRITICAL"
  desktop:
    enabled: false
  email:
    enabled: false
"""
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(yaml_content)
        cfg = load_config(cfg_file)
        assert cfg.database.path == "custom/path.db"
        assert cfg.dashboard.port == 8080
        assert cfg.dashboard.api_token == "mysecrettoken"
        assert cfg.notifications.min_severity == "CRITICAL"
        assert cfg.notifications.desktop.enabled is False

    def test_missing_config_uses_defaults(self, tmp_path):
        cfg = load_config(tmp_path / "nonexistent.yaml")
        assert cfg.dashboard.port == 5000
        assert cfg.dashboard.require_auth is True

    def test_geo_config(self, tmp_path):
        yaml_content = """
geo:
  enabled: false
  cache_ttl_days: 3
"""
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(yaml_content)
        cfg = load_config(cfg_file)
        assert cfg.geo.enabled is False
        assert cfg.geo.cache_ttl_days == 3

    def test_reputation_thresholds(self, tmp_path):
        yaml_content = """
reputation:
  suspicious_threshold: 20
  malicious_threshold: 50
  known_bad_threshold: 75
"""
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(yaml_content)
        cfg = load_config(cfg_file)
        assert cfg.reputation.suspicious_threshold == 20
        assert cfg.reputation.malicious_threshold == 50


# ── REST API auth tests ───────────────────────────────────────────────────────

class TestRestAPI:

    @pytest.fixture
    def client(self, tmp_path):
        """Flask test client with token auth enabled."""
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent))

        # Patch config before importing app
        import config as cfg_module
        from config import SentinelConfig, DashboardConfig, DatabaseConfig
        from pathlib import Path as P

        test_cfg = SentinelConfig()
        test_cfg.dashboard.api_token = "test-secret-token"
        test_cfg.dashboard.require_auth = True
        test_cfg.database.path = str(tmp_path / "test.db")
        cfg_module.cfg = test_cfg

        # Re-import app with patched config
        import importlib
        import dashboard.app as app_module
        importlib.reload(app_module)
        app_module.db = __import__('storage.db', fromlist=['Database']).Database(
            db_path=P(test_cfg.database.path)
        )
        app_module.app.config["TESTING"] = True
        return app_module.app.test_client()

    def test_api_requires_token(self, client):
        r = client.get("/api/v1/stats")
        assert r.status_code == 401

    def test_api_wrong_token_rejected(self, client):
        r = client.get("/api/v1/stats",
                       headers={"Authorization": "Bearer wrongtoken"})
        assert r.status_code == 403

    def test_api_valid_token_accepted(self, client):
        r = client.get("/api/v1/stats",
                       headers={"Authorization": "Bearer test-secret-token"})
        assert r.status_code == 200
        data = json.loads(r.data)
        assert "total_events" in data

    def test_api_alerts_endpoint(self, client):
        r = client.get("/api/v1/alerts",
                       headers={"Authorization": "Bearer test-secret-token"})
        assert r.status_code == 200

    def test_api_events_endpoint(self, client):
        r = client.get("/api/v1/events",
                       headers={"Authorization": "Bearer test-secret-token"})
        assert r.status_code == 200

    def test_legacy_endpoints_no_auth(self, client):
        """Legacy /api/* endpoints don't require auth (for dashboard UI)."""
        r = client.get("/api/stats")
        assert r.status_code == 200


# ── Notification dispatcher tests ─────────────────────────────────────────────

class TestNotifications:

    def _make_cfg(self, min_severity="HIGH", desktop=True, email=False):
        from config import (SentinelConfig, NotificationsConfig,
                            DesktopNotifConfig, EmailNotifConfig)
        cfg = SentinelConfig()
        cfg.notifications = NotificationsConfig(
            min_severity=min_severity,
            desktop=DesktopNotifConfig(enabled=desktop),
            email=EmailNotifConfig(enabled=email),
        )
        return cfg

    def test_low_alert_skipped_when_min_high(self):
        from notifications.notifier import notify_alert
        alert = {"severity": "LOW", "rule_name": "test", "description": "x", "src_ip": "1.2.3.4"}
        result = notify_alert(alert, self._make_cfg(min_severity="HIGH"))
        assert result["skipped"] is True

    def test_critical_meets_high_threshold(self):
        from notifications.notifier import _meets_threshold
        assert _meets_threshold("CRITICAL", "HIGH") is True
        assert _meets_threshold("HIGH", "HIGH") is True
        assert _meets_threshold("MEDIUM", "HIGH") is False

    def test_notify_batch_skips_below_threshold(self):
        from notifications.notifier import notify_batch
        alerts = [
            {"severity": "LOW",    "rule_name": "r1", "description": "d", "src_ip": "1.1.1.1"},
            {"severity": "MEDIUM", "rule_name": "r2", "description": "d", "src_ip": "1.1.1.1"},
        ]
        cfg = self._make_cfg(min_severity="HIGH", desktop=False)
        sent = notify_batch(alerts, cfg)
        assert sent == 0
