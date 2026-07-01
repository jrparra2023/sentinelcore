"""
SentinelCore — dashboard/app.py
Flask web dashboard + REST API with token authentication.

REST API endpoints (require Authorization: Bearer <token>):
  GET  /api/v1/stats
  GET  /api/v1/events?source=&event_type=&src_ip=&limit=
  GET  /api/v1/alerts?unacked=true&limit=
  POST /api/v1/alerts/<id>/acknowledge
  GET  /api/v1/reputation/top
  GET  /api/v1/reputation/<ip>

Web UI (no auth):
  GET  /
"""

import sys
from pathlib import Path
from functools import wraps
sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask, render_template, jsonify, request, abort
from storage.db import Database
from config import cfg

app = Flask(__name__)
db  = Database(db_path=Path(cfg.database.path))


# ── Auth decorator ────────────────────────────────────────────────────────────

def require_token(f):
    """Protect REST API endpoints with Bearer token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not cfg.dashboard.require_auth:
            return f(*args, **kwargs)
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            abort(401, "Missing Authorization header")
        token = auth.split(" ", 1)[1].strip()
        if token != cfg.dashboard.api_token:
            abort(403, "Invalid token")
        return f(*args, **kwargs)
    return decorated


# ── Web UI ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ── REST API v1 ───────────────────────────────────────────────────────────────

@app.route("/api/v1/stats")
@require_token
def api_stats():
    return jsonify(db.get_stats())


@app.route("/api/v1/events")
@require_token
def api_events():
    events = db.get_events(
        source=request.args.get("source"),
        event_type=request.args.get("event_type"),
        src_ip=request.args.get("src_ip"),
        limit=int(request.args.get("limit", 100)),
    )
    return jsonify(events)


@app.route("/api/v1/alerts")
@require_token
def api_alerts():
    unacked = request.args.get("unacked", "false").lower() == "true"
    alerts  = db.get_alerts(
        limit=int(request.args.get("limit", 200)),
        unacked_only=unacked,
    )
    return jsonify(alerts)


@app.route("/api/v1/alerts/<int:alert_id>/acknowledge", methods=["POST"])
@require_token
def api_acknowledge(alert_id):
    db.acknowledge_alert(alert_id)
    return jsonify({"status": "ok", "alert_id": alert_id})


@app.route("/api/v1/reputation/top")
@require_token
def api_reputation_top():
    from correlation.reputation import get_top_offenders
    limit     = int(request.args.get("limit", 10))
    offenders = get_top_offenders(db, limit=limit)
    return jsonify(offenders)


@app.route("/api/v1/reputation/<ip>")
@require_token
def api_reputation_ip(ip):
    from correlation.reputation import get_reputation_context
    return jsonify(get_reputation_context(db, ip))


# ── Legacy endpoints (no auth — for dashboard UI) ─────────────────────────────

@app.route("/api/stats")
def api_stats_legacy():
    return jsonify(db.get_stats())


@app.route("/api/alerts")
def api_alerts_legacy():
    unacked = request.args.get("unacked", "false").lower() == "true"
    return jsonify(db.get_alerts(limit=200, unacked_only=unacked))


@app.route("/api/events")
def api_events_legacy():
    return jsonify(db.get_events(
        source=request.args.get("source"),
        event_type=request.args.get("event_type"),
        src_ip=request.args.get("src_ip"),
        limit=int(request.args.get("limit", 100)),
    ))


@app.route("/api/alerts/<int:alert_id>/acknowledge", methods=["POST"])
def api_acknowledge_legacy(alert_id):
    db.acknowledge_alert(alert_id)
    return jsonify({"status": "ok", "alert_id": alert_id})


# ── Error handlers ────────────────────────────────────────────────────────────

@app.errorhandler(401)
def unauthorized(e):
    return jsonify({"error": "Unauthorized", "message": str(e)}), 401


@app.errorhandler(403)
def forbidden(e):
    return jsonify({"error": "Forbidden", "message": str(e)}), 403


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"[SentinelCore] Dashboard → http://{cfg.dashboard.host}:{cfg.dashboard.port}")
    if cfg.dashboard.require_auth and cfg.dashboard.api_token == "CHANGE_ME":
        print("[WARNING] Using default API token — change api_token in config.yaml!")
    app.run(host=cfg.dashboard.host, port=cfg.dashboard.port, debug=False)
