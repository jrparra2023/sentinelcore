"""
SentinelCore — dashboard/app.py
Flask web dashboard: live events, alerts, stats, acknowledge.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask, render_template, jsonify, request
from storage.db import Database

app = Flask(__name__)
db  = Database()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def api_stats():
    return jsonify(db.get_stats())


@app.route("/api/alerts")
def api_alerts():
    unacked_only = request.args.get("unacked", "false").lower() == "true"
    alerts = db.get_alerts(limit=200, unacked_only=unacked_only)
    return jsonify(alerts)


@app.route("/api/events")
def api_events():
    source     = request.args.get("source")
    event_type = request.args.get("event_type")
    src_ip     = request.args.get("src_ip")
    limit      = int(request.args.get("limit", 100))
    events = db.get_events(source=source, event_type=event_type,
                           src_ip=src_ip, limit=limit)
    return jsonify(events)


@app.route("/api/alerts/<int:alert_id>/acknowledge", methods=["POST"])
def api_acknowledge(alert_id):
    db.acknowledge_alert(alert_id)
    return jsonify({"status": "ok", "alert_id": alert_id})


if __name__ == "__main__":
    print("[SentinelCore] Dashboard running → http://127.0.0.1:5000")
    app.run(debug=False, port=5000)
