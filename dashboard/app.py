"""
dashboard/app.py — Real-time web dashboard for the SSH honeypot.

Run separately:
    python dashboard/app.py

Browse to: http://127.0.0.1:8080
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
from flask import Flask, render_template, jsonify, request
import logger as log_db

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["JSON_SORT_KEYS"] = False


def _fmt_ts(ts: float) -> str:
    if ts is None:
        return "—"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def api_stats():
    return jsonify(log_db.get_stats())


@app.route("/api/attempts")
def api_attempts():
    limit = int(request.args.get("limit", 50))
    rows = log_db.get_recent_attempts(limit)
    for r in rows:
        r["ts_fmt"] = _fmt_ts(r["ts"])
        r["success_label"] = "Success" if r["success"] else "Failed"
    return jsonify(rows)


@app.route("/api/sessions")
def api_sessions():
    rows = log_db.get_sessions()
    for r in rows:
        r["started_fmt"] = _fmt_ts(r["started_at"])
        r["ended_fmt"]   = _fmt_ts(r.get("ended_at"))
        duration = None
        if r.get("ended_at") and r.get("started_at"):
            duration = int(r["ended_at"] - r["started_at"])
            r["duration"] = f"{duration}s"
        else:
            r["duration"] = "active"
    return jsonify(rows)


@app.route("/api/commands/<int:session_id>")
def api_commands(session_id: int):
    rows = log_db.get_commands(session_id)
    for r in rows:
        r["ts_fmt"] = _fmt_ts(r["ts"])
    return jsonify(rows)


if __name__ == "__main__":
    log_db.init_db()
    print("Dashboard running at http://127.0.0.1:8080")
    app.run(host="127.0.0.1", port=8080, debug=False)
