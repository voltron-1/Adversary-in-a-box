"""
blue-team/dashboard/app.py — Blue Team Flask Dashboard
Real-time alert triage, playbook runner, and threat overview.
"""

import os
import json
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, jsonify, redirect, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "lab-secret-key")

ELASTICSEARCH_URL = os.environ.get("ELASTICSEARCH_URL", "http://elasticsearch:9200")
EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "/evidence"))

# Simulated alerts for demo when SIEM is not connected
DEMO_ALERTS = [
    {"id": "1", "timestamp": "2024-01-15T14:23:01Z", "severity": "critical", "technique": "T1566.001",
     "name": "Spearphishing Attachment Detected", "src_ip": "172.20.0.10", "dst_ip": "172.20.0.32",
     "status": "open", "description": "Phishing email with suspicious attachment detected by Suricata"},
    {"id": "2", "timestamp": "2024-01-15T14:25:33Z", "severity": "high", "technique": "T1595",
     "name": "Port Scan Detected", "src_ip": "172.20.0.10", "dst_ip": "172.20.0.30",
     "status": "open", "description": "20 ports scanned in 1 second from attacker IP"},
    {"id": "3", "timestamp": "2024-01-15T14:28:47Z", "severity": "critical", "technique": "T1190",
     "name": "SQL Injection Attempt", "src_ip": "172.20.0.10", "dst_ip": "172.20.0.30",
     "status": "investigating", "description": "SQL injection payload detected in login form"},
    {"id": "4", "timestamp": "2024-01-15T14:31:09Z", "severity": "high", "technique": "T1548.003",
     "name": "Sudo Privilege Escalation", "src_ip": "172.20.0.10", "dst_ip": "172.20.0.30",
     "status": "open", "description": "Sudo abuse via GTFOBins binary detected"},
    {"id": "5", "timestamp": "2024-01-15T14:35:22Z", "severity": "critical", "technique": "T1048.003",
     "name": "DNS Tunneling Detected", "src_ip": "172.20.0.30", "dst_ip": "8.8.8.8",
     "status": "open", "description": "High-entropy DNS subdomain detected — possible data exfiltration"},
]

PLAYBOOKS = [
    {"id": "phishing_ir", "name": "Phishing Response", "severity": "high", "techniques": ["T1566.001"]},
    {"id": "ransomware_ir", "name": "Ransomware Response", "severity": "critical", "techniques": ["T1486"]},
    {"id": "lateral_movement_ir", "name": "Lateral Movement Response", "severity": "critical", "techniques": ["T1550.002", "T1563.001"]},
    {"id": "data_exfil_ir", "name": "Data Exfiltration Response", "severity": "critical", "techniques": ["T1041", "T1048.003"]},
]


def get_alerts():
    """Fetch alerts from Elasticsearch or fall back to demo data."""
    try:
        import requests
        resp = requests.get(f"{ELASTICSEARCH_URL}/red-team-events-*/_search?size=50", timeout=3)
        if resp.ok:
            hits = resp.json().get("hits", {}).get("hits", [])
            return [h["_source"] for h in hits]
    except Exception:
        pass
    return DEMO_ALERTS


@app.route("/")
def index():
    alerts = get_alerts()
    stats = {
        "total": len(alerts),
        "critical": sum(1 for a in alerts if a.get("severity") == "critical"),
        "high": sum(1 for a in alerts if a.get("severity") == "high"),
        "open": sum(1 for a in alerts if a.get("status") == "open"),
    }
    return render_template("index.html", alerts=alerts[:10], stats=stats,
                           now=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))


@app.route("/alerts")
def alerts_page():
    alerts = get_alerts()
    severity_filter = request.args.get("severity", "all")
    if severity_filter != "all":
        alerts = [a for a in alerts if a.get("severity") == severity_filter]
    return render_template("alerts.html", alerts=alerts, severity_filter=severity_filter)


@app.route("/playbooks")
def playbooks_page():
    return render_template("playbooks.html", playbooks=PLAYBOOKS)


@app.route("/api/run-playbook", methods=["POST"])
def run_playbook():
    data = request.get_json()
    playbook_id = data.get("playbook_id")
    context = data.get("context", {})
    try:
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from response.playbook_engine import PlaybookEngine
        engine = PlaybookEngine(playbook_id)
        result = engine.execute(context)
        return jsonify({"success": True, "result": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/alerts")
def api_alerts():
    return jsonify(get_alerts())


@app.route("/api/stats")
def api_stats():
    alerts = get_alerts()
    return jsonify({
        "total_alerts": len(alerts),
        "critical": sum(1 for a in alerts if a.get("severity") == "critical"),
        "high": sum(1 for a in alerts if a.get("severity") == "high"),
        "medium": sum(1 for a in alerts if a.get("severity") == "medium"),
        "open": sum(1 for a in alerts if a.get("status") == "open"),
        "last_updated": datetime.utcnow().isoformat(),
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
