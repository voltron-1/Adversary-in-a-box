"""
blue-team/dashboard/app.py — Blue Team Flask Dashboard
Real-time alert triage, playbook runner, and threat overview.
"""

import hmac
import ipaddress
import os
import re
from datetime import UTC, datetime
from pathlib import Path

from flask import Flask, jsonify, render_template, request

# P6 (S5): a shared/committed default secret is no better than no secret --
# session cookies signed with a value readable from git are forgeable. Refuse
# to boot on an unset or known-default SECRET_KEY rather than fall back to one.
#
# #146: this denylist is duplicated in forensics/scoreboard/app.py because the
# two apps build from separate Docker contexts and cannot share an import. Keep
# the two copies in sync; tests/test_dashboard_security.py
# (TestInsecureKeyDenylistSync) fails CI if they drift or omit a .env.example
# placeholder.
INSECURE_SECRET_KEYS = frozenset(
    {
        "",
        "lab-secret-key",  # former hardcoded fallback (this app)
        "scoreboard-secret",  # former hardcoded fallback (scoreboard app)
        "lab-secret-change-me",  # former docker-compose default
        "adversary-in-a-box-lab-secret-key-change-me",  # .env.example placeholder
    }
)


def _require_secret_key() -> str:
    """Return SECRET_KEY, raising if unset or a known shared default."""
    key = os.environ.get("SECRET_KEY", "").strip()
    if key in INSECURE_SECRET_KEYS:
        raise RuntimeError(
            "SECRET_KEY is unset or set to a known default. Set a unique "
            "FLASK_SECRET_KEY in your .env (see .env.example) before starting "
            "the blue-team dashboard."
        )
    return key


# Read once at startup. The playbook runner can quarantine hosts and touches
# the Docker socket, so it is gated behind this token; an empty value disables
# the endpoint entirely (fail closed). A token left at a known committed
# default is no secret, so we treat it as unset -> endpoint disabled.
_raw_playbook_token = os.environ.get("PLAYBOOK_AUTH_TOKEN", "").strip()
PLAYBOOK_AUTH_TOKEN = "" if _raw_playbook_token in INSECURE_SECRET_KEYS else _raw_playbook_token


def _playbook_auth_ok(req) -> bool:
    """P6 (S5): authorize POST /api/run-playbook against PLAYBOOK_AUTH_TOKEN.
    Fail closed: if the token is unset, the endpoint is disabled entirely.
    Accepts the token via the X-Auth-Token header or `Authorization: Bearer`."""
    if not PLAYBOOK_AUTH_TOKEN:
        return False
    provided = req.headers.get("X-Auth-Token", "").strip()
    if not provided:
        auth = req.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            provided = auth[len("Bearer ") :].strip()
    return bool(provided) and hmac.compare_digest(provided, PLAYBOOK_AUTH_TOKEN)


app = Flask(__name__)
app.secret_key = _require_secret_key()

ELASTICSEARCH_URL = os.environ.get("ELASTICSEARCH_URL", "http://elasticsearch:9200")
EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "/evidence"))

# Simulated alerts for demo when SIEM is not connected
DEMO_ALERTS = [
    {
        "id": "1",
        "timestamp": "2024-01-15T14:23:01Z",
        "severity": "critical",
        "technique": "T1566.001",
        "name": "Spearphishing Attachment Detected",
        "src_ip": "172.20.0.10",
        "dst_ip": "172.20.0.32",
        "status": "open",
        "description": "Phishing email with suspicious attachment detected by Suricata",
    },
    {
        "id": "2",
        "timestamp": "2024-01-15T14:25:33Z",
        "severity": "high",
        "technique": "T1595",
        "name": "Port Scan Detected",
        "src_ip": "172.20.0.10",
        "dst_ip": "172.20.0.30",
        "status": "open",
        "description": "20 ports scanned in 1 second from attacker IP",
    },
    {
        "id": "3",
        "timestamp": "2024-01-15T14:28:47Z",
        "severity": "critical",
        "technique": "T1190",
        "name": "SQL Injection Attempt",
        "src_ip": "172.20.0.10",
        "dst_ip": "172.20.0.30",
        "status": "investigating",
        "description": "SQL injection payload detected in login form",
    },
    {
        "id": "4",
        "timestamp": "2024-01-15T14:31:09Z",
        "severity": "high",
        "technique": "T1548.003",
        "name": "Sudo Privilege Escalation",
        "src_ip": "172.20.0.10",
        "dst_ip": "172.20.0.30",
        "status": "open",
        "description": "Sudo abuse via GTFOBins binary detected",
    },
    {
        "id": "5",
        "timestamp": "2024-01-15T14:35:22Z",
        "severity": "critical",
        "technique": "T1048.003",
        "name": "DNS Tunneling Detected",
        "src_ip": "172.20.0.30",
        "dst_ip": "8.8.8.8",
        "status": "open",
        "description": "High-entropy DNS subdomain detected — possible data exfiltration",
    },
]

PLAYBOOKS = [
    {
        "id": "phishing_ir",
        "name": "Phishing Response",
        "severity": "high",
        "techniques": ["T1566.001"],
    },
    {
        "id": "ransomware_ir",
        "name": "Ransomware Response",
        "severity": "critical",
        "techniques": ["T1486"],
    },
    {
        "id": "lateral_movement_ir",
        "name": "Lateral Movement Response",
        "severity": "critical",
        "techniques": ["T1550.002", "T1563.001"],
    },
    {
        "id": "data_exfil_ir",
        "name": "Data Exfiltration Response",
        "severity": "critical",
        "techniques": ["T1041", "T1048.003"],
    },
]


# #144: the playbook `context` is operator-supplied and ends up .format()'d
# into argv for privileged IR scripts (block_ip.sh / isolate_host.sh run with
# NET_ADMIN + the Docker socket). Validate it at this trust boundary so the
# engine never sees an unexpected type or an injection payload.
#   - keys: only those the shipped playbooks actually interpolate, plus
#     campaign_id (read by PlaybookEngine for SIEM correlation)
#   - *_ip values must parse as IP addresses
#   - host / id values are constrained to a hostname-safe charset so no shell
#     or str.format metacharacter ( ; | $ { } space ... ) can reach argv. The
#     first character must be alphanumeric: a leading '-' is charset-valid but
#     would reach docker/bash argv as a flag (argument injection, CWE-88).
_CONTEXT_IP_KEYS = frozenset({"attacker_ip", "c2_ip"})
_CONTEXT_HOST_KEYS = frozenset({"affected_host", "pivot_host", "source_host", "campaign_id"})
_CONTEXT_KEYS = _CONTEXT_IP_KEYS | _CONTEXT_HOST_KEYS
_SAFE_HOST_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,252}\Z")


def _validate_context(raw: object) -> dict:
    """Return a vetted context dict or raise ValueError. Treats a missing /
    null context as empty; rejects any other non-dict, unknown keys, non-string
    values, malformed IPs, and metacharacter-bearing host/id values."""
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("context must be an object")
    clean: dict = {}
    for key, value in raw.items():
        if key not in _CONTEXT_KEYS:
            raise ValueError(f"unknown context key: {key}")
        if not isinstance(value, str):
            raise ValueError(f"context value for '{key}' must be a string")
        if key in _CONTEXT_IP_KEYS:
            try:
                ipaddress.ip_address(value)
            except ValueError as exc:
                raise ValueError(f"context value for '{key}' must be an IP") from exc
        elif not _SAFE_HOST_RE.match(value):
            raise ValueError(f"context value for '{key}' has invalid characters")
        clean[key] = value
    return clean


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
    return render_template(
        "index.html",
        alerts=alerts[:10],
        stats=stats,
        now=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
    )


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
    if not _playbook_auth_ok(request):
        # P6 (S5): reject unauthenticated/unconfigured playbook execution.
        return jsonify({"success": False, "error": "unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    playbook_id = data.get("playbook_id")
    # P6 (S5): only registered playbooks may run. PlaybookEngine builds a path
    # from this id (PLAYBOOK_DIR / f"{id}.yml"); an unvalidated id like
    # "../../etc/cron.d/x" would traverse out of the playbook dir, so restrict
    # it to the known registry rather than passing arbitrary input through.
    if playbook_id not in {p["id"] for p in PLAYBOOKS}:
        return jsonify({"success": False, "error": "unknown playbook_id"}), 400
    # #144: vet the operator-supplied context before it reaches the engine.
    try:
        context = _validate_context(data.get("context"))
    except ValueError as exc:
        return jsonify({"success": False, "error": f"invalid context: {exc}"}), 400
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
    return jsonify(
        {
            "total_alerts": len(alerts),
            "critical": sum(1 for a in alerts if a.get("severity") == "critical"),
            "high": sum(1 for a in alerts if a.get("severity") == "high"),
            "medium": sum(1 for a in alerts if a.get("severity") == "medium"),
            "open": sum(1 for a in alerts if a.get("status") == "open"),
            "last_updated": datetime.now(UTC).isoformat(),
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
