from flask import Flask, render_template, jsonify
import json
import os
import psutil
from datetime import datetime
from plyer import notification

app = Flask(__name__)

ALERT_FILE = "alerts.json"


def load_alerts():
    if not os.path.exists(ALERT_FILE):
        return []

    try:
        with open(ALERT_FILE, "r") as f:
            return json.load(f)
    except:
        return []


def save_alert(alert):
    alerts = load_alerts()
    alerts.insert(0, alert)

    with open(ALERT_FILE, "w") as f:
        json.dump(alerts[:50], f, indent=4)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/alerts")
def get_alerts():
    return jsonify(load_alerts())


@app.route("/api/network")
def get_network():

    connections = psutil.net_connections(kind="inet")

    active = 0

    for connection in connections:
        if connection.status == "ESTABLISHED":
            active += 1

    return jsonify({
        "active_connections": active
    })


@app.route("/api/demo-alert")
def demo_alert():

    alert = {
        "process": "Safe_Test_Process",
        "pid": 9999,
        "risk": "HIGH",
        "score": 90,
        "reason": "Demo suspicious behavior detected",
        "time": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    }

    save_alert(alert)

    notification.notify(
        title="Security Alert",
        message="Suspicious behavior detected!\nRisk: HIGH",
        timeout=8
    )

    return jsonify({
        "status": "Alert created successfully"
    })


if __name__ == "__main__":
    app.run(debug=True)