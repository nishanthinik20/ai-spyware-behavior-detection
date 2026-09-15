import time
import json
import os
import psutil
from datetime import datetime
from plyer import notification

from detector import analyze_process

ALERT_FILE = "alerts.json"

already_alerted = set()


def save_alert(alert):
    alerts = []

    if os.path.exists(ALERT_FILE):
        try:
            with open(ALERT_FILE, "r") as f:
                alerts = json.load(f)
        except:
            alerts = []

    alerts.insert(0, alert)
    alerts = alerts[:50]

    with open(ALERT_FILE, "w") as f:
        json.dump(alerts, f, indent=4)


def show_alert(process_name, pid, result):
    notification.notify(
        title="Security Alert",
        message=(
            f"Suspicious behavior detected!\n"
            f"Process: {process_name}\n"
            f"Risk: {result['risk']}"
        ),
        timeout=8
    )


def monitor_processes():

    print("Real-Time Security Monitor Started...")
    print("Monitoring running processes...\n")

    while True:

        for process in psutil.process_iter(
            ["pid", "name", "cpu_percent", "memory_percent","cmdline"]
        ):

            try:
                pid = process.info["pid"]
                name = process.info["name"]

                if not name:
                    continue

                cpu = process.info["cpu_percent"] or 0
                memory = process.info["memory_percent"] or 0
                cmdline = " ".join(process.info["cmdline"] or [])

                result = analyze_process(
                    name,
                    cpu,
                    memory,
                    cmdline
                )

                if result["risk"] == "HIGH":

                    alert_id = (name.lower(), pid)

                    if alert_id not in already_alerted:

                        alert = {
                            "process": name,
                            "pid": pid,
                            "risk": result["risk"],
                            "score": result["score"],
                            "reason": ", ".join(result["reasons"]),
                            "time": datetime.now().strftime(
                                "%Y-%m-%d %H:%M:%S"
                            )
                        }

                        save_alert(alert)
                        show_alert(name, pid, result)

                        already_alerted.add(alert_id)

                        print(
                            f"ALERT: {name} | "
                            f"Risk: {result['risk']} | "
                            f"Score: {result['score']}"
                        )

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess
            ):
                pass

        time.sleep(2)


if __name__ == "__main__":
    monitor_processes()