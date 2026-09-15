import os
import joblib

MODEL_FILE = "spyware_ai_model.pkl"

# Load trained AI model
ai_model = None

if os.path.exists(MODEL_FILE):
    ai_model = joblib.load(MODEL_FILE)


def analyze_process(process_name, cpu_usage, memory_usage, command_line=""):

    score = 0
    reasons = []

    suspicious_names = [
        "unknown.exe",
        "test_spyware.exe",
        "keylogger.exe"
    ]

    # 1. Suspicious process name
    if process_name.lower() in suspicious_names:
        score += 70
        reasons.append("Suspicious process name")

    # 2. Safe project test marker
    if "SAFE_SPYWARE_TEST" in command_line:
        score += 90
        reasons.append("Suspicious behavior test detected")

    # 3. High CPU
    if cpu_usage > 80:
        score += 15
        reasons.append("High CPU usage")

    # 4. High memory
    if memory_usage > 80:
        score += 15
        reasons.append("High memory usage")

    # -----------------------------
    # AI PREDICTION
    # -----------------------------
    ai_prediction = 0

    if ai_model is not None:

        suspicious_process = 1 if (
            process_name.lower() in suspicious_names
        ) else 0

        suspicious_behavior = 1 if (
            "SAFE_SPYWARE_TEST" in command_line
        ) else 0

        network_activity = 1 if cpu_usage > 30 else 0

        features = [[
            cpu_usage,
            memory_usage,
            network_activity,
            suspicious_process,
            suspicious_behavior
        ]]

        ai_prediction = int(ai_model.predict(features)[0])

        if ai_prediction == 1:
            score += 25
            reasons.append("AI model detected suspicious behavior")

    # -----------------------------
    # FINAL RISK
    # -----------------------------

    if score >= 70:
        risk = "HIGH"

    elif score >= 40:
        risk = "MEDIUM"

    else:
        risk = "LOW"

    return {
        "score": score,
        "risk": risk,
        "ai_prediction": ai_prediction,
        "reasons": reasons
    }