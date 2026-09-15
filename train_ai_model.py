import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib

# Features:
# CPU usage, Memory usage, Network activity,
# Suspicious process, Suspicious behavior

X = np.array([
    [10, 20, 0, 0, 0],
    [25, 30, 1, 0, 0],
    [40, 45, 1, 0, 0],
    [90, 85, 1, 1, 1],
    [95, 90, 1, 1, 1],
    [85, 80, 0, 1, 1],
    [15, 25, 0, 0, 0],
    [30, 35, 1, 0, 0],
    [88, 82, 1, 1, 0],
    [92, 87, 1, 1, 1],
    [20, 28, 0, 0, 0],
    [75, 70, 1, 0, 1]
])

# 0 = Normal
# 1 = Suspicious

y = np.array([
    0, 0, 0,
    1, 1, 1,
    0, 0,
    1, 1,
    0, 1
])

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X, y)

joblib.dump(model, "spyware_ai_model.pkl")

print("AI model trained successfully!")
print("Saved as: spyware_ai_model.pkl")