from sklearn.ensemble import IsolationForest
import numpy as np


model = IsolationForest(
    contamination=0.05,
    random_state=42,
    n_estimators=100,
)

training_data = np.array([
    [54],
    [60],
    [64],
    [70],
    [74],
    [80],
    [90],
    [128],
    [256],
    [512],
    [768],
    [1024],
])

model.fit(training_data)


def detect_anomaly(packet_size):
    size = float(packet_size)

    prediction = model.predict([[size]])[0]
    score = float(model.decision_function([[size]])[0])

    rule_based_anomaly = size < 20 or size > 1500
    model_anomaly = prediction == -1

    if rule_based_anomaly or model_anomaly:
        return {
            "anomaly": True,
            "score": score,
            "message": f"Suspicious packet size detected: {packet_size}",
        }

    return {
        "anomaly": False,
        "score": score,
        "message": None,
    }