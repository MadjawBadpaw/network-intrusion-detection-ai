import pickle
import numpy as np
import pandas as pd
from pathlib import Path
from collections import Counter

BASE_DIR  = Path(__file__).resolve().parent.parent
MODEL_DIR = BASE_DIR / "models"

print(f"Loading model from: {MODEL_DIR}")

with open(MODEL_DIR / "rf_model.pkl", "rb") as f:
    model = pickle.load(f)

with open(MODEL_DIR / "label_encoder.pkl", "rb") as f:
    le = pickle.load(f)

with open(MODEL_DIR / "feature_cols.pkl", "rb") as f:
    feature_cols = pickle.load(f)

print(f"Model loaded. Classes: {list(le.classes_)}")

SEVERITY = {
    "BENIGN":     {"level": "NONE",     "score": 0},
    "BruteForce": {"level": "HIGH",     "score": 3},
    "DDoS":       {"level": "CRITICAL", "score": 4},
    "PortScan":   {"level": "MEDIUM",   "score": 2},
    "WebAttack":  {"level": "HIGH",     "score": 3},
}

DESCRIPTIONS = {
    "BENIGN":     "Normal network traffic. No threats detected.",
    "DDoS":       "DDoS attack detected. Attacker flooding network to overwhelm services.",
    "PortScan":   "Port scanning detected. Attacker probing for open ports and services.",
    "BruteForce": "Brute force attack detected. Repeated login attempts to guess credentials.",
    "WebAttack":  "Web attack detected. SQL injection, XSS, or web brute force activity.",
}

RECOMMENDATIONS = {
    "BENIGN": [
        "Continue monitoring traffic normally",
        "Maintain regular security audits",
    ],
    "DDoS": [
        "Enable rate limiting on all public endpoints immediately",
        "Block source IPs at firewall level",
        "Contact ISP for upstream filtering",
        "Enable CDN/DDoS protection (Cloudflare, AWS Shield)",
        "Scale infrastructure to absorb traffic",
    ],
    "PortScan": [
        "Block scanning source IP at firewall",
        "Review and close unnecessary open ports",
        "Enable port scan detection alerts",
        "Consider moving services to non-standard ports",
        "Check if scan preceded any intrusion attempt",
    ],
    "BruteForce": [
        "Block attacking IP immediately",
        "Enable account lockout after failed attempts",
        "Implement multi-factor authentication",
        "Use fail2ban or similar tool",
        "Rotate potentially compromised credentials",
    ],
    "WebAttack": [
        "Block attacking IP at WAF level",
        "Review web application firewall rules",
        "Check application logs for successful exploitation",
        "Update and patch web application immediately",
        "Implement input validation and sanitization",
    ],
}


def predict_csv(df: pd.DataFrame) -> dict:
    missing = [c for c in feature_cols if c not in df.columns]
    for col in missing:
        df[col] = 0

    X = df[feature_cols].copy()
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)

    preds       = model.predict(X)
    probs       = model.predict_proba(X)
    labels      = le.inverse_transform(preds)
    label_names = list(le.classes_)

    flows = []
    for i, (label, prob) in enumerate(zip(labels, probs)):
        flows.append({
            "flow":       i + 1,
            "prediction": label,
            "confidence": round(float(prob.max()) * 100, 1),
            "severity":   SEVERITY.get(label, {}).get("level", "UNKNOWN"),
        })

    counts     = Counter(labels)
    attacks    = {k: v for k, v in counts.items() if k != "BENIGN"}
    total      = len(labels)
    top_attack = max(attacks, key=lambda k: SEVERITY.get(k, {}).get("score", 0)) if attacks else "BENIGN"
    sev_info   = SEVERITY.get(top_attack, SEVERITY["BENIGN"])

    return {
        "total_flows":     total,
        "benign_count":    counts.get("BENIGN", 0),
        "attack_count":    total - counts.get("BENIGN", 0),
        "attack_types":    dict(counts),
        "top_threat":      top_attack,
        "severity":        sev_info["level"],
        "description":     DESCRIPTIONS.get(top_attack, ""),
        "recommendations": RECOMMENDATIONS.get(top_attack, []),
        "flows":           flows[:100],
        "scores": {
            name: round(float(probs[:, i].mean()) * 100, 2)
            for i, name in enumerate(label_names)
        }
    }