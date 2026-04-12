import pandas as pd
import numpy as np
import os
import pickle
import sys
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
import seaborn as sns

sys.stdout.reconfigure(encoding='utf-8')

DATA_PATH  = "C:/network_ai/data/"
MODEL_PATH = "C:/network_ai/models/"
LABEL_COL  = " Label"

LABEL_MAP = {
    "BENIGN":                        "BENIGN",
    "DDoS":                          "DDoS",
    "PortScan":                      "PortScan",
    "Web Attack \x96 Brute Force":   "WebAttack",
    "Web Attack \x96 XSS":           "WebAttack",
    "Web Attack \x96 Sql Injection":  "WebAttack",
    "FTP-Patator":                   "BruteForce",
    "SSH-Patator":                   "BruteForce",
}

SAMPLES_PER_CLASS = 10000

print("Loading data...")

dfs = []
for file in os.listdir(DATA_PATH):
    if not file.endswith(".csv"):
        continue
    try:
        df = pd.read_csv(DATA_PATH + file, encoding="utf-8", encoding_errors="replace")
        dfs.append(df)
        print(f"Loaded: {file} — {len(df)} rows")
    except Exception as e:
        print(f"Skipped {file}: {e}")

data = pd.concat(dfs, ignore_index=True)
print(f"\nTotal rows: {len(data):,}")

data[LABEL_COL] = data[LABEL_COL].str.strip()
data["label"]   = data[LABEL_COL].map(LABEL_MAP)
data = data[data["label"].notna()]

print("\nLabel distribution after mapping:")
print(data["label"].value_counts())

print(f"\nBalancing to {SAMPLES_PER_CLASS} per class...")
balanced = []
for label in data["label"].unique():
    samples = data[data["label"] == label]
    n = min(len(samples), SAMPLES_PER_CLASS)
    balanced.append(samples.sample(n, random_state=42))

data = pd.concat(balanced, ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)
print("Balanced distribution:")
print(data["label"].value_counts())

drop_cols = [LABEL_COL, "label", " Destination IP", " Source IP", " Timestamp", "Flow ID"]
feature_cols = [
    c for c in data.columns
    if c not in drop_cols
    and data[c].dtype in ["float64", "int64"]
]

X = data[feature_cols].copy()
y = data["label"].copy()

X.replace([np.inf, -np.inf], np.nan, inplace=True)
X.fillna(0, inplace=True)

print(f"\nFeatures: {len(feature_cols)}")
print(f"Samples:  {len(X):,}")

le = LabelEncoder()
y_encoded = le.fit_transform(y)
print(f"\nClasses: {list(le.classes_)}")

X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)
print(f"\nTrain: {len(X_train):,} | Test: {len(X_test):,}")

print("\nTraining Random Forest...")
print("This takes 5-10 minutes...")

rf = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    min_samples_split=10,
    n_jobs=-1,
    random_state=42,
    verbose=1
)

rf.fit(X_train, y_train)
print("Training complete.")

print("\nEvaluating...")
y_pred = rf.predict(X_test)

print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=le.classes_))

cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt="d", xticklabels=le.classes_, yticklabels=le.classes_, cmap="Blues")
plt.title("Confusion Matrix — Network Intrusion Detection")
plt.ylabel("Actual")
plt.xlabel("Predicted")
plt.tight_layout()
plt.savefig("C:/network_ai/confusion_matrix.png", dpi=150)
print("Confusion matrix saved.")

importance = pd.DataFrame({
    "feature":    feature_cols,
    "importance": rf.feature_importances_
}).sort_values("importance", ascending=False).head(15)

print("\nTop 15 Most Important Features:")
print(importance.to_string(index=False))

os.makedirs(MODEL_PATH, exist_ok=True)

with open(MODEL_PATH + "rf_model.pkl", "wb") as f:
    pickle.dump(rf, f)

with open(MODEL_PATH + "label_encoder.pkl", "wb") as f:
    pickle.dump(le, f)

with open(MODEL_PATH + "feature_cols.pkl", "wb") as f:
    pickle.dump(feature_cols, f)

print(f"\nModel saved to {MODEL_PATH}")
print("Done.")