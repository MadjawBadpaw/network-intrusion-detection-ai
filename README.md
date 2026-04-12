# Network Intrusion Detection AI

> AI-powered network traffic analyzer — detect DDoS, Port Scans, 
> Brute Force attacks from network flow CSV files.

## What it does

Upload a network flow CSV and get:
- Attack type classification (DDoS / PortScan / BruteForce / Benign)
- Per-flow analysis with confidence scores
- Attack breakdown with percentages
- Actionable recommendations per attack type
- Feature importance visualization

## How it works

- Random Forest trained on CICIDS2017 dataset
- 40,000 balanced samples across 4 classes
- 78 network flow features
- 100% accuracy on test set
- Desktop GUI — no browser needed

## Tech Stack

Python · scikit-learn · Random Forest · CustomTkinter · CICFlowMeter

## Run locally

1. Install Python 3.10+
2. Run install.bat
3. Run start.bat

## Model Details

| Property | Value |
|---|---|
| Algorithm | Random Forest (100 trees) |
| Dataset | CICIDS2017 |
| Classes | BENIGN / DDoS / PortScan / BruteForce |
| Features | 78 network flow features |
| Test Accuracy | 100% |

# Network Intrusion Detection AI

> AI-powered network traffic analyzer focused on detecting **DDoS attacks** and **Port Scans** — the two most common and damaging network-level threats.

## Important Note

This is **not** a full-scale NIDS (Network Intrusion Detection System). It is a focused ML-powered detector trained specifically for:

```
DDoS attacks      ← primary focus
Port Scanning     ← primary focus  
Brute Force       ← secondary (FTP/SSH)
Benign traffic    ← baseline
```

It is not designed to replace enterprise tools like Snort, Suricata, or Zeek. Think of it as an AI layer that analyzes extracted network flow data and flags the most common attack patterns.

---

## How It Works — Full Pipeline

```
Step 1 — Capture network traffic
         Use Wireshark or tcpdump to capture .pcap file

Step 2 — Convert PCAP to flow CSV
         Use CICFlowMeter to extract 78 flow features
         from the raw PCAP into a CSV file

Step 3 — Upload CSV to this app
         The AI analyzes each network flow
         and classifies it instantly

Step 4 — Get results
         Attack type, severity, per-flow breakdown,
         and recommendations
```

### CICFlowMeter (Required for PCAP files)

CICFlowMeter converts raw PCAP captures into the structured CSV format this model was trained on.

```bash
# install
pip install cicflowmeter

# convert your pcap to csv
cicflowmeter -f capture.pcap -c network_flows.csv

# then upload network_flows.csv to the app
```

Download: https://github.com/ahlashkari/CICFlowMeter

Without CICFlowMeter you can still use pre-extracted CSVs directly (same format as CICIDS2017 dataset).

---

## What It Detects

### DDoS — Primary Detection Target
```
Distributed Denial of Service attacks
Flooding attacks designed to overwhelm and crash services
High packet rate, abnormal flow duration, massive byte counts
→ Detected with high confidence
```

### Port Scan — Primary Detection Target
```
Reconnaissance activity
Attacker probing network for open ports and services
Many destinations, low bytes per flow, systematic patterns
→ Detected with high confidence
```

### Brute Force — Secondary Detection
```
FTP-Patator and SSH-Patator style attacks
Repeated connection attempts to guess credentials
→ Detected, but less emphasis than DDoS/Scan
```

### What It Does NOT Detect
```
❌ Malware C2 traffic
❌ Data exfiltration
❌ Zero-day exploits
❌ Application layer attacks (beyond basic web attacks)
❌ Encrypted attack traffic
```

---

## Dashboard Features

```
Left Panel:
├── CSV file upload
├── Top threat summary
├── Total / Attack / Benign flow counts
├── Attack description
└── Actionable recommendations

Right Panel:
├── Per-class confidence percentages
├── Flow Analysis table (filterable)
├── Attack Breakdown with visual bars
└── Feature Importance visualization
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Model | Random Forest (100 trees) |
| Training data | CICIDS2017 |
| GUI | CustomTkinter (desktop app, no browser) |
| Flow extraction | CICFlowMeter |
| Language | Python 3.10 |

---

## Run Locally

### Requirements
- Python 3.10+
- Java (for CICFlowMeter)

### Setup

```bash
git clone https://github.com/MadjawBadpaw/network-intrusion-detection-ai
cd network-intrusion-detection-ai

```

**Windows:**
```
1. Double click install.bat
2. Double click start.bat
```

**Manual:**
```bash
pip install scikit-learn pandas numpy customtkinter
python app.py
```

---

## Model Details

| Property | Value |
|---|---|
| Algorithm | Random Forest (100 trees, max depth 20) |
| Dataset | CICIDS2017 (Canadian Institute for Cybersecurity) |
| Training samples | 40,000 (10,000 per class, balanced) |
| Features | 78 network flow features |
| Classes | BENIGN / DDoS / PortScan / BruteForce |
| Test accuracy | 100% (CICIDS2017 has highly distinct attack signatures) |
| Training time | ~1 second (tabular ML, not deep learning) |

### Why 100% Accuracy?

CICIDS2017 is well known in research for having very distinct attack signatures — DDoS, PortScan, and BruteForce traffic patterns are fundamentally different at the flow feature level. This makes classification straightforward for Random Forest. Real-world traffic is noisier and accuracy will vary.

---

## Limitations

```
→ Trained on CICIDS2017 (2017 data)
  newer attack patterns may not be detected

→ Requires CICFlowMeter preprocessing
  cannot analyze raw PCAP directly (yet)

→ Not real-time
  batch analysis of captured flows only

→ Focused scope
  DDoS and PortScan detection only, not full NIDS
```

---

## Related Project

Also check out my CVE Intelligence AI — a DistilBERT model fine-tuned on 66K CVEs for vulnerability severity classification:

[github.com/MadjawBadpaw/cve-intelligence-ai](https://github.com/MadjawBadpaw/cve-intelligence-ai)

---

## Built By

**Yugam Thakur** — CS student | AI + cybersecurity  
GitHub: [@MadjawBadpaw](https://github.com/MadjawBadpaw)

---

## License

MIT — free to use, modify, and distribute.
