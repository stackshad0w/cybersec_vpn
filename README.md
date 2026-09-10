# CyberSec IPsec VPN Analyzer (PRD-02/03)
> **Privacy-Preserving AI-Assisted IPsec VPN Security Assessment Platform**

An automated security audit and threat detection system that inspects network packet captures (.pcap / .pcapng), analyzes IKEv1/IKEv2 and ESP/AH protocol implementations, evaluates cryptographic strength, checks for anti-replay violations, identifies side-channel metadata leaks using Machine Learning, and produces executive/technical PDF reports with actionable Cisco/StrongSwan remediation steps.

---

## ⚡ Quick Start (Local Run)

### 1. Prerequisites
- Python 3.10+ (64-bit recommended)
- Git

### 2. Environment Setup
```bash
# Clone the repository
git clone https://github.com/stackshad0w/cybersec_vpn.git
cd cybersec_vpn

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .\.venv\Scripts\activate

# Install dependencies
pip install -r backend/requirements.txt
```

### 3. Generate Testbed PCAPs & Train AI Model
```bash
# Train Random Forest Traffic Classifier
python ml/training/train_traffic_classifier.py

# Generate reproducible testbed PCAPs (Secure, Weak, Transport, Demo)
python testbed/scripts/generate_test_pcaps.py
```

### 4. Run Backend & Dashboard
```bash
# Start FastAPI server
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
- **Web Dashboard**: Open [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive Swagger Docs**: Open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## 🐳 Docker Deployment

To launch the entire platform stack (FastAPI backend, PostgreSQL 16, Redis 7, background worker):

```bash
docker-compose up --build
```

---

## 🧪 Running Automated Tests

```bash
pytest backend/tests/ -v
```

---

## 🎯 PRD Features & Verification

| Requirement | Implementation | Status |
|---|---|---|
| **Untrusted Input PCAP Validation** | Magic bytes (`0xa1b2c3d4`, `0x0a0d0d0a`), SHA-256 calculation, size limits | ✅ Verified |
| **IKEv1 / IKEv2 Dissection** | Parses Initiator/Responder SPIs, Transforms, DH Groups, NAT-T non-ESP markers | ✅ Verified |
| **ESP Anti-Replay & Sequence Analysis** | Detects duplicate sequences, monotonic validation, Tunnel vs Transport inference | ✅ Verified |
| **Deterministic Security Rules** | Checks cipher strength, DH Group 14+, PFS status, SA lifetime, protocol deprecation | ✅ Verified |
| **8-Dimensional Risk Engine** | 0–100 score + risk tiers (Excellent, Good, Moderate, High Risk, Critical) | ✅ Verified |
| **AI Traffic Classification** | Local Random Forest model predicting `Video-like`, `VoIP-like`, `Web-like`, etc. | ✅ Verified (91% Video) |
| **Side-Channel Metadata Exposure** | Unpadded packet-size leak analysis, timing jitter, endpoint disclosure | ✅ Verified |
| **Executive & Technical PDF Reports** | Professional ReportLab generator with threat matrix and Cisco/StrongSwan CLI fixes | ✅ Verified |
| **PRD Demo Target Mode** | Pre-loaded target (Score 82, IKEv2, Tunnel, AES-256-GCM, PFS, Video 91%) | ✅ Verified |

---

## 📜 License
Internal Security Platform — Confidential.
