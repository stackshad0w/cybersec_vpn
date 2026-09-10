# System Architecture — AI-Powered IPsec VPN Analyzer

## Overview
The platform is designed to provide automated, privacy-preserving cryptographic audit, protocol compliance inspection, and machine-learning side-channel behavior classification of IPsec VPN network traffic captures.

```
+-----------------------------------------------------------------------------+
|                               Web Frontend / Stitch UI                     |
+-----------------------------------------------------------------------------+
                                       │ HTTP / REST
                                       ▼
+-----------------------------------------------------------------------------+
|                             FastAPI Gateway Layer                           |
|  - JWT Authentication & RBAC (Admin, Analyst, Viewer)                       |
|  - Multi-part PCAP Ingestion & Magic Byte Structural Validation             |
+-----------------------------------------------------------------------------+
                                       │
                                       ▼
+-----------------------------------------------------------------------------+
|                            Analysis Orchestrator                            |
+-----------------------------------------------------------------------------+
          │                                  │                        │
          ▼                                  ▼                        ▼
+───────────────────+              +───────────────────+    +─────────────────+
|   PCAP Parser     |              | Feature Extractor |    | Local Retention |
| - Scapy / Native  |              | - 14+ Flow Stats  |    | - Auto cleanup  |
| - UDP 500 / 4500  |              | - Zero Payload    |    | - Redacted logs |
| - ESP Proto 50/AH |              |   Inspection      |    +─────────────────+
+───────────────────+              +───────────────────+
          │                                  │
          ▼                                  ▼
+───────────────────+              +───────────────────+
| Protocol Analyzers|              | AI / ML Pipeline  |
| - IKEv1 / IKEv2   |              | - Random Forest   |
| - ESP Monotonicity|              | - Isolation Forest|
| - Mode Detection  |              | - Meta Exposure   |
+───────────────────+              +───────────────────+
          │                                  │
          └────────────────┬─────────────────┘
                           ▼
+-----------------------------------------------------------------------------+
|                    Deterministic Security Rules Engine                      |
| - Cryptographic Cipher Strength (AES-GCM, AES-CBC, 3DES, DES)               |
| - Key Exchange Groups (MODP 1024/1536/2048, ECP 256/384, Curve25519)        |
| - PFS Verification, Replay Window Validation, SA Lifetime Policies          |
+-----------------------------------------------------------------------------+
                                   │
                                   ▼
+-----------------------------------------------------------------------------+
|                               Risk Engine                                   |
| - 8 Weighted Dimensions (0–100 Score & Categorized Risk Tiers)              |
+-----------------------------------------------------------------------------+
                                   │
                                   ▼
+-----------------------------------------------------------------------------+
|                           Database & Reporting                              |
| - SQLAlchemy (PostgreSQL / SQLite fallback)                                 |
| - ReportLab Executive PDF, Technical Audit PDF, JSON SIEM Export            |
+-----------------------------------------------------------------------------+
```

## Privacy-First Architecture
1. **Zero External AI Transmission**: No network traffic or payloads are sent to external LLMs or third-party cloud APIs.
2. **Aggregate Metadata Only**: Machine learning features are strictly statistical (packet count, byte sizes, inter-arrival time distributions, burst rates, upload/download ratios).
3. **Secret Redaction**: Passwords, Pre-Shared Keys (PSKs), private keys, and authorization headers are never logged or stored.
