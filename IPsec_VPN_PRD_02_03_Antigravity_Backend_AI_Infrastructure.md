PRD-02/03 — AI-Powered IPsec VPN Analyzer
Backend + AI/ML + Security Engine + Infrastructure + Integration — Antigravity
Objective: Implement the real end-to-end working prototype behind the Stitch frontend, including packet analysis, security
assessment, AI classification, reports, testbed, Docker, testing and privacy controls.
1. Core Architecture
• Frontend → FastAPI → analysis job → PCAP parser → IPsec/IKE/ESP analyzer → deterministic security engine →
AI/ML → risk engine → database → reports → dashboard.
• Use Python, FastAPI, PostgreSQL, SQLAlchemy, Pydantic, Redis and a background worker. Use tshark and/or
PyShark/Scapy, pandas, NumPy and scikit-learn; XGBoost optional.
2. Authentication & Upload Security
• JWT authentication, secure password hashing and RBAC roles ADMIN, ANALYST and VIEWER.
• Accept .pcap/.pcapng only after extension, MIME and structural validation; create randomized filenames and SHA-256
hashes.
• Treat PCAP as untrusted input. Process in an isolated non-root container with CPU, memory, timeout and filesystem
restrictions.
• Never store/display private keys, PSKs, passwords or other cryptographic secrets.
3. IPsec/IKE/ESP Analysis
• Detect IKE on UDP 500/4500, ESP protocol 50 and AH protocol 51; recognize NAT-T.
• Extract observable IKE version, SPIs, proposals, encryption, integrity, PRF, DH group, authentication indicators, SA
lifetime, traffic selectors and NAT-T.
• Analyze ESP SPI, sequence number, packet size/timing, direction, packet count and flow duration.
• Return Tunnel, Transport or Unknown only when evidence supports the conclusion, with confidence and evidence.
4. Security Rules Engine
• Use deterministic rules for crypto strength, integrity, DH, PFS, authentication, SA lifetime, replay protection and protocol
version.
• Support organization-configurable policies because acceptable algorithms differ by environment.
• Every property uses VERIFIED, POTENTIAL/INFERRED or NOT_OBSERVABLE.
5. Risk Engine
• Prototype weights: cryptography 25%, key exchange 15%, authentication 15%, PFS 15%, replay protection 10%, SA
configuration 10%, protocol 5%, metadata exposure 5%.
• Return a 0–100 score and risk level: Excellent, Good, Moderate, High Risk or Critical. Make weights configurable.
6. AI Traffic Classification
• Extract only aggregate metadata: packet/byte counts, packet-size statistics, flow duration, packets/sec, bytes/sec,
inter-arrival statistics, upload/download ratio, burst rate and direction ratio.
• Initial labels: ICMP-like, Web-like, VoIP-like, Video-like, Email-like and Other.
• Start with Random Forest; optionally benchmark XGBoost, Gradient Boosting or SVM.
• Return prediction + confidence; do not claim exact application identity when evidence supports only a traffic class.

7. Anomaly + Metadata Exposure
• Use Isolation Forest or equivalent for unusual rates, sizes, bursts, durations and direction ratios.
• Calculate metadata exposure for endpoint, timing, packet-size, traffic-volume and IKE metadata.
• Store evidence for every anomaly/finding.
8. Database + Reports
• Tables: users, analyses, captures, ipsec_sessions, ike_sessions, security_findings, traffic_predictions,
metadata_exposure, reports and audit_logs.
• Generate Executive PDF, Technical PDF and JSON.
• Executive report: score, risk, top findings, business impact and priorities. Technical report: capture, IPsec/IKE/ESP,
crypto, DH, PFS, replay, traffic, AI, metadata, evidence and recommendations.
9. Privacy-First Architecture
• Raw PCAP → local parser → aggregated features → local security rules + local ML → results.
• External AI services must not receive raw payloads, passwords, PSKs, private keys or unnecessary internal network
data.
• Delete temporary files according to retention policy and redact sensitive logs.
10. Reproducible VPN Testbed
• Secure case: IKEv2 + Tunnel + AES-256-GCM + strong DH + PFS ON + replay ON.
• Weak case: IKEv2 + Tunnel + AES-128-CBC/HMAC + weaker DH + PFS OFF.
• Transport case: Transport + AES-GCM + PFS ON + replay ON.
• Generate authorized ICMP, web-like TCP, DNS, email-like TCP, VoIP-like UDP and video-like UDP traffic; capture and
label each configuration.
11. Infrastructure & Docker
• Repository: frontend/; backend/app/{api,models,schemas,services,analyzers,security,ml,reports}; backend/tests/;
ml/{dataset,training,models,evaluation}; testbed/{tunnel,transport,ikev2,crypto,scripts}; docker/; docs/;
docker-compose.yml.
• docker-compose up should start frontend, backend, PostgreSQL, Redis and worker.
• Provide .env.example with DATABASE_URL, JWT_SECRET, REDIS_URL, MAX_PCAP_SIZE,
PCAP_RETENTION_MINUTES and MODEL_PATH. Never hard-code secrets.
12. Demo Mode
• Include Load Demo Analysis so judges can see the complete product without building a VPN.
• Demo target: score 82, IPsec detected, IKEv2, Tunnel, AES-256-GCM, PFS enabled, replay enabled, Video-like 91%
confidence and sample findings.
13. Testing & Hardening
• Test huge/malformed/invalid PCAPs, unauthorized API access, IDOR, SQL injection, XSS, rate abuse and invalid JWTs.
• Test parser CPU/memory exhaustion and resource limits.
• Privacy tests: no raw PCAP to external AI, no secrets stored, temporary-file deletion, authenticated APIs, restricted
database access and redacted logs.

• Use pytest for backend and Playwright for frontend. Test login, upload, analysis, result, findings, AI result and report
generation.
14. End-to-End Definition of Done
• Login → upload real PCAP/PCAPNG → validate → analyze → detect IPsec → inspect IKE/ESP → determine mode
where observable → assess crypto/PFS/DH/replay → classify traffic → detect anomalies → calculate metadata exposure
and security score → show threat matrix → recommendations → PDF report.
• The application must clearly distinguish verified facts from inferred and unobservable properties.
• Prototype target: PCAP up to ~100 MB, typical analysis ≤60 seconds depending on capture complexity, normal
dashboard API <500 ms, and at least 3 concurrent analysis jobs.
Recommended SIH Positioning
A privacy-preserving AI-assisted IPsec security assessment platform that analyzes VPN captures, evaluates
cryptographic and protocol configurations, detects security weaknesses, infers encrypted traffic behavior from
metadata, and produces explainable risk scores and security reports.
