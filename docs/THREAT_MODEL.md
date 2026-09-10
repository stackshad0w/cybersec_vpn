# Threat Model & Security Posture — IPsec VPN Analyzer

## 1. Assets
- Uploaded packet captures (.pcap, .pcapng)
- Extracted cryptographic parameters and network telemetry
- Security findings, risk assessments, and forensic reports
- User authentication credentials and JWT secrets

## 2. Threat Actors & Scenarios
- **Untrusted User Uploading Malformed PCAPs**:
  - *Threat*: Buffer overflow, infinite parse loops, decompression bombs, or file header tampering.
  - *Mitigation*: Multi-stage structural validation (magic byte checks, max file size enforcement 100 MB, memory and execution timeouts, non-root isolated container execution).
- **Passive Wiretapper / Network Observer**:
  - *Threat*: Eavesdropping on encrypted VPN tunnels using packet-size analysis, burst patterns, or timing correlation to reveal application identity (video streaming, VoIP, web).
  - *Mitigation*: AI Traffic Classifier and Metadata Exposure Engine quantify side-channel leak indices and prescribe Traffic Flow Confidentiality (TFC padding) to neutralize leakage.
- **Replay Attack Injection**:
  - *Threat*: Re-injecting captured valid IPsec ESP packets to disrupt session state or replay encrypted commands.
  - *Mitigation*: Anti-Replay engine checks monotonic sequence numbers and detects duplicate ESP sequence counters.
- **Cryptographic Weakness Exploitation**:
  - *Threat*: Use of deprecated algorithms (DES, 3DES, MD5, Diffie-Hellman Group 1/2) vulnerable to Sweet32, Logjam, or precomputation attacks.
  - *Mitigation*: Deterministic Rules Engine flags deprecated ciphers as CRITICAL/HIGH risk and generates exact Cisco/StrongSwan upgrade commands.

## 3. RBAC Permissions Matrix
| Action | Admin | Analyst | Viewer |
|---|---|---|---|
| Upload Captures | Yes | Yes | No |
| View Analyses & Reports | Yes | Yes | Yes |
| Download PDFs / JSON | Yes | Yes | Yes |
| Re-run Analyses | Yes | Yes | No |
| Update Security Policies & Weights | Yes | No | No |
| Delete Analyses | Yes | No | No |
