# REST API Specification — CyberSec IPsec VPN Analyzer

Base URL: `http://localhost:8000/api/v1`

## Endpoints

### 1. Authentication
- `POST /auth/register`: Create new user (Role: ADMIN, ANALYST, VIEWER)
- `POST /auth/login`: Authenticate and receive Bearer JWT token
- `GET /auth/me`: Current user profile

### 2. PCAP Upload & Ingestion
- `POST /upload`: Multipart upload of `.pcap` or `.pcapng`
  - Validates magic bytes (`0xa1b2c3d4`, `0x0a0d0d0a`)
  - Verifies file size limit (default 100 MB)
  - Computes SHA-256 hash
  - Optionally auto-runs analysis pipeline

### 3. Analyses Management
- `GET /analyses`: List all analyses (paginated, status filter)
- `GET /analyses/{id}`: Detailed analysis results with sessions, findings, AI prediction, and metadata exposure
- `POST /analyses/{id}/run`: Trigger or re-run analysis
- `DELETE /analyses/{id}`: Delete analysis and cleanup disk capture

### 4. Demo Mode
- `POST /demo/load`: Instantly loads PRD target demo analysis
  - Score: 82 (Good)
  - Protocol: IKEv2
  - Mode: Tunnel
  - Cipher: AES-256-GCM
  - DH: Group 19 (256-bit ECP)
  - PFS: Enabled (VERIFIED)
  - Replay: Enabled (VERIFIED)
  - AI: Video-like (91% confidence)

### 5. Report Downloads
- `GET /analyses/{id}/reports/executive.pdf`: Download Executive Summary PDF
- `GET /analyses/{id}/reports/technical.pdf`: Download Full Forensic Technical Audit PDF
- `GET /analyses/{id}/reports/export.json`: Structured JSON forensic export

### 6. Security Policies
- `GET /policies`: Retrieve active security rules and risk weights
- `PUT /policies`: Update category weights and cipher requirements (Admin only)
