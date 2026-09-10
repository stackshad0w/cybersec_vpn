import json
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from backend.app.models.analysis import Analysis, AnalysisStatus, RiskLevel
from backend.app.models.capture import CaptureFile
from backend.app.models.ipsec import IPsecSession, IKESession, EvidenceStatus, IPsecMode
from backend.app.models.finding import SecurityFinding, FindingSeverity, FindingCategory
from backend.app.models.ml import TrafficPrediction
from backend.app.models.metadata import MetadataExposure
from backend.app.services.analysis_service import AnalysisService

class DemoService:
    """
    Implements PRD-compliant Demo Mode:
    - Overall Score: 82 (Good)
    - Protocol: IKEv2
    - Mode: Tunnel
    - Cipher: AES-256-GCM
    - DH: Group 19 (256-bit ECP)
    - PFS: Enabled (VERIFIED)
    - Anti-Replay: Enabled (VERIFIED, sequence 1-1420)
    - AI Classification: Video-like (91% confidence)
    - Actionable security findings and pre-generated Executive/Technical PDF reports.
    """

    @classmethod
    def load_demo_analysis(cls, db: Session, user_id: int = None) -> Analysis:
        # Check if demo analysis already exists
        existing_demo = db.query(Analysis).filter(Analysis.is_demo == 1).order_by(Analysis.id.desc()).first()
        if existing_demo and existing_demo.status == AnalysisStatus.COMPLETED:
            return existing_demo

        # Create virtual capture file
        demo_capture = CaptureFile(
            original_filename="demo_enterprise_vpn_ikev2_aes_gcm.pcapng",
            stored_filename="demo_enterprise_vpn_ikev2_aes_gcm_demo.pcapng",
            file_path="uploads/demo_enterprise_vpn_ikev2_aes_gcm_demo.pcapng",
            file_size=2_458_112,  # ~2.4 MB
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            file_format="pcapng",
            packet_count=1850,
            duration_seconds=42.5
        )
        db.add(demo_capture)
        db.flush()

        # Create Demo Analysis with Target PRD Score: 82 (RiskLevel.GOOD)
        analysis = Analysis(
            title="Enterprise Site-to-Site Gateway (Demo Capture)",
            status=AnalysisStatus.COMPLETED,
            security_score=82.0,
            risk_level=RiskLevel.GOOD,
            processing_time_seconds=1.42,
            is_demo=1,
            user_id=user_id,
            capture_id=demo_capture.id,
            completed_at=datetime.now(timezone.utc)
        )
        db.add(analysis)
        db.flush()

        # IKE Session (IKEv2, AES-256-GCM, DH Group 19, PFS ON, NAT-T active)
        ike_session = IKESession(
            analysis_id=analysis.id,
            version="IKEv2",
            initiator_spi="a4f210d3e5b78912",
            responder_spi="98c4b1a2f6e54321",
            encryption_algorithm="AES-256-GCM",
            integrity_algorithm="AEAD-AUTH",
            prf_algorithm="PRF_HMAC_SHA2_256",
            dh_group="Group 19 (256-bit Random ECP)",
            dh_group_number=19,
            pfs_enabled=True,
            pfs_status=EvidenceStatus.VERIFIED.value,
            auth_method="Digital Signature (RSA-PSS / ECDSA)",
            auth_status=EvidenceStatus.VERIFIED.value,
            nat_traversal_detected=True,
            nat_t_status=EvidenceStatus.VERIFIED.value,
            sa_lifetime_seconds=28800,
            traffic_selectors="TSi: 10.100.0.0/16 <-> TSr: 172.16.0.0/16",
            evidence="Observed IKE_SA_INIT (Exchange 34) and CREATE_CHILD_SA (Exchange 36) with explicit DH-19 transform."
        )
        db.add(ike_session)

        # IPsec ESP Session (Tunnel Mode, Anti-replay enabled, Sequence monotonic 1-1850)
        esp_session = IPsecSession(
            analysis_id=analysis.id,
            protocol="ESP",
            mode=IPsecMode.TUNNEL.value,
            mode_confidence=0.96,
            mode_evidence="Observed ESP flow over UDP 4500 encapsulation with outer gateway IPs (203.0.113.15 -> 198.51.100.4) routing private subnets. Encapsulated inner datagram structures confirmed.",
            src_ip="203.0.113.15",
            dst_ip="198.51.100.4",
            spi_inbound="0x7f3a910c",
            spi_outbound="0x12d4e8b0",
            packet_count=1850,
            total_bytes=2_412_000,
            replay_protection_enabled=True,
            replay_protection_status=EvidenceStatus.VERIFIED.value,
            min_sequence_number=1,
            max_sequence_number=1850,
            duplicate_sequences_count=0,
            out_of_order_count=0
        )
        db.add(esp_session)

        # PRD Target Findings
        findings = [
            SecurityFinding(
                analysis_id=analysis.id,
                title="Strong Modern Cryptography: Authenticated AES-256-GCM",
                category=FindingCategory.CRYPTOGRAPHY,
                severity=FindingSeverity.INFO,
                evidence_status=EvidenceStatus.VERIFIED.value,
                evidence="Observed AES-256-GCM AEAD encryption transform in IKEv2 proposal.",
                impact="Provides confidentiality with built-in hardware-accelerated integrity protection.",
                recommendation="Maintain current AEAD cipher suite across all peer configurations.",
                remediation_command=None
            ),
            SecurityFinding(
                analysis_id=analysis.id,
                title="Elliptic Curve Diffie-Hellman Group 19 Validated",
                category=FindingCategory.KEY_EXCHANGE,
                severity=FindingSeverity.INFO,
                evidence_status=EvidenceStatus.VERIFIED.value,
                evidence="Key exchange uses NIST P-256 (Group 19) ECP.",
                impact="Ensures ~128-bit symmetric security level with strong resistance against cryptanalysis.",
                recommendation="Group 19 is fully compliant with modern NSA Suite B / CNSA requirements.",
                remediation_command=None
            ),
            SecurityFinding(
                analysis_id=analysis.id,
                title="Perfect Forward Secrecy (PFS) Confirmed",
                category=FindingCategory.PFS,
                severity=FindingSeverity.INFO,
                evidence_status=EvidenceStatus.VERIFIED.value,
                evidence="Child SA re-key exchanges explicitly contain new ephemeral DH public values.",
                impact="Compromise of static gateway identities cannot decrypt previously captured sessions.",
                recommendation="Retain strict PFS enforcement.",
                remediation_command=None
            ),
            SecurityFinding(
                analysis_id=analysis.id,
                title="Anti-Replay Window Verification Passed",
                category=FindingCategory.REPLAY_PROTECTION,
                severity=FindingSeverity.INFO,
                evidence_status=EvidenceStatus.VERIFIED.value,
                evidence="ESP sequence numbers increment strictly monotonically (1 through 1850) with 0 duplicate packets.",
                impact="Prevents malicious injection of captured replayed packets into the protected network.",
                recommendation="Continue enforcing standard anti-replay window sizes (≥64 packets).",
                remediation_command=None
            ),
            SecurityFinding(
                analysis_id=analysis.id,
                title="Side-Channel Leak: Video Streaming Size Distribution Leaked",
                category=FindingCategory.METADATA_LEAK,
                severity=FindingSeverity.MEDIUM,
                evidence_status=EvidenceStatus.POTENTIAL_INFERRED.value,
                evidence="ESP packet size standard deviation (362.4 bytes) reveals variable-bitrate video chunk boundaries despite encryption.",
                impact="Passive network adversaries can fingerprint encrypted streaming video services without decrypting payload.",
                recommendation="Enable IPsec ESP packet padding / Traffic Flow Confidentiality (TFC) per RFC 4303.",
                remediation_command="Cisco: crypto ipsec security-association tfc / strongSwan: tfc = 1400"
            ),
            SecurityFinding(
                analysis_id=analysis.id,
                title="Long SA Lifetime Warning (28,800s / 8 Hours)",
                category=FindingCategory.SA_LIFETIME,
                severity=FindingSeverity.LOW,
                evidence_status=EvidenceStatus.VERIFIED.value,
                evidence="Configured SA duration is 8 hours (28,800 seconds).",
                impact="Acceptable for enterprise baseline, but high-assurance environments recommend 4-hour re-keying.",
                recommendation="Consider shortening SA re-key threshold to 14,400s (4 hours) or 10 GB transferred volume.",
                remediation_command="strongSwan: lifetime = 4h / Cisco: crypto ipsec security-association lifetime seconds 14400"
            ),
        ]
        for f in findings:
            db.add(f)

        # AI Traffic Prediction: Video-like 91% Confidence (Exact PRD Target)
        demo_features = {
            "packet_count": 1850,
            "byte_count": 2_412_000,
            "flow_duration": 42.5,
            "pkt_size_min": 78.0,
            "pkt_size_max": 1500.0,
            "pkt_size_mean": 1303.8,
            "pkt_size_std": 362.4,
            "pkt_size_median": 1420.0,
            "packets_per_sec": 43.5,
            "bytes_per_sec": 56752.9,
            "inter_arrival_mean": 0.0229,
            "inter_arrival_std": 0.0142,
            "upload_download_ratio": 0.082,
            "direction_ratio": 0.076,
            "burst_rate": 182.0
        }
        traffic_pred = TrafficPrediction(
            analysis_id=analysis.id,
            predicted_class="Video-like",
            confidence_score=0.91,  # 91% per PRD target
            secondary_class="Web-like",
            secondary_confidence=0.07,
            explanation="Classified as Video-like with 91.0% confidence based on high average packet size (1303.8 bytes), high throughput bursts (182 pkts/s), and asymmetric download streaming ratio (0.08).",
            features_json=json.dumps(demo_features),
            packet_count=1850,
            byte_count=2_412_000,
            flow_duration=42.5,
            packets_per_sec=43.5,
            bytes_per_sec=56752.9,
            mean_packet_size=1303.8,
            upload_download_ratio=0.082,
            burst_rate=182.0,
            is_anomaly=False,
            anomaly_score=0.08,
            anomaly_evidence="Flow characteristics fall within nominal behavioral baselines for standard IPsec VPN communications."
        )
        db.add(traffic_pred)

        # Metadata Exposure
        meta_exp = MetadataExposure(
            analysis_id=analysis.id,
            endpoint_exposure_score=45.0,
            timing_exposure_score=35.0,
            packet_size_exposure_score=78.0,
            volume_exposure_score=65.0,
            ike_exposure_score=25.0,
            overall_exposure_score=52.0,
            endpoint_evidence="Public gateway addresses visible on outer IP headers. NAT-T markers present on UDP 4500.",
            timing_evidence="Inter-packet arrival time reflects periodic video chunk rendering bursts.",
            packet_size_evidence="High packet size variance (std: 362.4 bytes) exposes variable-bitrate video chunk boundaries.",
            volume_evidence="Strong download asymmetry (0.082 upload/download ratio) reveals heavy video data consumption.",
            ike_evidence="IKEv2 protocol securely shields authentication identities under encrypted SK payloads."
        )
        db.add(meta_exp)

        db.commit()

        # Automatically generate Executive and Technical PDF reports for this demo
        AnalysisService.generate_reports_for_analysis(db, analysis)

        return analysis
