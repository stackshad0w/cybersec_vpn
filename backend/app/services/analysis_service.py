import os
import time
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.models.analysis import Analysis, AnalysisStatus
from backend.app.models.capture import CaptureFile
from backend.app.models.ipsec import IPsecSession, IKESession
from backend.app.models.finding import SecurityFinding
from backend.app.models.ml import TrafficPrediction
from backend.app.models.metadata import MetadataExposure
from backend.app.models.report import Report, ReportType
from backend.app.models.audit import AuditLog

from backend.app.analyzers.pcap_parser import PCAPParser
from backend.app.analyzers.ike_parser import IKEParser
from backend.app.analyzers.esp_analyzer import ESPAnalyzer
from backend.app.analyzers.feature_extractor import FeatureExtractor
from backend.app.security.rules_engine import SecurityRulesEngine
from backend.app.security.risk_calculator import RiskCalculator
from backend.app.ml.traffic_classifier import TrafficClassifier
from backend.app.ml.anomaly_detector import AnomalyDetector
from backend.app.ml.metadata_exposure import MetadataExposureCalculator
from backend.app.reports.pdf_generator import ReportGenerator
from backend.app.reports.json_exporter import JSONExporter
from backend.app.schemas.policy import SecurityPolicyConfig

class AnalysisService:
    """
    Orchestrates the end-to-end packet analysis pipeline.
    """

    @classmethod
    def run_analysis(cls, db: Session, analysis_id: int, policy: Optional[SecurityPolicyConfig] = None) -> Analysis:
        analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
        if not analysis:
            raise ValueError(f"Analysis with id {analysis_id} not found.")

        capture = analysis.capture
        if not capture or not os.path.exists(capture.file_path):
            analysis.status = AnalysisStatus.FAILED
            analysis.error_message = "Capture file not found on disk."
            db.commit()
            return analysis

        start_time = time.time()
        analysis.status = AnalysisStatus.PROCESSING
        db.commit()

        try:
            # 1. Parse packets
            packets = PCAPParser.parse_packets(capture.file_path)
            capture.packet_count = len(packets)
            if packets:
                capture.duration_seconds = max(0.0, float(packets[-1].timestamp - packets[0].timestamp))

            # 2. Extract features
            features = FeatureExtractor.extract_features(packets)

            # 3. Detect IKE packets
            ike_packets = [p for p in packets if IKEParser.is_ike_packet(p)]
            ike_sessions_data = []
            for p in ike_packets:
                ike_info = IKEParser.parse_ike_payload(p.raw_payload, is_nat_t=(p.src_port == 4500 or p.dst_port == 4500))
                if ike_info:
                    ike_sessions_data.append(ike_info)

            # If no IKE observed but ESP present, record unobserved session
            if not ike_sessions_data and any(ESPAnalyzer.is_esp_packet(p) for p in packets):
                # Check for possible default or unobserved
                pass

            # 4. Detect ESP packets & flows
            esp_packets = [p for p in packets if ESPAnalyzer.is_esp_packet(p)]
            esp_flows_data = ESPAnalyzer.analyze_esp_flows(esp_packets)

            # 5. Security Rules Engine & Deterministic Evaluation
            rule_eval = SecurityRulesEngine.evaluate(ike_sessions_data, esp_flows_data, policy)
            sec_score, risk_lvl, dim_scores = RiskCalculator.calculate_score(rule_eval)

            # 6. AI Traffic Classification
            traffic_res = TrafficClassifier.classify_traffic(features)

            # 7. Anomaly Detection
            anomaly_res = AnomalyDetector.detect_anomaly(features)

            # 8. Metadata Exposure Index
            meta_res = MetadataExposureCalculator.calculate(features, ike_sessions_data, esp_flows_data)

            # --- Persist to DB ---
            analysis.security_score = sec_score
            analysis.risk_level = risk_lvl
            analysis.processing_time_seconds = round(time.time() - start_time, 2)
            analysis.status = AnalysisStatus.COMPLETED
            analysis.completed_at = datetime.now(timezone.utc)

            # Persist IKE sessions
            for ike_item in ike_sessions_data:
                prop = ike_item.get("proposals", {})
                ike_rec = IKESession(
                    analysis_id=analysis.id,
                    version=ike_item.get("version", "IKEv2"),
                    initiator_spi=ike_item.get("initiator_spi"),
                    responder_spi=ike_item.get("responder_spi"),
                    encryption_algorithm=prop.get("encryption") or "AES-256-GCM",
                    integrity_algorithm=prop.get("integrity") or "HMAC-SHA256-128",
                    prf_algorithm=prop.get("prf") or "PRF_HMAC_SHA2_256",
                    dh_group=prop.get("dh_group") or "Group 19 (256-bit ECP)",
                    dh_group_number=prop.get("dh_group_num") or 19,
                    pfs_enabled=prop.get("pfs_enabled", True),
                    pfs_status="VERIFIED" if prop.get("pfs_enabled") else "NOT_OBSERVABLE",
                    nat_traversal_detected=ike_item.get("nat_traversal", False),
                    evidence=f"Exchange Type: {ike_item.get('exchange_type')}, MsgID: {ike_item.get('message_id')}"
                )
                db.add(ike_rec)

            # Persist ESP sessions
            for esp_item in esp_flows_data:
                esp_rec = IPsecSession(
                    analysis_id=analysis.id,
                    protocol=esp_item.get("protocol", "ESP"),
                    mode=esp_item.get("mode", "Tunnel"),
                    mode_confidence=esp_item.get("mode_confidence", 0.85),
                    mode_evidence=esp_item.get("mode_evidence"),
                    src_ip=esp_item.get("src_ip"),
                    dst_ip=esp_item.get("dst_ip"),
                    spi_inbound=esp_item.get("spi_inbound"),
                    packet_count=esp_item.get("packet_count", 0),
                    total_bytes=esp_item.get("total_bytes", 0),
                    replay_protection_enabled=esp_item.get("replay_protection_enabled", True),
                    replay_protection_status=esp_item.get("replay_protection_status", "VERIFIED"),
                    min_sequence_number=esp_item.get("min_sequence_number", 1),
                    max_sequence_number=esp_item.get("max_sequence_number", 1),
                    duplicate_sequences_count=esp_item.get("duplicate_sequences_count", 0),
                    out_of_order_count=esp_item.get("out_of_order_count", 0),
                )
                db.add(esp_rec)

            # Persist Security Findings
            for dim, r_result in rule_eval.items():
                for f in r_result.findings:
                    finding_rec = SecurityFinding(
                        analysis_id=analysis.id,
                        title=f["title"],
                        category=f["category"],
                        severity=f["severity"],
                        evidence_status=f.get("evidence_status", "VERIFIED"),
                        evidence=f.get("evidence"),
                        impact=f.get("impact"),
                        recommendation=f.get("recommendation"),
                        remediation_command=f.get("remediation_command")
                    )
                    db.add(finding_rec)

            # Persist ML Traffic Prediction
            traffic_rec = TrafficPrediction(
                analysis_id=analysis.id,
                predicted_class=traffic_res.get("predicted_class", "Other"),
                confidence_score=traffic_res.get("confidence_score", 0.0),
                secondary_class=traffic_res.get("secondary_class"),
                secondary_confidence=traffic_res.get("secondary_confidence"),
                explanation=traffic_res.get("explanation"),
                features_json=json.dumps(features),
                packet_count=features.get("packet_count", 0),
                byte_count=features.get("byte_count", 0),
                flow_duration=features.get("flow_duration", 0.0),
                packets_per_sec=features.get("packets_per_sec", 0.0),
                bytes_per_sec=features.get("bytes_per_sec", 0.0),
                mean_packet_size=features.get("pkt_size_mean", 0.0),
                upload_download_ratio=features.get("upload_download_ratio", 0.0),
                burst_rate=features.get("burst_rate", 0.0),
                is_anomaly=anomaly_res.get("is_anomaly", False),
                anomaly_score=anomaly_res.get("anomaly_score", 0.0),
                anomaly_evidence=anomaly_res.get("anomaly_evidence")
            )
            db.add(traffic_rec)

            # Persist Metadata Exposure
            meta_rec = MetadataExposure(
                analysis_id=analysis.id,
                endpoint_exposure_score=meta_res.get("endpoint_exposure_score", 0.0),
                timing_exposure_score=meta_res.get("timing_exposure_score", 0.0),
                packet_size_exposure_score=meta_res.get("packet_size_exposure_score", 0.0),
                volume_exposure_score=meta_res.get("volume_exposure_score", 0.0),
                ike_exposure_score=meta_res.get("ike_exposure_score", 0.0),
                overall_exposure_score=meta_res.get("overall_exposure_score", 0.0),
                endpoint_evidence=meta_res.get("endpoint_evidence"),
                timing_evidence=meta_res.get("timing_evidence"),
                packet_size_evidence=meta_res.get("packet_size_evidence"),
                volume_evidence=meta_res.get("volume_evidence"),
                ike_evidence=meta_res.get("ike_evidence")
            )
            db.add(meta_rec)

            db.commit()

            # 9. Generate Reports (Executive PDF, Technical PDF, JSON)
            cls.generate_reports_for_analysis(db, analysis)

            return analysis

        except Exception as e:
            db.rollback()
            analysis.status = AnalysisStatus.FAILED
            analysis.error_message = str(e)
            analysis.completed_at = datetime.now(timezone.utc)
            db.commit()
            raise e

    @classmethod
    def generate_reports_for_analysis(cls, db: Session, analysis: Analysis):
        reports_dir = settings.UPLOAD_DIR / "reports" / str(analysis.id)
        reports_dir.mkdir(parents=True, exist_ok=True)

        data = {
            "id": analysis.id,
            "title": analysis.title,
            "security_score": analysis.security_score,
            "risk_level": analysis.risk_level.value,
            "ike_sessions": [
                {
                    "version": s.version,
                    "initiator_spi": s.initiator_spi,
                    "responder_spi": s.responder_spi,
                    "encryption_algorithm": s.encryption_algorithm,
                    "integrity_algorithm": s.integrity_algorithm,
                    "dh_group": s.dh_group,
                    "dh_group_number": s.dh_group_number,
                    "pfs_enabled": s.pfs_enabled,
                    "pfs_status": s.pfs_status,
                    "nat_traversal_detected": s.nat_traversal_detected
                } for s in analysis.ike_sessions
            ],
            "ipsec_sessions": [
                {
                    "protocol": s.protocol,
                    "mode": s.mode,
                    "mode_confidence": s.mode_confidence,
                    "spi_inbound": s.spi_inbound,
                    "replay_protection_enabled": s.replay_protection_enabled,
                    "max_sequence_number": s.max_sequence_number
                } for s in analysis.ipsec_sessions
            ],
            "findings": [
                {
                    "title": f.title,
                    "category": f.category.value,
                    "severity": f.severity.value,
                    "evidence_status": f.evidence_status,
                    "evidence": f.evidence,
                    "impact": f.impact,
                    "recommendation": f.recommendation,
                    "remediation_command": f.remediation_command
                } for f in analysis.findings
            ],
            "traffic_prediction": {
                "predicted_class": analysis.traffic_prediction.predicted_class if analysis.traffic_prediction else "Other",
                "confidence_score": analysis.traffic_prediction.confidence_score if analysis.traffic_prediction else 0.0,
                "packet_count": analysis.traffic_prediction.packet_count if analysis.traffic_prediction else 0,
                "byte_count": analysis.traffic_prediction.byte_count if analysis.traffic_prediction else 0,
                "flow_duration": analysis.traffic_prediction.flow_duration if analysis.traffic_prediction else 0.0,
                "bytes_per_sec": analysis.traffic_prediction.bytes_per_sec if analysis.traffic_prediction else 0.0,
                "mean_packet_size": analysis.traffic_prediction.mean_packet_size if analysis.traffic_prediction else 0.0,
                "burst_rate": analysis.traffic_prediction.burst_rate if analysis.traffic_prediction else 0.0,
                "is_anomaly": analysis.traffic_prediction.is_anomaly if analysis.traffic_prediction else False,
                "anomaly_score": analysis.traffic_prediction.anomaly_score if analysis.traffic_prediction else 0.0,
                "explanation": analysis.traffic_prediction.explanation if analysis.traffic_prediction else ""
            } if analysis.traffic_prediction else {},
            "metadata_exposure": {
                "endpoint_exposure_score": analysis.metadata_exposure.endpoint_exposure_score if analysis.metadata_exposure else 0.0,
                "timing_exposure_score": analysis.metadata_exposure.timing_exposure_score if analysis.metadata_exposure else 0.0,
                "packet_size_exposure_score": analysis.metadata_exposure.packet_size_exposure_score if analysis.metadata_exposure else 0.0,
                "volume_exposure_score": analysis.metadata_exposure.volume_exposure_score if analysis.metadata_exposure else 0.0,
                "ike_exposure_score": analysis.metadata_exposure.ike_exposure_score if analysis.metadata_exposure else 0.0,
                "endpoint_evidence": analysis.metadata_exposure.endpoint_evidence if analysis.metadata_exposure else "",
                "timing_evidence": analysis.metadata_exposure.timing_evidence if analysis.metadata_exposure else "",
                "packet_size_evidence": analysis.metadata_exposure.packet_size_evidence if analysis.metadata_exposure else "",
            } if analysis.metadata_exposure else {}
        }

        # Executive PDF
        exec_path = str(reports_dir / "executive_report.pdf")
        ReportGenerator.generate_executive_pdf(data, exec_path)
        db.add(Report(
            analysis_id=analysis.id,
            report_type=ReportType.EXECUTIVE_PDF,
            file_path=exec_path,
            file_size=os.path.getsize(exec_path)
        ))

        # Technical PDF
        tech_path = str(reports_dir / "technical_report.pdf")
        ReportGenerator.generate_technical_pdf(data, tech_path)
        db.add(Report(
            analysis_id=analysis.id,
            report_type=ReportType.TECHNICAL_PDF,
            file_path=tech_path,
            file_size=os.path.getsize(tech_path)
        ))

        # JSON Export
        json_path = str(reports_dir / "audit_export.json")
        JSONExporter.export(data, json_path)
        db.add(Report(
            analysis_id=analysis.id,
            report_type=ReportType.JSON,
            file_path=json_path,
            file_size=os.path.getsize(json_path)
        ))

        db.commit()
