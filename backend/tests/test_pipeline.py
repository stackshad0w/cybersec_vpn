import os
from pathlib import Path
import pytest
from backend.app.analyzers.pcap_parser import PCAPParser
from backend.app.analyzers.ike_parser import IKEParser
from backend.app.analyzers.esp_analyzer import ESPAnalyzer
from backend.app.analyzers.feature_extractor import FeatureExtractor
from backend.app.security.rules_engine import SecurityRulesEngine
from backend.app.security.risk_calculator import RiskCalculator
from backend.app.ml.traffic_classifier import TrafficClassifier
from backend.app.ml.anomaly_detector import AnomalyDetector
from backend.app.ml.metadata_exposure import MetadataExposureCalculator
from backend.app.services.demo_service import DemoService
from backend.app.models.analysis import RiskLevel

BASE_DIR = Path(__file__).resolve().parent.parent.parent
TEST_PCAP_DIR = BASE_DIR / "testbed" / "pcaps"

def test_pcap_validation_valid():
    secure_pcap = str(TEST_PCAP_DIR / "secure_ikev2_tunnel.pcap")
    assert os.path.exists(secure_pcap)
    val = PCAPParser.validate_file(secure_pcap)
    assert val["valid"] is True
    assert val["format"] in ("pcap", "pcapng")
    assert len(val["sha256"]) == 64

def test_pcap_validation_invalid(tmp_path):
    # Create fake invalid file
    bad_file = tmp_path / "fake.pcap"
    bad_file.write_bytes(b"INVALID_HEADER_DATA_12345")
    val = PCAPParser.validate_file(str(bad_file))
    assert val["valid"] is False
    assert "Invalid capture magic" in val["error"]

def test_secure_ikev2_parsing():
    secure_pcap = str(TEST_PCAP_DIR / "secure_ikev2_tunnel.pcap")
    packets = PCAPParser.parse_packets(secure_pcap)
    assert len(packets) > 0

    ike_packets = [p for p in packets if IKEParser.is_ike_packet(p)]
    assert len(ike_packets) >= 1
    ike_info = IKEParser.parse_ike_payload(ike_packets[0].raw_payload, is_nat_t=True)
    assert ike_info is not None
    assert ike_info["version"] == "IKEv2"
    assert ike_info["proposals"]["dh_group_num"] == 19

    esp_packets = [p for p in packets if ESPAnalyzer.is_esp_packet(p)]
    assert len(esp_packets) >= 10
    esp_flows = ESPAnalyzer.analyze_esp_flows(esp_packets)
    assert len(esp_flows) >= 1
    flow = esp_flows[0]
    assert flow["mode"] == "Tunnel"
    assert flow["replay_protection_enabled"] is True
    assert flow["duplicate_sequences_count"] == 0

def test_security_rules_and_risk_scoring():
    ike_sessions = [{
        "version": "IKEv2",
        "encryption_algorithm": "AES-256-GCM",
        "integrity_algorithm": "HMAC-SHA256",
        "dh_group": "Group 19 (256-bit ECP)",
        "dh_group_number": 19,
        "pfs_enabled": True
    }]
    esp_sessions = [{
        "duplicate_sequences_count": 0,
        "packet_count": 100,
        "max_sequence_number": 100
    }]
    rule_results = SecurityRulesEngine.evaluate(ike_sessions, esp_sessions)
    score, risk_lvl, dim_scores = RiskCalculator.calculate_score(rule_results)
    
    assert score >= 80.0
    assert risk_lvl in (RiskLevel.EXCELLENT, RiskLevel.GOOD)

def test_weak_ikev1_scoring():
    ike_sessions = [{
        "version": "IKEv1",
        "exchange_type": 4, # Aggressive mode
        "encryption_algorithm": "3DES-CBC",
        "integrity_algorithm": "HMAC-MD5-96",
        "dh_group": "Group 2 (1024-bit)",
        "dh_group_number": 2,
        "pfs_enabled": False
    }]
    esp_sessions = [{
        "duplicate_sequences_count": 5, # replay attack
        "packet_count": 50,
        "max_sequence_number": 50
    }]
    rule_results = SecurityRulesEngine.evaluate(ike_sessions, esp_sessions)
    score, risk_lvl, dim_scores = RiskCalculator.calculate_score(rule_results)
    
    assert score < 50.0
    assert risk_lvl in (RiskLevel.HIGH_RISK, RiskLevel.CRITICAL)

def test_ml_traffic_classifier():
    features = {
        "packet_count": 1200,
        "byte_count": 1_600_000,
        "flow_duration": 30.0,
        "pkt_size_min": 80.0,
        "pkt_size_max": 1500.0,
        "pkt_size_mean": 1330.0,
        "pkt_size_std": 320.0,
        "pkt_size_median": 1420.0,
        "packets_per_sec": 40.0,
        "bytes_per_sec": 53333.0,
        "inter_arrival_mean": 0.025,
        "inter_arrival_std": 0.015,
        "upload_download_ratio": 0.09,
        "direction_ratio": 0.08,
        "burst_rate": 150.0
    }
    pred = TrafficClassifier.classify_traffic(features)
    assert pred["predicted_class"] == "Video-like"
    assert pred["confidence_score"] >= 0.80

def test_demo_endpoint(client):
    res = client.post("/api/v1/demo/load")
    assert res.status_code == 200
    data = res.json()
    assert data["security_score"] == 82.0
    assert data["risk_level"] == "Good"
    assert data["traffic_prediction"]["predicted_class"] == "Video-like"
    assert data["traffic_prediction"]["confidence_score"] == 0.91

def test_pdf_report_downloads(client):
    # Ensure demo is loaded
    demo_res = client.post("/api/v1/demo/load")
    analysis_id = demo_res.json()["id"]

    exec_res = client.get(f"/api/v1/analyses/{analysis_id}/reports/executive.pdf")
    assert exec_res.status_code == 200
    assert exec_res.headers["content-type"] == "application/pdf"
    assert len(exec_res.content) > 1000

    tech_res = client.get(f"/api/v1/analyses/{analysis_id}/reports/technical.pdf")
    assert tech_res.status_code == 200
    assert tech_res.headers["content-type"] == "application/pdf"
    assert len(tech_res.content) > 1000

    json_res = client.get(f"/api/v1/analyses/{analysis_id}/reports/export.json")
    assert json_res.status_code == 200
    assert json_res.headers["content-type"] == "application/json"

def test_testbed_scenario_loading(client):
    res_secure = client.post("/api/v1/demo/scenario/secure_ikev2")
    assert res_secure.status_code == 200
    data_secure = res_secure.json()
    assert data_secure["security_score"] >= 75
    assert len(data_secure["ipsec_sessions"]) >= 1

    res_weak = client.post("/api/v1/demo/scenario/weak_ikev1")
    assert res_weak.status_code == 200
    data_weak = res_weak.json()
    assert data_weak["security_score"] < 60
    assert data_weak["risk_level"] in ("High Risk", "Critical")
    # Verify replay violations or weak crypto finding
    finding_titles = [f["title"] for f in data_weak["findings"]]
    assert any("3DES" in t or "Replay" in t or "Diffie-Hellman" in t or "IKEv1" in t for t in finding_titles)

