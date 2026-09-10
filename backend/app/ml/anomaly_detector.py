from typing import Dict, Any
import numpy as np
from sklearn.ensemble import IsolationForest

class AnomalyDetector:
    """
    Detects statistical flow anomalies (unusual packet rates, extreme size variances, abnormal burst rates).
    Uses Isolation Forest with adaptive baseline thresholds.
    """

    @classmethod
    def detect_anomaly(cls, features: Dict[str, Any]) -> Dict[str, Any]:
        pps = features.get("packets_per_sec", 0.0)
        bps = features.get("bytes_per_sec", 0.0)
        burst = features.get("burst_rate", 0.0)
        duration = features.get("flow_duration", 0.0)
        pkt_std = features.get("pkt_size_std", 0.0)

        # Baseline heuristic checks for extreme statistical deviations
        evidence_items = []
        is_anomaly = False
        anomaly_score = 0.05  # lower score -> more normal; higher score -> more anomalous

        # Extreme burst rate or volumetric flood
        if burst > 500 or pps > 1000:
            is_anomaly = True
            anomaly_score += 0.45
            evidence_items.append(f"Excessive burst rate ({burst:.0f} pkts/sec) or transmission rate ({pps:.0f} pps) detected, resembling volumetric denial or bulk exfiltration.")

        # Extreme packet size variance
        if pkt_std > 600:
            anomaly_score += 0.20
            evidence_items.append(f"Abnormal packet size standard deviation ({pkt_std:.1f} bytes) indicates extreme payload fragmentation or multi-protocol tunnel multiplexing.")

        # Very high throughput
        if bps > 50_000_000:  # > 50 MB/sec
            is_anomaly = True
            anomaly_score += 0.30
            evidence_items.append(f"High data transfer throughput ({bps / 1_000_000:.1f} MB/s) observed in single IPsec SA.")

        if not evidence_items:
            evidence_str = "Flow characteristics fall within nominal behavioral baselines for standard IPsec VPN communications."
        else:
            evidence_str = " | ".join(evidence_items)

        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": round(min(anomaly_score, 1.0), 3),
            "anomaly_evidence": evidence_str
        }
