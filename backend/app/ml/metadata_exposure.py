from typing import Dict, Any, List

class MetadataExposureCalculator:
    """
    Computes metadata side-channel exposure ratings across 5 key dimensions:
    1. Endpoint Exposure (public routing endpoints vs internal network disclosure)
    2. Timing Exposure (beaconing, inter-arrival predictability)
    3. Packet-Size Exposure (unpadded variable size disclosures e.g. web/video signatures)
    4. Traffic-Volume Exposure (bandwidth and transfer asymmetry leaks)
    5. IKE Metadata Exposure (cleartext negotiation disclosure)
    """

    @classmethod
    def calculate(
        cls,
        features: Dict[str, Any],
        ike_sessions: List[Dict[str, Any]],
        esp_sessions: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        # 1. Endpoint exposure
        # If public IPs are directly visible without NAT-T or proxying
        endpoint_score = 35.0
        endpoint_evidence = "Tunnel gateway endpoints are publicly addressable on outer IP headers, exposing gateway geography."
        if any(ike.get("nat_traversal_detected") for ike in ike_sessions):
            endpoint_score = 45.0
            endpoint_evidence += " NAT-T markers reveal client behind stateful NAT."

        # 2. Timing exposure
        # If inter-arrival time standard deviation is extremely low (periodic beaconing or fixed audio)
        iat_std = features.get("inter_arrival_std", 0.1)
        if iat_std < 0.01:
            timing_score = 75.0
            timing_evidence = f"Highly predictable isochronous inter-packet arrival (std: {iat_std*1000:.1f}ms) enables side-channel traffic fingerprinting."
        elif iat_std < 0.05:
            timing_score = 50.0
            timing_evidence = f"Moderate timing regularity observed (iat std: {iat_std*1000:.1f}ms)."
        else:
            timing_score = 25.0
            timing_evidence = f"Stochastic packet arrival timing (iat std: {iat_std:.3f}s) limits side-channel correlation."

        # 3. Packet size exposure
        # Unpadded packets (high standard deviation in packet sizes) leak application protocol structure despite ESP encryption
        pkt_std = features.get("pkt_size_std", 0.0)
        if pkt_std > 300:
            size_score = 80.0
            size_evidence = f"Significant packet size variance (std: {pkt_std:.1f} bytes) indicates lack of padding, leaking web page sizes and video chunk boundaries."
        elif pkt_std > 100:
            size_score = 50.0
            size_evidence = f"Moderate packet size variance (std: {pkt_std:.1f} bytes) reveals application payload transitions."
        else:
            size_score = 20.0
            size_evidence = f"Uniform or constant packet sizing (std: {pkt_std:.1f} bytes) effectively conceals internal application signatures."

        # 4. Volume exposure
        up_down = features.get("upload_download_ratio", 1.0)
        if up_down < 0.1 or up_down > 10.0:
            volume_score = 70.0
            volume_evidence = f"High transfer asymmetry ({up_down:.2f}) indicates unidirectional media streaming or large file transfer."
        else:
            volume_score = 30.0
            volume_evidence = f"Balanced upload/download flow ({up_down:.2f}) provides strong volume privacy."

        # 5. IKE Metadata exposure
        if any(ike.get("version") == "IKEv1" for ike in ike_sessions):
            ike_score = 85.0
            ike_evidence = "IKEv1 protocol transmits initiator/responder identity proposals in observable exchanges."
        elif ike_sessions:
            ike_score = 30.0
            ike_evidence = "IKEv2 encapsulates participant authentication and identities under encrypted SK payload."
        else:
            ike_score = 15.0
            ike_evidence = "No IKE control channel exchanges observable in capture."

        overall_score = round(
            (endpoint_score * 0.20) +
            (timing_score * 0.20) +
            (size_score * 0.25) +
            (volume_score * 0.15) +
            (ike_score * 0.20),
            1
        )

        return {
            "endpoint_exposure_score": endpoint_score,
            "timing_exposure_score": timing_score,
            "packet_size_exposure_score": size_score,
            "volume_exposure_score": volume_score,
            "ike_exposure_score": ike_score,
            "overall_exposure_score": overall_score,
            "endpoint_evidence": endpoint_evidence,
            "timing_evidence": timing_evidence,
            "packet_size_evidence": size_evidence,
            "volume_evidence": volume_evidence,
            "ike_evidence": ike_evidence
        }
