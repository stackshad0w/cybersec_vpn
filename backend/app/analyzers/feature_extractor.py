import numpy as np
from typing import List, Dict, Any
from backend.app.analyzers.pcap_parser import PacketMetadata

class FeatureExtractor:
    """
    Extracts statistical, privacy-preserving flow metadata features from packet captures.
    Zero payload inspection is performed.
    """

    @classmethod
    def extract_features(cls, packets: List[PacketMetadata]) -> Dict[str, Any]:
        if not packets:
            return cls._default_features()

        packet_count = len(packets)
        lengths = np.array([p.length for p in packets], dtype=float)
        byte_count = int(np.sum(lengths))

        timestamps = np.array([p.timestamp for p in packets], dtype=float)
        # Sort by timestamp
        sort_idx = np.argsort(timestamps)
        timestamps = timestamps[sort_idx]
        lengths = lengths[sort_idx]

        flow_duration = float(timestamps[-1] - timestamps[0]) if packet_count > 1 else 0.01
        if flow_duration <= 0.0:
            flow_duration = 0.001

        # Packet size statistics
        pkt_size_min = float(np.min(lengths))
        pkt_size_max = float(np.max(lengths))
        pkt_size_mean = float(np.mean(lengths))
        pkt_size_std = float(np.std(lengths))
        pkt_size_median = float(np.median(lengths))

        # Rates
        packets_per_sec = float(packet_count / flow_duration)
        bytes_per_sec = float(byte_count / flow_duration)

        # Inter-arrival time statistics
        if packet_count > 1:
            iats = np.diff(timestamps)
            # Clip negative or infinitesimal differences
            iats = np.maximum(iats, 0.0)
            inter_arrival_mean = float(np.mean(iats))
            inter_arrival_std = float(np.std(iats))
        else:
            inter_arrival_mean = 0.0
            inter_arrival_std = 0.0

        # Directional statistics (infer primary direction from first packet)
        primary_src = packets[0].src_ip if packets[0].src_ip else "unknown"
        upload_packets = sum(1 for p in packets if p.src_ip == primary_src)
        download_packets = packet_count - upload_packets
        upload_bytes = sum(p.length for p in packets if p.src_ip == primary_src)
        download_bytes = byte_count - upload_bytes

        upload_download_ratio = float(upload_bytes / max(download_bytes, 1))
        direction_ratio = float(upload_packets / max(packet_count, 1))

        # Burst rate (maximum packets in any 1-second rolling window)
        burst_rate = cls._calculate_burst_rate(timestamps)

        return {
            "packet_count": packet_count,
            "byte_count": byte_count,
            "flow_duration": round(flow_duration, 4),
            "pkt_size_min": round(pkt_size_min, 2),
            "pkt_size_max": round(pkt_size_max, 2),
            "pkt_size_mean": round(pkt_size_mean, 2),
            "pkt_size_std": round(pkt_size_std, 2),
            "pkt_size_median": round(pkt_size_median, 2),
            "packets_per_sec": round(packets_per_sec, 2),
            "bytes_per_sec": round(bytes_per_sec, 2),
            "inter_arrival_mean": round(inter_arrival_mean, 6),
            "inter_arrival_std": round(inter_arrival_std, 6),
            "upload_download_ratio": round(upload_download_ratio, 4),
            "direction_ratio": round(direction_ratio, 4),
            "burst_rate": round(burst_rate, 2),
        }

    @classmethod
    def _calculate_burst_rate(cls, timestamps: np.ndarray) -> float:
        if len(timestamps) <= 1:
            return float(len(timestamps))
        
        # Count max packets in a 1.0s window
        max_burst = 1
        left = 0
        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > 1.0 and left < right:
                left += 1
            current_window = right - left + 1
            if current_window > max_burst:
                max_burst = current_window
        return float(max_burst)

    @classmethod
    def _default_features(cls) -> Dict[str, Any]:
        return {
            "packet_count": 0,
            "byte_count": 0,
            "flow_duration": 0.0,
            "pkt_size_min": 0.0,
            "pkt_size_max": 0.0,
            "pkt_size_mean": 0.0,
            "pkt_size_std": 0.0,
            "pkt_size_median": 0.0,
            "packets_per_sec": 0.0,
            "bytes_per_sec": 0.0,
            "inter_arrival_mean": 0.0,
            "inter_arrival_std": 0.0,
            "upload_download_ratio": 0.0,
            "direction_ratio": 0.0,
            "burst_rate": 0.0,
        }
