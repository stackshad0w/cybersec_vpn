import numpy as np
import pandas as pd
from typing import Tuple

FEATURE_COLUMNS = [
    "packet_count",
    "byte_count",
    "flow_duration",
    "pkt_size_min",
    "pkt_size_max",
    "pkt_size_mean",
    "pkt_size_std",
    "pkt_size_median",
    "packets_per_sec",
    "bytes_per_sec",
    "inter_arrival_mean",
    "inter_arrival_std",
    "upload_download_ratio",
    "direction_ratio",
    "burst_rate",
]

TRAFFIC_CLASSES = [
    "ICMP-like",
    "Web-like",
    "VoIP-like",
    "Video-like",
    "Email-like",
    "Other"
]

def generate_synthetic_traffic_dataset(samples_per_class: int = 500, random_state: int = 42) -> pd.DataFrame:
    """
    Generates a realistic statistical feature dataset of encrypted IPsec traffic flows.
    """
    np.random.seed(random_state)
    rows = []

    for cls_name in TRAFFIC_CLASSES:
        for _ in range(samples_per_class):
            if cls_name == "ICMP-like":
                pkt_count = np.random.randint(10, 100)
                pkt_min = np.random.uniform(64, 84)
                pkt_max = pkt_min + np.random.uniform(0, 10)
                pkt_mean = (pkt_min + pkt_max) / 2
                pkt_std = np.random.uniform(0.5, 4.0)
                pkt_median = pkt_mean
                duration = np.random.uniform(5.0, 60.0)
                pps = pkt_count / duration
                bps = pps * pkt_mean
                iat_mean = np.random.uniform(0.5, 2.0)
                iat_std = np.random.uniform(0.01, 0.1)
                up_down = np.random.uniform(0.9, 1.1)
                dir_ratio = np.random.uniform(0.48, 0.52)
                burst = np.random.uniform(1.0, 3.0)

            elif cls_name == "VoIP-like":
                pkt_count = np.random.randint(100, 1500)
                pkt_min = np.random.uniform(120, 200)
                pkt_max = pkt_min + np.random.uniform(10, 40)
                pkt_mean = np.random.uniform(150, 220)
                pkt_std = np.random.uniform(5.0, 15.0)
                pkt_median = pkt_mean
                duration = pkt_count * 0.02 * np.random.uniform(0.95, 1.05)
                pps = pkt_count / max(duration, 0.1)
                bps = pps * pkt_mean
                iat_mean = np.random.normal(0.02, 0.003)
                iat_std = np.random.uniform(0.001, 0.008)
                up_down = np.random.uniform(0.85, 1.15)
                dir_ratio = np.random.uniform(0.45, 0.55)
                burst = np.random.uniform(40.0, 60.0)

            elif cls_name == "Video-like":
                # High bandwidth, heavy download asymmetry, high MTU packets
                pkt_count = np.random.randint(500, 5000)
                duration = np.random.uniform(10.0, 120.0)
                pkt_min = np.random.uniform(60, 90)
                pkt_max = np.random.uniform(1420, 1514)
                pkt_mean = np.random.uniform(1150, 1380)
                pkt_std = np.random.uniform(250.0, 450.0)
                pkt_median = np.random.uniform(1300, 1460)
                pps = pkt_count / duration
                bps = pps * pkt_mean
                iat_mean = np.random.uniform(0.002, 0.015)
                iat_std = np.random.uniform(0.002, 0.02)
                up_down = np.random.uniform(0.02, 0.15)  # asymmetric download
                dir_ratio = np.random.uniform(0.05, 0.20)
                burst = np.random.uniform(80.0, 350.0)

            elif cls_name == "Web-like":
                pkt_count = np.random.randint(30, 400)
                duration = np.random.uniform(2.0, 45.0)
                pkt_min = np.random.uniform(60, 80)
                pkt_max = np.random.uniform(1300, 1514)
                pkt_mean = np.random.uniform(650, 950)
                pkt_std = np.random.uniform(350.0, 550.0)
                pkt_median = np.random.uniform(400, 850)
                pps = pkt_count / duration
                bps = pps * pkt_mean
                iat_mean = np.random.uniform(0.05, 0.5)
                iat_std = np.random.uniform(0.08, 0.8)
                up_down = np.random.uniform(0.15, 0.45)
                dir_ratio = np.random.uniform(0.20, 0.40)
                burst = np.random.uniform(15.0, 80.0)

            elif cls_name == "Email-like":
                pkt_count = np.random.randint(20, 150)
                duration = np.random.uniform(15.0, 180.0)
                pkt_min = np.random.uniform(60, 90)
                pkt_max = np.random.uniform(900, 1400)
                pkt_mean = np.random.uniform(300, 600)
                pkt_std = np.random.uniform(200.0, 400.0)
                pkt_median = np.random.uniform(200, 450)
                pps = pkt_count / duration
                bps = pps * pkt_mean
                iat_mean = np.random.uniform(0.8, 3.5)
                iat_std = np.random.uniform(0.5, 2.0)
                up_down = np.random.uniform(0.3, 0.8)
                dir_ratio = np.random.uniform(0.35, 0.65)
                burst = np.random.uniform(5.0, 20.0)

            else:  # Other
                pkt_count = np.random.randint(15, 600)
                duration = np.random.uniform(3.0, 90.0)
                pkt_min = np.random.uniform(50, 120)
                pkt_max = np.random.uniform(500, 1450)
                pkt_mean = np.random.uniform(250, 800)
                pkt_std = np.random.uniform(100.0, 400.0)
                pkt_median = np.random.uniform(200, 750)
                pps = pkt_count / duration
                bps = pps * pkt_mean
                iat_mean = np.random.uniform(0.1, 1.5)
                iat_std = np.random.uniform(0.1, 1.2)
                up_down = np.random.uniform(0.2, 1.5)
                dir_ratio = np.random.uniform(0.2, 0.8)
                burst = np.random.uniform(5.0, 50.0)

            rows.append({
                "packet_count": max(1, int(pkt_count)),
                "byte_count": max(100, int(pkt_count * pkt_mean)),
                "flow_duration": max(0.01, round(duration, 4)),
                "pkt_size_min": round(pkt_min, 2),
                "pkt_size_max": round(pkt_max, 2),
                "pkt_size_mean": round(pkt_mean, 2),
                "pkt_size_std": round(pkt_std, 2),
                "pkt_size_median": round(pkt_median, 2),
                "packets_per_sec": round(pps, 2),
                "bytes_per_sec": round(bps, 2),
                "inter_arrival_mean": max(0.0001, round(iat_mean, 6)),
                "inter_arrival_std": max(0.0001, round(iat_std, 6)),
                "upload_download_ratio": round(up_down, 4),
                "direction_ratio": round(dir_ratio, 4),
                "burst_rate": round(burst, 2),
                "label": cls_name
            })

    return pd.DataFrame(rows)
