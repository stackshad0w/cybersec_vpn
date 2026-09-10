import os
from pathlib import Path
from typing import Dict, Any, Tuple, Optional
import joblib
import pandas as pd
from backend.app.core.config import settings

class TrafficClassifier:
    """
    Inference service for AI-assisted IPsec VPN traffic classification.
    Classifies encrypted flows into traffic categories using aggregate metadata only.
    """
    _model_payload: Optional[Dict[str, Any]] = None

    @classmethod
    def load_model(cls) -> Optional[Dict[str, Any]]:
        if cls._model_payload is None:
            model_path = Path(settings.MODEL_PATH)
            if model_path.exists():
                try:
                    cls._model_payload = joblib.load(model_path)
                except Exception as e:
                    print(f"Error loading model from {model_path}: {e}")
                    cls._model_payload = None
        return cls._model_payload

    @classmethod
    def classify_traffic(cls, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runs model inference on statistical flow features.
        Returns predicted class, confidence, secondary candidate, and explanation.
        """
        payload = cls.load_model()
        if not payload:
            return cls._heuristic_classification(features)

        clf = payload["model"]
        feature_names = payload["feature_names"]
        
        # Build DataFrame with correct column order
        df = pd.DataFrame([[features.get(col, 0.0) for col in feature_names]], columns=feature_names)
        
        probs = clf.predict_proba(df)[0]
        classes = clf.classes_
        
        # Sort classes by probability descending
        sorted_indices = probs.argsort()[::-1]
        best_idx = sorted_indices[0]
        second_idx = sorted_indices[1] if len(sorted_indices) > 1 else best_idx
        
        pred_class = classes[best_idx]
        confidence = float(probs[best_idx])
        sec_class = classes[second_idx] if confidence < 0.99 else None
        sec_confidence = float(probs[second_idx]) if confidence < 0.99 else None

        explanation = cls._generate_explanation(pred_class, confidence, features)

        return {
            "predicted_class": pred_class,
            "confidence_score": round(confidence, 3),
            "secondary_class": sec_class,
            "secondary_confidence": round(sec_confidence, 3) if sec_confidence else None,
            "explanation": explanation,
        }

    @classmethod
    def _generate_explanation(cls, pred_class: str, confidence: float, f: Dict[str, Any]) -> str:
        mean_size = f.get("pkt_size_mean", 0)
        pps = f.get("packets_per_sec", 0)
        up_down = f.get("upload_download_ratio", 0)
        burst = f.get("burst_rate", 0)
        iat = f.get("inter_arrival_mean", 0)

        if pred_class == "Video-like":
            return (
                f"Classified as {pred_class} with {confidence*100:.1f}% confidence based on high average packet size "
                f"({mean_size:.1f} bytes), high throughput bursts ({burst:.0f} pkts/s), and asymmetric download streaming ratio ({up_down:.2f})."
            )
        elif pred_class == "VoIP-like":
            return (
                f"Classified as {pred_class} with {confidence*100:.1f}% confidence due to steady isochronous inter-packet arrival "
                f"({iat*1000:.1f} ms), small consistent audio codec payloads ({mean_size:.1f} bytes), and symmetric flow."
            )
        elif pred_class == "Web-like":
            return (
                f"Classified as {pred_class} with {confidence*100:.1f}% confidence reflecting request/response burstiness, "
                f"mixed MTU packet distributions (mean: {mean_size:.1f} bytes), and interactive HTTP/TLS session pacing."
            )
        elif pred_class == "ICMP-like":
            return (
                f"Classified as {pred_class} with {confidence*100:.1f}% confidence driven by low packet frequency "
                f"({pps:.1f} pps), uniform small packet sizing ({mean_size:.1f} bytes), and symmetric ping/echo timing."
            )
        elif pred_class == "Email-like":
            return (
                f"Classified as {pred_class} with {confidence*100:.1f}% confidence matching periodic client synchronization intervals "
                f"and moderate payload transfer sizes."
            )
        else:
            return (
                f"Classified as {pred_class} with {confidence*100:.1f}% confidence based on composite metadata indicators."
            )

    @classmethod
    def _heuristic_classification(cls, f: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback heuristic if model file is unavailable."""
        mean_size = f.get("pkt_size_mean", 0)
        pps = f.get("packets_per_sec", 0)
        up_down = f.get("upload_download_ratio", 0)

        if mean_size > 1100 and up_down < 0.2:
            pred_class = "Video-like"
            conf = 0.91
        elif mean_size < 250 and pps > 30:
            pred_class = "VoIP-like"
            conf = 0.88
        elif mean_size < 120 and pps < 5:
            pred_class = "ICMP-like"
            conf = 0.95
        elif mean_size > 600:
            pred_class = "Web-like"
            conf = 0.82
        else:
            pred_class = "Other"
            conf = 0.70

        return {
            "predicted_class": pred_class,
            "confidence_score": conf,
            "secondary_class": "Web-like" if pred_class != "Web-like" else "Other",
            "secondary_confidence": 0.15,
            "explanation": f"Heuristically inferred traffic pattern based on mean packet size ({mean_size:.1f} bytes) and transmission rate."
        }
