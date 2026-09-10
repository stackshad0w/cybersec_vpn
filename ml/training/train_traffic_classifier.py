import os
import sys
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from ml.dataset.synthetic_data_generator import (
    generate_synthetic_traffic_dataset,
    FEATURE_COLUMNS,
    TRAFFIC_CLASSES
)

def train_and_export_model(output_path: str = "ml/models/random_forest_vpn_traffic.joblib") -> dict:
    print("Generating representative encrypted VPN dataset...")
    df = generate_synthetic_traffic_dataset(samples_per_class=600, random_state=42)
    
    X = df[FEATURE_COLUMNS]
    y = df["label"]
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print("Training Random Forest Classifier (n_estimators=120)...")
    clf = RandomForestClassifier(
        n_estimators=120,
        max_depth=12,
        min_samples_split=4,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)
    
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"Model Validation Accuracy: {acc * 100:.2f}%")
    print("\nClassification Report:\n", classification_report(y_test, y_pred))
    
    # Bundle feature importances and metadata with model
    model_payload = {
        "model": clf,
        "feature_names": FEATURE_COLUMNS,
        "classes": list(clf.classes_),
        "feature_importances": dict(zip(FEATURE_COLUMNS, [round(float(imp), 4) for imp in clf.feature_importances_])),
        "accuracy": round(float(acc), 4)
    }
    
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model_payload, out_file)
    print(f"Model successfully saved to {out_file.resolve()}")
    return model_payload

if __name__ == "__main__":
    train_and_export_model()
