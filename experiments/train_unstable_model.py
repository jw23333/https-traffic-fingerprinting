#!/usr/bin/env python3
"""
Train a Random Forest model on unstable website data.

This demonstrates the problem: high training/test accuracy on unstable data,
but poor real-time GUI performance because the model learns noise instead of
stable traffic patterns.
"""

import sys
from pathlib import Path
import pandas as pd
import numpy as np
import joblib
import json
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

try:
    import matplotlib.pyplot as plt
except Exception:
    print("Missing dependency: matplotlib. Install with: pip install matplotlib")
    raise

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from process_dataset_pairs import summary_features, read_pairs_csv

EXPERIMENT_DIR = Path(__file__).parent / "unstable_case"
PAIRS_DIR = EXPERIMENT_DIR / "pairs"
MODELS_DIR = EXPERIMENT_DIR / "models"
LOGS_DIR = EXPERIMENT_DIR / "logs"

MODELS_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)


def plot_confusion_matrix_figure(cm: np.ndarray, class_names: list[str], out_path: Path):
    """Save a visual confusion matrix figure for unstable-model reporting."""
    fig, ax = plt.subplots(figsize=(8, 6))
    im = ax.imshow(cm, interpolation='nearest', cmap='Reds')

    ax.set_title('Unstable Model Confusion Matrix', fontsize=14, pad=12)
    ax.set_xlabel('Predicted Label', fontsize=11)
    ax.set_ylabel('True Label', fontsize=11)

    ax.set_xticks(np.arange(len(class_names)))
    ax.set_yticks(np.arange(len(class_names)))
    ax.set_xticklabels(class_names, rotation=45, ha='right')
    ax.set_yticklabels(class_names)

    threshold = cm.max() / 2.0 if cm.size else 0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(
                j,
                i,
                f"{cm[i, j]}",
                ha='center',
                va='center',
                color='white' if cm[i, j] > threshold else 'black',
                fontsize=11,
                fontweight='bold',
            )

    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    fig.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=300, bbox_inches='tight')
    plt.close(fig)


def build_unstable_dataset():
    """Load all burst-pair CSVs from unstable sites."""
    print("[*] Building dataset from unstable website pairs...")
    
    X_rows = []
    labels = []
    total_pairs = 0
    
    for site_dir in sorted(PAIRS_DIR.iterdir()):
        if not site_dir.is_dir():
            continue
        
        site_name = site_dir.name
        site_pairs = 0
        
        for pairs_csv in sorted(site_dir.glob("*_pairs.csv")):
            try:
                df = read_pairs_csv(pairs_csv)
                feats = summary_features(df)
                
                if feats is not None:
                    X_rows.append(feats)
                    labels.append(site_name)
                    site_pairs += len(df)
                    total_pairs += len(df)
            except Exception as e:
                print(f"    Warning: Could not read {pairs_csv.name}: {e}")
        
        print(f"    {site_name}: {site_pairs} pairs")
    
    if not X_rows:
        raise ValueError("No data found! Please run collect_unstable_websites.py first.")
    
    X = pd.DataFrame(X_rows)
    X = X.fillna(0.0)  # Handle any NaN values
    
    print(f"[+] Total pairs loaded: {total_pairs}")
    print(f"[+] Feature matrix shape: {X.shape}")
    print(f"[+] Label distribution:\n{pd.Series(labels).value_counts()}\n")
    
    return X, labels


def train_unstable_model(X, y):
    """Train Random Forest on unstable data and report metrics."""
    print("[*] Training Random Forest (200 trees) on unstable data...")
    
    # Encode labels
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )
    
    print(f"    Train set: {len(X_train)} samples")
    print(f"    Test set:  {len(X_test)} samples")
    print(f"    Classes: {le.classes_}")
    
    # Train model
    clf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)
    
    # Evaluate
    train_accuracy = clf.score(X_train, y_train)
    test_accuracy = clf.score(X_test, y_test)
    
    print(f"\n[+] Model Performance:")
    print(f"    Training Accuracy: {train_accuracy:.4f}")
    print(f"    Test Accuracy:     {test_accuracy:.4f}")
    print(f"    Difference:        {abs(train_accuracy - test_accuracy):.4f}")
    
    print(f"\n[+] Classification Report:")
    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=le.classes_))

    cm = confusion_matrix(y_test, y_pred)
    print("[+] Confusion Matrix:")
    print(cm)

    cm_plot_path = LOGS_DIR / "unstable_confusion_matrix.png"
    plot_confusion_matrix_figure(cm, list(le.classes_), cm_plot_path)
    print(f"[+] Confusion matrix plot saved to {cm_plot_path}")
    
    # This is the key insight: high accuracy but poor real-world performance
    print(f"\n[!] KEY INSIGHT: High accuracy ({test_accuracy:.1%}) masks poor generalization!")
    print(f"    The model learned unstable, noisy patterns that don't transfer to real-time predictions.")
    
    return clf, le, X.columns, float(test_accuracy), cm_plot_path


def save_model_bundle(clf, le, feature_names):
    """Save model bundle for GUI testing."""
    print("[*] Saving model bundle...")
    
    bundle = {
        "model": clf,
        "label_encoder": le,
        "feature_names": list(feature_names),
    }
    
    model_path = MODELS_DIR / "unstable_model.joblib"
    joblib.dump(bundle, model_path)
    
    print(f"[+] Model saved to {model_path}")
    return model_path


def main():
    print("="*70)
    print("UNSTABLE DATA MODEL TRAINING")
    print("="*70)
    
    # Step 1: Build dataset
    X, y = build_unstable_dataset()
    
    # Step 2: Train model
    clf, le, feature_names, test_accuracy, cm_plot_path = train_unstable_model(X, y)
    
    # Step 3: Save
    model_path = save_model_bundle(clf, le, feature_names)
    
    # Log results
    results = {
        "experiment": "unstable_websites",
        "websites": ["apple.com", "microsoft.com", "amazon.com", "nytimes.com"],
        "total_samples": len(X),
        "classes": list(le.classes_),
        "test_accuracy": test_accuracy,
        "confusion_matrix_plot": str(cm_plot_path),
        "note": "High accuracy but poor real-time generalization due to unstable traffic patterns",
    }
    
    log_file = LOGS_DIR / "training_results.json"
    with open(log_file, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\n[+] Training complete! Results logged to {log_file}")
    print(f"[+] Use with GUI: gui_capture_app.py --model {model_path}")


if __name__ == "__main__":
    main()
