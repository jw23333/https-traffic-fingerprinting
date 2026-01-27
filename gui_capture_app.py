#!/usr/bin/env python3
"""
A minimal Tkinter GUI for starting and stopping HTTPS captures using tshark.

- Start: begins a background capture (manual stop)
- Stop:  stops the capture cleanly; shows where the .pcap was saved

Defaults for this demo:
- interface: "en1"
- out_dir:   Project directory (same folder as these scripts)

You can extend this later with a timer, live packet counter, or a folder picker.
"""

import os
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext
from pathlib import Path

import numpy as np
import pandas as pd
import joblib

from capture_safari_all import start_capture, stop_capture, DEFAULT_OUT_DIR
from process_pcap import process_pcap
from process_dataset_pairs import read_pairs_csv, summary_features


class CaptureApp(tk.Tk):
    def __init__(self, interface: str = "en1", out_dir: str | None = None):
        super().__init__()
        self.title("HTTPS Capture")
        self.resizable(True, True)

        # Defaults and state
        self.interface = interface
        # Default to the project directory if not provided
        self.out_dir = os.path.expanduser(out_dir) if out_dir else DEFAULT_OUT_DIR
        self.proc = None
        self.pcap_path = None

        # Model bundle path candidates (adjust if needed)
        self.model_candidates = [
            os.path.join(os.getcwd(), "models", "rf_model.joblib"),
            os.path.join(os.getcwd(), "rf_model.joblib"),
        ]

        # Cleanup toggle: remove pcap/pairs/csv after prediction
        self.cleanup_after_predict = True

        # Confidence cutoff for monitored-site detection (abstain below this)
        self.confidence_threshold = 0.65
        
        # Margin threshold: reject if top-1 and top-2 probabilities are too close
        # Helps prevent false positives when model is unsure between similar sites
        self.margin_threshold = 0.20
        
        # Optional: only accept predictions for these specific labels (None = all trained labels)
        # Example: {"wikipedia_org", "npmjs_com"} to ignore decoy sites
        self.monitored_labels: set[str] | None = {"wikipedia_org", "npmjs_com"}

        # UI elements
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = tk.Label(self, textvariable=self.status_var, width=50, anchor="w")
        self.btn_start = tk.Button(self, text="Start", width=12, command=self.on_start)
        self.btn_stop = tk.Button(self, text="Stop", width=12, command=self.on_stop, state=tk.DISABLED)
        
        # Feature analysis display
        self.feature_text = scrolledtext.ScrolledText(self, width=80, height=20, wrap=tk.WORD, font=("Monaco", 10))
        self.feature_text.insert("1.0", "Capture traffic to see feature analysis...\n")
        self.feature_text.config(state=tk.DISABLED)

        # Layout
        self.status_label.grid(row=0, column=0, columnspan=2, padx=10, pady=(10, 6), sticky="w")
        self.btn_start.grid(row=1, column=0, padx=(10, 5), pady=(0, 10))
        self.btn_stop.grid(row=1, column=1, padx=(5, 10), pady=(0, 10))
        self.feature_text.grid(row=2, column=0, columnspan=2, padx=10, pady=(0, 10), sticky="nsew")
        
        # Make feature text area expandable
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # Placeholder for future periodic updates (timer, counters, etc.)
        # self.after(1000, self._tick)

    def on_start(self):
        if self.proc is not None and self.proc.poll() is None:
            print("Capture process already started")
            return
        try:
            self.proc, self.pcap_path = start_capture(
                interface=self.interface,
                out_dir=self.out_dir,
                prefix="safari",
                duration=None,
                fixed=False,
            )
            self.status_var.set("Capturing…")
            self.btn_start.config(state=tk.DISABLED)
            self.btn_stop.config(state=tk.NORMAL)
        except FileNotFoundError as e:
            messagebox.showerror("tshark not found", str(e))
        except Exception as e:
            messagebox.showerror("Error starting capture", str(e))

    def on_stop(self):
        if self.proc is None:
            return
        try:
            stop_capture(self.proc)
            self.status_var.set(f"Stopped — saved to {self.pcap_path}")
        except Exception as e:
            messagebox.showerror("Error stopping capture", str(e))
        finally:
            self.btn_start.config(state=tk.NORMAL)
            self.btn_stop.config(state=tk.DISABLED)
            self.proc = None
            # keep self.pcap_path for the saved location display

        # Process the pcap and run a prediction in background
        if self.pcap_path:
            threading.Thread(target=self._process_and_predict, args=(self.pcap_path,), daemon=True).start()

    def _process_and_predict(self, pcap_path: str):
        try:
            # Update UI: processing started
            self.after(0, lambda: self.status_var.set("Processing capture → features → prediction…"))

            # 1) Process pcap into burst pairs CSV (uses default pairs path next to pcap)
            _, pairs_path = process_pcap(
                pcap_path=pcap_path,
                iface=self.interface,
                packets_csv=None,
                pairs_csv=None,
                gap_ms=50.0,
            )

            # 2) Build a single-row feature DataFrame (summary mode)
            df = read_pairs_csv(Path(pairs_path))
            feats = summary_features(df)
            X = pd.DataFrame([feats]).fillna(0)

            # Match trainer preprocessing: replace inf/nan, then log1p on numeric cols
            X = X.replace([np.inf, -np.inf], 0).fillna(0)
            numeric_cols = X.select_dtypes(include=[np.number]).columns
            X[numeric_cols] = np.log1p(X[numeric_cols])

            # 3) Load model bundle
            bundle_path = None
            for cand in self.model_candidates:
                if os.path.exists(cand):
                    bundle_path = cand
                    break
            if not bundle_path:
                raise FileNotFoundError(
                    "Trained model not found. Expected models/rf_model.joblib or rf_model.joblib."
                )

            bundle = joblib.load(bundle_path)
            clf = bundle.get('model')
            le = bundle.get('label_encoder')
            feature_names = bundle.get('feature_names')
            if clf is None or le is None or feature_names is None:
                raise RuntimeError("Model bundle missing keys: 'model', 'label_encoder', 'feature_names'.")

            # 4) Align columns to training feature order
            X = X.reindex(columns=feature_names, fill_value=0)

            # 5) Predict and show result
            y_pred = clf.predict(X)[0]
            label = le.inverse_transform([y_pred])[0]
            proba = None
            proba_top2 = None
            margin = None
            try:
                probas = clf.predict_proba(X)[0]
                # Get top-1 and top-2 probabilities for margin check
                sorted_probas = np.sort(probas)[::-1]
                proba = float(sorted_probas[0])
                proba_top2 = float(sorted_probas[1]) if len(sorted_probas) > 1 else 0.0
                margin = proba - proba_top2
            except Exception:
                pass

            # 6) Get feature importances from the model
            feature_importances = clf.feature_importances_
            
            # Create importance ranking
            importance_df = pd.DataFrame({
                'feature': feature_names,
                'importance': feature_importances,
                'value': X.iloc[0].values
            }).sort_values('importance', ascending=False)
            
            # Build detailed analysis text (includes accept/reject decision)
            analysis = self._build_feature_analysis(label, proba, margin, importance_df)
            self.after(0, lambda: self._display_analysis(analysis))

            # Optional cleanup of files after prediction
            cleaned = False
            if self.cleanup_after_predict:
                try:
                    self._cleanup_files(pcap_path, pairs_path)
                    cleaned = True
                    print(f"[Cleanup] Deleted: {pcap_path}, {pairs_path}")
                except Exception as e:
                    cleaned = False
                    print(f"[Cleanup] Failed: {e}")

            # Decide whether to accept or reject the prediction
            # Check: confidence threshold, margin threshold, AND monitored label set
            accepted = True
            reject_reason = None
            
            if proba is None:
                accepted = True  # No probabilities available, accept by default
            elif self.monitored_labels is not None and label not in self.monitored_labels:
                accepted = False
                reject_reason = f"'{label}' not in monitored sites"
            elif proba < self.confidence_threshold:
                accepted = False
                reject_reason = f"low confidence ({proba:.1%} < {self.confidence_threshold:.0%})"
            elif margin is not None and margin < self.margin_threshold:
                accepted = False
                reject_reason = f"ambiguous ({proba:.1%} vs {proba_top2:.1%}, margin {margin:.1%} < {self.margin_threshold:.0%})"
            
            if accepted:
                if proba is not None:
                    base = f"Prediction: {label} (confidence {proba:.2f})"
                else:
                    base = f"Prediction: {label}"
            else:
                base = f"No monitored site detected ({reject_reason})"
            msg = base + (" — cleaned up" if cleaned else f" — pairs: {pairs_path}")
            self.after(0, lambda: self.status_var.set(msg))

        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Prediction error", str(e)))

    def _build_feature_analysis(self, label: str, proba: float | None, margin: float | None, importance_df: pd.DataFrame) -> str:
        """Build detailed feature analysis text showing what drove the classification."""
        lines = []
        lines.append("=" * 80)
        # Show classification result and whether it's accepted or rejected
        accepted = True
        if proba is None:
            accepted = True
        elif self.monitored_labels is not None and label not in self.monitored_labels:
            accepted = False
        elif proba < self.confidence_threshold:
            accepted = False
        elif margin is not None and margin < self.margin_threshold:
            accepted = False
            
        if accepted:
            lines.append(f"CLASSIFICATION RESULT: {label}")
            if proba is not None:
                lines.append(f"Confidence: {proba:.1%}")
            if margin is not None:
                lines.append(f"Margin (top1-top2): {margin:.1%}")
            lines.append(f"Decision: ACCEPTED")
        else:
            lines.append(f"NO MONITORED SITE DETECTED")
            lines.append(f"Decision: REJECTED")
            lines.append("")
            lines.append("Monitored sites:")
            for site in sorted(self.monitored_labels or []):
                lines.append(f"  • {site}")
            lines.append("=" * 80)
            return "\n".join(lines)
        lines.append("=" * 80)
        lines.append("")
        
        lines.append("TOP 5 MOST IMPORTANT FEATURES (for this model):")
        lines.append("-" * 80)
        for idx, row in importance_df.head(5).iterrows():
            feat_name = row['feature']
            importance = row['importance']
            value = row['value']
            # Reverse log1p transform to show original value
            original_value = np.expm1(value)
            lines.append(f"  {feat_name:25s}  importance={importance:6.3f}  value={original_value:12.2f}")
        lines.append("")
        
        lines.append("ALL EXTRACTED FEATURES:")
        lines.append("-" * 80)
        for idx, row in importance_df.iterrows():
            feat_name = row['feature']
            importance = row['importance']
            value = row['value']
            original_value = np.expm1(value)
            lines.append(f"  {feat_name:25s}  importance={importance:6.3f}  value={original_value:12.2f}")
        lines.append("")
        
        lines.append("INTERPRETATION:")
        lines.append("-" * 80)
        lines.append("• 'importance' = how much this feature contributes to the model's decisions")
        lines.append("• 'value' = the actual measurement from your captured traffic")
        lines.append("• Higher importance features have more influence on the classification")
        lines.append("• The Random Forest combined all these features to classify this traffic")
        lines.append("")
        
        return "\n".join(lines)
    
    def _display_analysis(self, analysis: str):
        """Update the feature text area with analysis results."""
        self.feature_text.config(state=tk.NORMAL)
        self.feature_text.delete("1.0", tk.END)
        self.feature_text.insert("1.0", analysis)
        self.feature_text.config(state=tk.DISABLED)

    def _cleanup_files(self, pcap_path: str, pairs_path: Path | str):
        # Also attempt to remove the per-packet CSV if present (<pcap>_dir.csv)
        pcap = Path(pcap_path)
        pairs = Path(pairs_path)
        dir_csv = pcap.with_name(pcap.stem + "_dir.csv")
        for p in [pairs, dir_csv, pcap]:
            try:
                if p.exists():
                    os.remove(p)
            except Exception:
                # Ignore cleanup errors silently
                pass

    # Example extension point for periodic UI updates (timer/counter)
    # def _tick(self):
    #     if self.proc is not None and self.proc.poll() is None:
    #         # Update timer, counter, etc.
    #         pass
    #     self.after(1000, self._tick)


if __name__ == "__main__":
    app = CaptureApp(interface="en1")
    app.mainloop()
