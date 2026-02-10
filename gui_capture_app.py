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
        self.confidence_threshold = 0.5
        
        # Margin threshold: reject if top-1 and top-2 probabilities are too close
        # Helps prevent false positives when model is unsure between similar sites
        self.margin_threshold = 0.20
        
        # Optional: only accept predictions for these specific labels (None = all trained labels)
        # Example: {"chickenpox", "measles"} to ignore decoy sites
        self.monitored_labels: set[str] | None = {"chickenpox", "measles"}

        # Technical details toggle state
        self.show_technical = False
        self.current_technical_data = None  # Store importance_df for toggle
        self.current_simple_text = ""  # Store simple explanation text

        # UI elements
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = tk.Label(self, textvariable=self.status_var, width=50, anchor="w")
        self.btn_start = tk.Button(self, text="Start", width=12, command=self.on_start)
        self.btn_stop = tk.Button(self, text="Stop", width=12, command=self.on_stop, state=tk.DISABLED)
        
        # Feature analysis display
        self.feature_text = scrolledtext.ScrolledText(self, width=80, height=20, wrap=tk.WORD, font=("Monaco", 10))
        self.feature_text.insert("1.0", "Capture traffic to see feature analysis...\n")
        self.feature_text.config(state=tk.DISABLED)
        
        # Toggle button for technical details
        self.btn_toggle_technical = tk.Button(
            self, 
            text="Show technical details ▼", 
            command=self.toggle_technical_details,
            state=tk.DISABLED
        )

        # Layout
        self.status_label.grid(row=0, column=0, columnspan=2, padx=10, pady=(10, 6), sticky="w")
        self.btn_start.grid(row=1, column=0, padx=(10, 5), pady=(0, 10))
        self.btn_stop.grid(row=1, column=1, padx=(5, 10), pady=(0, 10))
        self.feature_text.grid(row=2, column=0, columnspan=2, padx=10, pady=(0, 5), sticky="nsew")
        self.btn_toggle_technical.grid(row=3, column=0, columnspan=2, padx=10, pady=(0, 10), sticky="ew")
        
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
            self.after(0, lambda: self._display_analysis(analysis, importance_df))

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
                reject_reason = "not in monitored sites"
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

    def _get_feature_explanation(self, feature_name: str) -> str:
        """Map technical feature names to user-friendly explanations."""
        explanations = {
            # Bigrams (outbound transitions)
            'bigram_out_S_to_S': 'the pattern where your browser sent two small requests in a row. Even though the content is encrypted, the timing and size of these paired requests creates a signature - some pages make lots of quick small requests, others don\'t',
            'bigram_out_S_to_L': 'the pattern where a small request from your browser was immediately followed by sending a larger chunk of data. This sequence reveals how the page structures its communication - the rhythm of small-then-large is different for each website',
            'bigram_out_L_to_S': 'the pattern where your browser sent a large amount of data followed by a smaller request. This "heavy then light" sequence happens in specific situations and varies distinctly between different pages',
            'bigram_out_L_to_L': 'the pattern where your browser sent two large chunks of data consecutively. This sustained heavy communication pattern is quite rare and highly distinctive to specific types of web pages',
            
            # Bigrams (inbound transitions)
            'bigram_in_S_to_S': 'the pattern where the website sent you two small responses back-to-back. Even encrypted, these small-small delivery patterns are like a fingerprint - each page has its own rhythm of delivering small chunks of information',
            'bigram_in_S_to_L': 'the pattern where the website sent you a small response followed immediately by a large response. This acceleration from small to large reveals the page\'s content structure - perhaps a quick acknowledgment followed by heavy content',
            'bigram_in_L_to_S': 'the pattern where the website sent you a large response followed by a smaller one. This "deliver big then small" rhythm indicates how the page stages its content, which varies significantly between different websites',
            'bigram_in_L_to_L': 'the pattern where the website delivered two large responses consecutively. This sustained burst of heavy content is highly characteristic - different pages have very different patterns of when they send multiple large chunks',
            
            # Trigrams (outbound 3-burst patterns)
            'trigram_out_S_S_S': 'a distinctive rhythm where your browser made three small requests in sequence. This triple-small pattern is like a dance move - each website orchestrates its requests differently, creating unique three-step signatures',
            'trigram_out_S_S_L': 'a three-step pattern where your browser sent two small requests then ramped up to a large one. This escalating rhythm reveals the page\'s interaction flow and is surprisingly distinctive across different websites',
            'trigram_out_S_L_S': 'a three-step pattern where your browser alternated small-large-small. This oscillating rhythm is unusual and highly identifying - it reveals a specific type of page interaction that not all websites use',
            'trigram_out_S_L_L': 'a three-step pattern where your browser started small then sent two large chunks. This building momentum is characteristic of certain page types and their specific loading behavior',
            'trigram_out_L_S_S': 'a three-step pattern starting with a large request then two small ones. This "start heavy, end light" sequence is distinctive and reveals how certain pages structure their initial communication',
            'trigram_out_L_S_L': 'a three-step pattern alternating large-small-large. This back-and-forth rhythm is quite specific and appears in certain types of interactive pages, making it a strong identifier',
            'trigram_out_L_L_S': 'a three-step pattern with two large requests followed by a small one. This "heavy heavy light" sequence suggests a specific loading strategy unique to certain page architectures',
            'trigram_out_L_L_L': 'a three-step pattern of three large requests in a row. This sustained heavy communication is rare and extremely distinctive - very few page types create this intense request pattern',
            
            # Counts
            'count_out_small': 'how many small requests your browser made in total. A medical page about chickenpox might make 15 small requests while a measles page makes 22 - these countable differences add up to create a unique signature',
            'count_out_large': 'how many large data chunks your browser sent to the website. Different pages trigger different numbers of substantial requests based on their structure and functionality',
            'count_in_small': 'how many small responses you received from the website. Each page delivers its content through a characteristic number of small chunks - some use many tiny pieces, others use fewer',
            'count_in_large': 'how many large responses the website sent you. The number of substantial content deliveries varies dramatically - a text-heavy page might send 3 large chunks while an image-heavy one sends 20',
            
            # Ratios
            'ratio_out_small': 'what fraction of all your requests were small ones. If 80% of your requests were small versus 20%, that balance is revealing - different pages have very different mixes of small versus large requests',
            'ratio_out_large': 'what fraction of all your requests were large ones. This percentage reveals the communication style - some pages need mostly large uploads while others are dominated by small requests',
            'ratio_in_small': 'what fraction of the website\'s responses were small chunks. A page that delivers 90% small responses behaves very differently from one that sends 30% small, and this ratio is highly characteristic',
            'ratio_in_large': 'what fraction of the data you received came in large chunks. This reveals content delivery strategy - some sites send mostly big blocks (high ratio), others use incremental delivery (low ratio)',
            'ratio_out_in_bytes': 'the ratio of data sent versus received. A typical article might be 1:50 (50 times more downloaded than uploaded), while an interactive form might be 1:2. This fundamental balance is highly distinctive across different pages',
            
            # Aggregates
            'total_pairs': 'the total number of request-response exchanges. Loading the chickenpox page might involve 38 exchanges while measles takes 42 - even this simple count can be revealing when combined with other patterns',
            'total_out_bytes': 'the total bytes your browser sent during the visit. Different pages require different amounts of outgoing data - one might need 15KB of requests while another needs 45KB, creating measurable differences',
            'total_in_bytes': 'the total bytes downloaded from the website. Page sizes vary dramatically - a simple text page might be 200KB while a media-rich one is 2MB. Even encrypted, this total size is visible and distinctive',
            'mean_out_bytes': 'the average size of each request your browser sent. If your average request was 350 bytes versus 890 bytes, this reveals different page architectures - some use many tiny requests, others use fewer large ones',
            'mean_in_bytes': 'the average size of each response you received. A page that sends uniform 5KB chunks has a very different average than one mixing 1KB and 50KB responses, making this measurement quite revealing',
            'std_out_bytes': 'how much the request sizes varied - measured by standard deviation. Consistent request sizes (low variation) versus wildly different sizes (high variation) reveals the page\'s communication consistency',
            'std_in_bytes': 'how much the response sizes varied - measured by standard deviation. Pages with uniform content have low variation while pages mixing small scripts and large images have high variation, creating a distinctive signature',
            'mean_out_pkts': 'the average number of network packets per request burst. This low-level detail about how data gets packaged reveals protocol-level behavior that differs subtly but measurably between page types',
            'mean_in_pkts': 'the average number of network packets per response burst. How the server chunks its responses into packets is a technical signature - some servers are consistent, others vary based on content type',
            'mean_out_dur': 'the average time each outgoing burst took to send. This timing pattern captures both your connection speed and how the page spaces its requests - some pages wait between requests, others fire rapidly',
            'mean_in_dur': 'the average time each incoming burst took to arrive. This duration reveals the server\'s delivery speed and content streaming behavior - fast servers with small chunks have short durations, slower ones with large content take longer',
        }
        
        # Return explanation if available, otherwise create a generic one
        if feature_name in explanations:
            return explanations[feature_name]
        else:
            # Generic fallback for any features not in the dictionary
            return f'the "{feature_name}" characteristic of your traffic pattern'
    
    def _build_feature_analysis(self, label: str, proba: float | None, margin: float | None, importance_df: pd.DataFrame) -> str:
        """Build user-friendly feature analysis showing what exposed the traffic."""
        lines = []
        
        # Check if prediction is accepted or rejected
        accepted = True
        if proba is None:
            accepted = True
        elif self.monitored_labels is not None and label not in self.monitored_labels:
            accepted = False
        elif proba < self.confidence_threshold:
            accepted = False
        elif margin is not None and margin < self.margin_threshold:
            accepted = False
            
        # For rejected predictions, show rejection message
        if not accepted:
            lines.append("=" * 80)
            lines.append(f"NO MONITORED SITE DETECTED")
            lines.append(f"Decision: REJECTED")
            lines.append("")
            lines.append("Monitored sites:")
            for site in sorted(self.monitored_labels or []):
                lines.append(f"  • {site}")
            lines.append("=" * 80)
            return "\n".join(lines)
        
        # For accepted predictions, show only feature explanations (no header)
        # Get top 2 features only
        top_features = importance_df.head(2)
        
        if len(top_features) >= 1:
            first_feat = top_features.iloc[0]
            explanation = self._get_feature_explanation(first_feat['feature'])
            lines.append(f"What exposed your traffic the most is {explanation}.")
            lines.append("")
        
        if len(top_features) >= 2:
            second_feat = top_features.iloc[1]
            explanation = self._get_feature_explanation(second_feat['feature'])
            lines.append(f"The second most revealing aspect is {explanation}.")
            lines.append("")
        
        return "\n".join(lines)
    
    def _display_analysis(self, analysis: str, importance_df: pd.DataFrame = None):
        """Update the feature text area with analysis results."""
        # Store data for toggle functionality
        self.current_simple_text = analysis
        self.current_technical_data = importance_df
        self.show_technical = False  # Reset to collapsed state
        
        # Update button state
        if importance_df is not None and not importance_df.empty:
            self.btn_toggle_technical.config(state=tk.NORMAL, text="Show technical details ▼")
        else:
            self.btn_toggle_technical.config(state=tk.DISABLED)
        
        # Display simple text only
        self.feature_text.config(state=tk.NORMAL)
        self.feature_text.delete("1.0", tk.END)
        self.feature_text.insert("1.0", analysis)
        self.feature_text.config(state=tk.DISABLED)
    
    def toggle_technical_details(self):
        """Toggle between simple explanations and detailed technical feature data."""
        if self.current_technical_data is None:
            return
        
        self.show_technical = not self.show_technical
        
        self.feature_text.config(state=tk.NORMAL)
        self.feature_text.delete("1.0", tk.END)
        
        if self.show_technical:
            # Show simple text + technical details
            self.feature_text.insert("1.0", self.current_simple_text)
            self.feature_text.insert(tk.END, "\n" + "═" * 80 + "\n")
            self.feature_text.insert(tk.END, "TECHNICAL DETAILS - Feature Importance Ranking:\n")
            self.feature_text.insert(tk.END, "─" * 80 + "\n\n")
            
            for idx, row in self.current_technical_data.iterrows():
                feat_name = row['feature']
                importance = row['importance']
                value = row['value']
                # Reverse log1p transform to show original value
                original_value = np.expm1(value)
                self.feature_text.insert(
                    tk.END,
                    f"{feat_name:30s}  importance: {importance:6.4f}  value: {original_value:12.2f}\n"
                )
            
            self.btn_toggle_technical.config(text="Hide technical details ▲")
        else:
            # Show simple text only
            self.feature_text.insert("1.0", self.current_simple_text)
            self.btn_toggle_technical.config(text="Show technical details ▼")
        
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
1