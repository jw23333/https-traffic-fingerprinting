#!/usr/bin/env python3
"""Capture HTTPS traffic, inspect bursts/packets, and display the RF prediction.

Run: python3 gui_capture_app.py --interface en1
Saved capture: python3 gui_capture_app.py --pcap capture.pcap --local-ip 192.168.1.10
"""
from __future__ import annotations

import argparse
import ipaddress
import os
from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

import joblib
import numpy as np
import pandas as pd

from capture_safari_all import start_capture, stop_capture, DEFAULT_OUT_DIR
from process_pcap import (CaptureData, default_pairs_csv_path, get_local_ips,
                          load_capture_data, write_pairs_csv)
from process_dataset_pairs import summary_features
from traffic_inspector import TrafficInspector


def parse_client_ips(value: str) -> set[str]:
    """Validate comma/space-separated IPv4 or IPv6 client addresses."""
    ips = {str(ipaddress.ip_address(part.split('%', 1)[0]))
           for part in value.replace(',', ' ').split()}
    if not ips:
        raise ValueError('Enter at least one client IP address from the saved capture.')
    return ips


def predict_capture(capture: CaptureData, model_candidates: list[str],
                    confidence_threshold: float, margin_threshold: float,
                    monitored_labels: set[str] | None) -> dict:
    """Use the existing summary features, preprocessing and trained model."""
    if not capture.pairs:
        return {'available': False, 'reason': 'No outgoing/incoming burst pairs to classify.'}
    bundle_path = next((path for path in model_candidates if Path(path).is_file()), None)
    if bundle_path is None:
        raise FileNotFoundError('Trained model not found. Supply --model or place rf_model.joblib in the project directory.')
    bundle = joblib.load(bundle_path)
    clf = bundle.get('model')
    encoder = bundle.get('label_encoder')
    names = bundle.get('feature_names')
    if clf is None or encoder is None or names is None:
        raise ValueError('Model bundle must contain model, label_encoder and feature_names.')
    features = summary_features(pd.DataFrame(capture.pairs))
    raw = pd.DataFrame([features]).replace([np.inf, -np.inf], 0).fillna(0)
    missing = set(names) - set(raw.columns)
    if missing:
        raise ValueError('This inspector requires a summary-feature model. Missing features: ' + ', '.join(sorted(missing)[:5]))
    X = np.log1p(raw).reindex(columns=names)
    encoded_label = clf.predict(X)[0]
    label = str(encoder.inverse_transform([encoded_label])[0])
    confidence = margin = None
    if hasattr(clf, 'predict_proba'):
        probabilities = clf.predict_proba(X)[0]
        # Use the probability of the predicted class, regardless of class order.
        position = list(clf.classes_).index(encoded_label)
        confidence = float(probabilities[position])
        competitors = np.delete(probabilities, position)
        margin = confidence - float(competitors.max()) if len(competitors) else confidence
    reason = None
    if monitored_labels is not None and label not in monitored_labels:
        reason = 'Predicted page is outside the monitored set.'
    elif confidence is not None and confidence < confidence_threshold:
        reason = f'Confidence is below {confidence_threshold:.0%}.'
    elif margin is not None and margin < margin_threshold:
        reason = f'Top-two probability gap is below {margin_threshold:.0%}.'
    return {
        'available': True, 'label': label, 'confidence': confidence, 'margin': margin,
        'accepted': reason is None, 'reason': reason,
        'features': [(name, float(raw.iloc[0][name]), float(importance))
                     for name, importance in zip(names, clf.feature_importances_)],
    }


class CaptureApp(tk.Tk):
    def __init__(self, interface: str = 'en1', out_dir: str | None = None,
                 model_path: str | None = None, accept_all_labels: bool = False,
                 accept_labels: list[str] | None = None):
        super().__init__()
        self.title('HTTPS Traffic Inspector')
        self.geometry('1240x900')
        self.minsize(980, 760)
        self.interface = interface
        self.out_dir = os.path.expanduser(out_dir) if out_dir else DEFAULT_OUT_DIR
        self.proc = None
        self.pcap_path = None
        self.capture_data = None
        self.capture_local_ips = None
        self.processing = False
        self.closing = False
        self.events = queue.Queue()
        self.cleanup_after_predict = True
        # Preserve the existing project's current decision thresholds.
        self.confidence_threshold = 0.70
        self.margin_threshold = 0.20
        self.monitored_labels = (set(accept_labels) if accept_labels else
                                 None if accept_all_labels else {'chickenpox', 'measles'})
        self.model_candidates = ([os.path.expanduser(model_path)] if model_path else [
            str(Path.cwd() / 'models' / 'rf_model.joblib'),
            str(Path.cwd() / 'rf_model.joblib'),
            str(Path(__file__).parent / 'rf_model.joblib'),
        ])
        self._build_ui()
        self.protocol('WM_DELETE_WINDOW', self.on_close)
        self.after(100, self._poll_events)

    def _build_ui(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)
        controls = ttk.Frame(self, padding=(12, 10))
        controls.grid(row=0, column=0, sticky='ew')
        self.btn_start = ttk.Button(controls, text='Start capture', command=self.on_start)
        self.btn_start.pack(side='left')
        self.btn_stop = ttk.Button(controls, text='Stop capture', command=self.on_stop, state='disabled')
        self.btn_stop.pack(side='left', padx=8)
        self.btn_open = ttk.Button(controls, text='Open capture…', command=self.on_open)
        self.btn_open.pack(side='left')
        ttk.Label(controls, text=f'Interface: {self.interface} · TCP/UDP port 443').pack(side='right')

        prediction = ttk.LabelFrame(self, text='Current prediction', padding=(12, 8))
        prediction.grid(row=1, column=0, sticky='ew', padx=12)
        self.prediction_var = tk.StringVar(value='No capture analysed yet')
        self.prediction_detail_var = tk.StringVar(value='Stop a capture to inspect traffic and run the model.')
        ttk.Label(prediction, textvariable=self.prediction_var, font=('Helvetica', 16, 'bold')).pack(anchor='w')
        ttk.Label(prediction, textvariable=self.prediction_detail_var, wraplength=1100).pack(anchor='w', pady=(3, 0))
        self.status_var = tk.StringVar(value='Ready')
        ttk.Label(self, textvariable=self.status_var, wraplength=1100).grid(
            row=2, column=0, sticky='w', padx=14, pady=6)

        self.notebook = ttk.Notebook(self)
        self.notebook.grid(row=3, column=0, sticky='nsew', padx=12, pady=(0, 12))
        self.inspector = TrafficInspector(self.notebook)
        self.notebook.add(self.inspector, text='Traffic inspection')
        model_panel = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(model_panel, text='Model details')
        model_panel.columnconfigure(0, weight=1)
        model_panel.rowconfigure(2, weight=1)
        ttk.Label(model_panel, text='Random Forest features', font=('Helvetica', 14, 'bold')).grid(row=0, column=0, sticky='w')
        ttk.Label(model_panel, text='Values describe this capture. Importance is the model’s overall feature ranking; '
                  'it does not explain this individual prediction.', wraplength=1000).grid(row=1, column=0, sticky='w', pady=8)
        self.feature_table = ttk.Treeview(model_panel, columns=('feature', 'value', 'importance'), show='headings')
        for column, label in [('feature', 'Feature'), ('value', 'Capture value'), ('importance', 'Global importance')]:
            self.feature_table.heading(column, text=label)
            self.feature_table.column(column, width=420 if column == 'feature' else 180, anchor='w')
        self.feature_table.grid(row=2, column=0, sticky='nsew')
        scrollbar = ttk.Scrollbar(model_panel, command=self.feature_table.yview)
        scrollbar.grid(row=2, column=1, sticky='ns')
        self.feature_table.configure(yscrollcommand=scrollbar.set)

    def _reset_result(self, message: str):
        self.capture_data = None
        self.inspector.clear()
        self.feature_table.delete(*self.feature_table.get_children())
        self.prediction_var.set(message)
        self.prediction_detail_var.set('')
        self.notebook.select(self.inspector)

    def _set_busy(self, busy: bool):
        self.processing = busy
        self.btn_start.configure(state='disabled' if busy else 'normal')
        self.btn_open.configure(state='disabled' if busy else 'normal')
        self.btn_stop.configure(state='disabled')

    def on_start(self):
        if self.processing or self.proc is not None:
            return
        try:
            # Record direction-label information before capture starts.
            ips = get_local_ips(self.interface)
            self.proc, self.pcap_path = start_capture(
                interface=self.interface, out_dir=self.out_dir,
                prefix='safari', duration=None, fixed=False)
            self.capture_local_ips = ips
            self._reset_result('Capturing — prediction pending')
            self.status_var.set('Capturing… Browse to a page, then stop to inspect the traffic.')
            self.btn_start.configure(state='disabled')
            self.btn_open.configure(state='disabled')
            self.btn_stop.configure(state='normal')
        except Exception as error:
            messagebox.showerror('Capture error', str(error))

    def on_stop(self):
        if self.proc is None or self.processing:
            return
        self._set_busy(True)
        self.prediction_var.set('Processing capture…')
        self.status_var.set('Stopping capture and building packet/burst views…')
        threading.Thread(target=self._process_and_predict,
                         args=(self.pcap_path, self.capture_local_ips, True, self.proc), daemon=True).start()

    def on_open(self):
        if self.processing or self.proc is not None:
            return
        path = filedialog.askopenfilename(title='Open a saved capture',
                                         filetypes=[('Packet captures', '*.pcap *.pcapng'), ('All files', '*')])
        if not path:
            return
        value = simpledialog.askstring('Client IP in saved capture',
            'Enter the computer’s IP address(es) at the time of this capture.\n'
            'Separate multiple addresses with commas or spaces.\n'
            'These determine incoming and outgoing direction.', parent=self)
        if value is None:
            return
        try:
            ips = parse_client_ips(value)
        except ValueError as error:
            messagebox.showerror('Invalid client IP', str(error))
            return
        self.open_capture(path, ips)

    def open_capture(self, path: str, local_ips: set[str]):
        if self.processing or self.proc is not None:
            return
        self.pcap_path = path
        self._reset_result('Processing capture…')
        self._set_busy(True)
        self.status_var.set(f'Reading {Path(path).name}…')
        threading.Thread(target=self._process_and_predict,
                         args=(path, local_ips, False), daemon=True).start()

    def _process_and_predict(self, pcap_path: str, local_ips: set[str],
                             cleanup: bool = False, proc=None):
        """Worker thread: communicate through a queue, never touch Tk widgets."""
        try:
            if proc is not None:
                stop_capture(proc)
            capture = load_capture_data(pcap_path, self.interface, local_ips=local_ips)
        except Exception as error:
            self.events.put(('error', str(error)))
            return
        prediction_error = None
        prediction = None
        cleanup_error = None
        try:
            # Preserve the existing live capture's pairs-file behaviour.
            pairs_path = default_pairs_csv_path(pcap_path)
            if cleanup:
                write_pairs_csv(capture.pairs, pairs_path)
            prediction = predict_capture(capture, self.model_candidates, self.confidence_threshold,
                                         self.margin_threshold, self.monitored_labels)
            if cleanup and self.cleanup_after_predict:
                cleanup_error = self._cleanup_files(pcap_path, pairs_path)
        except Exception as error:
            prediction_error = str(error)
        self.events.put(('result', (capture, prediction, prediction_error, Path(pcap_path).name, cleanup_error)))

    def _poll_events(self):
        if self.closing:
            return
        try:
            while True:
                event, payload = self.events.get_nowait()
                self.proc = None
                self._set_busy(False)
                if event == 'error':
                    self.prediction_var.set('Capture could not be processed')
                    self.status_var.set(payload)
                    messagebox.showerror('Processing error', payload)
                else:
                    self._display_result(*payload)
        except queue.Empty:
            pass
        self.after(100, self._poll_events)

    def _display_result(self, capture, prediction, prediction_error, filename, cleanup_error=None):
        self.capture_data = capture
        self.inspector.set_capture(capture)
        self.feature_table.delete(*self.feature_table.get_children())
        self.status_var.set(f'{filename} · {len(capture.packets):,} packets · '
                            f'{len(capture.bursts):,} bursts · {len(capture.pairs):,} model pairs')
        if cleanup_error:
            self.status_var.set(self.status_var.get() + ' · ' + cleanup_error)
        if prediction_error:
            self.prediction_var.set('Prediction unavailable')
            self.prediction_detail_var.set(prediction_error + ' Traffic inspection is still available.')
            return
        if not prediction['available']:
            self.prediction_var.set('Prediction unavailable')
            self.prediction_detail_var.set(prediction['reason'])
            return
        label = prediction['label']
        confidence = prediction['confidence']
        score = f' · Confidence: {confidence:.1%}' if confidence is not None else ''
        self.prediction_var.set(f'Model prediction: {label}{score}')
        if prediction['accepted']:
            decision = 'Monitored page detected.' if self.monitored_labels is not None else 'Prediction accepted.'
        else:
            decision = 'No monitored site detected. ' + prediction['reason']
        gap = f' Top-two probability gap: {prediction["margin"]:.1%}.' if prediction['margin'] is not None else ''
        self.prediction_detail_var.set(decision + gap)
        for name, value, importance in sorted(prediction['features'], key=lambda feature: feature[2], reverse=True):
            self.feature_table.insert('', 'end', values=(name, f'{value:,.6g}', f'{importance:.4f}'))

    def _cleanup_files(self, pcap_path: str, pairs_path: Path | str):
        """Only delete files from this live capture; its metadata stays in memory."""
        pcap = Path(pcap_path)
        errors = []
        for path in (Path(pairs_path), pcap.with_name(pcap.stem + '_dir.csv'), pcap):
            try:
                path.unlink(missing_ok=True)
            except OSError as error:
                errors.append(f'{path.name}: {error}')
        return 'Temporary file cleanup failed: ' + '; '.join(errors) if errors else None

    def on_close(self):
        self.closing = True
        if self.proc is not None:
            stop_capture(self.proc)
        self.destroy()


def main():
    parser = argparse.ArgumentParser(description='HTTPS traffic inspection and Random Forest prediction')
    parser.add_argument('--interface', default='en1', help='Capture interface (default: en1)')
    parser.add_argument('--model', help='Path to a trusted model bundle (.joblib file)')
    parser.add_argument('--out-dir', help='Directory for temporary live capture files')
    parser.add_argument('--accept-all-labels', action='store_true', help='Accept every model label')
    parser.add_argument('--accept-labels', nargs='+', help='Monitored labels to accept')
    parser.add_argument('--pcap', help='Open an existing capture without starting live capture')
    parser.add_argument('--local-ip', nargs='+', help='Client IP address(es) recorded in --pcap')
    args = parser.parse_args()
    if args.pcap and not args.local_ip:
        parser.error('--pcap requires --local-ip to label historical packet direction correctly')
    ips = None
    if args.pcap:
        try:
            ips = parse_client_ips(' '.join(args.local_ip))
        except ValueError as error:
            parser.error(str(error))
    app = CaptureApp(interface=args.interface, out_dir=args.out_dir, model_path=args.model,
                     accept_all_labels=args.accept_all_labels, accept_labels=args.accept_labels)
    if args.pcap:
        app.after(100, lambda: app.open_capture(args.pcap, ips))
    app.mainloop()


if __name__ == '__main__':
    main()
