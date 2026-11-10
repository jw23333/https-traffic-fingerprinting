#!/usr/bin/env python3
"""Visit a selected page, capture its force reload, and inspect an RF/CNN prediction.

Run: python3 gui_capture_app.py --interface en1
Saved capture: python3 gui_capture_app.py --pcap capture.pcap --local-ip 192.168.1.10
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import queue
import re
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd

from capture_safari_all import start_capture, stop_capture, DEFAULT_OUT_DIR
from collect_dataset import (CAPTURE_SECONDS, SITES, CaptureCancelled, SafariSession,
                             capture_visit, sanitize_name)
from process_pcap import (CaptureData, default_pairs_csv_path, get_local_ips,
                          load_capture_data, write_pairs_csv)
from process_dataset_pairs import summary_features
from traffic_inspector import TrafficInspector


CUSTOM_URL_OPTION = 'Custom URL…'


def available_models(model_path: str | None = None) -> dict[str, str]:
    """Offer the main completed comparison models and an explicit CLI model."""
    root = Path(__file__).resolve().parent
    candidates = [
        ('Random Forest · bursts', root / 'models/rf_feature_removal_15pages_20261101/baseline.joblib'),
        ('Random Forest · packets', root / 'models/rf_signed_packets_15pages_20261101/model.joblib'),
        ('CNN · packets', root / 'models/cnn_signed_packets_15pages_300epochs_local/final.pt'),
    ]
    models = {name: str(path) for name, path in candidates if path.is_file()}
    if model_path:
        explicit = str(Path(model_path).expanduser().resolve())
        if explicit not in models.values():
            models[f'Selected model · {Path(explicit).stem}'] = explicit
    if not models:
        historical = [Path.cwd() / 'models/rf_model.joblib', Path.cwd() / 'rf_model.joblib',
                      root / 'rf_model.joblib', root / 'rf_model_force_reload_rethresholded.joblib']
        path = next((path for path in historical if path.is_file()), historical[-1])
        models['Random Forest · bursts'] = str(path)
    return models


def model_inspection_input(path: str):
    """Read the saved representation so the plots match the selected model."""
    if Path(path).suffix == '.pt':
        import torch
        bundle = torch.load(path, map_location='cpu', weights_only=True)
    else:
        bundle = joblib.load(path)
    if bundle.get('model_type') in ('signed_packet_cnn', 'signed_packet_rf'):
        length = int(bundle['preprocessing']['sequence_length'])
        if length < 1:
            raise ValueError('The saved packet input length must be positive.')
        return 'packets', length
    return 'bursts', None


def normalize_visit_url(value: str) -> str:
    """Accept HTTPS targets supported by the existing port-443 capture flow."""
    url = value.strip()
    if not url:
        raise ValueError('Enter the URL to visit.')
    if any(character.isspace() or ord(character) < 32 or ord(character) == 127
           for character in url) or '\\' in url:
        raise ValueError('Use a URL without spaces, control characters or backslashes.')
    if url.startswith('//'):
        url = 'https:' + url
    elif not re.match(r'^[A-Za-z][A-Za-z0-9+.-]*:', url):
        url = 'https://' + url
    try:
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port
    except ValueError as error:
        raise ValueError('Enter a valid HTTPS URL.') from error
    if parts.scheme.lower() != 'https':
        raise ValueError('Use an https:// URL; this capture records HTTPS on port 443.')
    if not host:
        raise ValueError('Enter a URL with a website address, for example https://www.nhs.uk/.')
    if parts.username is not None or parts.password is not None:
        raise ValueError('Use a URL without an embedded username or password.')
    if port not in (None, 443):
        raise ValueError('Use HTTPS on port 443; other ports are outside this capture filter.')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        try:
            labels = host.encode('idna').decode('ascii').rstrip('.').split('.')
        except UnicodeError as error:
            raise ValueError('Enter a valid website address.') from error
        if any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
               for label in labels):
            raise ValueError('Enter a valid website address.')
    return url


def parse_client_ips(value: str) -> set[str]:
    """Validate comma/space-separated IPv4 or IPv6 client addresses."""
    ips = {str(ipaddress.ip_address(part.split('%', 1)[0]))
           for part in value.replace(',', ' ').split()}
    if not ips:
        raise ValueError('Enter at least one client IP address from the saved capture.')
    return ips


def predict_capture(capture: CaptureData, model_candidates: list[str],
                    confidence_threshold: float) -> dict:
    """Dispatch model inference and apply the frontend's confidence threshold."""
    bundle_path = next((path for path in model_candidates if Path(path).is_file()), None)
    if bundle_path is not None and Path(bundle_path).suffix == '.pt':
        from cnn_model import predict_cnn_capture
        prediction = predict_cnn_capture(capture, bundle_path)
        if prediction['available']:
            # CNN inference returns scores only. The frontend owns acceptance.
            reason = (f'Confidence is below {confidence_threshold:.0%}.'
                      if prediction['confidence'] < confidence_threshold else None)
            prediction.update(accepted=reason is None, reason=reason)
        return prediction
    if bundle_path is None:
        if not capture.pairs:
            return {'available': False, 'reason': 'No outgoing/incoming burst pairs to classify.'}
        raise FileNotFoundError('Trained model not found. Supply --model with a trusted .joblib or .pt model.')
    bundle = joblib.load(bundle_path)
    if bundle.get('model_type') == 'signed_packet_rf':
        from packet_rf_model import PacketRFPredictor
        prediction = PacketRFPredictor(bundle_path, bundle=bundle).predict_capture(capture)
        if prediction['available']:
            reason = (f'Confidence is below {confidence_threshold:.0%}.'
                      if prediction['confidence'] < confidence_threshold else None)
            prediction.update(accepted=reason is None, reason=reason)
        return prediction
    if not capture.pairs:
        return {'available': False, 'reason': 'No outgoing/incoming burst pairs to classify.'}
    clf = bundle.get('model')
    encoder = bundle.get('label_encoder')
    names = bundle.get('feature_names')
    if clf is None or encoder is None or names is None:
        raise ValueError('Model bundle must contain model, label_encoder and feature_names.')
    thresholds = bundle.get('burst_size_thresholds')
    threshold_options = ({'out_small_threshold': thresholds['out_bytes'],
                          'in_small_threshold': thresholds['in_bytes']}
                         if thresholds is not None else {})
    features = summary_features(pd.DataFrame(capture.pairs), **threshold_options)
    raw = pd.DataFrame([features]).replace([np.inf, -np.inf], 0).fillna(0)
    missing = set(names) - set(raw.columns)
    if missing:
        raise ValueError('This inspector requires a summary-feature model. Missing features: ' + ', '.join(sorted(missing)[:5]))
    X = np.log1p(raw).reindex(columns=names)
    encoded_label = clf.predict(X)[0]
    label = str(encoder.inverse_transform([encoded_label])[0])
    confidence = None
    if hasattr(clf, 'predict_proba'):
        probabilities = clf.predict_proba(X)[0]
        # Use the probability of the predicted class, regardless of class order.
        position = list(clf.classes_).index(encoded_label)
        confidence = float(probabilities[position])
    reason = None
    if confidence is not None and confidence < confidence_threshold:
        reason = f'Confidence is below {confidence_threshold:.0%}.'
    return {
        'available': True, 'label': label, 'confidence': confidence,
        'model_type': 'rf', 'score_type': 'mean_tree_probability',
        'accepted': reason is None, 'reason': reason,
        'model_path': str(Path(bundle_path).resolve()),
        'features': [(name, float(raw.iloc[0][name]), float(importance))
                     for name, importance in zip(names, clf.feature_importances_)],
    }


class CaptureApp(tk.Tk):
    def __init__(self, interface: str = 'en1', out_dir: str | None = None,
                 model_path: str | None = None,
                 manual_capture: bool = False, keep_captures: bool = True):
        super().__init__()
        self.title('HTTPS Traffic Inspector')
        self.geometry('1180x860')
        self.minsize(980, 740)
        self.interface = interface
        self.manual_capture = manual_capture
        default_dir = DEFAULT_OUT_DIR if manual_capture else str(Path(DEFAULT_OUT_DIR) / 'gui_captures')
        self.out_dir = os.path.expanduser(out_dir) if out_dir else default_dir
        self.proc = None
        self.pcap_path = None
        self.capture_data = None
        self.capture_local_ips = None
        self.processing = False
        self.closing = False
        self.events = queue.Queue()
        self.keep_captures_var = tk.BooleanVar(value=keep_captures)
        self.cleanup_after_predict = not keep_captures
        self.cancel_event = threading.Event()
        self.worker = None
        self.safari_session = SafariSession(verify_url=True)
        self.visit_number = 0
        self.visit_context = None
        self.page_urls = {sanitize_name(url).capitalize(): url for url in SITES}
        # The acceptance threshold applies equally to all trained page labels.
        self.confidence_threshold = 0.40
        self.models = available_models(model_path)
        explicit = str(Path(model_path).expanduser().resolve()) if model_path else None
        self.selected_model = next((name for name, path in self.models.items() if path == explicit),
                                   next(iter(self.models)))
        self.model_candidates = [self.models[self.selected_model]]
        self._build_ui()
        if Path(self.model_candidates[0]).is_file():
            try:
                self.inspector.set_model_input(*model_inspection_input(self.model_candidates[0]))
            except Exception as error:
                self.after_idle(messagebox.showerror, 'Model could not be loaded', str(error))
        self.protocol('WM_DELETE_WINDOW', self.on_close)
        self.after(100, self._poll_events)

    def _build_ui(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)
        controls = ttk.Frame(self, padding=(12, 10))
        controls.grid(row=0, column=0, sticky='ew')
        actions = ttk.Frame(controls)
        actions.pack(fill='x')
        self.page_var = tk.StringVar(value=next(iter(self.page_urls)))
        self.page_selector = None
        self.custom_url_var = tk.StringVar()
        self.custom_url_entry = None
        self.custom_url_row = None
        if not self.manual_capture:
            ttk.Label(actions, text='Page:').pack(side='left', padx=(0, 6))
            self.page_selector = ttk.Combobox(actions, textvariable=self.page_var,
                values=[*self.page_urls, CUSTOM_URL_OPTION], state='readonly', width=16)
            self.page_selector.pack(side='left', padx=(0, 10))
            self.page_selector.bind('<<ComboboxSelected>>', self._on_page_selected)
        self.btn_start = ttk.Button(actions,
            text='Start capture' if self.manual_capture else 'Visit & capture',
            command=self.on_start if self.manual_capture else self.on_visit)
        self.btn_start.pack(side='left')
        self.btn_stop = ttk.Button(actions,
            text='Stop capture' if self.manual_capture else 'Cancel',
            command=self.on_stop if self.manual_capture else self.on_cancel, state='disabled')
        self.btn_stop.pack(side='left', padx=8)
        self.btn_open = ttk.Button(actions, text='Open capture…', command=self.on_open)
        self.btn_open.pack(side='left')
        options = ttk.Frame(controls)
        options.pack(fill='x', pady=(7, 0))
        ttk.Label(options, text='Model').pack(side='left', padx=(0, 8))
        self.model_var = tk.StringVar(value=self.selected_model)
        self.model_selector = ttk.Combobox(options, textvariable=self.model_var,
            values=list(self.models), state='readonly', width=36)
        self.model_selector.pack(side='left')
        self.model_selector.bind('<<ComboboxSelected>>', self.on_model_selected)
        self.keep_checkbox = ttk.Checkbutton(options, text='Keep capture files', variable=self.keep_captures_var)
        self.keep_checkbox.pack(side='right')
        if not self.manual_capture:
            self.custom_url_row = ttk.Frame(controls)
            ttk.Label(self.custom_url_row, text='URL:').pack(side='left', padx=(0, 6))
            self.custom_url_entry = ttk.Entry(self.custom_url_row, textvariable=self.custom_url_var)
            self.custom_url_entry.pack(side='left', fill='x', expand=True)

        prediction = ttk.Frame(self, padding=(12, 8))
        prediction.grid(row=1, column=0, sticky='ew', padx=12)
        self.prediction_var = tk.StringVar(value='No capture analysed yet')
        self.prediction_detail_var = tk.StringVar(value='Capture a visit to inspect traffic and run the model.')
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
        model_panel.rowconfigure(3, weight=1)
        self.model_heading_var = tk.StringVar(value='Model input and scores')
        ttk.Label(model_panel, textvariable=self.model_heading_var, font=('Helvetica', 14, 'bold')).grid(row=0, column=0, sticky='w')
        self.model_info_var = tk.StringVar(value='Model details appear after prediction.')
        ttk.Label(model_panel, textvariable=self.model_info_var, wraplength=1000).grid(row=1, column=0, sticky='w', pady=(6, 0))
        self.model_description_var = tk.StringVar(value='Model details appear after prediction.')
        ttk.Label(model_panel, textvariable=self.model_description_var,
                  wraplength=1000).grid(row=2, column=0, sticky='w', pady=8)
        self.feature_table = ttk.Treeview(model_panel, columns=('feature', 'value', 'importance'), show='headings')
        for column, label in [('feature', 'Feature'), ('value', 'Capture value'), ('importance', 'Global importance')]:
            self.feature_table.heading(column, text=label)
            self.feature_table.column(column, width=420 if column == 'feature' else 180, anchor='w')
        self.feature_table.grid(row=3, column=0, sticky='nsew')
        scrollbar = ttk.Scrollbar(model_panel, command=self.feature_table.yview)
        scrollbar.grid(row=3, column=1, sticky='ns')
        self.feature_table.configure(yscrollcommand=scrollbar.set)

    def _reset_result(self, message: str):
        self.capture_data = None
        self.inspector.clear()
        self.feature_table.delete(*self.feature_table.get_children())
        self.prediction_var.set(message)
        self.prediction_detail_var.set('')
        self.model_info_var.set('Model details appear after prediction.')
        self.notebook.select(self.inspector)

    def on_model_selected(self, event=None):
        if self.processing or self.proc is not None or self.closing:
            return
        name = self.model_var.get()
        path = self.models[name]
        try:
            mode, input_length = model_inspection_input(path)
        except Exception as error:
            self.model_var.set(self.selected_model)
            messagebox.showerror('Model could not be loaded', str(error))
            return
        self.selected_model = name
        self.model_candidates = [path]
        self.inspector.set_model_input(mode, input_length)
        self.feature_table.delete(*self.feature_table.get_children())
        self.model_info_var.set(f'Model: {path}')
        self.model_heading_var.set('Model input and scores')
        self.model_description_var.set('Model details appear after prediction.')
        if self.capture_data is not None:
            self._set_busy(True)
            self.prediction_var.set('Updating prediction…')
            self.prediction_detail_var.set('')
            self.status_var.set('Applying the selected model to this capture…')
            self._start_worker(self._predict_loaded_capture, self.capture_data, path)

    def _predict_loaded_capture(self, capture, path):
        """Reuse the in-memory recording, including captures discarded from disk."""
        prediction, error = None, None
        try:
            prediction = predict_capture(capture, [path], self.confidence_threshold)
        except Exception as exception:
            error = str(exception)
        self.events.put(('result', (capture, prediction, error, self.pcap_path)))

    def _on_page_selected(self, event=None):
        if self.page_var.get() == CUSTOM_URL_OPTION:
            self.custom_url_row.pack(fill='x', pady=(7, 0))
            self.custom_url_entry.focus_set()
        else:
            self.custom_url_row.pack_forget()

    def _set_busy(self, busy: bool):
        self.processing = busy
        self.btn_start.configure(state='disabled' if busy else 'normal')
        self.btn_open.configure(state='disabled' if busy else 'normal')
        self.btn_stop.configure(state='disabled')
        self.keep_checkbox.configure(state='disabled' if busy else 'normal')
        self.model_selector.configure(state='disabled' if busy else 'readonly')
        if self.page_selector is not None:
            self.page_selector.configure(state='disabled' if busy else 'readonly')
        if self.custom_url_entry is not None:
            self.custom_url_entry.configure(state='disabled' if busy else 'normal')

    def _start_worker(self, target, *args):
        self.worker = threading.Thread(target=target, args=args, daemon=True)
        self.worker.start()

    def on_visit(self):
        if self.processing or self.proc is not None or self.closing:
            return
        custom_url = self.page_var.get() == CUSTOM_URL_OPTION
        try:
            if custom_url:
                url = normalize_visit_url(self.custom_url_var.get())
                self.custom_url_var.set(url)
            else:
                url = self.page_urls.get(self.page_var.get())
                if url is None:
                    raise ValueError('Choose a page from the list.')
        except ValueError as error:
            messagebox.showerror('Page selection', str(error))
            return
        if not any(Path(path).is_file() for path in self.model_candidates):
            messagebox.showerror('Model not found', 'Supply --model with a trained model before capturing a visit.')
            return
        self.cleanup_after_predict = not self.keep_captures_var.get()
        self.cancel_event.clear()
        self.visit_number += 1
        self.visit_context = {'requested_url': url, 'requested_page': sanitize_name(url),
                              'method': 'guided_force_reload', 'capture_seconds': CAPTURE_SECONDS,
                              'custom_url': custom_url}
        self._reset_result('Preparing visit — prediction pending')
        self._set_busy(True)
        self.btn_stop.configure(state='normal')
        self.status_var.set('Preparing Safari… The page will be reloaded and recording will stop automatically.')
        self._start_worker(self._capture_guided_visit, url, self.visit_number)

    def on_cancel(self):
        if self.processing:
            self.cancel_event.set()
            self.btn_stop.configure(state='disabled')
            self.status_var.set('Cancelling visit… A partial recording will be discarded.')

    def _capture_guided_visit(self, url: str, visit_number: int):
        """Reuse collection's capture routine. The chosen URL is never a model input."""
        try:
            ips = get_local_ips(self.interface)
            directory = Path(self.out_dir) / sanitize_name(url)
            if self.visit_context and self.visit_context.get('custom_url'):
                # Separate arbitrary URLs from labelled pages, including URLs
                # whose paths happen to end in a known condition name.
                host = sanitize_name('https://' + urlsplit(url).netloc)
                digest = hashlib.sha256(url.encode('utf-8')).hexdigest()[:12]
                directory = Path(self.out_dir) / 'custom' / f'{host}-{digest}'
            path = capture_visit(url, directory, visit_number,
                interface=self.interface, session=self.safari_session,
                cancel_event=self.cancel_event,
                progress=lambda message: self.events.put(('progress', message)))
            if self.cancel_event.is_set():
                path.unlink(missing_ok=True)
                raise CaptureCancelled('Visit cancelled; recording discarded.')
            self.pcap_path = str(path)
            self.capture_local_ips = ips
            self.events.put(('processing', 'Building burst/packet views and predicting…'))
            self._process_and_predict(str(path), ips, True)
        except CaptureCancelled as error:
            self.events.put(('cancelled', str(error)))
        except Exception as error:
            self.events.put(('error', str(error)))

    def on_start(self):
        if self.processing or self.proc is not None:
            return
        try:
            self.visit_context = None
            self.cleanup_after_predict = not self.keep_captures_var.get()
            # Record direction-label information before capture starts.
            ips = get_local_ips(self.interface)
            self.proc, self.pcap_path = start_capture(
                interface=self.interface, out_dir=self.out_dir,
                prefix='safari', duration=None, fixed=False)
            self.capture_local_ips = ips
            self._reset_result('Capturing — prediction pending')
            self.status_var.set('Capturing… In Safari, press Option+Command+R to reload the page from origin, '
                                'then stop to inspect the traffic.')
            self.btn_start.configure(state='disabled')
            self.btn_open.configure(state='disabled')
            self.btn_stop.configure(state='normal')
            self.keep_checkbox.configure(state='disabled')
            self.model_selector.configure(state='disabled')
        except Exception as error:
            messagebox.showerror('Capture error', str(error))

    def on_stop(self):
        if self.proc is None or self.processing:
            return
        self._set_busy(True)
        self.prediction_var.set('Processing capture…')
        self.status_var.set('Stopping capture and building packet/burst views…')
        self._start_worker(self._process_and_predict, self.pcap_path, self.capture_local_ips, True, self.proc)

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
        self.visit_context = None
        self._reset_result('Processing capture…')
        self._set_busy(True)
        self.status_var.set(f'Reading {Path(path).name}…')
        self._start_worker(self._process_and_predict, path, local_ips, False)

    def _process_and_predict(self, pcap_path: str, local_ips: set[str],
                             cleanup: bool = False, proc=None):
        """Worker thread: communicate through a queue, never touch Tk widgets."""
        def check_cancelled():
            if cleanup and self.visit_context is not None and self.cancel_event.is_set():
                self._cleanup_files(pcap_path, default_pairs_csv_path(pcap_path))
                raise CaptureCancelled('Visit cancelled; recording discarded.')

        check_cancelled()
        try:
            if proc is not None:
                stop_capture(proc)
            capture = load_capture_data(pcap_path, self.interface, local_ips=local_ips)
        except Exception as error:
            self.events.put(('error', str(error)))
            return
        check_cancelled()
        prediction_error = None
        prediction = None
        cleanup_error = None
        try:
            # Preserve the existing live capture's pairs-file behaviour.
            pairs_path = default_pairs_csv_path(pcap_path)
            if cleanup:
                write_pairs_csv(capture.pairs, pairs_path)
            prediction = predict_capture(capture, self.model_candidates, self.confidence_threshold)
            check_cancelled()
            if cleanup and self.cleanup_after_predict:
                cleanup_error = self._cleanup_files(pcap_path, pairs_path)
        except CaptureCancelled:
            raise
        except Exception as error:
            prediction_error = str(error)
        if cleanup and (not self.cleanup_after_predict or prediction_error is not None):
            # Keep the replay information even if the model failed to load.
            # The requested page is recorded separately from model output.
            metadata = {
                'pcap': str(Path(pcap_path).resolve()),
                'local_ips': sorted(local_ips),
                'interface': self.interface,
                'visit': self.visit_context,
                'prediction': {key: value for key, value in (prediction or {}).items() if key != 'features'},
                'prediction_error': prediction_error,
                'features': {name: value for name, value, _ in (prediction or {}).get('features', [])},
            }
            try:
                Path(pcap_path).with_suffix('.capture.json').write_text(json.dumps(metadata, indent=2) + '\n')
            except OSError as error:
                cleanup_error = f'Capture kept, but its metadata could not be saved: {error}'
        self.events.put(('result', (capture, prediction, prediction_error, pcap_path, cleanup_error)))

    def _poll_events(self):
        if self.closing:
            return
        try:
            while True:
                event, payload = self.events.get_nowait()
                if event in ('progress', 'processing'):
                    if not self.cancel_event.is_set():
                        self.status_var.set(payload)
                    if event == 'processing':
                        self.btn_stop.configure(state='disabled')
                        self.prediction_var.set('Processing capture…')
                    continue
                self.proc = None
                self._set_busy(False)
                if event == 'error':
                    self.prediction_var.set('Capture could not be processed')
                    print(payload, file=sys.stderr)
                    message = str(payload).strip() or 'The recording could not be processed. Try opening it again.'
                    if 'osascript' in message:
                        message = 'Safari could not prepare the visit. Check its automation permissions and try again.'
                    else:
                        message = message.splitlines()[0][:180]
                    self.status_var.set(message)
                    self.lift()
                    self.focus_force()
                    messagebox.showerror('Processing error', message)
                elif event == 'cancelled':
                    self.prediction_var.set('Visit cancelled — no prediction made')
                    self.status_var.set(payload)
                else:
                    self._display_result(*payload)
                    self.lift()
                    self.focus_force()
        except queue.Empty:
            pass
        self.after(100, self._poll_events)

    def _display_result(self, capture, prediction, prediction_error, filename, cleanup_error=None):
        new_capture = getattr(self, 'capture_data', None) is not capture
        self.capture_data = capture
        if new_capture:
            self.inspector.set_capture(capture)
        self.feature_table.delete(*self.feature_table.get_children())
        self.status_var.set(f'{len(capture.packets):,} packets · {len(capture.bursts):,} bursts')
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
        if prediction.get('model_path'):
            self.model_info_var.set(f'Model: {prediction["model_path"]}')
        confidence = prediction['confidence']
        score = f' · Confidence: {confidence:.1%}' if confidence is not None else ''
        custom_url = bool(self.visit_context and self.visit_context.get('custom_url'))
        title = 'Closest trained page' if custom_url else 'Model prediction'
        self.prediction_var.set(f'{title}: {label}{score}')
        if custom_url:
            decision = ('Scores compare trained pages only; they do not confirm the identity of this URL. '
                        + ('Confidence threshold passed.' if prediction['accepted'] else
                           'Confidence threshold failed: ' + prediction['reason']))
        elif prediction['accepted']:
            decision = 'Prediction accepted.'
        else:
            decision = 'Prediction rejected. ' + prediction['reason']
        self.prediction_detail_var.set(decision)
        if prediction.get('model_type') in ('cnn', 'packet_rf'):
            cnn = prediction['model_type'] == 'cnn'
            self.model_heading_var.set('CNN class scores' if cnn else 'Packet-sequence RF class scores')
            self.model_description_var.set(
                'Uncalibrated softmax scores; these are calculated differently from RF scores.' if cnn else
                'Mean tree probabilities for the RF using signed packet-size sequences.')
            self.feature_table.configure(displaycolumns=('feature', 'value'))
            self.feature_table.heading('feature', text='Page')
            self.feature_table.heading('value', text='Softmax score' if cnn else 'RF score')
            for page, probability in sorted(prediction['class_scores'].items(),
                                             key=lambda item: item[1], reverse=True):
                self.feature_table.insert('', 'end', values=(page, f'{probability:.1%}', ''))
            return
        if hasattr(self, 'model_heading_var'):
            self.model_heading_var.set('Random Forest features')
            self.model_description_var.set(
                'Values describe this capture. Importance is the model’s overall feature ranking; '
                'it does not explain this individual prediction.')
        self.feature_table.configure(displaycolumns=('feature', 'value', 'importance'))
        self.feature_table.heading('feature', text='Feature')
        self.feature_table.heading('value', text='Capture value')
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
        if self.closing:
            return
        self.closing = True
        self.cancel_event.set()
        self._set_busy(True)
        self.status_var.set('Stopping work before closing…')
        if self.proc is not None and (self.worker is None or not self.worker.is_alive()):
            self._start_worker(stop_capture, self.proc)
        self._finish_close()

    def _finish_close(self):
        # Keep the process alive until capture_visit's finally block has stopped
        # tshark. Destroying Tk immediately could orphan a recording child.
        if self.worker is not None and self.worker.is_alive():
            self.after(100, self._finish_close)
        else:
            self.destroy()


def main():
    parser = argparse.ArgumentParser(description='HTTPS traffic inspection and RF/CNN prediction')
    parser.add_argument('--interface', default='en1', help='Capture interface (default: en1)')
    parser.add_argument('--model', help='Path to a trusted RF (.joblib) or packet CNN (.pt) model')
    parser.add_argument('--out-dir', help='Capture directory (guided default: gui_captures in the project)')
    parser.add_argument('--manual-capture', action='store_true', help='Use the original manual Start/Stop controls')
    parser.add_argument('--discard-captures', action='store_true', help='Delete live files after successful prediction instead of keeping them')
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
                     manual_capture=args.manual_capture, keep_captures=not args.discard_captures)
    if args.pcap:
        app.after(100, lambda: app.open_capture(args.pcap, ips))
    app.mainloop()


if __name__ == '__main__':
    main()
