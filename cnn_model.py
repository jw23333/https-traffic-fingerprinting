"""Compact packet CNN and threshold-free predictions for the frontend.

Confidence is the largest uncalibrated softmax score. This module deliberately
does not accept, reject, or choose application thresholds.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import numpy as np
import torch
from torch import nn
from torch.nn import functional as F

from packet_sequences import signed_sequence


ARCHITECTURE = {'channels': [32, 64, 128], 'kernels': [7, 5, 3], 'dropout': .3}


def fit_preprocessing(sequences: list[np.ndarray], fit_indices) -> dict:
    """Fit the input policy using only the fitting subset, never validation/test."""
    counts = [len(sequences[index]) for index in fit_indices]
    length = max(64, int(np.ceil(np.percentile(counts, 95) / 64)) * 64)
    scale = max(float(np.abs(sequences[index][:length]).max()) for index in fit_indices)
    if not np.isfinite(scale) or scale <= 0:
        raise ValueError('Training packet sizes must be finite and nonzero.')
    return {'sequence_length': length, 'size_scale': scale,
            'length_rule': '95th percentile of fitting lengths, rounded up to a multiple of 64',
            'scale_rule': 'Largest absolute retained packet size in fitting visits',
            'truncation': 'Keep first N packets', 'padding': 'Append zeros; masked in the CNN'}


def encode_sequences(sequences: list[np.ndarray], config: dict):
    length, scale = int(config['sequence_length']), float(config['size_scale'])
    if length < 1 or not np.isfinite(scale) or scale <= 0:
        raise ValueError('Invalid saved input length or scale.')
    values = np.zeros((len(sequences), 1, length), dtype=np.float32)
    lengths = np.empty(len(sequences), dtype=np.int64)
    for index, sequence in enumerate(sequences):
        sequence = np.asarray(sequence, dtype=np.float32)
        if sequence.ndim != 1 or not len(sequence) or not np.isfinite(sequence).all() or np.any(sequence == 0):
            raise ValueError('Expected nonempty, finite, nonzero signed packet sizes.')
        count = min(len(sequence), length)
        values[index, 0, :count] = sequence[:count] / scale
        lengths[index] = count
    return torch.from_numpy(values), torch.from_numpy(lengths)


class PacketCNN(nn.Module):
    def __init__(self, classes: int, channels=None, kernels=None, dropout: float = .3):
        super().__init__()
        channels = ARCHITECTURE['channels'] if channels is None else channels
        kernels = ARCHITECTURE['kernels'] if kernels is None else kernels
        if len(channels) != len(kernels) or not len(channels):
            raise ValueError('Provide matching convolution channels and kernels.')
        self.convolutions = nn.ModuleList()
        incoming = 1
        for outgoing, kernel in zip(channels, kernels):
            self.convolutions.append(nn.Conv1d(incoming, outgoing, kernel, padding=kernel // 2))
            incoming = outgoing
        self.dropout = nn.Dropout(dropout)
        self.classifier = nn.Linear(incoming, classes)

    @staticmethod
    def mask(values, lengths):
        positions = torch.arange(values.shape[-1], device=values.device)
        return positions[None, None, :] < lengths[:, None, None]

    def forward(self, values, lengths):
        values = values.masked_fill(~self.mask(values, lengths), 0)
        for index, convolution in enumerate(self.convolutions):
            values = F.elu(convolution(values))
            valid = self.mask(values, lengths)
            values = values.masked_fill(~valid, 0)
            if index < len(self.convolutions) - 1:
                # Invalid zero padding must not beat valid negative activations.
                values = F.max_pool1d(values.masked_fill(~valid, torch.finfo(values.dtype).min),
                                      kernel_size=2, stride=2, ceil_mode=True)
                lengths = (lengths + 1) // 2
                values = values.masked_fill(~self.mask(values, lengths), 0)
        pooled = values.sum(dim=-1) / lengths[:, None].to(values.dtype)
        return self.classifier(self.dropout(pooled))


class CNNPredictor:
    def __init__(self, checkpoint_path: str | Path):
        self.path = Path(checkpoint_path).resolve()
        checkpoint = torch.load(self.path, map_location='cpu', weights_only=True)
        if checkpoint.get('model_type') != 'signed_packet_cnn':
            raise ValueError('Not a signed-packet CNN checkpoint.')
        self.labels = checkpoint['labels']
        self.preprocessing = checkpoint['preprocessing']
        self.model = PacketCNN(len(self.labels), **checkpoint['architecture'])
        self.model.load_state_dict(checkpoint['state_dict'])
        self.model.eval()

    def predict_sequence(self, sequence: np.ndarray) -> dict:
        values, lengths = encode_sequences([sequence], self.preprocessing)
        with torch.inference_mode():
            probabilities = self.model(values, lengths).softmax(dim=1)[0].numpy()
        if not np.isfinite(probabilities).all():
            raise ValueError('CNN returned nonfinite scores.')
        winner = int(probabilities.argmax())
        return {'available': True, 'label': self.labels[winner],
                'confidence': float(probabilities[winner]),
                'class_scores': {label: float(score) for label, score in zip(self.labels, probabilities)},
                'score_type': 'uncalibrated_softmax', 'model_type': 'cnn',
                'model_path': str(self.path), 'features': [],
                'input_packets': len(sequence), 'used_packets': int(lengths[0])}

    def predict_capture(self, capture) -> dict:
        if not capture.packets:
            return {'available': False, 'reason': 'No packets to classify.'}
        return self.predict_sequence(signed_sequence(capture.packets))


@lru_cache(maxsize=4)
def _cached_predictor(path: str, modified_ns: int) -> CNNPredictor:
    return CNNPredictor(path)


def predict_cnn_capture(capture, checkpoint_path: str | Path) -> dict:
    path = Path(checkpoint_path).resolve()
    return _cached_predictor(str(path), path.stat().st_mtime_ns).predict_capture(capture)
