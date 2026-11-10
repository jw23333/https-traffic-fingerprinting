"""RF inference on the exact padded/scaled packet representation used by CNN."""
from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np

from cnn_model import encode_sequences
from packet_sequences import signed_sequence


def packet_matrix(sequences, preprocessing) -> np.ndarray:
    """Flatten only the singleton CNN channel; do not add summary features/log1p."""
    values, _ = encode_sequences(sequences, preprocessing)
    return values.numpy()[:, 0, :].copy()


class PacketRFPredictor:
    def __init__(self, path: str | Path, *, bundle=None):
        self.path = Path(path).resolve()
        self.bundle = joblib.load(self.path) if bundle is None else bundle
        if self.bundle.get('model_type') != 'signed_packet_rf':
            raise ValueError('Not a signed-packet RF bundle.')
        self.model = self.bundle['model']
        self.encoder = self.bundle['label_encoder']
        self.preprocessing = self.bundle['preprocessing']

    def predict_sequence(self, sequence) -> dict:
        values = packet_matrix([sequence], self.preprocessing)
        probabilities = self.model.predict_proba(values)[0]
        class_labels = self.encoder.inverse_transform(self.model.classes_)
        winner = int(probabilities.argmax())
        return {'available': True, 'label': str(class_labels[winner]),
                'confidence': float(probabilities[winner]),
                'class_scores': {str(label): float(score)
                                 for label, score in zip(class_labels, probabilities)},
                'model_type': 'packet_rf', 'score_type': 'mean_tree_probability',
                'model_path': str(self.path), 'features': [],
                'input_packets': len(sequence),
                'used_packets': min(len(sequence), self.preprocessing['sequence_length'])}

    def predict_capture(self, capture) -> dict:
        if not capture.packets:
            return {'available': False, 'reason': 'No packets to classify.'}
        return self.predict_sequence(signed_sequence(capture.packets))
