"""Check matched RF/CNN packet values and frontend-owned score thresholds."""
from pathlib import Path
import tempfile
import unittest

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

from cnn_model import encode_sequences
from gui_capture_app import predict_capture
from packet_rf_model import PacketRFPredictor, packet_matrix
from process_pcap import CaptureData


class PacketRFTests(unittest.TestCase):
    def test_rf_values_exactly_equal_cnn_values_including_padding_and_truncation(self):
        sequences = [np.array([100, -1400, 66], dtype=np.float32),
                     np.array([200, -800, -400, 100], dtype=np.float32)]
        before = [sequence.copy() for sequence in sequences]
        config = {'sequence_length': 3, 'size_scale': 1506.}
        matrix = packet_matrix(sequences, config)
        cnn, _ = encode_sequences(sequences, config)
        np.testing.assert_array_equal(matrix, cnn.numpy()[:, 0, :])
        self.assertEqual(matrix.shape, (2, 3))
        self.assertLess(matrix[0, 1], 0)
        for source, old in zip(sequences, before):
            np.testing.assert_array_equal(source, old)
        padded = packet_matrix([sequences[0][:1]], config)
        np.testing.assert_array_equal(padded[0, 1:], [0, 0])

    def test_packet_rf_replay_returns_all_class_scores_without_a_threshold(self):
        labels = ['chickenpox', 'measles', 'mumps', 'rubella']
        sequences = [np.array([100 + 50 * index, -300 - 100 * index], dtype=np.float32)
                     for index in range(4)]
        config = {'sequence_length': 64, 'size_scale': 1506.}
        encoder = LabelEncoder().fit(labels)
        model = RandomForestClassifier(n_estimators=5, random_state=42)
        model.fit(packet_matrix(sequences, config), encoder.transform(labels))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'packet_rf.joblib'
            joblib.dump({'model_type': 'signed_packet_rf', 'model': model,
                         'label_encoder': encoder, 'preprocessing': config}, path)
            predictor = PacketRFPredictor(path)
            result = predictor.predict_sequence(sequences[0])
            self.assertNotIn('accepted', result)
            self.assertAlmostEqual(sum(result['class_scores'].values()), 1.)
            self.assertEqual(result['confidence'], max(result['class_scores'].values()))
            self.assertEqual(result['label'], max(result['class_scores'], key=result['class_scores'].get))
            capture = CaptureData([
                {'frame.time_relative': '.1', 'signed_len': '100'},
                {'frame.time_relative': '.2', 'signed_len': '-300'}], [], [])
            accepted = predict_capture(capture, [str(path)], 0.)
            rejected = predict_capture(capture, [str(path)], 1.01)
            self.assertTrue(accepted['accepted'])
            self.assertFalse(rejected['accepted'])
            self.assertEqual(accepted['confidence'], rejected['confidence'])
            self.assertEqual(accepted['score_type'], 'mean_tree_probability')


if __name__ == '__main__':
    unittest.main()
