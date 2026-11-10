"""Check direction reconstruction, padding, leakage boundaries and score delivery."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

import numpy as np
import pandas as pd
import torch

from cnn_model import ARCHITECTURE, CNNPredictor, PacketCNN, encode_sequences, fit_preprocessing
from gui_capture_app import CaptureApp, predict_capture
from packet_sequences import infer_client_ips, signed_sequence
from process_pcap import CaptureData
from train_cnn import checkpoint, split_development


class PacketRepresentationTests(unittest.TestCase):
    def test_recovers_historical_ipv4_and_ipv6_clients_from_connections(self):
        rows = [
            {'ip.src': '192.0.2.5', 'ip.dst': '198.51.100.8',
             'tcp.srcport': '51000', 'tcp.dstport': '443'},
            {'ipv6.src': '2001:db8::8', 'ipv6.dst': '2001:db8::5',
             'udp.srcport': '443', 'udp.dstport': '51001'},
        ]
        self.assertEqual(infer_client_ips(rows), {'192.0.2.5', '2001:db8::5'})
        rows.append({'ip.src': '198.51.100.8', 'ip.dst': '192.0.2.5',
                     'tcp.srcport': '51000', 'tcp.dstport': '443'})
        with self.assertRaises(ValueError):
            infer_client_ips(rows)

    def test_sequence_preserves_packet_order_and_signed_size(self):
        sequence = signed_sequence([
            {'frame.time_relative': '.2', 'signed_len': '-1400'},
            {'frame.time_relative': '.1', 'signed_len': '100'}])
        np.testing.assert_array_equal(sequence, [100, -1400])

    def test_preprocessing_depends_only_on_fitting_visits(self):
        sequences = [np.array([100, -200]), np.ones(1000) * 99999]
        config = fit_preprocessing(sequences, [0])
        self.assertEqual(config['sequence_length'], 64)
        self.assertEqual(config['size_scale'], 200.)
        sequences[1] = np.ones(10000) * 1e6
        self.assertEqual(fit_preprocessing(sequences, [0]), config)

    def test_validation_never_changes_the_original_test_assignments(self):
        records = pd.DataFrame([
            {'label': label, 'split': 'test' if visit == 4 else 'train'}
            for label in ('chickenpox', 'measles', 'mumps', 'rubella') for visit in range(5)])
        fit, validation, development, test = split_development(records, 42, 1)
        self.assertEqual((len(fit), len(validation), len(development), len(test)), (12, 4, 16, 4))
        self.assertFalse(set(fit) & set(validation))
        self.assertFalse(set(development) & set(test))
        self.assertEqual(set(test), set(records.index[records.split == 'test']))


class CNNPredictionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        torch.set_num_threads(1)

    def test_padding_cannot_change_prediction_or_create_nonfinite_gradients(self):
        torch.manual_seed(42)
        model = PacketCNN(4, **ARCHITECTURE).eval()
        sequence = [np.array([100, -1400, -900, 66, -300], dtype=np.float32)]
        a, lengths = encode_sequences(sequence, {'sequence_length': 16, 'size_scale': 1500})
        b, other_lengths = encode_sequences(sequence, {'sequence_length': 64, 'size_scale': 1500})
        b[:, :, 5:] = 9999  # Even arbitrary data outside the valid length must be masked.
        torch.testing.assert_close(model(a, lengths), model(b, other_lengths), atol=1e-6, rtol=1e-5)
        model.train()
        loss = model(a, lengths).square().sum()
        loss.backward()
        self.assertTrue(all(torch.isfinite(p.grad).all() for p in model.parameters()))

    def test_checkpoint_returns_scores_and_frontend_alone_applies_thresholds(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'model.pt'
            torch.manual_seed(42)
            model = PacketCNN(4, **ARCHITECTURE)
            torch.save(checkpoint(model, ['chickenpox', 'measles', 'mumps', 'rubella'],
                                  {'sequence_length': 64, 'size_scale': 1500}, {}), path)
            capture = CaptureData([
                {'frame.time_relative': '.1', 'signed_len': '100'},
                {'frame.time_relative': '.2', 'signed_len': '-1400'}], [], [])
            predictor = CNNPredictor(path)
            first = predictor.predict_capture(capture)
            second = predictor.predict_capture(capture)
            self.assertEqual(first, second)
            self.assertNotIn('accepted', first)
            self.assertAlmostEqual(sum(first['class_scores'].values()), 1., places=6)
            self.assertEqual(first['confidence'], max(first['class_scores'].values()))
            accepted = predict_capture(capture, [str(path)], 0.)
            rejected = predict_capture(capture, [str(path)], 1.)
            self.assertTrue(accepted['accepted'])
            self.assertFalse(rejected['accepted'])
            self.assertEqual(accepted['confidence'], rejected['confidence'])
            app = SimpleNamespace(
                inspector=Mock(), feature_table=Mock(get_children=Mock(return_value=[])),
                status_var=Mock(), prediction_var=Mock(), prediction_detail_var=Mock(),
                model_info_var=Mock(), model_heading_var=Mock(), model_description_var=Mock(),
                visit_context={'custom_url': False})
            CaptureApp._display_result(app, capture, accepted, None, '/tmp/fixture.pcap')
            self.assertIn(f'{accepted["confidence"]:.1%}', app.prediction_var.set.call_args.args[0])
            self.assertEqual(app.feature_table.insert.call_count, 4)


if __name__ == '__main__':
    unittest.main()
