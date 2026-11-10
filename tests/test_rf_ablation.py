"""Check information removal, training-only thresholds and replayable results."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

import joblib
import numpy as np
import pandas as pd

import process_dataset_pairs as pipeline
import run_rf_ablation as experiment
from gui_capture_app import predict_capture
from process_pcap import CaptureData


def pairs(out=100, incoming=1000, packets=2, duration=.02):
    return pd.DataFrame([
        {'out_bytes': out, 'in_bytes': incoming, 'out_pkts': packets, 'in_pkts': packets + 1,
         'out_start': index, 'out_end': index + duration,
         'in_start': index + .1, 'in_end': index + .1 + duration}
        for index in range(3)])


class FeatureRemovalTests(unittest.TestCase):
    def setUp(self):
        self.thresholds = {'out_bytes': 150, 'in_bytes': 1500}
        self.original = pairs()

    def test_held_out_values_cannot_change_fitted_thresholds(self):
        frames = [pairs(10, 100), pairs(20, 200), pairs(100000, 1000000)]
        thresholds = experiment.fit_byte_thresholds(frames, [0, 1])
        self.assertEqual(thresholds, {'out_bytes': 15., 'in_bytes': 150.})
        frames[2] = pairs(1, 1)
        self.assertEqual(experiment.fit_byte_thresholds(frames, [0, 1]), thresholds)

    def test_removal_hides_each_property_including_derived_size_patterns(self):
        changes = {
            'without_size': pairs(100000, 1000000),
            'without_duration': pairs(duration=.08),
            'without_packet_count': pairs(packets=100),
        }
        original = experiment.feature_table([self.original], self.thresholds)
        self.assertEqual(original.shape[1], 36)
        for variant, changed in changes.items():
            with self.subTest(variant=variant):
                altered = experiment.feature_table([changed], self.thresholds)
                self.assertFalse(original.equals(altered))
                pd.testing.assert_frame_equal(
                    experiment.select_features(original, variant),
                    experiment.select_features(altered, variant))
        without_size = experiment.select_features(original, 'without_size')
        self.assertEqual(set(without_size), {'total_pairs', 'mean_out_pkts', 'mean_in_pkts',
                                            'mean_out_dur', 'mean_in_dur'})

    def test_explicit_thresholds_do_not_change_existing_gui_feature_defaults(self):
        before = pipeline.summary_features(self.original)
        changed = pipeline.summary_features(self.original, out_small_threshold=150,
                                            in_small_threshold=1500)
        self.assertNotEqual(before['count_out_small'], changed['count_out_small'])
        self.assertEqual(pipeline.summary_features(self.original), before)


class ExperimentReplayTests(unittest.TestCase):
    def test_saved_results_share_the_split_and_replay_with_saved_models(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rows = []
            for label, scale in [('chickenpox', 1), ('measles', 2), ('mumps', 3), ('rubella', 4)]:
                for visit in range(4):
                    path = root / f'{label}_{visit}.csv'
                    pairs(100 * scale + visit, 1000 * scale, scale + 1).to_csv(path, index=False)
                    rows.append({'label': label, 'pcap': f'{label}_{visit}.pcap', 'pairs_csv': str(path)})
            metadata = root / 'metadata.csv'
            pd.DataFrame(rows).to_csv(metadata, index=False)
            before = {path: experiment.sha256(path) for path in root.glob('*.csv')}
            output, models = root / 'results', root / 'models'
            with redirect_stdout(io.StringIO()):
                result = experiment.run_experiment(metadata, output, models,
                                                   test_size=.25, trees=5)
            saved = json.loads((output / 'results.json').read_text())
            self.assertEqual(saved['metadata_sha256'], before[metadata])
            split = pd.read_csv(output / 'split.csv')
            predictions = pd.read_csv(output / 'predictions.csv')
            self.assertEqual(split.split.value_counts().to_dict(), {'train': 12, 'test': 4})
            self.assertEqual(len(predictions), 16)
            self.assertTrue((output / 'confusion_matrices.svg').is_file())
            for variant, details in result['variants'].items():
                observed = predictions[predictions.variant == variant]
                self.assertEqual(set(observed.sample_id), set(split[split.split == 'test'].sample_id))
                self.assertEqual(int(observed.correct.sum()), details['correct'])
                bundle = joblib.load(models / f'{variant}.joblib')
                sample = split.loc[split.sample_id == observed.iloc[0].sample_id].iloc[0]
                features = experiment.feature_table([pd.read_csv(sample.resolved_pairs_csv)],
                                                     bundle['burst_size_thresholds'])
                X = np.log1p(features[bundle['feature_names']])
                label = bundle['label_encoder'].inverse_transform(bundle['model'].predict(X))[0]
                self.assertEqual(label, observed.iloc[0].predicted_label)
                # Inference must use each retrained model's saved byte boundaries,
                # including when they differ from the legacy GUI defaults.
                capture = CaptureData([], [], pd.read_csv(sample.resolved_pairs_csv).to_dict('records'))
                gui_prediction = predict_capture(capture, [str(models / f'{variant}.joblib')], 0.)
                self.assertEqual(gui_prediction['label'], label)
                self.assertAlmostEqual(gui_prediction['confidence'],
                                       float(bundle['model'].predict_proba(X).max()))
                self.assertEqual(dict((name, value) for name, value, _ in gui_prediction['features']),
                                 features[bundle['feature_names']].iloc[0].to_dict())
                self.assertEqual(len(details['removed_features']) + details['features'], 36)
            self.assertEqual({path: experiment.sha256(path) for path in before}, before)
            with self.assertRaises(FileExistsError):
                experiment.run_experiment(metadata, output, models, test_size=.25, trees=5)


if __name__ == '__main__':
    unittest.main()
