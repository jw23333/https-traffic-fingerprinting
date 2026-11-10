"""Protect the fresh holdout and shared RF fitting order when expanding data."""
from pathlib import Path
import tempfile
import unittest

import numpy as np
import pandas as pd

from prepare_expanded_dataset import declare_holdout
from run_rf_ablation import resolve_split
from collect_dataset import SITES, sanitize_name
from prepare_expanded_dataset import LABELS, prepare


class ExpandedSplitTests(unittest.TestCase):
    def test_preparation_uses_the_shared_page_list_and_accepts_historical_subsets(self):
        self.assertEqual(len(SITES), 15)
        self.assertEqual(LABELS, tuple(sanitize_name(url) for url in SITES))
        self.assertEqual(len(set(LABELS)), 15)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pd.DataFrame(columns=['label', 'pcap', 'pairs_csv']).to_csv(root / 'previous.csv', index=False)
            for label in LABELS:
                (root / label).mkdir()
            with self.assertRaisesRegex(ValueError, 'flu: expected exactly 200'):
                prepare(root, root / 'previous.csv', root / 'new', labels=['flu'])
            self.assertFalse((root / 'new').exists())
            with self.assertRaisesRegex(ValueError, 'distinct labels'):
                prepare(root, root / 'previous.csv', root / 'new', labels=['flu', 'flu'])

    def test_balanced_holdout_uses_only_new_visits_and_is_reproducible(self):
        records = pd.DataFrame([{'label': label, 'pcap': f'/tmp/{label}_{i}.pcap'}
                                for label in ('a', 'b', 'c', 'd') for i in range(20)])
        previous = {str(Path(path).resolve()) for path in records.groupby('label').head(7).pcap}
        split = declare_holdout(records, previous, 4, 42)
        pd.testing.assert_frame_equal(split, declare_holdout(records, previous, 4, 42))
        self.assertEqual(split[split.split == 'test'].groupby('label').size().tolist(), [4]*4)
        self.assertEqual(split[split.split == 'train'].groupby('label').size().tolist(), [16]*4)
        self.assertFalse(set(split[split.split == 'test'].pcap) & previous)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'assignments.csv'
            split.to_csv(path, index=False)
            train, test = resolve_split(split, np.repeat(range(4), 20), .2, 42, path)
            self.assertEqual(set(train), set(split.index[split.split == 'train']))
            self.assertEqual(set(test), set(split.index[split.split == 'test']))
            broken = split.copy()
            broken.loc[0, 'pcap'] = '/tmp/different.pcap'
            broken.to_csv(path, index=False)
            with self.assertRaises(ValueError):
                resolve_split(split, np.repeat(range(4), 20), .2, 42, path)

    def test_refuses_to_reuse_previously_inspected_visits_as_a_fallback(self):
        records = pd.DataFrame([{'label': 'a', 'pcap': f'/tmp/a_{i}.pcap'} for i in range(10)])
        previous = {str(Path(path).resolve()) for path in records.iloc[:8].pcap}
        with self.assertRaises(ValueError):
            declare_holdout(records, previous, 4, 42)


if __name__ == '__main__':
    unittest.main()
