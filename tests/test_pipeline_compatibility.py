"""Exercise the existing PCAP -> pairs -> RF features -> GUI prediction contract."""
from contextlib import ExitStack, redirect_stdout
import csv
import io
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest.mock import patch

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

import build_pairs_dataset as builder
from gui_capture_app import predict_capture
from process_dataset_pairs import build_dataset_from_metadata
from process_pcap import load_capture_data


def fixture_pcap(path):
    """A saved packet fixture only; sends no network traffic."""
    contents = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    client, server = b'\xc0\x00\x02\x0a', b'\xc6\x33\x64\x14'
    for index in range(8):
        outgoing = index % 4 < 2
        source, destination = (client, server) if outgoing else (server, client)
        ports = (51000, 443) if outgoing else (443, 51000)
        payload = b'x' * (20 if outgoing else 200)
        tcp = struct.pack('!HHIIBBHHH', *ports, index*300, 1, 0x50, 0x18, 65535, 0, 0)
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(tcp)+len(payload), index, 0, 64, 6, 0, source, destination)
        ethernet = b'\0'*12 + b'\x08\x00'
        packet = ethernet + ip + tcp + payload
        contents.extend(struct.pack('<IIII', 1700000000, 100000+index*10000, len(packet), len(packet)))
        contents.extend(packet)
    path.write_bytes(contents)


@unittest.skipUnless(shutil.which('tshark'), 'tshark is required to read the fixture')
class PipelineCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.raw = self.root / 'raw'
        for label in ('chickenpox','measles','mumps','rubella'):
            folder = self.raw / label
            folder.mkdir(parents=True)
            for visit in (1,2): fixture_pcap(folder / f'{label}_{visit}.pcap')
        self.pairs = self.root / 'pairs'
        self.meta = self.root / 'metadata.csv'
        self.stack.enter_context(patch('process_pcap.get_local_ips', return_value={'192.0.2.10'}))
        self.stack.enter_context(redirect_stdout(io.StringIO()))

    def test_separate_collection_preserves_features_and_gui_prediction(self):
        rows = builder.build(self.raw, self.pairs, 'fixture', self.meta)
        self.assertEqual(len(rows), 8)
        with self.meta.open() as handle:
            self.assertEqual(csv.DictReader(handle).fieldnames, ['label','pcap','pairs_csv'])
        X, labels, paths = build_dataset_from_metadata(self.meta)
        self.assertEqual(X.shape, (8,36))
        self.assertEqual(set(labels), {'chickenpox','measles','mumps','rubella'})
        self.assertTrue(all(Path(path).is_file() for path in paths))
        encoder = LabelEncoder().fit(labels)
        model = RandomForestClassifier(n_estimators=3, random_state=42)
        model.fit(np.log1p(X), encoder.transform(labels))
        bundle = self.root / 'fixture_model.joblib'
        joblib.dump({'model':model,'label_encoder':encoder,'feature_names':list(X.columns)}, bundle)
        capture = load_capture_data(rows[0]['pcap'], 'fixture', local_ips={'192.0.2.10'})
        self.assertEqual(len(capture.packets), 8)
        self.assertEqual(len(capture.pairs), 2)
        self.assertEqual(sorted(i for b in capture.bursts for i in b['packet_indices']),list(range(8)))
        prediction = predict_capture(capture, [str(bundle)], 0)
        self.assertTrue(prediction['available'])
        self.assertEqual(len(prediction['features']), 36)
        self.assertIn(prediction['label'], set(labels))

    def test_original_build_defaults_still_work(self):
        with patch.object(builder,'RAW_DATASET',self.raw), \
             patch.object(builder,'PAIRS_DATASET',self.pairs), \
             patch.object(builder,'METADATA_FILE',str(self.meta)):
            rows=builder.build()
        self.assertEqual(len(rows),8)
        self.assertTrue(self.meta.is_file())

    def test_wrong_folder_does_not_overwrite_existing_metadata(self):
        self.meta.write_text('existing metadata')
        with self.assertRaisesRegex(ValueError,'--raw-dir'):
            builder.build(self.root,self.pairs,'fixture',self.meta)
        self.assertEqual(self.meta.read_text(),'existing metadata')


if __name__ == '__main__':
    unittest.main()
