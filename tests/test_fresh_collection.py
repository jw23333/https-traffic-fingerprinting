"""Check balanced fresh collection and safe resume without Safari or tshark."""
from collections import Counter
from contextlib import ExitStack, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import collect_fresh_dataset as fresh
import extend_dataset as extension


class FreshCollectionTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory())) / 'fresh'
        self.sites = fresh.SITES[:3]
        self.stack.enter_context(patch.object(fresh, 'SITES', self.sites))
        self.stack.enter_context(patch.object(extension, 'valid_capture', return_value=True))
        self.stack.enter_context(patch.object(extension.time, 'sleep'))
        self.stack.enter_context(redirect_stdout(io.StringIO()))

    def capture(self, url, folder, visit, **kwargs):
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f'{extension.sanitize_name(url)}_{visit}_test.pcap'
        path.write_text(f'{url} {visit}')
        return path

    def test_preview_new_folder_has_no_filesystem_or_browser_side_effects(self):
        with patch.object(extension, 'capture_visit') as visit, \
             patch.object(extension, 'SafariSession') as session:
            fresh.collect(self.root, target=5, batch_size=2, dry_run=True)
        self.assertFalse(self.root.exists())
        visit.assert_not_called()
        session.assert_not_called()

    def test_rotates_balanced_batches_and_shares_one_safari_session(self):
        with patch.object(extension, 'capture_visit', side_effect=self.capture) as visit:
            fresh.collect(self.root, target=5, batch_size=2, interface='fixture')
        self.assertEqual(visit.call_count, 15)
        calls = visit.call_args_list
        for end, per_page in ((6, 2), (12, 4), (15, 5)):
            self.assertEqual(Counter(call.args[0] for call in calls[:end]),
                             {url: per_page for url in self.sites})
        self.assertTrue(all(call.kwargs['session'] is calls[0].kwargs['session'] for call in calls))
        self.assertTrue(all(call.kwargs['interface'] == 'fixture' for call in calls))
        config = json.loads((self.root / 'collection_config.json').read_text())
        self.assertEqual(config['target_visits_per_page'], 5)
        self.assertEqual(config['visits_per_batch'], 2)
        self.assertEqual(config['sites'], self.sites)
        self.assertEqual(len(list(self.root.rglob('*.pcap'))), 15)
        self.assertFalse(list(self.root.rglob('*.jsonl')))

    def test_interrupt_and_resume_fill_exact_target_without_reusing_or_deleting_files(self):
        saved = 0
        def interrupted(*args, **kwargs):
            nonlocal saved
            if saved == 7:
                raise KeyboardInterrupt
            saved += 1
            return self.capture(*args, **kwargs)
        with patch.object(extension, 'capture_visit', side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
            fresh.collect(self.root, target=5, batch_size=2)
        before = {path: path.read_bytes() for path in self.root.rglob('*.pcap')}
        self.assertEqual(len(before), 7)
        with patch.object(extension, 'capture_visit', side_effect=self.capture) as visit:
            fresh.collect(self.root, target=5, batch_size=2)
        self.assertEqual(visit.call_count, 8)
        self.assertEqual({path: path.read_bytes() for path in before}, before)
        self.assertEqual([len(list((self.root / extension.sanitize_name(url)).glob('*.pcap')))
                          for url in self.sites], [5, 5, 5])
        with patch.object(extension, 'capture_visit') as visit, \
             patch.object(extension, 'SafariSession') as session:
            fresh.collect(self.root, target=5, batch_size=2)
        visit.assert_not_called()
        session.assert_not_called()

    def test_cannot_silently_change_settings_or_adopt_old_captures(self):
        with patch.object(extension, 'capture_visit', side_effect=self.capture):
            fresh.collect(self.root, target=1, batch_size=1)
        before = {path: path.read_bytes() for path in self.root.rglob('*') if path.is_file()}
        with patch.object(extension, 'capture_visit') as visit:
            with self.assertRaisesRegex(ValueError, 'settings differ'):
                fresh.collect(self.root, target=2, batch_size=1)
        visit.assert_not_called()
        self.assertEqual({path: path.read_bytes() for path in before}, before)
        old = self.root.parent / 'old'
        old.mkdir()
        self.capture(self.sites[0], old / 'chickenpox', 1)
        with self.assertRaisesRegex(ValueError, 'cannot adopt'):
            fresh.collect(old)
        self.assertFalse((old / 'collection_config.json').exists())

    def test_invalid_batch_does_not_create_state(self):
        with self.assertRaises(ValueError):
            fresh.collect(self.root, batch_size=0)
        self.assertFalse(self.root.exists())


class DefaultTargetTests(unittest.TestCase):
    def test_default_protocol_requests_3000_visits_in_twenty_visit_batches(self):
        with patch.object(fresh, 'extend_collection') as collect:
            fresh.collect(dry_run=True)
        args, kwargs = collect.call_args
        self.assertEqual(len(kwargs['sites']) * args[1], 3000)
        self.assertEqual(kwargs['batch_size'], 20)
        self.assertTrue(kwargs['create'])
        self.assertTrue(kwargs['dry_run'])


if __name__ == '__main__':
    unittest.main()
