"""Check append-only top-up and restart behaviour without driving Safari."""
from contextlib import ExitStack, redirect_stdout
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import extend_dataset as extension


class ExtendDatasetTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.sites = extension.SITES[:2]
        self.first = self.root / 'chickenpox'
        self.second = self.root / 'measles'
        self.first.mkdir()
        self.second.mkdir()
        for index in (1, 2):
            (self.first / f'chickenpox_{index}_old.pcap').write_bytes(b'complete')
        for index in (1, 2, 3):
            (self.second / f'measles_{index}_old.pcap').write_bytes(b'complete')
        self.stack.enter_context(patch.object(extension, 'valid_capture',
                                              side_effect=lambda path: path.read_bytes() == b'complete'))
        self.stack.enter_context(patch.object(extension.time, 'sleep'))
        self.stack.enter_context(redirect_stdout(io.StringIO()))

    def capture(self, url, folder, visit, **kwargs):
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f'{extension.sanitize_name(url)}_{visit}_new.pcap'
        path.write_bytes(b'complete')
        return path

    def test_added_page_is_planned_without_writes_and_collected_in_a_new_folder(self):
        sites = [self.sites[0], extension.SITES[4]]
        added = self.root / extension.sanitize_name(sites[1])
        before = {path: path.read_bytes() for path in self.root.rglob('*.pcap')}
        plan = extension.collection_plan(self.root, 3, sites)
        self.assertEqual([page['needed'] for page in plan], [1, 3])
        self.assertFalse(added.exists())
        with patch.object(extension, 'capture_visit', side_effect=self.capture) as capture:
            extension.extend_collection(self.root, 3, sites=sites)
        self.assertEqual(capture.call_count, 4)
        self.assertEqual(len(list(added.glob('*.pcap'))), 3)
        self.assertEqual({path: path.read_bytes() for path in before}, before)

    def test_dry_run_counts_missing_visits_without_creating_or_opening_anything(self):
        before = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        with patch.object(extension, 'capture_visit') as capture, \
             patch.object(extension, 'SafariSession') as session:
            extension.extend_collection(self.root, 4, dry_run=True, sites=self.sites)
        capture.assert_not_called()
        session.assert_not_called()
        self.assertFalse((self.root / '.collection.lock').exists())
        self.assertEqual({p: p.read_bytes() for p in before}, before)
        self.assertEqual([page['needed'] for page in extension.collection_plan(self.root, 4, self.sites)], [2, 1])

    def test_collects_only_missing_visits_with_one_shared_session_and_preserves_old_files(self):
        before = {p: p.read_bytes() for p in self.root.rglob('*.pcap')}
        with patch.object(extension, 'capture_visit', side_effect=self.capture) as capture:
            extension.extend_collection(self.root, 4, sites=self.sites, interface='fixture')
        self.assertEqual(capture.call_count, 3)
        self.assertEqual([call.args[2] for call in capture.call_args_list], [3, 4, 4])
        self.assertTrue(all(call.kwargs['interface'] == 'fixture' for call in capture.call_args_list))
        sessions = [call.kwargs['session'] for call in capture.call_args_list]
        self.assertTrue(all(session is sessions[0] for session in sessions))
        self.assertEqual(len(list(self.first.glob('*.pcap'))), 4)
        self.assertEqual(len(list(self.second.glob('*.pcap'))), 4)
        self.assertEqual({p: p.read_bytes() for p in before}, before)
        with patch.object(extension, 'capture_visit') as capture:
            extension.extend_collection(self.root, 4, sites=self.sites)
        capture.assert_not_called()

    def test_rerunning_after_interrupt_keeps_successful_new_capture_and_fills_the_remainder(self):
        calls = 0
        def interrupt_after_one(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise KeyboardInterrupt
            return self.capture(*args, **kwargs)
        with patch.object(extension, 'capture_visit', side_effect=interrupt_after_one), \
             self.assertRaises(KeyboardInterrupt):
            extension.extend_collection(self.root, 4, sites=self.sites[:1])
        self.assertEqual(len(list(self.first.glob('*.pcap'))), 3)
        with patch.object(extension, 'capture_visit', side_effect=self.capture) as capture:
            extension.extend_collection(self.root, 4, sites=self.sites[:1])
        capture.assert_called_once()
        self.assertEqual(capture.call_args.args[2], 4)
        self.assertEqual(len(list(self.first.glob('*.pcap'))), 4)

    def test_invalid_files_are_not_counted_deleted_or_reused(self):
        invalid = self.first / 'chickenpox_10_interrupted.pcap'
        invalid.write_bytes(b'invalid')
        page = extension.collection_plan(self.root, 3, self.sites[:1])[0]
        self.assertEqual((len(page['valid']), page['needed'], page['next_visit']), (2, 1, 11))
        with patch.object(extension, 'capture_visit', side_effect=self.capture) as capture:
            extension.extend_collection(self.root, 3, sites=self.sites[:1])
        self.assertEqual(capture.call_args.args[2], 11)
        self.assertEqual(invalid.read_bytes(), b'invalid')

    def test_permanent_failure_is_bounded_and_preserves_completed_files(self):
        with patch.object(extension, 'capture_visit', side_effect=RuntimeError('permission denied')) as capture:
            with self.assertRaisesRegex(RuntimeError, 'rerun this command'):
                extension.extend_collection(self.root, 4, sites=self.sites[:1])
        self.assertEqual(capture.call_count, extension.MAX_VISIT_ATTEMPTS)
        self.assertEqual(len(list(self.first.glob('*.pcap'))), 2)

    def test_wrong_root_and_invalid_targets_do_not_create_collection_state(self):
        empty = self.root / 'wrong_parent'
        empty.mkdir()
        with self.assertRaises(ValueError):
            extension.extend_collection(empty, 200, sites=self.sites)
        with self.assertRaises(ValueError):
            extension.extend_collection(self.root, 0, sites=self.sites)
        self.assertFalse((empty / '.collection.lock').exists())
        self.assertFalse((self.root / '.collection.lock').exists())

    def test_second_extension_cannot_run_in_the_same_collection(self):
        with extension.collection_lock(self.root):
            with self.assertRaisesRegex(RuntimeError, 'already using'):
                with extension.collection_lock(self.root):
                    self.fail('Second collector acquired the same collection lock')


class CaptureCountValidationTests(unittest.TestCase):
    def test_counts_only_readable_nonempty_captures(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.pcap'
            path.write_bytes(b'header')
            with patch.object(extension.subprocess, 'run') as read:
                self.assertFalse(extension.valid_capture(path))
                read.assert_not_called()
            path.write_bytes(b'x' * 100)
            with patch.object(extension.subprocess, 'run', return_value=Mock(stdout='1\n')) as read:
                self.assertTrue(extension.valid_capture(path))
                self.assertNotIn('-i', read.call_args.args[0])
            with patch.object(extension.subprocess, 'run', return_value=Mock(stdout='')):
                self.assertFalse(extension.valid_capture(path))
            with patch.object(extension.subprocess, 'run', side_effect=subprocess.CalledProcessError(2, 'tshark')):
                self.assertFalse(extension.valid_capture(path))


if __name__ == '__main__':
    unittest.main()
