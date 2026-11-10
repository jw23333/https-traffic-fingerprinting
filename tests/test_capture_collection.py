"""Check recording order and cleanup without opening Safari or capturing traffic."""

from contextlib import ExitStack, redirect_stdout
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

import capture_safari_all as backend
import collect_dataset as collector


PCAP_HEADER = b'\xd4\xc3\xb2\xa1' + b'\0' * 20
PCAPNG_HEADER = b'\x0a\x0d\x0d\x0a' + b'\0' * 24


class CaptureReadinessTests(unittest.TestCase):
    def test_waits_for_header_even_on_quiet_interface(self):
        for header in (PCAP_HEADER, PCAPNG_HEADER):
            with self.subTest(header=header[:4]), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'capture.pcap'
                path.write_bytes(header[:4])
                proc = Mock(returncode=None)
                proc.poll.return_value = None
                with patch.object(backend.time, 'sleep',
                                  side_effect=lambda _: path.write_bytes(header)) as pause:
                    backend._wait_for_capture_ready(proc, str(path), 1)
                pause.assert_called_once()

    def test_exited_process_is_not_ready_even_with_header(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.pcap'
            path.write_bytes(PCAP_HEADER)
            proc = Mock(returncode=2)
            proc.poll.return_value = 2
            with self.assertRaisesRegex(RuntimeError, 'exited during startup'):
                backend._wait_for_capture_ready(proc, str(path), 1)

    def test_readiness_timeout(self):
        proc = Mock(returncode=None)
        proc.poll.return_value = None
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'not-created.pcap')
            with patch.object(backend.time, 'monotonic', side_effect=[0, 2]):
                with self.assertRaises(TimeoutError):
                    backend._wait_for_capture_ready(proc, path, 1)

    def test_startup_failure_stops_process_and_removes_partial_file(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            path = Path(directory) / 'partial.pcap'
            path.touch()
            stack.enter_context(patch.object(backend, 'check_tshark_available'))
            stack.enter_context(patch.object(backend, 'build_pcap_path', return_value=str(path)))
            popen = stack.enter_context(patch.object(backend.subprocess, 'Popen'))
            stack.enter_context(patch.object(backend, '_wait_for_capture_ready',
                                            side_effect=TimeoutError('not ready')))
            stop = stack.enter_context(patch.object(backend, 'stop_capture'))
            stack.enter_context(redirect_stdout(io.StringIO()))
            with self.assertRaisesRegex(RuntimeError, 'not ready'):
                backend.start_capture('en1', directory)
            stop.assert_called_once_with(popen.return_value)
            self.assertFalse(path.exists())


class ProcessLifecycleTests(unittest.TestCase):
    """Exercise real child processes, substituting a program that uses no network."""

    PROGRAM = '''
import signal, struct, sys, time
from pathlib import Path
interface = sys.argv[sys.argv.index('-i') + 1]
path = Path(sys.argv[sys.argv.index('-w') + 1])
def finish(*args):
    path.with_suffix('.stopped').touch()
    sys.exit(0)
signal.signal(signal.SIGINT, finish)
if interface == 'denied':
    print('capture permission denied', file=sys.stderr, flush=True)
    sys.exit(2)
if interface != 'hang':
    time.sleep(0.1)
    path.write_bytes(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
while True:
    time.sleep(0.05)
'''

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.directory = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.children = []
        real_popen = subprocess.Popen

        def simulated_tshark(cmd, **kwargs):
            proc = real_popen([sys.executable, '-c', self.PROGRAM, *cmd[1:]], **kwargs)
            self.children.append(proc)
            return proc

        self.stack.enter_context(patch.object(backend.subprocess, 'Popen', simulated_tshark))
        self.stack.enter_context(patch.object(backend, 'check_tshark_available'))
        self.stack.enter_context(redirect_stdout(io.StringIO()))

    def test_background_process_is_ready_and_stops_gracefully(self):
        proc, path = backend.start_capture('simulated', self.directory, startup_timeout=2)
        try:
            self.assertEqual(Path(path).stat().st_size, 24)
            self.assertIsNone(proc.poll())
        finally:
            backend.stop_capture(proc)
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(Path(path).with_suffix('.stopped').exists())

    def test_startup_failure_and_timeout_leave_no_running_process(self):
        for interface, message in [('denied', 'capture permission denied'),
                                   ('hang', 'did not become ready')]:
            with self.subTest(interface=interface):
                with self.assertRaisesRegex(RuntimeError, message):
                    backend.start_capture(interface, self.directory, startup_timeout=0.5)
                self.assertIsNotNone(self.children[-1].poll())
                self.assertFalse(list(Path(self.directory).glob('*.pcap')))


class VisitTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        directory = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.path = Path(directory) / 'trace.pcap'
        self.path.write_bytes(PCAP_HEADER)
        self.events = []
        self.proc = Mock(returncode=None)
        self.proc.wait.side_effect = subprocess.TimeoutExpired('tshark', 2.5)
        self.stack.enter_context(redirect_stdout(io.StringIO()))
        self.reset = self.stack.enter_context(patch.object(collector, 'reset_safari'))
        self.session = Mock(window_id=42)
        self.session.prepare.side_effect=lambda _: self.events.append('prepare')
        self.stack.enter_context(patch.object(collector, 'start_capture', side_effect=self.start))
        self.reload = self.stack.enter_context(patch.object(
            collector, 'reload_from_origin', side_effect=lambda **_: self.events.append('force_reload')))
        self.stop = self.stack.enter_context(patch.object(collector, 'stop_capture',
                                                         side_effect=self.finish))
        self.inspect = self.stack.enter_context(patch.object(
            collector.subprocess, 'run', return_value=Mock(stdout='1\n')))
        self.stack.enter_context(patch.object(collector.time, 'monotonic',
                                              side_effect=[100, 100.25]))

    def start(self, **kwargs):
        self.events.append('ready')
        self.assertFalse(kwargs['fixed'])
        self.assertEqual(kwargs['interface'], 'test-interface')
        return self.proc, str(self.path)

    def finish(self, proc):
        self.events.append('stop')
        proc.returncode = 0

    def visit(self):
        return collector.capture_visit(collector.SITES[0], self.path.parent, 1,
                                       interface='test-interface', session=self.session)

    def test_capture_ready_before_force_reload_then_stop(self):
        self.assertEqual(self.visit(), self.path)
        self.assertEqual(self.events, ['prepare', 'ready', 'force_reload', 'stop'])
        self.reload.assert_called_once_with(window_id=42)
        self.reset.assert_not_called()
        self.proc.wait.assert_called_once_with(timeout=2.25)
        self.assertTrue(self.path.exists())

    def test_cancel_during_recording_stops_and_discards_without_validation(self):
        cancelled = threading.Event()
        def cancel_during_wait(**kwargs):
            cancelled.set()
            raise subprocess.TimeoutExpired('tshark', kwargs['timeout'])
        self.proc.wait.side_effect = cancel_during_wait
        with patch.object(collector.time, 'monotonic', side_effect=[100, 100.25, 100.35]):
            with self.assertRaises(collector.CaptureCancelled):
                collector.capture_visit(collector.SITES[0], self.path.parent, 1,
                    interface='test-interface', session=self.session, cancel_event=cancelled)
        self.stop.assert_called_once_with(self.proc)
        self.inspect.assert_not_called()
        self.assertFalse(self.path.exists())

    def test_guided_capture_uses_same_absolute_deadline_as_batch(self):
        progress = []
        with patch.object(collector.time, 'monotonic', side_effect=[100, 100.25, 100.6, 102.5]):
            result = collector.capture_visit(collector.SITES[0], self.path.parent, 1,
                interface='test-interface', session=self.session,
                cancel_event=threading.Event(), progress=progress.append)
        self.assertEqual(result, self.path)
        self.assertEqual(self.events, ['prepare', 'ready', 'force_reload', 'stop'])
        self.assertEqual(self.proc.wait.call_count, 2)
        self.stop.assert_called_once_with(self.proc)
        self.assertIn('Recording the 2.5-second force reload…', progress)
        self.assertTrue(self.path.exists())

    def test_cancel_before_preparation_does_not_start_capture(self):
        cancelled = threading.Event()
        cancelled.set()
        with self.assertRaises(collector.CaptureCancelled):
            collector.capture_visit(collector.SITES[0], self.path.parent, 1,
                interface='test-interface', session=self.session, cancel_event=cancelled)
        self.session.prepare.assert_not_called()
        self.reload.assert_not_called()
        self.stop.assert_not_called()

    def test_cancel_after_readiness_still_stops_child(self):
        cancelled = threading.Event()
        def cancel_on_ready(**kwargs):
            cancelled.set()
            return self.start(**kwargs)
        with patch.object(collector, 'start_capture', side_effect=cancel_on_ready):
            with self.assertRaises(collector.CaptureCancelled):
                collector.capture_visit(collector.SITES[0], self.path.parent, 1,
                    interface='test-interface', session=self.session, cancel_event=cancelled)
        self.stop.assert_called_once_with(self.proc)
        self.reload.assert_not_called()
        self.assertFalse(self.path.exists())

    def test_force_reload_failure_stops_and_discards_trace(self):
        self.reload.side_effect = RuntimeError('force reload failed')
        with self.assertRaisesRegex(RuntimeError, 'force reload failed'):
            self.visit()
        self.stop.assert_called_once_with(self.proc)
        self.assertFalse(self.path.exists())

    def test_keyboard_interrupt_stops_and_discards_trace(self):
        self.proc.wait.side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.visit()
        self.stop.assert_called_once_with(self.proc)
        self.assertFalse(self.path.exists())

    def test_premature_exit_is_rejected(self):
        self.proc.wait.side_effect = None
        with self.assertRaisesRegex(RuntimeError, 'ended before being stopped'):
            self.visit()
        self.assertFalse(self.path.exists())

    def test_stalled_force_reload_is_rejected(self):
        collector.time.monotonic.side_effect = [100, 103]
        with self.assertRaisesRegex(RuntimeError, 'exceeded the capture window'):
            self.visit()
        self.stop.assert_called_once_with(self.proc)
        self.proc.wait.assert_not_called()
        self.assertFalse(self.path.exists())

    def test_forced_shutdown_is_not_counted_as_success(self):
        def forced_stop(proc):
            proc.returncode = -15

        self.stop.side_effect = forced_stop
        with self.assertRaisesRegex(RuntimeError, 'did not stop cleanly'):
            self.visit()
        self.assertFalse(self.path.exists())

    def test_empty_or_unreadable_capture_is_rejected(self):
        for outcome in (Mock(stdout=''), subprocess.CalledProcessError(2, 'tshark')):
            with self.subTest(outcome=outcome):
                self.path.touch()
                self.inspect.side_effect = [outcome]
                with self.assertRaises((RuntimeError, subprocess.CalledProcessError)):
                    self.visit()
                self.assertFalse(self.path.exists())
                # Each visit reads the clock twice.
                collector.time.monotonic.side_effect = [100, 100.25]


class BatchTests(unittest.TestCase):
    def test_explicit_visit_target_overrides_default_and_invalid_target_creates_nothing(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory) / 'fresh'
            stack.enter_context(patch.object(collector, 'VISITS_PER_SITE', 70))
            visit = stack.enter_context(patch.object(collector, 'capture_visit', return_value=Path('saved')))
            stack.enter_context(patch.object(collector.time, 'sleep'))
            stack.enter_context(redirect_stdout(io.StringIO()))
            self.assertTrue(collector.run_collection([collector.SITES[4]], dataset_dir=root, visits_per_site=2))
            self.assertEqual(visit.call_count, 2)
            self.assertEqual([call.args[2] for call in visit.call_args_list], [1, 2])
            invalid = Path(directory) / 'invalid'
            with self.assertRaises(ValueError):
                collector.run_collection(dataset_dir=invalid, visits_per_site=0)
            self.assertFalse(invalid.exists())

    def test_first_visit_is_retried_without_losing_a_scheduled_visit(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory) / 'fresh'
            stack.enter_context(patch.object(collector, 'VISITS_PER_SITE', 2))
            visit = stack.enter_context(patch.object(
                collector, 'capture_visit', side_effect=[RuntimeError('Safari window not ready'),
                                                         Path('a'), Path('b'), Path('c'), Path('d')]))
            stack.enter_context(patch.object(collector.time, 'sleep'))
            output = stack.enter_context(redirect_stdout(io.StringIO()))
            result = collector.run_collection([collector.SITES[0], collector.SITES[2]],
                                               dataset_dir=root, interface='test-interface')
            self.assertTrue(result)
            self.assertEqual(visit.call_count, 5)
            self.assertEqual(visit.call_args_list[0].args[2], 1)
            self.assertEqual(visit.call_args_list[1].args[2], 1)
            self.assertEqual(visit.call_args_list[0].args[1], root / 'chickenpox')
            self.assertEqual(visit.call_args_list[-1].args[1], root / 'mumps')
            sessions=[call.kwargs['session'] for call in visit.call_args_list]
            self.assertTrue(all(session is sessions[0] for session in sessions))
            self.assertIn('4 saved, 0 failed', output.getvalue())
            log=(root/'collection_log.jsonl').read_text()
            self.assertIn('Safari window not ready', log)
            self.assertIn('attempt_failed', log)

    def test_permanent_failure_is_logged_and_reported_after_bounded_retries(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root=Path(directory)
            stack.enter_context(patch.object(collector, 'VISITS_PER_SITE', 1))
            stack.enter_context(patch.object(collector, 'MAX_VISIT_ATTEMPTS', 2))
            visit=stack.enter_context(patch.object(collector, 'capture_visit',
                                                  side_effect=RuntimeError('not permitted')))
            stack.enter_context(patch.object(collector.time, 'sleep'))
            stack.enter_context(redirect_stdout(io.StringIO()))
            self.assertFalse(collector.run_collection([collector.SITES[0]], dataset_dir=root))
            self.assertEqual(visit.call_count, 2)
            self.assertIn('not permitted', (root/'collection_log.jsonl').read_text())


class SafariAutomationTests(unittest.TestCase):
    def test_automation_error_keeps_original_stderr(self):
        error=subprocess.CalledProcessError(1, 'osascript', stderr='Safari did not open (-1719)')
        with patch.object(collector.subprocess, 'run', side_effect=error):
            with self.assertRaisesRegex(RuntimeError, r'Safari did not open \(-1719\)'):
                collector.open_private_window()

    def test_prepare_settles_before_any_recording_or_reload(self):
        events=[]
        with patch.object(collector, 'open_private_window', side_effect=lambda:events.append('window')), \
             patch.object(collector, 'load_in_safari', side_effect=lambda _:events.append('navigate')), \
             patch.object(collector.time, 'sleep', side_effect=lambda _:events.append('settle')), \
             patch.object(collector, 'reload_from_origin') as reload:
            collector.open_private_and_load(collector.SITES[0])
        self.assertEqual(events, ['window','navigate','settle'])
        reload.assert_not_called()


class SafariSessionTests(unittest.TestCase):
    def setUp(self):
        self.stack=ExitStack()
        self.addCleanup(self.stack.close)
        self.open=self.stack.enter_context(patch.object(collector,'open_private_window',return_value=42))
        self.exists=self.stack.enter_context(patch.object(collector,'safari_window_exists',return_value=True))
        self.load=self.stack.enter_context(patch.object(collector,'load_in_safari'))
        self.pause=self.stack.enter_context(patch.object(collector.time,'sleep'))
        self.reset=self.stack.enter_context(patch.object(collector,'reset_safari'))
        self.session=collector.SafariSession()

    def test_repeated_visits_reuse_window_and_do_not_navigate_again(self):
        for _ in range(3): self.session.prepare(collector.SITES[0])
        self.open.assert_called_once()
        self.load.assert_called_once_with(collector.SITES[0],window_id=42)
        self.pause.assert_called_once_with(collector.PRELOAD_SETTLE_SECONDS)
        self.reset.assert_not_called()

    def test_changing_pages_reuses_the_same_window(self):
        self.session.prepare(collector.SITES[0])
        self.session.prepare(collector.SITES[1])
        self.session.prepare(collector.SITES[1])
        self.open.assert_called_once()
        self.assertEqual(self.load.call_count,2)
        self.load.assert_called_with(collector.SITES[1],window_id=42)
        self.assertEqual(self.pause.call_count,2)
        self.reset.assert_not_called()

    def test_closed_collection_window_is_replaced_without_closing_other_windows(self):
        self.open.side_effect=[42,43]
        self.session.prepare(collector.SITES[0])
        self.exists.return_value=False
        self.session.prepare(collector.SITES[0])
        self.assertEqual(self.open.call_count,2)
        self.load.assert_called_with(collector.SITES[0],window_id=43)
        self.reset.assert_not_called()

    def test_guided_session_restores_page_changed_outside_the_gui(self):
        self.session.verify_url = True
        self.session.prepare(collector.SITES[0])
        with patch.object(collector, 'safari_window_url', return_value=collector.SITES[1]):
            self.session.prepare(collector.SITES[0])
        self.assertEqual(self.load.call_count, 2)
        self.load.assert_called_with(collector.SITES[0], window_id=42)
        self.open.assert_called_once()

    def test_guided_session_keeps_matching_page_with_fragment(self):
        self.session.verify_url = True
        self.session.prepare(collector.SITES[0])
        with patch.object(collector, 'safari_window_url', return_value=collector.SITES[0]+'#symptoms'):
            self.session.prepare(collector.SITES[0])
        self.load.assert_called_once()
        self.pause.assert_called_once()


if __name__ == '__main__':
    unittest.main()
