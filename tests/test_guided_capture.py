"""Check guided capture orchestration and data retention without driving Safari."""
from pathlib import Path
import json
import queue
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import gui_capture_app as gui
from process_pcap import CaptureData, default_pairs_csv_path


class GuidedCaptureTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'visit.pcap'
        self.path.write_bytes(b'original capture')
        self.app = SimpleNamespace(
            interface='test-interface', out_dir=self.directory.name,
            safari_session=object(), cancel_event=threading.Event(),
            events=queue.Queue(), _process_and_predict=Mock(), visit_context=None,
        )

    def test_selected_url_goes_to_shared_collector_and_capture_goes_to_prediction(self):
        ips = {'192.0.2.10'}
        with patch.object(gui, 'get_local_ips', return_value=ips), \
             patch.object(gui, 'capture_visit', return_value=self.path) as visit:
            gui.CaptureApp._capture_guided_visit(self.app, gui.SITES[0], 7)
        self.assertEqual(visit.call_args.args,
            (gui.SITES[0], Path(self.directory.name)/'chickenpox', 7))
        self.assertIs(visit.call_args.kwargs['session'], self.app.safari_session)
        self.assertIs(visit.call_args.kwargs['cancel_event'], self.app.cancel_event)
        self.assertEqual(visit.call_args.kwargs['interface'], 'test-interface')
        self.app._process_and_predict.assert_called_once_with(str(self.path), ips, True)

    def test_custom_url_uses_same_collector_and_is_stored_outside_labelled_pages(self):
        url = 'https://example.com/conditions/chickenpox/?view=full'
        self.app.visit_context = {'requested_url': url, 'custom_url': True}
        with patch.object(gui, 'get_local_ips', return_value={'192.0.2.10'}), \
             patch.object(gui, 'capture_visit', return_value=self.path) as visit:
            gui.CaptureApp._capture_guided_visit(self.app, url, 8)
        self.assertEqual(visit.call_args.args[0], url)
        self.assertEqual(visit.call_args.args[1].parent, Path(self.directory.name) / 'custom')
        self.assertIs(visit.call_args.kwargs['session'], self.app.safari_session)
        self.assertIs(visit.call_args.kwargs['cancel_event'], self.app.cancel_event)
        self.app._process_and_predict.assert_called_once_with(str(self.path), {'192.0.2.10'}, True)

    def test_navigation_failure_is_reported_without_predicting(self):
        with patch.object(gui, 'get_local_ips', return_value={'192.0.2.10'}), \
             patch.object(gui, 'capture_visit', side_effect=RuntimeError('Safari permission denied')):
            gui.CaptureApp._capture_guided_visit(self.app, gui.SITES[0], 1)
        self.app._process_and_predict.assert_not_called()
        self.assertEqual(self.app.events.get_nowait(), ('error', 'Safari permission denied'))

    def test_cancel_at_capture_completion_discards_file_without_predicting(self):
        def finish_and_cancel(*args, **kwargs):
            self.app.cancel_event.set()
            return self.path
        with patch.object(gui, 'get_local_ips', return_value={'192.0.2.10'}), \
             patch.object(gui, 'capture_visit', side_effect=finish_and_cancel):
            gui.CaptureApp._capture_guided_visit(self.app, gui.SITES[0], 1)
        self.app._process_and_predict.assert_not_called()
        self.assertFalse(self.path.exists())
        self.assertEqual(self.app.events.get_nowait()[0], 'cancelled')


class RetentionAndPredictionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'visit.pcap'
        self.path.write_bytes(b'original capture')
        self.capture = CaptureData([], [], [{
            'index': 0, 'out_bytes': 100, 'in_bytes': 200,
            'out_pkts': 1, 'in_pkts': 2,
            'out_start': 0., 'out_end': .01, 'in_start': .02, 'in_end': .03,
        }])
        self.prediction = {
            'available': True, 'label': 'rubella', 'confidence': .8,
            'accepted': True, 'reason': None, 'features': [('total_pairs', 1., .2)],
        }
        self.app = SimpleNamespace(
            interface='test-interface', model_candidates=['fixture.joblib'],
            confidence_threshold=.4,
            cleanup_after_predict=False, cancel_event=threading.Event(),
            visit_context={'requested_url': gui.SITES[0], 'requested_page': 'chickenpox'},
            events=queue.Queue(),
        )
        self.app._cleanup_files = lambda *args: gui.CaptureApp._cleanup_files(self.app, *args)

    def process(self, cleanup=True):
        with patch.object(gui, 'load_capture_data', return_value=self.capture), \
             patch.object(gui, 'predict_capture', return_value=self.prediction) as predict:
            gui.CaptureApp._process_and_predict(self.app, str(self.path), {'192.0.2.10'}, cleanup)
        return predict

    def test_requested_page_cannot_replace_model_prediction_and_files_are_replayable(self):
        predict = self.process()
        self.assertIs(predict.call_args.args[0], self.capture)
        self.assertEqual(len(predict.call_args.args), 3)
        self.assertNotIn(gui.SITES[0], predict.call_args.args)
        event, payload = self.app.events.get_nowait()
        self.assertEqual(event, 'result')
        self.assertEqual(payload[1]['label'], 'rubella')
        metadata = json.loads(self.path.with_suffix('.capture.json').read_text())
        self.assertEqual(metadata['visit']['requested_page'], 'chickenpox')
        self.assertEqual(metadata['prediction']['label'], 'rubella')
        self.assertEqual(metadata['local_ips'], ['192.0.2.10'])
        self.assertTrue(self.path.is_file())
        self.assertTrue(default_pairs_csv_path(str(self.path)).is_file())

    def test_custom_url_stays_in_metadata_and_never_becomes_a_model_input(self):
        url = 'https://example.com/a-page?language=en'
        self.app.visit_context = {'requested_url': url, 'custom_url': True}
        predict = self.process()
        self.assertIs(predict.call_args.args[0], self.capture)
        self.assertNotIn(url, predict.call_args.args)
        metadata = json.loads(self.path.with_suffix('.capture.json').read_text())
        self.assertEqual(metadata['visit']['requested_url'], url)
        self.assertTrue(metadata['visit']['custom_url'])
        self.assertEqual(metadata['prediction']['label'], 'rubella')

    def test_discard_option_preserves_previous_live_cleanup_behaviour(self):
        self.app.cleanup_after_predict = True
        self.process()
        self.assertFalse(self.path.exists())
        self.assertFalse(default_pairs_csv_path(str(self.path)).exists())
        self.assertFalse(self.path.with_suffix('.capture.json').exists())

    def test_opening_existing_capture_never_overwrites_source_or_pairs(self):
        pairs = default_pairs_csv_path(str(self.path))
        pairs.write_text('existing pairs')
        self.process(cleanup=False)
        self.assertEqual(self.path.read_bytes(), b'original capture')
        self.assertEqual(pairs.read_text(), 'existing pairs')
        self.assertFalse(self.path.with_suffix('.capture.json').exists())

    def test_cancel_before_prediction_discards_capture_without_calling_model(self):
        self.app.cancel_event.set()
        with patch.object(gui, 'predict_capture') as predict, \
             self.assertRaises(gui.CaptureCancelled):
            gui.CaptureApp._process_and_predict(self.app, str(self.path), {'192.0.2.10'}, True)
        predict.assert_not_called()
        self.assertFalse(self.path.exists())

    def test_metadata_write_error_keeps_prediction_and_capture(self):
        real_write = Path.write_text
        def write(path, *args, **kwargs):
            if path.suffix == '.json':
                raise OSError('disk is full')
            return real_write(path, *args, **kwargs)
        with patch.object(Path, 'write_text', write):
            self.process()
        event, payload = self.app.events.get_nowait()
        self.assertEqual(event, 'result')
        self.assertEqual(payload[1]['label'], 'rubella')
        self.assertIsNone(payload[2])
        self.assertIn('disk is full', payload[4])
        self.assertTrue(self.path.exists())

    def test_prediction_failure_still_retains_client_ips_for_replay(self):
        self.app.cleanup_after_predict = True
        with patch.object(gui, 'load_capture_data', return_value=self.capture), \
             patch.object(gui, 'predict_capture', side_effect=RuntimeError('incompatible model')):
            gui.CaptureApp._process_and_predict(self.app, str(self.path), {'192.0.2.10'}, True)
        self.assertTrue(self.path.exists())
        metadata = json.loads(self.path.with_suffix('.capture.json').read_text())
        self.assertEqual(metadata['local_ips'], ['192.0.2.10'])
        self.assertEqual(metadata['prediction_error'], 'incompatible model')


class FourPagePredictionTests(unittest.TestCase):
    def setUp(self):
        self.labels = ['chickenpox', 'measles', 'mumps', 'rubella']
        self.capture = CaptureData([], [], [{
            'index': 0, 'out_bytes': 100, 'in_bytes': 200,
            'out_pkts': 1, 'in_pkts': 2,
            'out_start': 0., 'out_end': .01, 'in_start': .02, 'in_end': .03,
        }])
        names = list(gui.summary_features(gui.pd.DataFrame(self.capture.pairs)))
        self.clf = Mock(classes_=list(range(4)),
                        feature_importances_=[1 / len(names)] * len(names))
        encoder = Mock()
        encoder.inverse_transform.side_effect = lambda ids: [self.labels[i] for i in ids]
        self.bundle = {'model': self.clf, 'label_encoder': encoder, 'feature_names': names}

    def predict(self, probabilities, confidence=.4):
        self.clf.predict.return_value = [int(gui.np.argmax(probabilities))]
        self.clf.predict_proba.return_value = [gui.np.array(probabilities)]
        with patch.object(gui.joblib, 'load', return_value=self.bundle):
            return gui.predict_capture(self.capture, [__file__], confidence)

    def test_all_four_pages_are_accepted_when_confident(self):
        for index, label in enumerate(self.labels):
            with self.subTest(label=label):
                probabilities = [.03] * 4
                probabilities[index] = .91
                prediction = self.predict(probabilities)
                self.assertEqual(prediction['label'], label)
                self.assertTrue(prediction['accepted'])
                self.assertIsNone(prediction['reason'])

    def test_low_confidence_is_still_rejected_for_every_page(self):
        for index, label in enumerate(self.labels):
            with self.subTest(label=label):
                probabilities = [.65 / 3] * 4
                probabilities[index] = .35
                prediction = self.predict(probabilities)
                self.assertFalse(prediction['accepted'])
                self.assertIn('Confidence is below', prediction['reason'])

    def test_40_percent_is_accepted_even_with_a_close_runner_up(self):
        prediction = self.predict([.4, .39, .11, .1])
        self.assertTrue(prediction['accepted'])
        self.assertIsNone(prediction['reason'])

    def test_preset_result_uses_the_same_acceptance_message_for_all_pages(self):
        app = SimpleNamespace(
            inspector=Mock(), feature_table=Mock(get_children=Mock(return_value=[])),
            status_var=Mock(), prediction_var=Mock(), prediction_detail_var=Mock(),
            model_info_var=Mock(), visit_context={'custom_url': False})
        for index, label in enumerate(self.labels):
            with self.subTest(label=label):
                probabilities = [.03] * 4
                probabilities[index] = .91
                prediction = self.predict(probabilities)
                gui.CaptureApp._display_result(app, self.capture, prediction, None,
                                              '/tmp/four-page-prediction.pcap')
                self.assertIn(f'Model prediction: {label}', app.prediction_var.set.call_args.args[0])
                self.assertEqual(app.prediction_detail_var.set.call_args.args[0],
                                 'Prediction accepted.')


class WorkerLifecycleTests(unittest.TestCase):
    def test_progress_does_not_reenable_controls_before_capture_finishes(self):
        app = SimpleNamespace(closing=False, events=queue.Queue(),
            cancel_event=threading.Event(), status_var=Mock(), btn_stop=Mock(),
            prediction_var=Mock(), _set_busy=Mock(), after=Mock(), _poll_events=Mock())
        app.events.put(('progress', 'Recording'))
        app.events.put(('processing', 'Predicting'))
        gui.CaptureApp._poll_events(app)
        app._set_busy.assert_not_called()
        app.btn_stop.configure.assert_called_once_with(state='disabled')

    def test_closing_waits_for_worker_cleanup_before_destroying_tk(self):
        app = SimpleNamespace(worker=Mock(), after=Mock(), destroy=Mock(), _finish_close=Mock())
        app.worker.is_alive.side_effect = [True, False]
        gui.CaptureApp._finish_close(app)
        app.destroy.assert_not_called()
        app.after.assert_called_once_with(100, app._finish_close)
        gui.CaptureApp._finish_close(app)
        app.destroy.assert_called_once()


class CustomURLTests(unittest.TestCase):
    def test_normalizes_bare_address_and_preserves_path_query_and_fragment(self):
        self.assertEqual(gui.normalize_visit_url(' example.com/a?x=1#section '),
                         'https://example.com/a?x=1#section')
        self.assertEqual(gui.normalize_visit_url('https://[::1]:443/a'),
                         'https://[::1]:443/a')

    def test_rejects_unsupported_or_malformed_targets(self):
        for url in ('', 'http://example.com', 'file:///tmp/file', 'javascript:alert(1)',
                    'https:///path', 'https://example.com:8443', 'https://example.com:no',
                    'https://user:secret@example.com', 'https://exa mple.com',
                    'https://example.com\n/path', 'https://[broken', 'https://bad_host/'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                gui.normalize_visit_url(url)

    def make_app(self, selection, url=''):
        return SimpleNamespace(
            processing=False, proc=None, closing=False,
            page_urls={'Chickenpox': gui.SITES[0]},
            page_var=Mock(get=Mock(return_value=selection)),
            custom_url_var=Mock(get=Mock(return_value=url)),
            model_candidates=[__file__], keep_captures_var=Mock(get=Mock(return_value=True)),
            cancel_event=threading.Event(), visit_number=0,
            _reset_result=Mock(), visit_var=Mock(), _set_busy=Mock(),
            btn_stop=Mock(), status_var=Mock(), _start_worker=Mock(),
            _capture_guided_visit=Mock())

    def test_custom_url_button_starts_shared_worker_with_normalized_target(self):
        app = self.make_app(gui.CUSTOM_URL_OPTION, 'example.com/path?x=1')
        gui.CaptureApp.on_visit(app)
        app._start_worker.assert_called_once_with(
            app._capture_guided_visit, 'https://example.com/path?x=1', 1)
        self.assertTrue(app.visit_context['custom_url'])
        self.assertEqual(app.visit_context['method'], 'guided_force_reload')

    def test_invalid_url_does_not_clear_results_or_launch_browser_worker(self):
        app = self.make_app(gui.CUSTOM_URL_OPTION, 'http://example.com')
        with patch.object(gui.messagebox, 'showerror') as error:
            gui.CaptureApp.on_visit(app)
        error.assert_called_once()
        app._start_worker.assert_not_called()
        app._reset_result.assert_not_called()

    def test_preset_selection_ignores_unused_custom_input(self):
        app = self.make_app('Chickenpox', 'http://invalid-unused-input')
        gui.CaptureApp.on_visit(app)
        app._start_worker.assert_called_once_with(app._capture_guided_visit, gui.SITES[0], 1)
        self.assertFalse(app.visit_context['custom_url'])

    def test_custom_result_never_claims_the_requested_page_was_detected(self):
        app = SimpleNamespace(
            inspector=Mock(), feature_table=Mock(get_children=Mock(return_value=[])), status_var=Mock(),
            prediction_var=Mock(), prediction_detail_var=Mock(), model_info_var=Mock(),
            visit_context={'custom_url': True})
        prediction = {'available': True, 'label': 'measles', 'confidence': .95,
                      'accepted': True, 'reason': None, 'features': []}
        gui.CaptureApp._display_result(app, CaptureData([], [], []), prediction,
                                      None, '/tmp/custom.pcap')
        self.assertIn('Closest trained page: measles', app.prediction_var.set.call_args.args[0])
        detail = app.prediction_detail_var.set.call_args.args[0]
        self.assertIn('do not confirm the identity', detail)
        self.assertNotIn('Monitored page detected', detail)

    def test_custom_condition_paths_produce_bounded_single_component_filenames(self):
        self.assertEqual(gui.sanitize_name(gui.SITES[0]), 'chickenpox')
        name = gui.sanitize_name('https://example.com/conditions/../../other/path?' + 'x' * 300)
        self.assertNotIn('/', name)
        self.assertNotIn('..', name)
        self.assertLessEqual(len(name), 80)


if __name__ == '__main__':
    unittest.main()
