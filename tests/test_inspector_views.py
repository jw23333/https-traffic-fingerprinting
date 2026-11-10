"""Regressions for section boundaries and reusing a recording across models."""
import queue
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from matplotlib.figure import Figure

from gui_capture_app import CaptureApp
from process_pcap import CaptureData
from traffic_inspector import draw_packet_sequence, packet_window_bounds


class PacketSectionTests(unittest.TestCase):
    def test_first_and_last_sections_include_the_end_packets(self):
        self.assertEqual(packet_window_bounds(-10, 350), (0, 100))
        self.assertEqual(packet_window_bounds(999, 350), (250, 350))
        self.assertEqual(packet_window_bounds(5, 8), (0, 8))
        self.assertEqual(packet_window_bounds(0, 0), (0, 0))

    def test_plot_keeps_packet_order_and_direction_at_a_model_boundary(self):
        capture = CaptureData([
            {'signed_len': 70}, {'signed_len': -1500}, {'signed_len': 100}], [], [])
        axis = Figure().subplots()
        draw_packet_sequence(axis, capture, start=1, stop=3, input_length=2)
        segments = axis.collections[0].get_segments()
        self.assertEqual([segment[-1].tolist() for segment in segments], [[2., -1500.], [3., 100.]])
        self.assertEqual(axis.get_xlim(), (1.5, 3.5))
        self.assertIn('Outside model input', [label.get_text() for label in axis.texts])

    def test_padding_positions_have_a_label_and_no_fabricated_packets(self):
        capture = CaptureData([{'signed_len': 70}], [], [])
        axis = Figure().subplots()
        draw_packet_sequence(axis, capture, input_length=64)
        self.assertEqual(len(axis.collections[0].get_segments()), 1)
        self.assertIn('Zero padding', [label.get_text() for label in axis.texts])


class ModelSwitchTests(unittest.TestCase):
    def test_selector_reuses_the_loaded_capture_and_selects_its_input_view(self):
        capture = CaptureData([{'signed_len': 70}], [], [])
        app = SimpleNamespace(processing=False, proc=None, closing=False,
            model_var=Mock(get=Mock(return_value='CNN')), models={'CNN': 'selected.pt'},
            selected_model='RF', model_candidates=['previous.joblib'], capture_data=capture,
            inspector=Mock(), feature_table=Mock(get_children=Mock(return_value=[])),
            model_info_var=Mock(), model_heading_var=Mock(), model_description_var=Mock(),
            _set_busy=Mock(), prediction_var=Mock(), prediction_detail_var=Mock(),
            status_var=Mock(), _start_worker=Mock(), _predict_loaded_capture=Mock())
        with patch('gui_capture_app.model_inspection_input', return_value=('packets', 3328)):
            CaptureApp.on_model_selected(app)
        self.assertEqual(app.model_candidates, ['selected.pt'])
        app.inspector.set_model_input.assert_called_once_with('packets', 3328)
        app._start_worker.assert_called_once_with(app._predict_loaded_capture, capture, 'selected.pt')
        app.inspector.set_capture.assert_not_called()

    def test_switch_predicts_from_memory_even_when_the_pcap_has_been_discarded(self):
        capture = CaptureData([{'signed_len': 70}], [], [])
        app = SimpleNamespace(events=queue.Queue(), pcap_path='/missing/discarded.pcap',
                              confidence_threshold=.4)
        prediction = {'available': True, 'label': 'measles'}
        with patch('gui_capture_app.predict_capture', return_value=prediction) as predict, \
                patch('gui_capture_app.load_capture_data', side_effect=AssertionError('PCAP reread')):
            CaptureApp._predict_loaded_capture(app, capture, 'selected.pt')
        predict.assert_called_once_with(capture, ['selected.pt'], .4)
        event, result = app.events.get_nowait()
        self.assertEqual(event, 'result')
        self.assertIs(result[0], capture)
        self.assertIs(result[1], prediction)
        self.assertIsNone(result[2])

    def test_model_result_preserves_the_existing_section_on_the_same_capture(self):
        capture = CaptureData([], [], [])
        app = SimpleNamespace(capture_data=capture, inspector=Mock(),
            feature_table=Mock(get_children=Mock(return_value=[])), status_var=Mock(),
            prediction_var=Mock(), prediction_detail_var=Mock())
        CaptureApp._display_result(app, capture, None, 'Unavailable model', 'discarded.pcap')
        app.inspector.set_capture.assert_not_called()


if __name__ == '__main__':
    unittest.main()
