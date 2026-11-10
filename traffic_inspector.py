"""Linked traffic overviews and packet sections for the capture application."""
from tkinter import StringVar, BooleanVar, ttk

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
from matplotlib.figure import Figure
from matplotlib.ticker import FuncFormatter, MaxNLocator

from process_pcap import CaptureData

OUT_COLOR = '#2563eb'
IN_COLOR = '#ea7a16'
SELECT_COLOR = '#7c3aed'
UNUSED_COLOR = '#94a3b8'
PACKET_WINDOW = 100


class InspectionToolbar(NavigationToolbar2Tk):
    toolitems = tuple(item for item in NavigationToolbar2Tk.toolitems
                      if item[0] in ('Home', 'Pan', 'Zoom'))


def draw_burst_overview(ax, capture: CaptureData | None):
    """Draw every burst, including those excluded from model pairs."""
    ax.clear()
    ax.axhline(0, color='#64748b', linewidth=.8)
    ax.set_xlabel('Time since capture began (seconds)')
    ax.set_ylabel('Burst size (bytes)')
    ax.yaxis.set_major_formatter(FuncFormatter(lambda value, _: f'{abs(value):,.0f}'))
    ax.grid(axis='x', alpha=.15)
    if capture is None or not capture.bursts:
        ax.text(.5, .5, 'Capture a visit or open a recording to explore its traffic.',
                transform=ax.transAxes, ha='center', va='center', color='#64748b',
                bbox={'facecolor': 'white', 'edgecolor': 'none', 'pad': 8})
        ax.set_xlim(0, 1)
        ax.set_ylim(-1, 1)
        ax.set_yticks([])
        return None
    times = [burst['start'] for burst in capture.bursts]
    sizes = [burst['bytes'] * (1 if burst['dir'] == 'out' else -1)
             for burst in capture.bursts]
    colors = [OUT_COLOR if value > 0 else IN_COLOR for value in sizes]
    bars = ax.vlines(times, 0, sizes, colors=colors, linewidth=3)
    bars.set_picker(True)
    bars.set_pickradius(6)
    end = max(float(packet['frame.time_relative']) for packet in capture.packets)
    ax.set_xlim(-max(end * .015, .002), max(end * 1.02, .05))
    extent = max(max(abs(size) for size in sizes), 1) * 1.15
    ax.set_ylim(-extent, extent)
    return bars


def draw_packet_detail(ax, packets: list):
    """Show the actual packets belonging to a burst, on the capture timeline."""
    ax.clear()
    ax.set_xlabel('Time since capture began (seconds)')
    ax.set_ylabel('Packet size (bytes)')
    ax.axhline(0, color='#64748b', linewidth=.8)
    ax.yaxis.set_major_formatter(FuncFormatter(lambda value, _: f'{abs(value):,.0f}'))
    ax.grid(axis='y', alpha=.15)
    if not packets:
        ax.text(.5, .5, 'Select a section above to inspect its packets.',
                transform=ax.transAxes, ha='center', va='center', color='#64748b',
                bbox={'facecolor': 'white', 'edgecolor': 'none', 'pad': 8})
        ax.set_xlim(0, 1)
        ax.set_ylim(-1, 1)
        ax.set_yticks([])
        return
    times = [float(packet['frame.time_relative']) for packet in packets]
    sizes = [int(packet['signed_len']) for packet in packets]
    colors = [OUT_COLOR if value > 0 else IN_COLOR for value in sizes]
    ax.vlines(times, 0, sizes, colors=colors, linewidth=2)
    ax.scatter(times, sizes, color=colors, s=12)
    duration = max(times) - min(times)
    padding = max(duration * .05, .000001) if duration else .001
    ax.set_xlim(min(times) - padding, max(times) + padding)
    extent = max(max(abs(value) for value in sizes), 1) * 1.15
    ax.set_ylim(-extent, extent)
    ax.xaxis.set_major_locator(MaxNLocator(nbins=5))
    ax.xaxis.set_major_formatter(FuncFormatter(lambda value, _: f'{value:.6f}'))


def packet_window_bounds(center: int, count: int, width: int = PACKET_WINDOW):
    """Keep a fixed-size packet section inside the available input positions."""
    width = max(1, width)
    start = min(max(0, center - width // 2), max(0, count - width))
    return start, min(count, start + width)


def draw_packet_sequence(ax, capture, start=0, stop=None, input_length=None):
    """Plot the saved input order, with padding and omitted tails labelled."""
    ax.clear()
    ax.set_xlabel('Packet number in capture order')
    ax.set_ylabel('Packet size (bytes)')
    ax.axhline(0, color='#64748b', linewidth=.8)
    ax.yaxis.set_major_formatter(FuncFormatter(lambda value, _: f'{abs(value):,.0f}'))
    ax.xaxis.set_major_locator(MaxNLocator(nbins=8, integer=True))
    ax.grid(axis='x', alpha=.15)
    if capture is None or not capture.packets:
        ax.text(.5, .5, 'Capture a visit or open a recording to explore its packets.',
                transform=ax.transAxes, ha='center', va='center', color='#64748b',
                bbox={'facecolor': 'white', 'edgecolor': 'none', 'pad': 8})
        ax.set_xlim(.5, 1.5)
        ax.set_ylim(-1, 1)
        ax.set_yticks([])
        return
    count = len(capture.packets)
    total = max(count, input_length or 0)
    stop = total if stop is None else min(stop, total)
    positions = list(range(start + 1, min(stop, count) + 1))
    sizes = [int(packet['signed_len']) for packet in capture.packets[start:stop]]
    colors = [UNUSED_COLOR if input_length is not None and position > input_length else
              OUT_COLOR if value > 0 else IN_COLOR
              for position, value in zip(positions, sizes)]
    ax.vlines(positions, 0, sizes, colors=colors, linewidth=.8 if stop - start > 200 else 1.5)
    if stop - start <= 200:
        ax.scatter(positions, sizes, color=colors, s=12)
    if input_length is not None and count != input_length:
        boundary = min(count, input_length) + .5
        if boundary < stop + .5 and max(count, input_length) > start:
            ax.axvspan(max(start + .5, boundary), stop + .5,
                       color='#e2e8f0', alpha=.55, zorder=0)
            ax.axvline(boundary, color=UNUSED_COLOR, linestyle='--', linewidth=1)
            ax.text(.99, .95,
                    'Zero padding' if count < input_length else 'Outside model input',
                    transform=ax.transAxes, ha='right', va='top',
                    fontsize=9, color='#475569',
                    bbox={'facecolor': 'white', 'edgecolor': 'none', 'alpha': .8})
    ax.set_xlim(start + .5, max(start + 1.5, stop + .5))
    extent = max([abs(value) for value in sizes] or [1]) * 1.15
    ax.set_ylim(-extent, extent)


class TrafficInspector(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.capture = None
        self.selected_index = None
        self.window_start = 0
        self.input_length = None
        self._selection_artists = []
        self.mode_var = StringVar(value='bursts')
        self.table_visible = BooleanVar(value=False)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=3)
        self.rowconfigure(5, weight=2)

        heading = ttk.Frame(self)
        heading.grid(row=0, column=0, sticky='ew', padx=12, pady=(10, 3))
        self.overview_label = ttk.Label(heading, text='Traffic overview', font=('Helvetica', 14, 'bold'))
        self.overview_label.pack(side='left')
        for label, value in [('Packets', 'packets'), ('Bursts', 'bursts')]:
            ttk.Radiobutton(heading, text=label, value=value, variable=self.mode_var,
                            command=self._refresh_overview).pack(side='right', padx=(10, 0))
        legend = ttk.Frame(self)
        legend.grid(row=1, column=0, sticky='ew', padx=12)
        ttk.Label(legend, text='↑ Outgoing', foreground=OUT_COLOR).pack(side='left')
        ttk.Label(legend, text='↓ Incoming', foreground=IN_COLOR).pack(side='left', padx=18)
        self.hint = ttk.Label(legend)
        self.hint.pack(side='right')

        overview = ttk.Frame(self)
        overview.grid(row=2, column=0, sticky='nsew', padx=8)
        self.burst_figure = Figure(figsize=(10, 3.3), dpi=100, layout='constrained')
        self.burst_ax = self.burst_figure.add_subplot()
        self.burst_canvas = FigureCanvasTkAgg(self.burst_figure, master=overview)
        self.overview_toolbar = InspectionToolbar(self.burst_canvas, overview, pack_toolbar=False)
        self.overview_toolbar.pack(side='bottom', fill='x')
        self.burst_canvas.get_tk_widget().pack(fill='both', expand=True)
        self.burst_canvas.mpl_connect('pick_event', self._on_burst_pick)
        self.burst_canvas.mpl_connect('button_press_event', self._on_chart_click)

        navigation = ttk.Frame(self)
        navigation.grid(row=3, column=0, sticky='ew', padx=12, pady=3)
        self.previous_button = ttk.Button(navigation, command=lambda: self._step(-1))
        self.previous_button.pack(side='left')
        self.next_button = ttk.Button(navigation, command=lambda: self._step(1))
        self.next_button.pack(side='left', padx=8)
        ttk.Checkbutton(navigation, text='Show packet table', variable=self.table_visible,
                        command=self._toggle_table).pack(side='right')

        self.detail_label = ttk.Label(self, font=('Helvetica', 12, 'bold'))
        self.detail_label.grid(row=4, column=0, sticky='w', padx=12, pady=(7, 3))
        self.details = ttk.Panedwindow(self, orient='horizontal')
        self.details.grid(row=5, column=0, sticky='nsew', padx=8)
        packet_panel = ttk.Frame(self.details)
        self.table_panel = ttk.Frame(self.details)
        self.details.add(packet_panel, weight=3)
        self.packet_figure = Figure(figsize=(6, 2.5), dpi=100, layout='constrained')
        self.packet_ax = self.packet_figure.add_subplot()
        self.packet_canvas = FigureCanvasTkAgg(self.packet_figure, master=packet_panel)
        self.detail_toolbar = InspectionToolbar(self.packet_canvas, packet_panel, pack_toolbar=False)
        self.detail_toolbar.pack(side='bottom', fill='x')
        self.packet_canvas.get_tk_widget().pack(fill='both', expand=True)
        self.table_panel.columnconfigure(0, weight=1)
        self.table_panel.rowconfigure(0, weight=1)
        columns = ('packet', 'time', 'direction', 'size')
        self.packet_table = ttk.Treeview(self.table_panel, columns=columns, show='headings', height=7)
        for column, title, width in zip(columns, ('Packet #', 'Time (s)', 'Direction', 'Bytes'),
                                        (75, 105, 85, 80)):
            self.packet_table.heading(column, text=title)
            self.packet_table.column(column, width=width, minwidth=50, anchor='w')
        self.packet_table.grid(row=0, column=0, sticky='nsew')
        scroll = ttk.Scrollbar(self.table_panel, orient='vertical', command=self.packet_table.yview)
        scroll.grid(row=0, column=1, sticky='ns')
        self.packet_table.configure(yscrollcommand=scroll.set)
        horizontal = ttk.Scrollbar(self.table_panel, orient='horizontal', command=self.packet_table.xview)
        horizontal.grid(row=1, column=0, sticky='ew')
        self.packet_table.configure(xscrollcommand=horizontal.set)
        self.input_label = ttk.Label(self)
        self.input_label.grid(row=6, column=0, sticky='w', padx=12, pady=(5, 8))
        self.clear()

    def _toggle_table(self):
        if self.table_visible.get():
            self.details.add(self.table_panel, weight=2)
            self.details.sashpos(0, int(self.details.winfo_width() * .65))
        else:
            self.details.forget(self.table_panel)

    def clear(self):
        self.capture = None
        self.selected_index = None
        self.window_start = 0
        self._refresh_overview()

    def set_capture(self, capture: CaptureData):
        self.capture = capture
        self.selected_index = None
        self.window_start = 0
        self._refresh_overview()

    def set_model_input(self, mode: str, sequence_length=None):
        """Choose the model's default view while retaining the loaded capture."""
        self.mode_var.set(mode)
        self.input_length = sequence_length
        self._refresh_overview()

    def _refresh_overview(self):
        self._selection_artists = []
        packets = self.mode_var.get() == 'packets'
        if packets:
            self.burst_bars = None
            draw_packet_sequence(self.burst_ax, self.capture, input_length=self.input_length)
        else:
            self.burst_bars = draw_burst_overview(self.burst_ax, self.capture)
        self.overview_label.configure(text='Packet overview' if packets else 'Burst overview')
        self.hint.configure(text='Click to inspect a nearby section' if packets else
                            'Click a burst to inspect its packets')
        self.previous_button.configure(text='← Previous section' if packets else '← Previous burst')
        self.next_button.configure(text='Next section →' if packets else 'Next burst →')
        self.input_label.configure(text='Packets are shown in arrival order.' if packets else
                                   'Bursts group packets in one direction with gaps up to 50 ms.')
        self.overview_toolbar.update()
        if self.capture is None or not self.capture.packets:
            draw_packet_detail(self.packet_ax, [])
            self.packet_table.delete(*self.packet_table.get_children())
            self.detail_label.configure(text='Selected packets')
            self.previous_button.configure(state='disabled')
            self.next_button.configure(state='disabled')
        elif packets:
            if self.input_length is not None:
                used = min(len(self.capture.packets), self.input_length)
                padding = max(0, self.input_length - used)
                self.input_label.configure(text=f'Model input · {used:,} packets used · '
                                          f'{padding:,} padding positions')
            self.select_packet_section(self.window_start + PACKET_WINDOW // 2)
        elif self.capture.bursts:
            self.select_burst(self.selected_index or 0)
        self.burst_canvas.draw_idle()
        self.packet_canvas.draw_idle()

    def _on_burst_pick(self, event):
        if (self.mode_var.get() != 'bursts' or event.artist is not self.burst_bars
                or self._toolbar_active() or not len(event.ind)):
            return
        mouse_x = event.mouseevent.xdata
        if mouse_x is None:
            return
        index = min(event.ind, key=lambda i: abs(self.capture.bursts[i]['start'] - mouse_x))
        self._last_pick_event = event.mouseevent
        self.select_burst(int(index))

    def _toolbar_active(self):
        return bool(self.overview_toolbar.mode)

    def _on_chart_click(self, event):
        if (event.inaxes is not self.burst_ax or event.button != 1 or self._toolbar_active()
                or self.capture is None or not self.capture.packets or event.xdata is None):
            return
        if self.mode_var.get() == 'packets':
            self.select_packet_section(round(event.xdata) - 1)
            return
        if getattr(self, '_last_pick_event', None) is event or not self.capture.bursts:
            return
        index = min(range(len(self.capture.bursts)),
                    key=lambda i: abs(self.capture.bursts[i]['start'] - event.xdata))
        pixel_x = self.burst_ax.transData.transform((self.capture.bursts[index]['start'], 0))[0]
        if abs(pixel_x - event.x) <= 8:
            self.select_burst(index)

    def _step(self, offset):
        if self.mode_var.get() == 'packets':
            self.select_packet_section(self.window_start + PACKET_WINDOW // 2 + offset * PACKET_WINDOW)
        elif self.selected_index is not None:
            self.select_burst(self.selected_index + offset)

    def _clear_selection(self):
        for artist in self._selection_artists:
            artist.remove()
        self._selection_artists = []

    def _fill_packet_table(self, indices):
        self.packet_table.delete(*self.packet_table.get_children())
        for index in indices:
            packet = self.capture.packets[index]
            direction = 'Outgoing' if int(packet['signed_len']) > 0 else 'Incoming'
            self.packet_table.insert('', 'end', values=(
                index + 1, f'{float(packet["frame.time_relative"]):.6f}', direction,
                f'{abs(int(packet["signed_len"])):,}'))

    def select_packet_section(self, center: int):
        if self.capture is None or not self.capture.packets:
            return
        total = max(len(self.capture.packets), self.input_length or 0)
        start, stop = packet_window_bounds(center, total)
        self.window_start = start
        self._clear_selection()
        self._selection_artists = [self.burst_ax.axvspan(start + .5, stop + .5,
                                                       color=SELECT_COLOR, alpha=.15)]
        draw_packet_sequence(self.packet_ax, self.capture, start, stop, self.input_length)
        self.detail_label.configure(text=f'Packet section · positions {start + 1:,}–{stop:,}')
        self.detail_toolbar.update()
        self._fill_packet_table(range(start, min(stop, len(self.capture.packets))))
        self.previous_button.configure(state='normal' if start > 0 else 'disabled')
        self.next_button.configure(state='normal' if stop < total else 'disabled')
        self.burst_canvas.draw_idle()
        self.packet_canvas.draw_idle()

    def select_burst(self, index: int):
        if self.capture is None or not 0 <= index < len(self.capture.bursts):
            return
        self.selected_index = index
        burst = self.capture.bursts[index]
        self._clear_selection()
        signed_size = burst['bytes'] * (1 if burst['dir'] == 'out' else -1)
        line = self.burst_ax.vlines(burst['start'], 0, signed_size,
                                   colors=SELECT_COLOR, linewidth=5, zorder=4)
        span = self.burst_ax.axvspan(burst['start'], burst['end'], color=SELECT_COLOR, alpha=.12)
        self._selection_artists = [line, span]
        direction = 'Outgoing' if burst['dir'] == 'out' else 'Incoming'
        count = burst['count']
        self.detail_label.configure(text=f'Burst {index + 1} · {direction} · '
                                    f'{count:,} packet' + ('s' if count != 1 else ''))
        packets = [self.capture.packets[i] for i in burst['packet_indices']]
        draw_packet_detail(self.packet_ax, packets)
        self.detail_toolbar.update()
        self._fill_packet_table(burst['packet_indices'])
        self.previous_button.configure(state='normal' if index > 0 else 'disabled')
        self.next_button.configure(state='normal' if index + 1 < len(self.capture.bursts) else 'disabled')
        self.burst_canvas.draw_idle()
        self.packet_canvas.draw_idle()
