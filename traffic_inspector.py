"""Linked burst and packet views for the Tkinter capture application."""
from tkinter import ttk

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
from matplotlib.figure import Figure
from matplotlib.ticker import FuncFormatter, MaxNLocator

from process_pcap import CaptureData

OUT_COLOR = '#2563eb'
IN_COLOR = '#ea7a16'
SELECT_COLOR = '#7c3aed'


def draw_burst_overview(ax, capture: CaptureData | None):
    """Draw all bursts, including those excluded from model pairs."""
    ax.clear()
    ax.axhline(0, color='#64748b', linewidth=0.8)
    ax.set_xlabel('Time since capture began (seconds)')
    ax.set_ylabel('Burst size (bytes)\nOutgoing ↑  /  Incoming ↓')
    ax.yaxis.set_major_formatter(FuncFormatter(lambda value, _: f'{abs(value):,.0f}'))
    ax.grid(axis='x', alpha=0.15)
    if capture is None or not capture.bursts:
        ax.text(0.5, 0.5, 'Capture traffic or open a saved capture to inspect bursts.',
                transform=ax.transAxes, ha='center', va='center', color='#64748b')
        ax.set_xlim(0, 1)
        ax.set_ylim(-1, 1)
        return None
    bursts = capture.bursts
    times = [burst['start'] for burst in bursts]
    sizes = [burst['bytes'] * (1 if burst['dir'] == 'out' else -1) for burst in bursts]
    colors = [OUT_COLOR if burst['dir'] == 'out' else IN_COLOR for burst in bursts]
    bars = ax.vlines(times, 0, sizes, colors=colors, linewidth=3)
    bars.set_picker(True)
    bars.set_pickradius(6)
    end = max(float(packet['frame.time_relative']) for packet in capture.packets)
    ax.set_xlim(-max(end * 0.015, 0.002), max(end * 1.02, 0.05))
    extent = max(max(abs(size) for size in sizes), 1) * 1.15
    ax.set_ylim(-extent, extent)
    return bars


def draw_packet_detail(ax, packets: list):
    ax.clear()
    ax.set_xlabel('Time since capture began (seconds)')
    ax.set_ylabel('Packet size (bytes)')
    ax.grid(axis='y', alpha=0.15)
    if not packets:
        ax.text(0.5, 0.5, 'Select a burst to see its packets.', transform=ax.transAxes,
                ha='center', va='center', color='#64748b')
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        return
    times = [float(packet['frame.time_relative']) for packet in packets]
    sizes = [abs(int(packet['signed_len'])) for packet in packets]
    color = OUT_COLOR if packets[0]['direction'] == 'out' else IN_COLOR
    ax.vlines(times, 0, sizes, colors=color, linewidth=2)
    ax.scatter(times, sizes, color=color, s=12)
    duration = max(times) - min(times)
    padding = max(duration * 0.05, 0.000001) if duration else 0.001
    ax.set_xlim(min(times) - padding, max(times) + padding)
    ax.set_ylim(0, max(max(sizes), 1) * 1.15)
    ax.xaxis.set_major_locator(MaxNLocator(nbins=5))
    ax.xaxis.set_major_formatter(FuncFormatter(lambda value, _: f'{value:.6f}'))


class TrafficInspector(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.capture = None
        self.selected_index = None
        self._selection_artists = []
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=3)
        self.rowconfigure(5, weight=2)

        ttk.Label(self, text='Burst overview', font=('Helvetica', 14, 'bold')).grid(
            row=0, column=0, sticky='w', padx=12, pady=(10, 3))
        legend = ttk.Frame(self)
        legend.grid(row=1, column=0, sticky='ew', padx=12)
        ttk.Label(legend, text='● Outgoing: computer → network', foreground=OUT_COLOR).pack(side='left')
        ttk.Label(legend, text='● Incoming: network → computer', foreground=IN_COLOR).pack(side='left', padx=20)
        ttk.Label(legend, text='Each line is one burst; height = total bytes.').pack(side='right')

        overview = ttk.Frame(self)
        overview.grid(row=2, column=0, sticky='nsew', padx=8)
        self.burst_figure = Figure(figsize=(10, 3.3), dpi=100, layout='constrained')
        self.burst_ax = self.burst_figure.add_subplot()
        self.burst_canvas = FigureCanvasTkAgg(self.burst_figure, master=overview)
        toolbar = NavigationToolbar2Tk(self.burst_canvas, overview, pack_toolbar=False)
        toolbar.pack(side='bottom', fill='x')
        self.burst_canvas.get_tk_widget().pack(fill='both', expand=True)
        self.burst_canvas.mpl_connect('pick_event', self._on_burst_pick)
        self.burst_canvas.mpl_connect('button_press_event', self._on_chart_click)
        self.burst_bars = draw_burst_overview(self.burst_ax, None)
        toolbar.update()

        navigation = ttk.Frame(self)
        navigation.grid(row=3, column=0, sticky='ew', padx=12, pady=3)
        self.previous_button = ttk.Button(navigation, text='← Previous burst', command=lambda: self._step(-1))
        self.previous_button.pack(side='left')
        self.next_button = ttk.Button(navigation, text='Next burst →', command=lambda: self._step(1))
        self.next_button.pack(side='left', padx=8)
        ttk.Label(navigation, text='Click a burst to inspect it. Use the toolbar to zoom or pan.').pack(side='left', padx=12)

        self.detail_label = ttk.Label(self, text='Packets in selected burst', font=('Helvetica', 12, 'bold'))
        self.detail_label.grid(row=4, column=0, sticky='w', padx=12, pady=(8, 3))
        details = ttk.Panedwindow(self, orient='horizontal')
        details.grid(row=5, column=0, sticky='nsew', padx=8)
        packet_panel = ttk.Frame(details)
        table_panel = ttk.Frame(details)
        details.add(packet_panel, weight=3)
        details.add(table_panel, weight=2)
        self.packet_figure = Figure(figsize=(6, 2.5), dpi=100, layout='constrained')
        self.packet_ax = self.packet_figure.add_subplot()
        self.packet_canvas = FigureCanvasTkAgg(self.packet_figure, master=packet_panel)
        packet_toolbar = NavigationToolbar2Tk(self.packet_canvas, packet_panel, pack_toolbar=False)
        packet_toolbar.pack(side='bottom', fill='x')
        self.packet_canvas.get_tk_widget().pack(fill='both', expand=True)
        draw_packet_detail(self.packet_ax, [])

        table_panel.columnconfigure(0, weight=1)
        table_panel.rowconfigure(0, weight=1)
        columns = ('packet', 'time', 'direction', 'size', 'protocol')
        self.packet_table = ttk.Treeview(table_panel, columns=columns, show='headings', height=7)
        for column, title, width in zip(columns, ('Packet #', 'Time (s)', 'Direction', 'Bytes', 'Protocol'),
                                         (70, 100, 85, 85, 90)):
            self.packet_table.heading(column, text=title)
            self.packet_table.column(column, width=width, minwidth=50, anchor='e' if column in ('time', 'size') else 'w')
        self.packet_table.grid(row=0, column=0, sticky='nsew')
        scroll = ttk.Scrollbar(table_panel, orient='vertical', command=self.packet_table.yview)
        scroll.grid(row=0, column=1, sticky='ns')
        self.packet_table.configure(yscrollcommand=scroll.set)
        horizontal = ttk.Scrollbar(table_panel, orient='horizontal', command=self.packet_table.xview)
        horizontal.grid(row=1, column=0, sticky='ew')
        self.packet_table.configure(xscrollcommand=horizontal.set)

        ttk.Label(self, text='Bursts group consecutive packets in one direction with gaps ≤ 50 ms. '
                  'Captured traffic may include background applications.').grid(
                      row=6, column=0, sticky='w', padx=12, pady=(6, 10))
        self.clear()

    def clear(self):
        self.capture = None
        self.selected_index = None
        self._selection_artists = []
        self.burst_bars = draw_burst_overview(self.burst_ax, None)
        draw_packet_detail(self.packet_ax, [])
        self.packet_table.delete(*self.packet_table.get_children())
        self.detail_label.configure(text='Packets in selected burst')
        self.previous_button.configure(state='disabled')
        self.next_button.configure(state='disabled')
        self.burst_canvas.draw_idle()
        self.packet_canvas.draw_idle()

    def set_capture(self, capture: CaptureData):
        self.clear()
        self.capture = capture
        self.burst_bars = draw_burst_overview(self.burst_ax, capture)
        # Clear the previous capture's navigation history.
        self.burst_canvas.toolbar.update()
        if capture.bursts:
            self.select_burst(0)
        else:
            self.detail_label.configure(text='No TCP/UDP port 443 packets in this capture.')
        self.burst_canvas.draw_idle()

    def _on_burst_pick(self, event):
        if event.artist is not self.burst_bars or self._toolbar_active() or not len(event.ind):
            return
        mouse_x = event.mouseevent.xdata
        if mouse_x is None:
            return
        index = min(event.ind, key=lambda i: abs(self.capture.bursts[i]['start'] - mouse_x))
        self._last_pick_event = event.mouseevent
        self.select_burst(int(index))

    def _toolbar_active(self):
        return bool(self.burst_canvas.toolbar.mode)

    def _on_chart_click(self, event):
        # Also select short bursts that would be hard to hit on their vertical line.
        if (event.inaxes is not self.burst_ax or event.button != 1 or self._toolbar_active()
                or self.capture is None or not self.capture.bursts or event.xdata is None):
            return
        if getattr(self, '_last_pick_event', None) is event:
            return
        index = min(range(len(self.capture.bursts)),
                    key=lambda i: abs(self.capture.bursts[i]['start'] - event.xdata))
        pixel_x = self.burst_ax.transData.transform((self.capture.bursts[index]['start'], 0))[0]
        if abs(pixel_x - event.x) <= 8:
            self.select_burst(index)

    def _step(self, offset):
        if self.selected_index is not None:
            self.select_burst(self.selected_index + offset)

    def select_burst(self, index: int):
        if self.capture is None or not 0 <= index < len(self.capture.bursts):
            return
        self.selected_index = index
        burst = self.capture.bursts[index]
        for artist in self._selection_artists:
            artist.remove()
        signed_size = burst['bytes'] * (1 if burst['dir'] == 'out' else -1)
        selected = self.burst_ax.vlines(burst['start'], 0, signed_size,
                                       colors=SELECT_COLOR, linewidth=5, zorder=4)
        # A translucent span shows duration separately from the size line.
        span = self.burst_ax.axvspan(burst['start'], burst['end'], color=SELECT_COLOR, alpha=0.12)
        self._selection_artists = [selected, span]
        direction = 'Outgoing' if burst['dir'] == 'out' else 'Incoming'
        duration_ms = (burst['end'] - burst['start']) * 1000
        self.detail_label.configure(text=f'Burst B{index + 1} · {direction} · {burst["count"]:,} packets · '
                                    f'{burst["bytes"]:,} bytes · {duration_ms:.1f} ms')
        packets = [self.capture.packets[i] for i in burst['packet_indices']]
        draw_packet_detail(self.packet_ax, packets)
        self.packet_canvas.toolbar.update()
        self.packet_table.delete(*self.packet_table.get_children())
        for packet_index, packet in zip(burst['packet_indices'], packets):
            self.packet_table.insert('', 'end', values=(
                packet.get('frame.number') or packet_index + 1,
                f'{float(packet["frame.time_relative"]):.6f}', direction,
                f'{abs(int(packet["signed_len"])):,}', packet.get('_ws.col.Protocol', '')))
        self.previous_button.configure(state='normal' if index > 0 else 'disabled')
        self.next_button.configure(state='normal' if index + 1 < len(self.capture.bursts) else 'disabled')
        self.burst_canvas.draw_idle()
        self.packet_canvas.draw_idle()
