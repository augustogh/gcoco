#!/usr/bin/env python3
import os
import sys
import datetime
<<<<<<< HEAD
=======
import json
>>>>>>> e59a7d4 (feat: implement threat intelligence integration and ASCII world map visualization for monitoring network traffic)
from typing import Dict, List, Set, Tuple, Any, Optional

from rich.text import Text
from rich.panel import Panel

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Footer, Static, Tree
from textual.binding import Binding
from textual.message import Message

from engine import NetworkEngine
<<<<<<< HEAD
from threat_intel import query_virustotal_ip, is_public_ip
=======
from threat_intel import query_virustotal_ip, is_public_ip, get_ip_geolocation, get_own_geolocation
from ui_map import WorldMapWidget, MapScreen
>>>>>>> e59a7d4 (feat: implement threat intelligence integration and ASCII world map visualization for monitoring network traffic)

# --- Custom Textual Messages ---
class NetworkScanResult(Message):
    """Event sent when the background socket scan completes."""
    def __init__(self, grouped_data: Dict[str, Dict[int, List[Dict[str, Any]]]], proc_threats: Dict[str, Set[str]]):
        super().__init__()
        self.grouped_data = grouped_data
        self.proc_threats = proc_threats

class VirusTotalResult(Message):
    """Event sent when an async VirusTotal reputation query resolves."""
    def __init__(self, ip: str, is_malicious: bool):
        super().__init__()
        self.ip = ip
        self.is_malicious = is_malicious

<<<<<<< HEAD
=======
class GeolocationResult(Message):
    """Event sent when a public IP geolocation query completes."""
    def __init__(self, ip: str, coords: Optional[Tuple[float, float]]):
        super().__init__()
        self.ip = ip
        self.coords = coords

class OwnGeolocationResult(Message):
    """Event sent when the public IP geolocation query for the host completes."""
    def __init__(self, coords: Optional[Tuple[float, float]]):
        super().__init__()
        self.coords = coords


>>>>>>> e59a7d4 (feat: implement threat intelligence integration and ASCII world map visualization for monitoring network traffic)
# --- Design Configuration ---
COLORS = [
    "#00FF66",  # Neon Green
    "#00E5FF",  # Neon Cyan
    "#FF007F",  # Neon Pink / Hot Pink
    "#FF9900",  # Neon Orange
    "#CC33FF",  # Neon Purple / Violet
    "#FFFF00",  # Neon Yellow
    "#3388FF",  # Neon Sky Blue
    "#00FFCC",  # Neon Mint / Turquoise
    "#FFCC00",  # Amber / Gold
    "#E600FF",  # Bright Orchid
    "#9D00FF",  # Deep Violet
]

FLOW_FRAMES = [
    "──❯───❯──",
    "───❯───❯─",
    "────❯───❯",
    "❯────❯───",
    "─❯────❯──",
]

FAST_FLOW_FRAMES = [
    "──►──►──",
    "───►──►─",
    "─►──►───",
    "►──►────",
]

PULSE_FRAMES = [
    "  ( )  ",
    "  (░)  ",
    "  (▒)  ",
    "  (▓)  ",
    "  (█)  ",
    "  (▓)  ",
    "  (▒)  ",
    "  (░)  "
]

SPARKLINE_BASE = " ▂▃▆█▅▂ "

def get_proc_color(proc_key: str) -> str:
    """Generates a stable color index for a process name/PID."""
    color_index = abs(hash(proc_key)) % len(COLORS)
    return COLORS[color_index]

def get_sparkline_frame(frame_idx: int) -> str:
    """Shifts the sparkline character sequence to animate a wave traffic flow."""
    idx = frame_idx % len(SPARKLINE_BASE)
    return SPARKLINE_BASE[idx:] + SPARKLINE_BASE[:idx]


class NetTraceHeader(Static):
    """Custom premium header widget with neon styling."""
    def render(self) -> Text:
        return Text.assemble(
            (" ⚡ ", "bold #FFFF00"),
            ("GCOCO HIDS", "bold #00FF66"),
            (" // ", "bold #3a3f58"),
            ("REAL-TIME HIDS/IPS & NETWORK MONITOR", "bold white"),
            (" ⚡", "bold #FFFF00")
        )


class NetTraceApp(App):
    """
    Main Textual TUI Application.
    Combines connection scanning, local heuristics, and async VirusTotal API checks.
    """
    
    CSS = """
    Screen {
        background: #090a10;
        color: #e2e8f0;
    }
    
    NetTraceHeader {
        background: #10121e;
        color: #e2e8f0;
        text-align: center;
        height: 3;
        content-align: center middle;
        border-bottom: double #2e3440;
    }
    
    #body {
        layout: horizontal;
        height: 1fr;
    }
    
    #sidebar {
        width: 38;
        height: 100%;
        border-right: double #2e3440;
        background: #10121e;
        padding: 1 2;
    }
    
    #main-container {
        width: 1fr;
        height: 100%;
        background: #090a10;
        layout: vertical;
    }
    
    #tree-container {
        height: 70%;
        background: transparent;
        padding: 1;
    }
    
    #alerts-panel {
        height: 30%;
        border-top: double #2e3440;
        background: #0d0f18;
        padding: 1 2;
    }
    
    Tree {
        background: transparent;
        color: #e2e8f0;
        border: none;
    }
    
    Tree:focus {
        border: none;
    }
    
    Footer {
        background: #10121e;
        color: #a0aec0;
        border-top: double #2e3440;
    }
<<<<<<< HEAD
=======

    /* --- Fullscreen Map Screen --- */
    #fullscreen-map-container {
        width: 100%;
        height: 1fr;
        background: #090a10;
        align: center middle;
        overflow: hidden;
    }

    #fullscreen-map {
        width: auto;
        height: auto;
        content-align: center middle;
        color: #3b4252;
    }
>>>>>>> e59a7d4 (feat: implement threat intelligence integration and ASCII world map visualization for monitoring network traffic)
    """
    
    BINDINGS = [
        Binding("c", "toggle_states", "Toggle States (Est / All)", show=True),
        Binding("r", "manual_scan", "Force Scan", show=True),
        Binding("f", "toggle_expand", "Expand/Collapse", show=True),
        Binding("k", "kill_selected", "Kill Selected PID", show=True),
<<<<<<< HEAD
=======
        Binding("m", "toggle_map", "View Map", show=True),
>>>>>>> e59a7d4 (feat: implement threat intelligence integration and ASCII world map visualization for monitoring network traffic)
        Binding("q", "quit", "Quit", show=True),
    ]

    def compose(self) -> ComposeResult:
        yield NetTraceHeader()
        with Horizontal(id="body"):
            yield Static(id="sidebar")
            with Vertical(id="main-container"):
                with Container(id="tree-container"):
                    tree = Tree("Network Connections Root", id="net_tree")
                    tree.show_root = False
                    yield tree
                yield Static(id="alerts-panel")
        yield Footer()

    def on_mount(self) -> None:
        # Initialize the backend engine
        self.engine = NetworkEngine()
        
        # State control
        self.show_all_states = False
        self.all_expanded = True
        self.animation_frame_idx = 0
        
        # Threat intelligence state
        self.vt_api_key = self.engine.config.get("vt_api_key", "")
        self.malicious_ips: Set[str] = set()
        self.vt_pending: Set[str] = set()
<<<<<<< HEAD
        
=======

        # Geolocation state
        self.geo_data: Dict[str, Tuple[float, float]] = {}   # ip -> (lat, lon)
        self.origin_coords: Optional[Tuple[float, float]] = None
        self.geo_pending: Set[str] = set()  # IPs currently being geolocated

>>>>>>> e59a7d4 (feat: implement threat intelligence integration and ASCII world map visualization for monitoring network traffic)
        # Connection cache
        self.grouped_data: Dict[str, Dict[int, List[Dict[str, Any]]]] = {}
        self.proc_threats: Dict[str, Set[str]] = {}

        # Cache reference to Widgets
        self.ui_tree = self.query_one("#net_tree", Tree)
        
        # Set up periodic tasks
        # 1. Threaded socket scan every 1.5s (completely thread-safe via @work)
        self.set_interval(1.5, self.trigger_network_scan)
        # 2. Cycle flow and sparkline animations every 150ms
        self.set_interval(0.150, self.animate_connections)
        # 3. Refresh the alerts panel every 1.5s
        self.set_interval(1.5, self.update_alerts_panel)

<<<<<<< HEAD
=======
        # Kick off own-host geolocation query (fire-and-forget)
        self.fetch_own_geolocation()

>>>>>>> e59a7d4 (feat: implement threat intelligence integration and ASCII world map visualization for monitoring network traffic)
        # Trigger initial scan & draw
        self.trigger_network_scan()
        self.update_sidebar()
        self.update_alerts_panel()

    # --- Scanning & Message Handling ---
    def trigger_network_scan(self) -> None:
        """Triggers the threaded network scan."""
        self.run_background_scan()

    @work(exclusive=True, thread=True)
    def run_background_scan(self) -> None:
        """Background thread worker for reading sockets and running heuristics."""
        grouped, threats = self.engine.scan_connections(self.show_all_states)
        self.post_message(NetworkScanResult(grouped, threats))

    def on_network_scan_result(self, event: NetworkScanResult) -> None:
        """Main thread callback when network scan finishes."""
        self.grouped_data = event.grouped_data
        self.proc_threats = event.proc_threats
        
        # Check remote IPs against VirusTotal asynchronously
        self.trigger_vt_checks()
        
        # Render the tree and sidebar
        self.update_tree()
        self.update_sidebar()

    def trigger_vt_checks(self) -> None:
<<<<<<< HEAD
        """Spawns VirusTotal queries for any unverified public IP addresses."""
        if not self.vt_api_key:
            return
        
=======
        """Spawns VirusTotal AND geolocation queries for any unverified public IPs."""
>>>>>>> e59a7d4 (feat: implement threat intelligence integration and ASCII world map visualization for monitoring network traffic)
        for proc_key, ports_dict in self.grouped_data.items():
            for port, conns in ports_dict.items():
                for conn in conns:
                    ip = conn.get("remote_ip", "")
<<<<<<< HEAD
                    if is_public_ip(ip) and ip not in self.malicious_ips and ip not in self.vt_pending:
                        self.vt_pending.add(ip)
                        self.query_vt_ip(ip, proc_key)

=======
                    if not is_public_ip(ip):
                        continue

                    # VirusTotal check (only when API key is configured)
                    if self.vt_api_key and ip not in self.malicious_ips and ip not in self.vt_pending:
                        self.vt_pending.add(ip)
                        self.query_vt_ip(ip, proc_key)

                    # Geolocation check (independent of VT key)
                    if ip not in self.geo_data and ip not in self.geo_pending:
                        self.geo_pending.add(ip)
                        self.fetch_ip_geolocation(ip)

>>>>>>> e59a7d4 (feat: implement threat intelligence integration and ASCII world map visualization for monitoring network traffic)
    @work(exclusive=False)
    async def query_vt_ip(self, ip: str, proc_key: str) -> None:
        """Asynchronous API caller worker for VirusTotal lookup."""
        is_malicious = await query_virustotal_ip(ip, self.vt_api_key)
        if is_malicious is not None:
            self.post_message(VirusTotalResult(ip, is_malicious))

<<<<<<< HEAD
=======
    @work(exclusive=False)
    async def fetch_own_geolocation(self) -> None:
        """Fire-and-forget worker that geolocates the host's own public IP."""
        try:
            coords = await get_own_geolocation()
            self.post_message(OwnGeolocationResult(coords))
        except Exception:
            # Silent failure — map simply shows no origin marker
            pass

    @work(exclusive=False)
    async def fetch_ip_geolocation(self, ip: str) -> None:
        """Fire-and-forget worker that geolocates a single remote public IP."""
        try:
            coords = await get_ip_geolocation(ip)
            self.post_message(GeolocationResult(ip, coords))
        except Exception:
            # Silent failure — no marker drawn for this IP
            self.geo_pending.discard(ip)

>>>>>>> e59a7d4 (feat: implement threat intelligence integration and ASCII world map visualization for monitoring network traffic)
    def on_virus_total_result(self, event: VirusTotalResult) -> None:
        """Applies VirusTotal results when async HTTP lookup resolves."""
        ip = event.ip
        if ip in self.vt_pending:
            self.vt_pending.remove(ip)
            
        if event.is_malicious:
            self.malicious_ips.add(ip)
            
            # Retrieve executable information and log a forensic event
            for proc_key, ports_dict in self.grouped_data.items():
                pid = None
                if "(PID: " in proc_key:
                    try:
                        pid = int(proc_key.split("(PID: ")[1].split(")")[0])
                    except ValueError:
                        pass
                
                if pid is not None:
                    details = self.engine.get_process_details(pid)
                    exe_path = details["exe"]
                    # Log alert using heuristics module helper to keep logs synchronized
                    from heuristics import log_threat_alert
                    log_threat_alert(pid, exe_path, ip, "[MALICIOUS_IP]", self.engine.logged_alerts)

            # Force immediate tree refresh to display alert coloring
            self.update_tree()
            self.update_alerts_panel()

<<<<<<< HEAD
=======
    def on_own_geolocation_result(self, event: OwnGeolocationResult) -> None:
        """Stores the host's own coordinates when the geolocation query resolves."""
        if event.coords:
            self.origin_coords = event.coords
            # Refresh the map if it is currently the active screen
            self._refresh_map_if_visible()

    def on_geolocation_result(self, event: GeolocationResult) -> None:
        """Stores a remote IP's coordinates and updates the map in real-time."""
        self.geo_pending.discard(event.ip)
        if event.coords:
            self.geo_data[event.ip] = event.coords
            self._refresh_map_if_visible()

    def _refresh_map_if_visible(self) -> None:
        """
        If MapScreen is currently active (top of the screen stack),
        force the WorldMapWidget to repaint immediately so new geo-points
        appear without any user interaction.
        """
        from ui_map import MapScreen, WorldMapWidget
        if self.screen and isinstance(self.screen, MapScreen):
            try:
                map_widget = self.screen.query_one("#fullscreen-map", WorldMapWidget)
                map_widget.refresh()
            except Exception:
                pass

>>>>>>> e59a7d4 (feat: implement threat intelligence integration and ASCII world map visualization for monitoring network traffic)
    # --- UI Rendering & Node Threat Bubbling ---
    def update_sidebar(self) -> None:
        """Updates the sidebar statistics, legends, and config settings."""
        stats = self.engine.get_stats(show_all_states=self.show_all_states)
        
        sidebar_text = Text()
        sidebar_text.append(" █▀▀ █▀▀ █▀█ █▀▀ █▀█ \n", "bold #00E5FF")
        sidebar_text.append(" █▄█ █▄▄ █▄█ █▄▄ █▄█ \n\n", "bold #00E5FF")
        
        # System status
        if not self.engine.is_root:
            sidebar_text.append(" [!] Running without ROOT (Sudo)\n", "bold #FF3333")
            sidebar_text.append(" Limited PID matching details.\n\n", "dim #FF3333")
        else:
            sidebar_text.append(" [✔] Running as ROOT (Sudo)\n", "bold #00FF66")
            sidebar_text.append(" Full socket-to-process logs.\n\n", "dim #00FF66")

        # Threat Intel settings status
        if self.vt_api_key:
            sidebar_text.append(" VT Threat Intel: ACTIVE\n", "bold #00FF66")
            sidebar_text.append(f" Pending: {len(self.vt_pending)} | Malicious: {len(self.malicious_ips)}\n\n", "dim")
        else:
            sidebar_text.append(" VT Threat Intel: INACTIVE\n", "bold #888888")
            sidebar_text.append(" (vt_api_key missing in YAML)\n\n", "dim")

        # System Metrics
        sidebar_text.append("─── SYSTEM METRICS ───\n", "bold #CC33FF")
        sidebar_text.append(" Sockets Scan:   ", "dim")
        sidebar_text.append(f"{stats['total_sockets']}\n", "bold white")
        sidebar_text.append(" Monitored PIDs: ", "dim")
        sidebar_text.append(f"{stats['processes_count']}\n", "bold white")
        sidebar_text.append(" Established:    ", "dim")
        sidebar_text.append(f"{stats['established']}\n", "bold #00FF66")
        sidebar_text.append(" Listening:      ", "dim")
        sidebar_text.append(f"{stats['listening']}\n", "bold #3388FF")
        
        # Filter mode
        filter_mode = "ALL STATES" if self.show_all_states else "ESTABLISHED"
        filter_color = "#FF9900" if self.show_all_states else "#00FF66"
        sidebar_text.append(" Scan Filter:    ", "dim")
        sidebar_text.append(f"{filter_mode}\n\n", f"bold {filter_color}")

        # Legend
        sidebar_text.append("─── THREAT LEGEND ───\n", "bold #CC33FF")
        sidebar_text.append(" ☠ [REV_SHELL]   ", "bold #FF3333")
        sidebar_text.append(" Reverse shell interpreter\n", "dim")
        sidebar_text.append(" ☠ [EXFILTRATION]", "bold #FF3333")
        sidebar_text.append(" Upload limit exceeded\n", "dim")
        sidebar_text.append(" ☠ [SCANNING]    ", "bold #FF3333")
        sidebar_text.append(" SYN scan detected\n", "dim")
        sidebar_text.append(" ☠ [BACKDOOR]    ", "bold #FF3333")
        sidebar_text.append(" Unapproved listen port\n", "dim")
        sidebar_text.append(" ☠ [MALICIOUS_IP]", "bold #FF3333")
        sidebar_text.append(" VirusTotal API Flagged\n\n", "dim")

        sidebar_text.append("─── HOTKEYS ───\n", "bold #CC33FF")
        sidebar_text.append(" [c] ", "bold #FFFF00")
        sidebar_text.append("Toggle Scan Filter\n", "dim")
        sidebar_text.append(" [r] ", "bold #FFFF00")
        sidebar_text.append("Force Socket Scan\n", "dim")
        sidebar_text.append(" [f] ", "bold #FFFF00")
        sidebar_text.append("Expand/Collapse Tree\n", "dim")
        sidebar_text.append(" [k] ", "bold #FFFF00")
        sidebar_text.append("Kill Selected Process\n", "dim")
<<<<<<< HEAD
=======
        sidebar_text.append(" [m] ", "bold #FFFF00")
        sidebar_text.append("Open Geo Map\n", "dim")
>>>>>>> e59a7d4 (feat: implement threat intelligence integration and ASCII world map visualization for monitoring network traffic)
        sidebar_text.append(" [q] ", "bold #FFFF00")
        sidebar_text.append("Quit Application\n", "dim")

        self.query_one("#sidebar", Static).update(sidebar_text)

    def check_proc_has_threats(self, proc_key: str, ports_dict: Dict[int, List[Dict[str, Any]]]) -> Tuple[bool, Set[str]]:
        """
        Determines if a process (or any of its ports/connections) has threat flags.
        Bubbles up warnings from child nodes to the top-level process node.
        """
        threats = set(self.proc_threats.get(proc_key, []))
        
        # Also check all connections for malicious IP tag or heuristics
        for port, conns in ports_dict.items():
            for conn in conns:
                ip = conn.get("remote_ip", "")
                if ip in self.malicious_ips:
                    threats.add("[MALICIOUS_IP]")
                for tag in conn.get("threat_tags", []):
                    threats.add(tag)
        
        return len(threats) > 0, threats

    def check_port_has_threats(self, conns: List[Dict[str, Any]]) -> Tuple[bool, Set[str]]:
        """Determines if a specific port has threat flags bubbled up from connections."""
        threats = set()
        for conn in conns:
            ip = conn.get("remote_ip", "")
            if ip in self.malicious_ips:
                threats.add("[MALICIOUS_IP]")
            for tag in conn.get("threat_tags", []):
                threats.add(tag)
        return len(threats) > 0, threats

    def update_tree(self) -> None:
        """
        Synchronizes the Tree UI nodes with the scanned connections.
        Performs in-place updates to preserve expand/collapse states.
        """
        root = self.ui_tree.root
        active_proc_keys = set(self.grouped_data.keys())

        # 1. Clean up obsolete processes
        to_remove_proc = []
        for proc_node in root.children:
            if proc_node.data and proc_node.data[0] == "proc":
                proc_key = proc_node.data[1]
                if proc_key not in active_proc_keys:
                    to_remove_proc.append(proc_node)
        for node in to_remove_proc:
            node.remove()

        # 2. Add or update active processes
        for proc_key in active_proc_keys:
            pid = None
            if "(PID: " in proc_key:
                try:
                    pid = int(proc_key.split("(PID: ")[1].split(")")[0])
                except ValueError:
                    pass

            ports_dict = self.grouped_data[proc_key]
            has_threat, threat_tags = self.check_proc_has_threats(proc_key, ports_dict)
            
            if has_threat:
                tags_str = " " + " ".join(sorted(threat_tags))
                proc_label = Text.assemble(
                    ("☠ ALERT ☠ ", "bold #FF3333 blink"),
                    (f"{proc_key}{tags_str}", "bold #FF3333")
                )
            else:
                proc_color = get_proc_color(proc_key)
                proc_label = Text.assemble(
                    ("◈ ", f"bold {proc_color}"),
                    (proc_key, f"bold {proc_color}")
                )

            proc_node = self.find_child_by_data(root, ("proc", proc_key))
            if proc_node is None:
                proc_node = root.add(proc_label, data=("proc", proc_key, pid), expand=self.all_expanded)
            else:
                proc_node.label = proc_label
                proc_node.data = ("proc", proc_key, pid)

            # Ports sync
            active_port_keys = {("port", proc_key, port) for port in ports_dict}
            
            # Clean up obsolete ports
            to_remove_port = []
            for port_node in proc_node.children:
                if port_node.data and port_node.data[0] == "port":
                    p_key = (port_node.data[0], port_node.data[1], port_node.data[2])
                    if p_key not in active_port_keys:
                        to_remove_port.append(port_node)
            for node in to_remove_port:
                node.remove()

            # Add/update ports
            for port in ports_dict:
                port_conns = ports_dict[port]
                port_has_threat, port_threats = self.check_port_has_threats(port_conns)
                proto = port_conns[0]["protocol"] if port_conns else "TCP"
                
                if port_has_threat:
                    port_label = Text.assemble(
                        ("  ├─ Local Port: ", "dim #FF3333"),
                        (f"{port}", "bold #FF3333"),
                        (f" ({proto}) ⚠ WARNING", "bold #FF3333")
                    )
                else:
                    proc_color = get_proc_color(proc_key)
                    port_label = Text.assemble(
                        ("  ├─ Local Port: ", "dim"),
                        (f"{port}", f"bold {proc_color}"),
                        (f" ({proto})", "yellow")
                    )

                port_node = self.find_child_by_data(proc_node, ("port", proc_key, port))
                if port_node is None:
                    port_node = proc_node.add(port_label, data=("port", proc_key, port, pid), expand=self.all_expanded)
                else:
                    port_node.label = port_label
                    port_node.data = ("port", proc_key, port, pid)

                # Connections sync
                active_conn_keys = {
                    ("conn", proc_key, port, c["remote_ip"], c["remote_port"])
                    for c in port_conns
                }

                # Clean up obsolete connections
                to_remove_conn = []
                for conn_node in port_node.children:
                    if conn_node.data and conn_node.data[0] == "conn":
                        conn_k = conn_node.data[1]["key"]
                        if conn_k not in active_conn_keys:
                            to_remove_conn.append(conn_node)
                for node in to_remove_conn:
                    node.remove()

                # Add/update connection targets
                for c in port_conns:
                    conn_key = ("conn", proc_key, port, c["remote_ip"], c["remote_port"])
                    status = c["status"]
                    threat_tags_list = list(c.get("threat_tags", []))
                    if c["remote_ip"] in self.malicious_ips and "[MALICIOUS_IP]" not in threat_tags_list:
                        threat_tags_list.append("[MALICIOUS_IP]")

                    node_data = {
                        "key": conn_key,
                        "color": get_proc_color(proc_key),
                        "remote_ip": c["remote_ip"],
                        "remote_port": c["remote_port"],
                        "status": status,
                        "protocol": c["protocol"],
                        "pid": pid,
                        "proc_key": proc_key,
                        "threat_tags": threat_tags_list
                    }

                    conn_node = self.find_child_by_conn_key(port_node, conn_key)
                    if conn_node is None:
                        conn_node = port_node.add(Text("Initializing..."), data=("conn", node_data))
                    else:
                        conn_node.data = ("conn", node_data)

    def animate_connections(self) -> None:
        """Runs at high frequency (150ms) to animate flow symbols and sparklines."""
        self.animation_frame_idx += 1

        def recurse_tree(node) -> None:
            if node.data and node.data[0] == "conn":
                conn_info = node.data[1]
                proc_color = conn_info["color"]
                remote_ip = conn_info["remote_ip"]
                remote_port = conn_info["remote_port"]
                status = conn_info["status"]
                threat_tags = conn_info["threat_tags"]
                
                has_threat = len(threat_tags) > 0
                
                # Format connection indicators & sparklines
                if status == "ESTABLISHED":
                    status_color = "#00FF66"
                    flow_symbol = FLOW_FRAMES[self.animation_frame_idx % len(FLOW_FRAMES)]
                    symbol_color = proc_color if not has_threat else "#FF3333"
                elif status == "LISTEN":
                    status_color = "#3388FF"
                    flow_symbol = PULSE_FRAMES[self.animation_frame_idx % len(PULSE_FRAMES)]
                    symbol_color = "#3388FF" if not has_threat else "#FF3333"
                elif status in ("SYN_SENT", "SYN_RECV"):
                    status_color = "#FF9900"
                    flow_symbol = FAST_FLOW_FRAMES[self.animation_frame_idx % len(FAST_FLOW_FRAMES)]
                    symbol_color = "#FF9900" if not has_threat else "#FF3333"
                else:
                    status_color = "#888888"
                    flow_symbol = "  ──  "
                    symbol_color = "dim"

                # Sparkline only renders on public remote IP targets
                sparkline = ""
                if is_public_ip(remote_ip):
                    spark = get_sparkline_frame(self.animation_frame_idx)
                    sparkline = f" [{spark}]"
                
                remote_str = f"{remote_ip}:{remote_port}" if remote_ip != "*" else "Listening Sockets (*)"
                
                if has_threat:
                    # Render severe alert coloring (Bold Bright Red)
                    threats_str = " " + " ".join(threat_tags)
                    node.label = Text.assemble(
                        ("    └─ ALERT Remote: ", "bold #FF3333 blink"),
                        (f"{remote_str}{sparkline}", "bold #FF3333"),
                        (" [", "bold #FF3333"),
                        (status, "bold #FF3333"),
                        (f"] {flow_symbol}", "bold #FF3333"),
                        (threats_str, "bold #FF3333 blink")
                    )
                else:
                    node.label = Text.assemble(
                        ("    └─ Remote: ", "dim"),
                        (f"{remote_str}{sparkline}", f"bold {proc_color}"),
                        (" [", "dim"),
                        (status, f"bold {status_color}"),
                        ("] ", "dim"),
                        (f" {flow_symbol} ", f"bold {symbol_color}")
                    )
                
            for child in node.children:
                recurse_tree(child)

        recurse_tree(self.ui_tree.root)

    def update_alerts_panel(self) -> None:
        """Reads alerts.log and renders the latest 10 security incidents in a clean log format."""
        alerts_text = Text()
        alerts_text.append("☠ DETECTED SYSTEM ALERTS (alerts.log) ☠\n", "bold #FF3333")
        alerts_text.append("─" * 80 + "\n", "dim #2e3440")
        
        alerts_list = []
        if os.path.exists("alerts.log"):
            try:
                with open("alerts.log", "r") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                alerts_list.append(json.loads(line))
                            except Exception:
                                pass
            except Exception as e:
                alerts_text.append(f"Error loading alerts.log: {e}\n", "red")
        
        # Display the 10 most recent alerts (last entries in the file)
        recent_alerts = alerts_list[-10:] if alerts_list else []
        if not recent_alerts:
            alerts_text.append(" No alerts triggered. System status: SECURE.\n", "dim #00FF66")
        else:
            for alert in reversed(recent_alerts):
                ts = alert.get("timestamp", "")
                # Format timestamp slightly cleaner
                if len(ts) > 19:
                    ts = ts[11:19]  # Just get HH:MM:SS
                
                pid = alert.get("pid", "?")
                exe = os.path.basename(alert.get("executable", "unknown"))
                remote = alert.get("remote_ip", "")
                t_type = alert.get("threat_type", "")
                
                remote_str = f" -> {remote}" if remote else ""
                
                alerts_text.append(f"[{ts}] ", "dim")
                alerts_text.append(f"{t_type} ", "bold #FF3333")
                alerts_text.append(f"PID:{pid} ", "bold yellow")
                alerts_text.append(f"({exe})", "white")
                alerts_text.append(f"{remote_str}\n", "bold #FF9900")

        self.query_one("#alerts-panel", Static).update(alerts_text)

    # --- Node Helpers ---
    def find_child_by_data(self, parent_node, data_key) -> Optional[Tree]:
        """Finds a child node whose data matches the prefix of data_key."""
        for child in parent_node.children:
            if child.data and child.data[0] == data_key[0] and child.data[1] == data_key[1]:
                if len(data_key) > 2 and len(child.data) > 2:
                    if child.data[2] == data_key[2]:
                        return child
                else:
                    return child
        return None

    def find_child_by_conn_key(self, parent_node, conn_key) -> Optional[Tree]:
        """Finds a connection child node matching the unique conn_key."""
        for child in parent_node.children:
            if child.data and child.data[0] == "conn":
                if child.data[1]["key"] == conn_key:
                    return child
        return None

    # --- Actions ---
    def action_toggle_states(self) -> None:
        """Toggles filters between established connections and listening states."""
        self.show_all_states = not self.show_all_states
        self.trigger_network_scan()
        self.notify(
            "Scan filter changed to: " + ("ALL STATES" if self.show_all_states else "ESTABLISHED ONLY"),
            title="Scan Filter",
            severity="info",
            timeout=2.0
        )

    def action_manual_scan(self) -> None:
        """Triggers an immediate connections scan."""
        self.trigger_network_scan()
        self.notify("Manual connections scan started...", title="Scanning Sockets", timeout=1.0)

    def action_toggle_expand(self) -> None:
        """Toggles the tree's node expansion state."""
        self.all_expanded = not self.all_expanded
        for node in self.ui_tree.root.children:
            if self.all_expanded:
                node.expand()
                for subnode in node.children:
                    subnode.expand()
            else:
                node.collapse()
        self.notify(
            "Tree nodes " + ("expanded" if self.all_expanded else "collapsed"),
            title="Tree Layout",
            timeout=1.5
        )

    def action_kill_selected(self) -> None:
        """
        Kill Switch: Terminates the selected process using os.kill(PID, signal.SIGKILL).
        Works on Process nodes, Port nodes, and Connection nodes under the target process.
        """
        cursor = self.ui_tree.cursor_node
        if cursor is None:
            self.notify("No node selected in the network tree.", title="Kill Switch", severity="warning")
            return

        pid = None
        proc_name = "Unknown"
        
        node_data = cursor.data
        if not node_data:
            self.notify("Cannot terminate system processes.", title="Kill Switch", severity="warning")
            return

        node_type = node_data[0]
        if node_type == "proc":
            # ("proc", proc_key, pid)
            pid = node_data[2]
            proc_name = node_data[1]
        elif node_type == "port":
            # ("port", proc_key, port, pid)
            pid = node_data[3]
            proc_name = node_data[1]
        elif node_type == "conn":
            # ("conn", conn_info)
            conn_info = node_data[1]
            pid = conn_info.get("pid")
            proc_name = conn_info.get("proc_key", "Unknown")

        if pid is None:
            self.notify("No valid PID found for the selected node.", title="Kill Switch", severity="warning")
            return

        # Attempt process termination
        success = self.engine.kill_process(pid)
        if success:
            self.notify(
                f"Terminated threat {proc_name} (PID: {pid}) via SIGKILL.",
                title="THREAT NEUTRALIZED",
                severity="success",
                timeout=3.0
            )
            # Immediately run a new scan and refresh UI logs
            self.trigger_network_scan()
            self.update_alerts_panel()
        else:
            self.notify(
                f"Could not kill process {pid}. (Requires Sudo privileges).",
                title="TERMINATION FAILED",
                severity="error",
                timeout=3.0
            )


<<<<<<< HEAD
=======
    def action_toggle_map(self) -> None:
        """Opens the fullscreen interactive geo-map screen (press 'm' or 'Escape' to return)."""
        from ui_map import MapScreen
        self.push_screen(MapScreen())


>>>>>>> e59a7d4 (feat: implement threat intelligence integration and ASCII world map visualization for monitoring network traffic)
if __name__ == "__main__":
    if os.getuid() != 0:
        print("[WARNING] Running without ROOT privileges.", file=sys.stderr)
        print("[WARNING] Sockets belonging to other users will display as 'System/Unknown'.", file=sys.stderr)
        print("[TIP] To run full HIDS, execute: sudo venv/bin/python main.py", file=sys.stderr)
        print("Press Enter to launch...", end="", file=sys.stderr)
        try:
            input()
        except (KeyboardInterrupt, EOFError):
            sys.exit(0)

    app = NetTraceApp()
    app.run()
