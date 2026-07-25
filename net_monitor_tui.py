#!/usr/bin/env python3
import os
import sys
from typing import Dict, List, Optional
from rich.text import Text
from rich.panel import Panel

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal
from textual.widgets import Footer, Static, Tree
from textual.binding import Binding

from network_engine import NetworkEngine

# --- Design Configuration ---
# 12 vibrant neon/cyberpunk colors for processes
COLORS = [
    "#00FF66",  # Neon Green
    "#00E5FF",  # Neon Cyan
    "#FF007F",  # Neon Pink / Hot Pink
    "#FF9900",  # Neon Orange
    "#CC33FF",  # Neon Purple / Violet
    "#FFFF00",  # Neon Yellow
    "#FF3333",  # Neon Red
    "#3388FF",  # Neon Sky Blue
    "#00FFCC",  # Neon Mint / Turquoise
    "#FFCC00",  # Amber / Gold
    "#E600FF",  # Bright Orchid
    "#9D00FF"   # Deep Violet
]

# Flow animation frames for established connections (moving packet simulation)
FLOW_FRAMES = [
    "──❯───❯──",
    "───❯───❯─",
    "────❯───❯",
    "❯────❯───",
    "─❯────❯──",
]

# Fast flow frames for connecting states (SYN_SENT/SYN_RECV)
FAST_FLOW_FRAMES = [
    "──►──►──",
    "──►──►──",
    "─►──►───",
    "►──►────",
]

# Pulse animation frames for listening sockets (simulates heartbeat/waiting)
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

def get_proc_color(proc_key: str) -> str:
    """Generates a stable color index for a process name/PID to ensure consistency."""
    color_index = abs(hash(proc_key)) % len(COLORS)
    return COLORS[color_index]


class NetTraceHeader(Static):
    """Custom premium header widget with neon styling."""
    def render(self) -> Text:
        return Text.assemble(
            (" ⚡ ", "bold #FFFF00"),
            ("GCOCO", "bold #00FF66"),
            ("// ", "bold #3a3f58"),
            ("LIVE NETWORK CONNECTION MONITOR", "bold white"),
            (" ⚡", "bold #FFFF00")
        )


class NetTraceApp(App):
    """
    Main Textual TUI Application for Net-Trace.
    Displays a live hierarchical view of processes, local ports, and remote destinations
    with real-time animations representing traffic/connection states.
    """
    
    # CSS stylesheet configured to match premium cyberpunk dark theme
    CSS = """
    Screen {
        background: #0d0f18;
        color: #e2e8f0;
    }
    
    NetTraceHeader {
        background: #141726;
        color: #e2e8f0;
        text-align: center;
        height: 3;
        content-align: center middle;
        border-bottom: double #3a3f58;
    }
    
    #body {
        layout: horizontal;
        height: 1fr;
    }
    
    #sidebar {
        width: 38;
        height: 100%;
        border-right: double #3a3f58;
        background: #141726;
        padding: 1 2;
    }
    
    #main-panel {
        width: 1fr;
        height: 100%;
        background: #0d0f18;
        padding: 1;
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
        background: #141726;
        color: #a0aec0;
        border-top: double #3a3f58;
    }
    """
    
    BINDINGS = [
        Binding("c", "toggle_states", "Toggle Filter (Established / All)", show=True),
        Binding("r", "manual_refresh", "Manual Scan", show=True),
        Binding("f", "toggle_expand", "Expand/Collapse Tree", show=True),
        Binding("q", "quit", "Quit", show=True),
    ]

    def compose(self) -> ComposeResult:
        yield NetTraceHeader()
        with Horizontal(id="body"):
            yield Static(id="sidebar")
            with Container(id="main-panel"):
                # Tree initialization with hidden root to make Processes the top level
                tree = Tree("Network Connections Root", id="net_tree")
                tree.show_root = False
                yield tree
        yield Footer()

    def on_mount(self) -> None:
        # Initialize network scanning engine
        self.engine = NetworkEngine()
        
        # State control
        self.show_all_states = False  # Start showing ESTABLISHED connections only
        self.all_expanded = True      # Start with tree expanded
        self.animation_frame_idx = 0  # Frame counter for animating elements
        
        # Reference to the Tree widget
        #self.tree = self.query_one("#net_tree", Tree)
        self.ui_tree = self.query_one("#net_tree", Tree)

        # Periodic timers:
        # 1. Update tree structure & read sockets every 1.5s (efficient, low CPU)
        self.set_interval(1.5, self.refresh_data)
        
        # 2. Cycle flow animation frames every 150ms (smooth visuals)
        self.set_interval(0.150, self.animate_connections)
        
        # Trigger initial draw
        self.refresh_data()

    def refresh_data(self) -> None:
        """Polls network engine and updates Tree and Sidebar statistics."""
        try:
            self.update_tree()
        except Exception:
            # Prevent app crashes due to transient socket errors
            pass
        self.update_sidebar()

    def update_sidebar(self) -> None:
        """Calculates latest metrics and updates the sidebar layout."""
        stats = self.engine.get_stats(show_all_states=self.show_all_states)
        
        # Construct sidebar content using rich styling
        sidebar_text = Text()
        #sidebar_text.append("\n")
        sidebar_text.append(" █▀▀ █▀▀ █▀█ █▀▀ █▀█ \n", "bold #00E5FF")
        sidebar_text.append(" █▄█ █▄▄ █▄█ █▄▄ █▄█ \n\n", "bold #00E5FF")
        
        # Permission Mode Banner
        if not self.engine.is_root:
            sidebar_text.append(" [WARNING] Running without Sudo.\n", "bold #FF3333")
            sidebar_text.append(" Sockets owned by other users\n", "dim #FF3333")
            sidebar_text.append(" will show as 'System/Unknown'.\n\n", "dim #FF3333")
        else:
            sidebar_text.append(" [SYSTEM] Running as ROOT (Sudo).\n", "bold #00FF66")
            sidebar_text.append(" Full process-to-socket mapping.\n\n", "dim #00FF66")

        # System Metrics
        sidebar_text.append("─── SYSTEM METRICS ───\n", "bold #CC33FF")
        sidebar_text.append(" Total Sockets:  ", "dim")
        sidebar_text.append(f"{stats['total_sockets']}\n", "bold white")
        sidebar_text.append(" Active PIDs:    ", "dim")
        sidebar_text.append(f"{stats['processes_count']}\n", "bold white")
        sidebar_text.append(" Established:    ", "dim")
        sidebar_text.append(f"{stats['established']}\n", "bold #00FF66")
        sidebar_text.append(" Listening:      ", "dim")
        sidebar_text.append(f"{stats['listening']}\n", "bold #3388FF")
        
        # Display Current Mode
        sidebar_text.append(" Scan Filter:     ", "dim")
        filter_mode = "ALL STATES" if self.show_all_states else "ESTABLISHED ONLY"
        filter_color = "#FF9900" if self.show_all_states else "#00FF66"
        sidebar_text.append(f"{filter_mode}\n\n", f"bold {filter_color}")

        # Legend
        sidebar_text.append("─── FLOW LEGEND ───\n", "bold #CC33FF")
        sidebar_text.append(" ■ ESTABLISHED  ", "bold #00FF66")
        sidebar_text.append(" (Moving ──❯──)\n", "dim")
        sidebar_text.append(" ■ LISTEN       ", "bold #3388FF")
        sidebar_text.append(" (Pulsing  (░) )\n", "dim")
        sidebar_text.append(" ■ CONNECTING   ", "bold #FF9900")
        sidebar_text.append(" (Fast   ──►──)\n", "dim")
        sidebar_text.append(" ■ INACTIVE     ", "dim #888888")
        sidebar_text.append(" (Static ──  )\n\n", "dim #888888")

        # Shortcuts / Keys Panel
        sidebar_text.append("─── HOTKEYS ───\n", "bold #CC33FF")
        sidebar_text.append(" [c] ", "bold #FFFF00")
        sidebar_text.append("Toggle Scan Filter\n", "dim")
        sidebar_text.append(" [r] ", "bold #FFFF00")
        sidebar_text.append("Force Manual Scan\n", "dim")
        sidebar_text.append(" [f] ", "bold #FFFF00")
        sidebar_text.append("Expand/Collapse Tree\n", "dim")
        sidebar_text.append(" [q] ", "bold #FFFF00")
        sidebar_text.append("Quit Application\n", "dim")

        self.query_one("#sidebar", Static).update(sidebar_text)

    def update_tree(self) -> None:
        """
        Synchronizes the Tree state with the network scanner snapshot.
        Adds/removes nodes in-place to avoid collapsing user-expanded subtrees.
        """
        grouped_data = self.engine.get_connections(show_all_states=self.show_all_states)
        root = self.ui_tree.root

        # Process synchronization
        active_proc_keys = set(grouped_data.keys())

        # 1. Clean up stale process nodes
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
            proc_color = get_proc_color(proc_key)
            proc_label = Text.assemble(
                ("◈ ", f"bold {proc_color}"),
                (proc_key, f"bold {proc_color}")
            )
            
            proc_node = self.find_child_by_data(root, ("proc", proc_key))
            if proc_node is None:
                proc_node = root.add(proc_label, data=("proc", proc_key), expand=self.all_expanded)
            else:
                proc_node.label = proc_label

            # Port synchronization under process
            local_ports = grouped_data[proc_key]
            active_port_keys = {("port", proc_key, port) for port in local_ports}

            # Clean up stale ports
            to_remove_port = []
            for port_node in proc_node.children:
                if port_node.data not in active_port_keys:
                    to_remove_port.append(port_node)
            for node in to_remove_port:
                node.remove()

            # Add or update active ports
            for port in local_ports:
                port_key = ("port", proc_key, port)
                conns = local_ports[port]
                proto = conns[0]["protocol"] if conns else "TCP"
                
                port_label = Text.assemble(
                    ("  ├─ Local Port: ", "dim"),
                    (f"{port}", f"bold {proc_color}"),
                    (f" ({proto})", "yellow")
                )
                
                port_node = self.find_child_by_data(proc_node, port_key)
                if port_node is None:
                    port_node = proc_node.add(port_label, data=port_key, expand=self.all_expanded)
                else:
                    port_node.label = port_label

                # Connection targets synchronization under port
                active_conn_keys = {
                    ("conn", proc_key, port, c["remote_ip"], c["remote_port"])
                    for c in conns
                }

                # Clean up stale connection targets
                to_remove_conn = []
                for conn_node in port_node.children:
                    if conn_node.data and conn_node.data[0] == "conn":
                        conn_k = conn_node.data[1]["key"]
                        if conn_k not in active_conn_keys:
                            to_remove_conn.append(conn_node)
                for node in to_remove_conn:
                    node.remove()

                # Add or update active connection targets
                for c in conns:
                    conn_key = ("conn", proc_key, port, c["remote_ip"], c["remote_port"])
                    status = c["status"]
                    
                    node_data = {
                        "key": conn_key,
                        "color": proc_color,
                        "remote_ip": c["remote_ip"],
                        "remote_port": c["remote_port"],
                        "status": status,
                        "protocol": c["protocol"]
                    }
                    
                    conn_node = self.find_child_by_conn_key(port_node, conn_key)
                    if conn_node is None:
                        # Set initial placeholder label, will be populated on the next animation tick
                        placeholder = Text("Loading connection...")
                        port_node.add(placeholder, data=("conn", node_data))
                    else:
                        conn_node.data = ("conn", node_data)

    def animate_connections(self) -> None:
        """
        Runs at high frequency (150ms) to update the visual flow symbols
        without running expensive network queries.
        """
        self.animation_frame_idx += 1

        def recurse(node) -> None:
            if node.data and node.data[0] == "conn":
                conn_info = node.data[1]
                proc_color = conn_info["color"]
                remote_ip = conn_info["remote_ip"]
                remote_port = conn_info["remote_port"]
                status = conn_info["status"]
                
                # Format status color & flow character mapping
                if status == "ESTABLISHED":
                    status_color = "#00FF66" # Neon green
                    frame = FLOW_FRAMES[self.animation_frame_idx % len(FLOW_FRAMES)]
                    frame_color = proc_color
                elif status == "LISTEN":
                    status_color = "#3388FF" # Neon blue
                    frame = PULSE_FRAMES[self.animation_frame_idx % len(PULSE_FRAMES)]
                    frame_color = "#3388FF"
                elif status in ("SYN_SENT", "SYN_RECV"):
                    status_color = "#FF9900" # Neon orange
                    frame = FAST_FLOW_FRAMES[self.animation_frame_idx % len(FAST_FLOW_FRAMES)]
                    frame_color = "#FF9900"
                else:
                    status_color = "#888888" # Grey for inactive
                    frame = "  ──  "
                    frame_color = "dim"
                
                # Special representation for listen/local-only connections
                remote_str = f"{remote_ip}:{remote_port}" if remote_ip != "*" else "Listening Sockets (*)"
                
                node.label = Text.assemble(
                    ("    └─ Remote: ", "dim"),
                    (remote_str, f"bold {proc_color}"),
                    (" [", "dim"),
                    (status, f"bold {status_color}"),
                    ("] ", "dim"),
                    (f" {frame} ", f"bold {frame_color}")
                )
                
            for child in node.children:
                recurse(child)

        recurse(self.ui_tree.root)

    def find_child_by_data(self, parent_node, data_key) -> Optional[Tree]:
        """Utility method to find a child node by its exact data signature."""
        for child in parent_node.children:
            if child.data == data_key:
                return child
        return None

    def find_child_by_conn_key(self, parent_node, conn_key) -> Optional[Tree]:
        """Utility method to find a connection child node by its target identifier key."""
        for child in parent_node.children:
            if child.data and child.data[0] == "conn":
                if child.data[1]["key"] == conn_key:
                    return child
        return None

    # --- Actions ---
    def action_toggle_states(self) -> None:
        """Toggles scan filter between ESTABLISHED only and ALL connections."""
        self.show_all_states = not self.show_all_states
        self.refresh_data()
        self.notify(
            "Scan filter changed to: " + ("ALL STATES" if self.show_all_states else "ESTABLISHED ONLY"),
            title="Scan Filter",
            severity="info",
            timeout=2.0
        )

    def action_manual_refresh(self) -> None:
        """Manually forces a socket scan."""
        self.refresh_data()
        self.notify("Manual network scan completed.", title="Scan Completed", timeout=1.0)

    def action_toggle_expand(self) -> None:
        """Toggles expanded state of all process and port nodes in the tree."""
        self.all_expanded = not self.all_expanded
        for node in self.ui_tree.root.children:
            if self.all_expanded:
                node.expand()
                for subnode in node.children:
                    subnode.expand()
            else:
                node.collapse()
        self.notify(
            "Tree nodes " + ("expanded" if self.all_expanded else "collapsed") + ".",
            title="Tree State",
            timeout=1.5
        )


if __name__ == "__main__":
    # Warn normal users about permissions before starting
    if os.getuid() != 0:
        print("[WARNING] Running as normal user. Some system processes and connection details will not be visible.", file=sys.stderr)
        print("[TIP] For best results, run: sudo venv/bin/python net_monitor_tui.py", file=sys.stderr)
        print("Press Enter to launch anyway...", end="", file=sys.stderr)
        try:
            input()
        except (KeyboardInterrupt, EOFError):
            sys.exit(0)

    app = NetTraceApp()
    app.run()
