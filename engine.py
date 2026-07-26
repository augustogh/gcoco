import os
import sys
import signal
import psutil
import socket
import logging
import yaml
from typing import Dict, List, Set, Tuple, Any, Optional
from heuristics import run_heuristics_checks

logger = logging.getLogger("engine")

class NetworkEngine:
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = config_path
        self.config: Dict[str, Any] = {}
        self.load_config()

        # Cache for process names/executables to avoid repeated disk lookup
        self.process_cache: Dict[int, Dict[str, Any]] = {}
        
        # State tracking for heuristics
        self.upload_baselines: Dict[int, int] = {}
        self.logged_alerts: Set[Tuple[int, str, str]] = set()

        self.is_root = (os.getuid() == 0)

    def load_config(self) -> None:
        """Loads configuration from YAML file."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, "r") as f:
                    self.config = yaml.safe_load(f) or {}
                logger.info("Configuration loaded successfully.")
            else:
                logger.warning(f"Config file {self.config_path} not found. Using empty config.")
                self.config = {}
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            self.config = {}

    def get_process_details(self, pid: Optional[int]) -> Dict[str, Any]:
        """Retrieves process name and executable path, with caching."""
        if pid is None:
            return {"name": "System / Unknown", "exe": ""}
        
        if pid in self.process_cache:
            return self.process_cache[pid]
        
        try:
            process = psutil.Process(pid)
            name = process.name()
            try:
                exe = process.exe()
            except (psutil.AccessDenied, AttributeError):
                exe = name
            
            details = {"name": name, "exe": exe}
            self.process_cache[pid] = details
            return details
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            name = f"Process {pid}"
            details = {"name": name, "exe": name}
            self.process_cache[pid] = details
            return details

    def scan_connections(self, show_all_states: bool = False) -> Tuple[Dict[str, Dict[int, List[Dict[str, Any]]]], Dict[str, Set[str]]]:
        """
        Scans all network connections, groups them by process, and applies heuristic tags.
        Returns:
            grouped_data: hierarchical connection details.
            proc_threats: active threat tags per process key.
        """
        # Clear cache periodically if it grows too large
        if len(self.process_cache) > 2000:
            self.process_cache.clear()

        grouped_data: Dict[str, Dict[int, List[Dict[str, Any]]]] = {}
        
        try:
            conns = psutil.net_connections(kind='inet')
        except psutil.AccessDenied:
            try:
                conns = psutil.net_connections(kind='inet4')
            except Exception:
                conns = []
        except Exception:
            conns = []

        for conn in conns:
            status = conn.status
            # If not showing all states, restrict to ESTABLISHED
            if not show_all_states and status != 'ESTABLISHED':
                continue

            protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"

            if conn.raddr:
                r_ip, r_port = conn.raddr
            else:
                r_ip, r_port = "*", 0

            l_ip, l_port = conn.laddr if conn.laddr else ("*", 0)

            # Get process identification details
            pid = conn.pid
            details = self.get_process_details(pid)
            p_name = details["name"]
            
            if pid is not None:
                proc_key = f"{p_name} (PID: {pid})"
            else:
                proc_key = "System / Unknown (Need Sudo)"

            # Initialize hierarchy
            if proc_key not in grouped_data:
                grouped_data[proc_key] = {}
            
            if l_port not in grouped_data[proc_key]:
                grouped_data[proc_key][l_port] = []

            grouped_data[proc_key][l_port].append({
                "local_ip": l_ip,
                "remote_ip": r_ip,
                "remote_port": r_port,
                "status": status,
                "protocol": protocol,
                "threat_tags": []
            })

        # Run heuristic checks on the grouped data (mutates in-place and returns threat mapping)
        proc_threats = run_heuristics_checks(
            grouped_data, 
            self.config, 
            self.upload_baselines, 
            self.logged_alerts
        )

        return grouped_data, proc_threats

    def kill_process(self, pid: int) -> bool:
        """
        Attempts to kill a process by PID using SIGKILL.
        Returns:
            True: if successfully terminated.
            False: if permission denied or process not found.
        """
        try:
            os.kill(pid, signal.SIGKILL)
            # Remove from baselines and caches to clean up memory
            if pid in self.upload_baselines:
                del self.upload_baselines[pid]
            if pid in self.process_cache:
                del self.process_cache[pid]
            logger.info(f"Process with PID {pid} killed successfully.")
            return True
        except (ProcessLookupError, PermissionError) as e:
            logger.error(f"Failed to kill process {pid}: {e}")
            return False

    def get_stats(self, show_all_states: bool = False) -> Dict[str, int]:
        """Computes summary network metrics."""
        try:
            conns = psutil.net_connections(kind='inet')
        except Exception:
            conns = []
        
        stats = {
            "total_sockets": len(conns),
            "established": 0,
            "listening": 0,
            "other_states": 0,
            "processes_count": len(set(c.pid for c in conns if c.pid is not None))
        }

        for c in conns:
            if c.status == 'ESTABLISHED':
                stats["established"] += 1
            elif c.status == 'LISTEN':
                stats["listening"] += 1
            else:
                stats["other_states"] += 1

        return stats
