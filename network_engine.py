import os
import psutil
import socket
from typing import Dict, List, Tuple, Optional

class NetworkEngine:
    def __init__(self):
        # Cache for process names to avoid querying psutil on every single connection scan
        self.process_name_cache: Dict[int, str] = {}
        self.is_root = (os.getuid() == 0)

    def get_process_name(self, pid: Optional[int]) -> str:
        if pid is None:
            return "System / Unknown (Need Sudo)"
        
        if pid in self.process_name_cache:
            return self.process_name_cache[pid]
        
        try:
            process = psutil.Process(pid)
            name = process.name()
            self.process_name_cache[pid] = name
            return name
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            name = f"Process {pid} (Access Denied)" if not self.is_root else f"Process {pid}"
            self.process_name_cache[pid] = name
            return name

    def get_connections(self, show_all_states: bool = False) -> Dict[str, Dict[int, List[Dict]]]:
        """
        Fetches the current connections and returns them grouped:
        {
            "Process Name (PID: 1234)": {
                local_port: [
                    {
                        "remote_ip": str,
                        "remote_port": int,
                        "status": str,
                        "protocol": str,
                        "raw_conn": psutil.sconn
                    },
                    ...
                ]
            }
        }
        """
        # Reset cache size check to avoid unbounded growth (unlikely but safe)
        if len(self.process_name_cache) > 2000:
            self.process_name_cache.clear()
            self.is_root = (os.getuid() == 0)

        grouped_data: Dict[str, Dict[int, List[Dict]]] = {}
        
        try:
            conns = psutil.net_connections(kind='inet')
        except psutil.AccessDenied:
            # Fall back to user-only connections if general access is denied
            # (though net_connections with kind='inet' usually doesn't raise AccessDenied on Linux, it just returns None for PIDs of other users)
            try:
                conns = psutil.net_connections(kind='inet4')
            except Exception:
                conns = []

        for conn in conns:
            # Filter by status: by default only ESTABLISHED
            status = conn.status
            if not show_all_states and status != 'ESTABLISHED':
                continue

            # Determine protocol
            protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"

            # Parse remote address
            if conn.raddr:
                r_ip, r_port = conn.raddr
            else:
                # If listening, remote address is empty
                r_ip, r_port = "*", 0

            # If showing only established, we usually don't have listeners anyway.
            # But if show_all_states is True, we want to see LISTENs.
            
            l_ip, l_port = conn.laddr if conn.laddr else ("*", 0)

            # Get process display name
            pid = conn.pid
            p_name = self.get_process_name(pid)
            if pid is not None:
                proc_key = f"{p_name} (PID: {pid})"
            else:
                proc_key = "System / Unknown (Need Sudo)"

            # Initialize dicts
            if proc_key not in grouped_data:
                grouped_data[proc_key] = {}
            
            if l_port not in grouped_data[proc_key]:
                grouped_data[proc_key][l_port] = []

            grouped_data[proc_key][l_port].append({
                "local_ip": l_ip,
                "remote_ip": r_ip,
                "remote_port": r_port,
                "status": status,
                "protocol": protocol
            })

        return grouped_data

    def get_stats(self, show_all_states: bool = False) -> Dict[str, int]:
        """Returns brief network stats."""
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
