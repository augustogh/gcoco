import os
import json
import datetime
import logging
from typing import Dict, List, Set, Tuple, Any

logger = logging.getLogger("heuristics")

ALERTS_LOG_PATH = "alerts.log"

# Set of standard outgoing ports to reduce false positives for reverse shells
STANDARD_REMOTE_PORTS = {22, 53, 80, 443, 8080, 8443}

# Known shells, interpreters and net tools
INTERPRETERS = {
    "bash", "sh", "zsh", "python", "python3", "python3.14", 
    "nc", "netcat", "ncat", "perl", "ruby", "node", "php"
}

def log_threat_alert(pid: int, executable: str, remote_ip: str, threat_type: str, logged_alerts: Set[Tuple[int, str, str]]):
    """
    Logs a security alert to alerts.log in JSON format.
    Uses logged_alerts set to avoid duplicate logs for the same threat on the same process/IP.
    """
    alert_key = (pid, threat_type, remote_ip)
    if alert_key in logged_alerts:
        return

    logged_alerts.add(alert_key)
    
    alert_event = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "pid": pid,
        "executable": executable,
        "remote_ip": remote_ip if remote_ip else "",
        "threat_type": threat_type
    }
    
    try:
        # Open in append mode and write line-delimited JSON
        with open(ALERTS_LOG_PATH, "a") as f:
            f.write(json.dumps(alert_event) + "\n")
        logger.info(f"Forensic Alert Logged: {threat_type} on PID {pid}")
    except Exception as e:
        logger.error(f"Failed to write forensic alert to log file: {e}")

def run_heuristics_checks(
    connections_data: Dict[str, Dict[int, List[Dict[str, Any]]]],
    config: Dict[str, Any],
    upload_baselines: Dict[int, int],
    logged_alerts: Set[Tuple[int, str, str]]
) -> Dict[str, Set[str]]:
    """
    Runs heuristic checks on connection snapshot.
    Modifies connections_data in-place to append threat tags to connection dicts.
    Returns:
        Dict[str, Set[str]]: Maps proc_key (e.g. "python (PID: 1234)") to set of threat tags.
    """
    # 1. Parse configuration parameters
    max_upload = config.get("max_upload_bytes", 10 * 1024 * 1024)
    whitelist = set(config.get("binary_whitelist", []))
    allowed_ports = set(config.get("allowed_listening_ports", []))

    # PID-level tracking
    syn_sent_counts: Dict[int, int] = {}
    proc_threats: Dict[str, Set[str]] = {}

    # Gather SYN_SENT counts and general metadata first
    for proc_key, ports_dict in connections_data.items():
        # Extract PID from proc_key (e.g., "python (PID: 1234)")
        pid = None
        if "(PID: " in proc_key:
            try:
                pid = int(proc_key.split("(PID: ")[1].split(")")[0])
            except ValueError:
                pass

        if not pid:
            continue

        for port, conns in ports_dict.items():
            for conn in conns:
                if conn.get("status") == "SYN_SENT":
                    syn_sent_counts[pid] = syn_sent_counts.get(pid, 0) + 1

    # Main detection loop
    for proc_key, ports_dict in connections_data.items():
        # Get process PID, name, and binary path if available
        pid = None
        proc_name = ""
        exe_path = ""
        write_chars = 0
        io_error = False

        if "(PID: " in proc_key:
            try:
                pid = int(proc_key.split("(PID: ")[1].split(")")[0])
                proc_name = proc_key.split(" (PID:")[0]
            except ValueError:
                pass

        # We need process details for whitelist and EXFILTRATION detection
        import psutil
        if pid is not None:
            try:
                proc = psutil.Process(pid)
                exe_path = proc.exe()
                # Get I/O stats
                try:
                    io = proc.io_counters()
                    # write_chars matches wchar in /proc/<pid>/io (total write system call bytes)
                    write_chars = io.write_chars
                except (psutil.AccessDenied, AttributeError):
                    io_error = True
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                exe_path = proc_name

        proc_threats[proc_key] = set()

        # Heuristic checks per connection
        for port, conns in ports_dict.items():
            for conn in conns:
                status = conn.get("status", "")
                remote_ip = conn.get("remote_ip", "")
                remote_port = conn.get("remote_port", 0)
                conn_tags = set()

                # --- 1. [REV_SHELL] Detection ---
                # Check if process is an interpreter and connects to a non-standard remote port
                is_interpreter = proc_name.lower() in INTERPRETERS or os.path.basename(exe_path).lower() in INTERPRETERS
                is_established_or_connecting = status in ("ESTABLISHED", "SYN_SENT", "SYN_RECV")
                is_non_standard_port = remote_port not in STANDARD_REMOTE_PORTS
                
                # Check that it's actually remote (not local loopback)
                is_remote = remote_ip not in ("*", "127.0.0.1", "::1", "0.0.0.0")

                if is_interpreter and is_established_or_connecting and is_non_standard_port and is_remote:
                    tag = "[REV_SHELL]"
                    conn_tags.add(tag)
                    proc_threats[proc_key].add(tag)
                    log_threat_alert(pid, exe_path or proc_name, remote_ip, tag, logged_alerts)

                # --- 2. [EXFILTRATION] Detection ---
                # Non-whitelisted binary exceeding upload limit since first observed
                if pid is not None and not io_error:
                    # If not in whitelist, check upload bytes
                    is_whitelisted = exe_path in whitelist or proc_name in whitelist
                    if not is_whitelisted:
                        # Register baseline if first seen
                        if pid not in upload_baselines:
                            upload_baselines[pid] = write_chars
                        
                        uploaded_bytes = write_chars - upload_baselines[pid]
                        if uploaded_bytes > max_upload:
                            tag = "[EXFILTRATION]"
                            conn_tags.add(tag)
                            proc_threats[proc_key].add(tag)
                            log_threat_alert(pid, exe_path or proc_name, remote_ip, tag, logged_alerts)

                # --- 3. [SCANNING] Detection ---
                # Multiple connections in SYN_SENT status from same PID
                if pid is not None and syn_sent_counts.get(pid, 0) >= 5:
                    tag = "[SCANNING]"
                    conn_tags.add(tag)
                    proc_threats[proc_key].add(tag)
                    log_threat_alert(pid, exe_path or proc_name, remote_ip, tag, logged_alerts)

                # --- 4. [BACKDOOR] Detection ---
                # Listening on a port not listed in allowed_listening_ports
                if status == "LISTEN" and port not in allowed_ports:
                    tag = "[BACKDOOR]"
                    conn_tags.add(tag)
                    proc_threats[proc_key].add(tag)
                    log_threat_alert(pid, exe_path or proc_name, "", tag, logged_alerts)

                # Save tags to connection dict for rendering in TUI
                conn["threat_tags"] = list(conn_tags)

    return proc_threats
