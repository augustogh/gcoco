#!/usr/bin/env python3
import sys
from heuristics import run_heuristics_checks

def test_heuristics():
    print("=== Running HIDS Heuristics Verification ===")
    
    # 1. Mock configuration
    config = {
        "max_upload_bytes": 1000,
        "binary_whitelist": ["/usr/sbin/sshd"],
        "allowed_listening_ports": [22, 443]
    }
    
    # 2. Mock connection data
    # Case A: Normal whitelisted service sshd listening on 22 (Allowed)
    # Case B: Python interpreter connecting to remote port 4444 (Should trigger [REV_SHELL])
    # Case C: Rogue listening port 9999 (Should trigger [BACKDOOR])
    # Case D: Non-whitelisted process (curl) with high SYN_SENT (Should trigger [SCANNING])
    connections_data = {
        "sshd (PID: 101)": {
            22: [{"local_ip": "0.0.0.0", "remote_ip": "*", "remote_port": 0, "status": "LISTEN", "protocol": "TCP"}]
        },
        "python (PID: 102)": {
            50123: [{"local_ip": "192.168.1.5", "remote_ip": "8.8.8.8", "remote_port": 4444, "status": "ESTABLISHED", "protocol": "TCP"}]
        },
        "rogue_binary (PID: 103)": {
            9999: [{"local_ip": "0.0.0.0", "remote_ip": "*", "remote_port": 0, "status": "LISTEN", "protocol": "TCP"}]
        },
        "curl (PID: 104)": {
            50001: [
                {"local_ip": "192.168.1.5", "remote_ip": "8.8.8.8", "remote_port": 80, "status": "SYN_SENT", "protocol": "TCP"},
                {"local_ip": "192.168.1.5", "remote_ip": "8.8.8.9", "remote_port": 80, "status": "SYN_SENT", "protocol": "TCP"},
                {"local_ip": "192.168.1.5", "remote_ip": "8.8.8.10", "remote_port": 80, "status": "SYN_SENT", "protocol": "TCP"},
                {"local_ip": "192.168.1.5", "remote_ip": "8.8.8.11", "remote_port": 80, "status": "SYN_SENT", "protocol": "TCP"},
                {"local_ip": "192.168.1.5", "remote_ip": "8.8.8.12", "remote_port": 80, "status": "SYN_SENT", "protocol": "TCP"}
            ]
        }
    }
    
    upload_baselines = {}
    logged_alerts = set()
    
    # Run the checks
    threats = run_heuristics_checks(connections_data, config, upload_baselines, logged_alerts)
    
    print("\nResults:")
    for proc, tags in threats.items():
        print(f"Process: {proc} -> Tags: {list(tags)}")

    # Asserts
    assert "[REV_SHELL]" in threats["python (PID: 102)"], "Failed to detect reverse shell!"
    assert "[BACKDOOR]" in threats["rogue_binary (PID: 103)"], "Failed to detect backdoor listening port!"
    assert "[SCANNING]" in threats["curl (PID: 104)"], "Failed to detect high SYN_SENT volume!"
    assert not threats["sshd (PID: 101)"], "Whitelisted sshd on standard port flagged incorrectly!"
    
    print("\n✔ All Heuristic tests passed successfully!")

if __name__ == "__main__":
    test_heuristics()
