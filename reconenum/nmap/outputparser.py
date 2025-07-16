import json
import os
import re
from pathlib import Path


def parse_host_discovery(json_data,scantype):
    """
    Parses Nmap host discovery JSON to extract info per IP.
    Returns a dict indexed by IP:
    {
        "192.168.1.1": {
            "ip": "192.168.1.1",
            "hostname": None,
            "state": "up",
            "reason": "syn-ack"
        }
    }
    """
    result = {}

    for host in json_data.get("Host", []):
        addr_entry = host.get("HostAddress", [{}])[0]
        ip = addr_entry.get("Address", "Unknown")

        # Extract hostname only if different from IP
        hostname = None
        hostnames = host.get("HostNames", {}).get("HostName", [])
        if hostnames:
            name_entry = hostnames[0].get("Name", "")
            if name_entry != ip:
                hostname = name_entry

        status = host.get("Status", {})
        state = status.get("State", "unknown")
        reason = status.get("Reason", "unknown")

        result[ip] = {
            "ip": ip,
            "hostname": hostname,
            "state": state,
            "reason": reason
        }
    directory = Path('./scans/')
    for file_path in directory.iterdir():
        if file_path.is_file() and re.compile(rf'{scantype}*').match(file_path.name):
            file_path.unlink()
    with open(f"./scans/{scantype}_aggregated.json", "w") as f:
        json.dump(result, f, indent=4)

    return result

def parse_full_discovery(json_data,scantype):
    """
    Parses Nmap host discovery JSON to extract info per IP.
    Returns a dict indexed by IP:
    {
        "192.168.1.1": {
            "ip": "192.168.1.1",
            "hostname": None,
            "state": "up",
            "reason": "syn-ack"
        }
    }
    """
    print("awa")
    directory = Path('./scans/')
    for file_path in directory.iterdir():
        if file_path.is_file() and re.compile(rf'host_discovery*').match(file_path.name):
            file_path.unlink()
        if file_path.is_file() and re.compile(rf'stealth_discovery*').match(file_path.name):
            file_path.unlink()
