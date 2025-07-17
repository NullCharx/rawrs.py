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

def parse_full_discovery(json_data,scantype,ip_range):
    """
       Parses full -sVC discovery JSON output into a structured dict and saves it to disk.

       Output format:
       {
           "ip:192.168.1.1": {
               "ports": [
                   {
                       "port": 80,
                       "protocol": "tcp",
                       "state": "open",
                       "service": {
                           "name": "http",
                           "product": "Apache",
                           ...
                       },
                       "scripts": [
                           {"id": "http-title", "output": "Apache2 Ubuntu"},
                           ...
                       ]
                   }
               ]
           }
       }
       """

    results = {}

    for host in json_data.get("Host", []):
        ip = None
        for addr in host.get("HostAddress", []):
            if addr.get("AddressType") == "ipv4":
                ip = addr.get("Address")
                break

        if not ip:
            continue

        key = f"ip:{ip}"
        results[key] = {
            "ports": []
        }

        for port in host.get("Port", []):
            port_info = {
                "port": port.get("PortId"),
                "protocol": port.get("Protocol"),
                "state": port.get("State", {}).get("State"),
                "service": {},
                "scripts": []
            }

            service = port.get("Service", {})
            if service:
                port_info["service"] = {
                    "name": service.get("Name"),
                    "product": service.get("Product"),
                    "version": service.get("Version"),
                    "ostype": service.get("OSType"),
                    "extrainfo": service.get("Extrainfo"),
                    "tunnel": service.get("Tunnel"),
                    "method": service.get("Method"),
                    "conf": service.get("Conf"),
                    "cpe": service.get("CPE")
                }

            for script in port.get("Script", []):
                port_info["scripts"].append({
                    "id": script.get("Id"),
                    "output": script.get("Output")
                })

            results[key]["ports"].append(port_info)

    # Clean up previous discovery outputs
    directory = Path('./scans/')
    for file_path in directory.iterdir():
        if file_path.is_file() and (
                re.match(r'host_discovery.*', file_path.name) or
                re.match(r'stealth_discovery.*', file_path.name) or
                re.match(r'full_discovery*', file_path.name)
        ):
            file_path.unlink()

    # Save parsed results
    with open("./scans/final_scan_aggregated.json", "w") as f:
        json.dump(results, f, indent=4)

    return results