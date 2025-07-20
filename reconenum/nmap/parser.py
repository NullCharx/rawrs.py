import json
import re
from datetime import datetime
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
    directory = Path('./scans/raw/json')
    for file_path in directory.iterdir():
        if file_path.is_file() and re.compile(rf'{scantype}*').match(file_path.name):
            file_path.unlink()
    with open(f"./scans/raw/json/{scantype}_aggregated.json", "w") as f:
        json.dump(result, f, indent=4)

    return result

def parse_full_discovery(json_data, output_path="./scans/final_scan_aggregated.json"):
    """
    Parses Nmap formatted JSON data (from a -sVC scan) and returns a cleaned dict.
    Also writes to a JSON file with simplified structure.

    Output format:
    {
        "ip:192.168.1.1": {
            "hostname": "host.local",
            "ports": [
                {
                    "port": "80",
                    "protocol": "tcp",
                    "state": "open",
                    "reason": "syn-ack",
                    "service": {
                        "name": "http",
                        "product": "Apache httpd",
                        "version": "2.4.41",
                        "extrainfo": "Ubuntu",
                        ...
                    },
                    "scripts": [
                        {"id": "vuln", "output": "..."}
                    ]
                },
                ...
            ]
        },
        ...
    }
    """
    result = {}

    for host in json_data.get("Host", []):
        ip = None
        hostname = None

        # Get IP address
        for addr in host.get("HostAddress", []):
            if addr.get("AddressType") == "ipv4":
                ip = addr.get("Address")
                break

        if not ip:
            continue

        # Get hostname (PTR or otherwise)
        for hn in host.get("HostNames", {}).get("HostName", []):
            if hn.get("Name") != ip:
                hostname = hn.get("Name")
                break

        key = f"{ip}"
        result[key] = {
            "hostname": hostname,
            "ports": []
        }

        ports = host.get("Port", [])
        if ports:
            for port in ports :
                port_info = {
                    "port": port.get("PortID"),
                    "protocol": port.get("Protocol"),
                    "state": port.get("State", {}).get("State"),
                    "reason": port.get("State", {}).get("Reason"),
                    "service": {},
                    "scripts": []
                }

                service = port.get("Service",[])
                if service:
                    port_info["service"] = {
                        "name": service.get("Name"),
                        "product": service.get("Product"),
                        "version": service.get("Version"),
                        "extrainfo": service.get("Extrainfo"),
                        "method": service.get("Method"),
                        "conf": service.get("Conf"),
                        "cpe": service.get("CPE")
                    }

                    scripts = port.get("Script", [])
                    if scripts:
                        for script in scripts:
                            port_info["scripts"].append({
                                "id": script.get("ID"),
                                "output": script.get("Output")
                            })

                result[key]["ports"].append(port_info)

    # Save the cleaned results
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(result, f, indent=4)

    return result