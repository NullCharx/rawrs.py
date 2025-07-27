import html
import ipaddress
import json
import os
import re
from pathlib import Path


def parse_nmap_host_discovery(json_data, scantype):
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
    directory = Path('./scans/nmap/json')
    for file_path in directory.iterdir():
        if file_path.is_file() and re.compile(rf'{scantype}*').match(file_path.name):
            file_path.unlink()
    with open(f"./scans/nmap/json/{scantype}_aggregated.json", "w") as f:
        json.dump(result, f, indent=4)

    return result


def parse_nmap_full_discovery(json_data, output_path="./results/nmap_aggregated_scan.json"):
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
    os.remove("./scans/nmap/json/host_discovery_aggregated.json")
    os.remove("./scans/nmap/json/stealth_discovery_aggregated.json")
    return result


def parse_ip_inputs(input_string):
    """
    Takes a list with one element (e.g., a CIDR or comma-separated IPs)
    or multiple elements (e.g., plain IP strings), and returns a list of IPs.
    CIDRs are expanded into all contained IPs.
    """
    if isinstance(input_string, str):
        input_string = [input_string]

    ips = []

    for entry in input_string:
        # Split by comma in case of comma-separated entries
        parts = [p.strip() for p in entry.split(',') if p.strip()]
        for part in parts:
            #Return the CIDR
            if '/' in part:
                return [part]
            else:
                #Get the parsed list and try to parse it before adding
                try:
                    ip = ipaddress.ip_address(part)
                    ips.append(str(ip))
                except ValueError as e:
                    raise ValueError(f"Invalid IP address '{part}': {e}")
    return ips


def parseWebtechResults(list):
    """
    Parse the whateb scaner results in a new easier readable and processable file
    :param list:
    :return:
    """
    results = {}
    for target in list:
        with open(f"./scans/whatweb/{target}.json", "r") as f:
            data = json.load(f)

        for entry in data:
            target = entry.get("target", "unknown")
            plugins = entry.get("plugins", {})

            target_info = {}

            # Extract basic information if available
            http_server = plugins.get("HTTPServer", {}).get("string", [])
            if http_server:
                target_info["server"] = http_server[0]

            title = plugins.get("Title", {}).get("string", [])
            if title:
                # Decode HTML entities
                target_info["title"] = html.unescape(title[0])

            # Example of extracting version info from server string
            # You can extend this logic for specific parsing
            if http_server:
                parts = http_server[0].split()
                if len(parts) > 1 and any(char.isdigit() for char in parts[1]):
                    target_info["version"] = parts[1]

            # Add other plugins that may have version-like info
            for plugin_name, plugin_data in plugins.items():
                strings = plugin_data.get("string", [])
                if strings:
                    target_info[plugin_name.lower()] = strings

            results[target] = target_info
    with open(f"./results/whatweb_aggregated.json", "w") as f:
        json.dump(results, f, indent=2)

    return results
