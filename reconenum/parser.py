import html
import ipaddress
import json
import os
import re
from pathlib import Path
from tabnanny import verbose
from urllib.parse import urlparse

from core import context_manager
from core.config import bcolors

"""
Parsing of any arguments or command output of any of the subtools go in this file
"""
def parse_ip_inputs(input_string, isauto : bool = False, verbose : bool = False):

    """
    Takes a list with one element (e.g., a CIDR or comma-separated IPs)
    or multiple elements (e.g., plain IP strings), and returns a list of IPs.
    CIDRs are expanded into all contained IPs.
    """
    #Every tool should call loadProjectContextOnMemory() in its argument handler
    # so it doesnt need to be read from file in every tool
    ips = []
    if isauto:
        targetdata = context_manager.getNmapAggregatedData()
        #Get the context keys from previous nmap if the aggregated file exists, else try to pull the targets from context
        if targetdata:
            ips = targetdata
        else:
            ips = context_manager.targets
    #If ips still empty (due to being auto or not having previ ctx)
    if not ips:

        if isinstance(input_string, str):
            input_string = [input_string]

        for entry in input_string:
            parts = [p.strip() for p in entry.split(',') if p.strip()]
            for part in parts:
                # Handle CIDR first
                if '/' in part and '://':
                    try:
                        ipaddress.ip_network(part, strict=False)
                        return [part]
                    except ValueError as e:
                        if verbose>0:
                            print(f"\n{bcolors.FAIL}[-] Invalid CIDR '{part}': {e}. Might be a URL instead{bcolors.RESET}")
                # Parrse as url
                parsed = urlparse(part)
                # If it got scheme (shceme://), check the ip and accept it if its valid
                if parsed.scheme:
                    test_parse = parsed
                    host = parsed.hostname
                    if host:
                        try:
                            ip = ipaddress.ip_address(host)
                            ips.append(str(ip))
                        except ValueError as e:
                            if verbose > 0:
                                print(f"\n{bcolors.FAIL}[-] Invalid IP address extracted from '{part}': {e}. Skipping{bcolors.RESET}")
                    else:
                        if verbose>0:
                            print(f"\n{bcolors.FAIL}[-] Invalid IP address extracted from '{part}'. Skipping{bcolors.RESET}")
                else:
                    #IF not check port. Port only works if there is a scheme present. Can be real or not
                    test_parse = urlparse(f'bogus://{part}')

                if test_parse.port:
                    host = test_parse.hostname
                    print(host)
                    if host:
                        try:
                            ip = ipaddress.ip_address(host)
                            ips.append(str(entry))
                        except ValueError as e:
                            if verbose > 0:
                                print(
                                f"\n{bcolors.FAIL}[-] Invalid IP address extracted from '{part}': {e}. Skipping{bcolors.RESET}")
                    else:
                        if verbose > 0:
                            print(
                            f"\n{bcolors.FAIL}[-] Invalid IP address extracted from '{part}'. Skipping{bcolors.RESET}")

                else:
                    #If no port and no scheme directly check the IP
                    host = test_parse.hostname
                    path = test_parse.path
                    if host:
                        if "localhost" in host:
                            ips.append('127.0.0.1'+path)
                        else:
                            try:
                                ip = ipaddress.ip_address(host)
                                ips.append(str(ip))
                            except ValueError as e:
                                if verbose > 0:
                                    print(
                                    f"\n{bcolors.FAIL}[-] Invalid IP address extracted from Skipping'{part}': {e}.{bcolors.RESET}")
                    else:
                        if verbose > 0:
                            print(
                            f"\n{bcolors.FAIL}[-] Invalid IP address extracted from '{part}'. Skipping{bcolors.RESET}")
    if not ips:
        print(f"\n{bcolors.FAIL}[-] No valid IPs given. Aborting{bcolors.RESET}")
        exit(-1)
    return ips

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
    directory = Path(f'{context_manager.current_project}/scans/nmap/json')
    for file_path in directory.iterdir():
        if file_path.is_file() and re.compile(rf'{scantype}*').match(file_path.name):
            file_path.unlink()
    with open(f"{context_manager.current_project}/scans/nmap/json/{scantype}_aggregated.json", "w") as f:
        json.dump(result, f, indent=4)

    return result

def parse_nmap_full_discovery(json_data, output_path= None, overwrite=False):
    """
    Parses Nmap formatted JSON data (from a -sVC scan) and returns a cleaned dict.
    Also writes to a JSON file with simplified structure.

    If overwrite=False, merges new hosts into existing results.

    Output format:
    {
        "192.168.1.1": {
            "hostname": "host.local",
            "ports": [
                ...
            ]
        },
        ...
    }
    """
    if not output_path:
        output_path = f"{context_manager.current_project}/results/nmap_aggregated_scan.json"


    if not overwrite:
        if os.path.exists(output_path):
            with open(output_path, "r") as f:
                result = json.load(f)
        else:
            result = {}
    else:
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

        # Skip if host already exists and not overwriting
        if not overwrite and ip in result:
            if verbose >0:
                print(f"[+] Target {ip} skipped; ALready present on previous file")
            continue

        # Get hostname (PTR or otherwise)
        for hn in host.get("HostNames", {}).get("HostName", []):
            if hn.get("Name") != ip:
                hostname = hn.get("Name")
                break

        result[ip] = {
            "hostname": hostname,
            "ports": []
        }
        ports = host.get("Port", [])
        if ports:
            for port in ports:
                port_info = {
                    "port": port.get("PortID"),
                    "protocol": port.get("Protocol"),
                    "state": port.get("State", {}).get("State"),
                    "reason": port.get("State", {}).get("Reason"),
                    "service": {},
                    "scripts": []
                }

                service = port.get("Service", {})
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

                result[ip]["ports"].append(port_info)

    with open(output_path, "w") as f:
        json.dump(result, f, indent=4)

    # Cleanup temp scan files
    try:
        os.remove(f"{context_manager.current_project}/scans/nmap/json/host_discovery_aggregated.json")
        os.remove(f"{context_manager.current_project}/scans/nmap/json/stealth_discovery_aggregated.json")
    except FileNotFoundError:
        pass

    return result

def parse_webtechresults(listoftargets, output_path = None, overwrite:bool = False):
    """
    Parse the whateb scaner results in a new easier readable and processable file
    :param overwrite: wether to add to
    :param output_path: output path for the aggregated scan
    :param listoftargets:
    :return:
    """
    if not output_path:
        output_path = f"{context_manager.current_project}/results/nmap_aggregated_scan.json"

    if not overwrite:
        if os.path.exists(output_path):
            with open(output_path, "r") as f:
                results = json.load(f)
        else:
            results = {}
    else:
        results = {}
    for target in listoftargets:
        safestring = ""
        if "http" in target:
            safestring = "http:" + target[8:]
        elif "https" in target:
            safestring = "https:" + target[9:]
        else:
            safestring = target

        try:
            with open(f"{context_manager.current_project}/scans/webtech/whatweb_{safestring}.json", "r") as f:
                data = json.load(f)
        except FileExistsError:
            pass
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

            # Version info for server
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
    with open(f"{output_path}", "w") as f:
        json.dump(results, f, indent=4)

    return results

def target_web_sorter(targets):
    """
    Given a target list or project context target dict, determine which targets are web-enabled.

    If targets is a dict (project context):
        - Iterate through each target and check the 'ports' list.
        - If any port's service name contains 'http' or 'https', add IP:PORT to scannedlist.

    If targets is a list (IP addresses or hostnames):
        - Parse each entry with parse_web_port_or_scheme() to determine the web-enabled addresses.

    CIDR, single IPs, and IP lists:
        - Either already specify port/protocol (IP:PORT or PROTOCOL://IP)
        - Or will have http:// or https:// automatically prepended.
    """
    scannedlist = []

    if isinstance(targets, dict):
        # Context dict case
        for ip, data in targets.items():
            ports = data.get('ports', [])
            for port_info in ports:
                service = port_info.get("service", {})
                service_name = service.get("name", "").lower()
                if "http" in service_name or "https" in service_name:
                    port_number = service.get("port", port_info.get("port"))
                    scannedlist.append(f"{ip}:{port_number}")

    elif isinstance(targets, list):
        # Simple list of targets case
        for target in targets:
            scannedlist += parse_web_port_or_scheme(target)

    else:
        raise TypeError("targets must be either a dict or a list")

    return scannedlist


def parse_web_port_or_scheme(url) -> list:
    """
    Check if a target ip (url) has a scheme or port usable for web analysis. If not its not
    valid or assume that the target will correctly process an http or https petition
    :param url:
    :return:
    """
    parsecheck = urlparse(url)
    if parsecheck.scheme:
        if parsecheck.scheme == "http" or parsecheck.scheme == "https":
            return [url]
        else:
            #if any other scheme was present, not suitable for web analysis
            return []
    else:
        burl = "bogus://" + url
        burlparse=urlparse(burl)
        if burlparse.port:
            return [url]
        else:
            #If no scheme and no port, default to check both normal and secure default http ports
            return ["http://" + url, "https://" + url]

def filter_alive_targets(alive_list, subargs):
    """
    Filters subargs based on alive_list.

    alive_list : list
        List of currently alive targets.
    subargs : dict | list
        - If dict (from JSON): remove any keys not present in alive_list.
        - If list (from context or parsed input): return as is.
    """
    if isinstance(subargs, dict):
        # Keep only keys that are in alive_list
        return {k: v for k, v in subargs.items() if k in alive_list}

    elif isinstance(subargs, list):
        # Already a filtered list — return immediately
        return subargs

    else:
        raise TypeError("subargs must be either a dict or a list-YOU SHOULDN'T BE SEEING HERE")


def parse_web_targets(alivetargets, inputtargets):
    '''
    Get a list of web enabled targets with valid ports scehemes or URLs
    :param alivetargets: targets scanned and responding (list)
    :param inputtargets: nmap context dict or target list
    :return:
    '''
    filteredtargets = filter_alive_targets(list(alivetargets.keys()), inputtargets)
    # Then probably get alivetargets,finaldata and parsedtargets into a common parse method to not clog everything in various methods
    parsedtargets = target_web_sorter(filteredtargets)  # Parse web identified targets
    print(f"[+] Web enabled targets: {len(parsedtargets)}\n")
    return parsedtargets

def parse_wapiti(targets, output_path=None):
    """
    Parse Wapiti scan results for a given list of targets.
    Each target's file should exist as wapiti_{safe_target}.json in output_path.
    Returns: [{target, vulnerabilities}, ...]
    """
    results = []

    if not output_path:
        output_path = Path(context_manager.current_project) / "scans" / "webtech"
    else:
        output_path = Path(output_path)

    for target in targets:
        # Ensure consistent filename
        target_url = target if target.startswith("http") else "http://" + target
        safestring = target_url.replace("://", "_").replace("/", "_")
        file_path = output_path / f"wapiti_{safestring}.json"

        if not file_path.exists():
            print(f"[!] Wapiti file not found for target {target}")
            continue
        if file_path.stat().st_size == 0:
            print(f"[!] Skipping empty Wapiti file: {file_path}")
            continue

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                json_data = json.load(f)

            if not isinstance(json_data, dict):
                print(f"[!] Unexpected JSON format in {file_path}")
                continue

            results.append({
                "target": json_data.get("target", target),
                "vulnerabilities": json_data.get("vulnerabilities", [])
            })

        except json.JSONDecodeError as e:
            print(f"[!] Invalid JSON in {file_path}: {e}")
        except Exception as e:
            print(f"[!] Error reading {file_path}: {e}")

    return results


def parse_nikto(targets, output_path=None):
    """
    Parse Nikto JSON results for a list of targets.

    :param targets: List of target IPs/hosts.
    :param output_path: Optional path to scans/webtech directory.
    :return: List of dicts in the aggregated format.
    """
    if not output_path:
        output_path = f"{context_manager.current_project}/scans/webtech/"
    output_path = Path(output_path)

    aggregated = []

    for target in targets:
        target_entry = {"target": target, "ports": {}}

        # Nikto files are usually saved per-port
        # Example filename: nikto_192.168.1.1_80.json
        for json_file in output_path.glob(f"nikto_{target}_*.json"):
            port = json_file.stem.split("_")[-1]  # get last part (e.g., 80)
            port_key = f"{target}:{port}"
            findings = []

            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                continue  # Skip invalid/missing files

            # Nikto JSON usually has a "vulnerabilities" or "items" list
            for item in data.get("vulnerabilities", data.get("items", [])):
                findings.append({
                    "message": item.get("msg", item.get("description", "")),
                    "uri": item.get("uri") or None,
                    "references": (
                        item.get("references", [])
                        if isinstance(item.get("references"), list)
                        else [item["references"]] if item.get("references") else []
                    )
                })

            # Only add if we have findings
            if findings:
                target_entry["ports"][port_key] = findings

        # Only append target if it has any ports with findings
        if target_entry["ports"]:
            aggregated.append(target_entry)

    return aggregated

def normalize_host(target_str):
    """Extract host from target (host:port or URL)."""
    if target_str.startswith("http"):
        parsed = urlparse(target_str)
        return parsed.hostname or target_str
    return target_str.split(":")[0]


def aggregate_webvulns(output_path, parsedtargets):
    """
    Aggreagate and summarize the results of wapiti and nikto under one file
    :param output_path:
    :param parsedtargets:
    :return:
    """
    aggregated = {}

    if not output_path:
        output_path = Path(context_manager.current_project) / "results" / "webvulns_aggregated.json"
    else:
        output_path = Path(output_path)

    for target in parsedtargets:
        print(target)
        target_url = target if target.startswith("http") else "http://" + target
        safestring = target_url.replace("://", "_").replace("/", "_")

        wapiti_file = Path(context_manager.current_project) / "scans" / "webtech" / f"wapiti_{safestring}.json"
        nikto_file = Path(context_manager.current_project) / "scans" / "webtech" / f"nikto_{safestring}.json"

        findings = []

        # --- Wapiti ---
        try:
            with open(wapiti_file, "r", encoding="utf-8") as f:
                wapiti_data = json.load(f)

            if isinstance(wapiti_data, dict):
                # Skip non-vuln keys
                for key, items in wapiti_data.items():
                    if key.lower() in ["infos", "host", "ip", "port", "banner", "target", "date", "version", "scope"]:
                        continue
                    if isinstance(items, list):
                        for vuln in items:
                            if isinstance(vuln, dict):
                                findings.append({k: v for k, v in vuln.items() if v})
                            else:
                                findings.append({"name": vuln})
        except (FileNotFoundError, json.JSONDecodeError):
            pass

        # --- Nikto ---
        try:
            with open(nikto_file, "r", encoding="utf-8") as f:
                nikto_data = json.load(f)

            if isinstance(nikto_data, dict) and "vulnerabilities" in nikto_data:
                for vuln in nikto_data["vulnerabilities"]:
                    if isinstance(vuln, dict):
                        findings.append({k: v for k, v in vuln.items() if v})
                    else:
                        findings.append({"name": vuln})
            elif isinstance(nikto_data, list):
                for vuln in nikto_data:
                    if isinstance(vuln, dict):
                        findings.append({k: v for k, v in vuln.items() if v})
                    else:
                        findings.append({"name": vuln})
        except (FileNotFoundError, json.JSONDecodeError):
            pass

        # Deduplicate
        unique_findings = []
        seen = set()
        for vuln in findings:
            sig = (vuln.get("name") or vuln.get("msg") or str(vuln), vuln.get("url"), vuln.get("method"))
            if sig not in seen:
                seen.add(sig)
                unique_findings.append(vuln)

        if unique_findings:
            aggregated[target] = unique_findings

    output_data = [{"target": tgt, "vulnerabilities": vulns} for tgt, vulns in aggregated.items()]

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)

    print(f"[+] Aggregated web vulnerabilities written to {output_path}")

def parse_fuzzer(output_path, parsedtargets):
    aggregated = {}

    if not output_path:
        output_path = Path(context_manager.current_project) / "results" / "fuzzing_aggregated.json"
    else:
        output_path = Path(output_path)

    for target in parsedtargets:
        print(f"Processing target: {target}")
        target_url = target if target.startswith("http") else "http://" + target
        safestring = target_url.replace("://", "_").replace("/", "_")

        fuzzfile = Path(context_manager.current_project) / "scans" / "fuzz" / f"fuzzing_{safestring}.txt"

        # Initialize findings for this target
        findings = {}

        # Attempt to read the fuzzing results
        try:
            with open(fuzzfile, "r", encoding="utf-8") as f:
                fuzz_data = json.load(f)

                # Extract relevant information
                commandline = fuzz_data.get("commandline", "N/A")
                time = fuzz_data.get("time", "N/A")
                output_file = fuzz_data["config"].get("outputfile", "N/A")
                url = fuzz_data["config"].get("url", "N/A")
                wordlist = fuzz_data["config"]["inputproviders"][0].get("value", "N/A")
                recursion_depth = fuzz_data["config"].get("recursion_depth", "N/A")
                results_count = len(fuzz_data.get("results", []))

                # Aggregate findings
                findings = {
                    "Command Line": commandline,
                    "Time": time,
                    "Output File": output_file,
                    "Target URL": url,
                    "Wordlist Used": wordlist,
                    "Recursion Depth": recursion_depth,
                    "Results Count": results_count
                }

                # Store findings in the aggregated dictionary
                aggregated[target_url] = findings

        except (FileNotFoundError, json.JSONDecodeError):
            print(f"Error reading file: {fuzzfile}. Skipping this target.")

    # Write the aggregated results to the output file
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(aggregated, f, indent=2)

    print(f"[+] Aggregated fuzzing data written to {output_path}")