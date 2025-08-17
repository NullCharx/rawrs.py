from core import context_manager
from core.config import bcolors
from core.context_manager import saveTargetContext, setTargets
from reconenum.parser import parse_nmap_full_discovery, parse_nmap_host_discovery

from urllib.parse import urlparse
import datetime
import subprocess
import json
import os

def run_nmap_scan(nmap_args: list, verbose: int, output_prefix="scan"):
    # Generate timestamp for unique file naming
    scandate = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

    # Define the XML output path
    xml_path = f"{context_manager.current_project}/scans/nmap/xml/{output_prefix}-{scandate}.xml"

    # Get Go path for nmap-formatter
    gopath = subprocess.run(
        ["go", "env", "GOPATH"],
        capture_output=True,
        text=True
    ).stdout.strip()

    nmaptargetlist = []

    # --- Handle all possible input types (str list, dict)---
    for element in nmap_args:
        if isinstance(element, dict):
            # Parsed nmap JSON - keys are IPs
            nmaptargetlist.extend(element.keys())
            continue

        if isinstance(element, list):
            for target in element:
                parsed = urlparse(target)
                if not parsed.scheme:
                    parsed = urlparse("bogus://" + target)
                if parsed.port:
                    nmaptargetlist.append(parsed.hostname)
                    if verbose > 1:
                        print(parsed.hostname)
                else:
                    nmaptargetlist.append(target)
                    if verbose > 1:
                        print(target)
            continue

        # Fallback — just convert to string and add
        nmaptargetlist.append(str(element))

    # --- Run nmap ---
    try:
        # Remove the first element if it's an option like "-sn"
        if nmaptargetlist and nmaptargetlist[0].startswith('-'):
            nmaptargetlist = nmaptargetlist[1:]

        if verbose > 0:
            print(f"[+] Running Nmap: {' '.join(['nmap'] + nmaptargetlist + ['-oX', xml_path])}{bcolors.GRAY}")

        subprocess.run(
            ["nmap"] + nmaptargetlist + ["-oX", xml_path],
            capture_output=False if verbose > 1 else True,
            check=True
        )

        # JSON output path
        target = ''.join(nmaptargetlist).replace("/", "-", 1)
        json_output_path = f"{context_manager.current_project}/scans/nmap/json/{output_prefix}_{target}.json"

        # Remove old JSON if exists
        try:
            os.remove(json_output_path)
        except OSError:
            pass

        # Run nmap-formatter to convert XML to JSON
        subprocess.run(
            [f"{gopath}/bin/nmap-formatter", "json", xml_path, "-f", json_output_path],
            capture_output=False if verbose > 1 else True,
            text=True,
            check=True
        )

        # Load JSON data
        with open(json_output_path, 'r') as file:
            json_data = json.load(file)

        return json_data

    except subprocess.CalledProcessError as e:
        print(f"{bcolors.FAIL}[!] Error during scan or formatting: {e.stderr}{bcolors.RESET}")
        return None

    finally:
        # Cleanup XML unless it's a full scan
        if os.path.exists(xml_path) and output_prefix != "full_scan":
            os.remove(xml_path)



def full_discovery(ip_range : list, verbose : int, is_overwrite : bool):


    print(f"{bcolors.OKCYAN}[+] Starting full discovery on {ip_range}...")

    # STEP 0 – check the targets for alive hosts
    all_up_hosts = parsealivehosts(ip_range, is_overwrite, verbose)

    # STEP 4 – Port scan with service detection (-sVC)
    targets = list(all_up_hosts.keys())
    print(f"{bcolors.OKCYAN}[+] Performing service detection on discovered hosts: {targets}\n...")
    args = ["-sVC","-Pn"]
    args.append(targets)
    full_scan = run_nmap_scan(args, verbose,"full_scan")
    aggregated_scan = parse_nmap_full_discovery(json_data=full_scan, overwrite=is_overwrite)

    #Sort services on the in-memory context so its quickly accessed instead of reading the scan files
    extract_service_data(aggregated_scan)

    if is_overwrite and verbose > 1:
        print(f"\n{bcolors.OKCYAN}[✔] Merging with saved targets.{bcolors.RESET}\n\n")
    print(f"\n{bcolors.OKGREEN}[✔] Full discovery completed.{bcolors.RESET}\n\n")


def extract_service_data(aggregated_scan):
    """
    Extracts relevant service data from the full aggregated scan and writes it to the context file for
    easier access
    :param:aggregated_scan: the output of the parse_nmap_full_discovery to be saved to context
    :return:
    """
    global current_project
    # Load context with plain IPs
    with open(f"{context_manager.current_project}/context.json", "r") as f:
        context = json.load(f)
    targets = context.get("targets", [])

    http_services = {}
    for ip in targets:

        services = []
        try:
            ports = aggregated_scan[ip].get("ports", [])
        except KeyError as e:
            continue
        if ports:
            for port in ports:
                service_name = port.get("service", {}).get("name", "")
                services.append({
                    "port": port.get("port",-1),
                    "service": service_name,
                    })

        if services:
            http_services[ip] = services
        else:
            http_services[ip] = []
        saveTargetContext(http_services)


def parsealivehosts(ip_range, is_overwrite, verbose):
    """
    For a given CIDR or comma separate IP list, returns only the IP targets that
    responded UP to either a normal or stealth scan
    :param:ip_range: the CIDR or comma separate IP list
    :param:is_overwrite: if the targets are added to or overwrite any existing project targets
    :param:verbose: verbosity
    """
    # STEP 1 – Basic Host Discovery (ping scan)
    print(f"{bcolors.OKCYAN}[+] Discovering hosts...")
    args = ["-sn"]
    args.append(ip_range)
    host_discovery_results = run_nmap_scan(args, verbose, "host_discovery")
    if host_discovery_results.get("Host", []):
        host_discovery_results = parse_nmap_host_discovery(host_discovery_results, "host_discovery")
        if verbose > 0:
            print(f"{bcolors.OKCYAN}[+] Ping scan found {len(host_discovery_results)} hosts up.")
            print(f"{bcolors.RESET}---------------------------------{bcolors.OKCYAN}")
    # STEP 2 – Additional discovery for stealthy or filtered hosts
    args[0] = f"-sS"
    print(f"{bcolors.OKCYAN}[+] Discovering quiet hosts (stealth)...")
    stealth_discovery_result = run_nmap_scan(args, verbose, "stealth_discovery")
    if stealth_discovery_result.get("Host", []):
        stealth_discovery_result = parse_nmap_host_discovery(stealth_discovery_result, "stealth_discovery")
        if verbose > 0:
            print(f"{bcolors.OKCYAN}[+] Stealth scan found {len(stealth_discovery_result)} hosts up.\n")
            print(f"{bcolors.RESET}---------------------------------{bcolors.OKCYAN}\n")
    elif not host_discovery_results.get("Host", []) and not stealth_discovery_result.get("Host", []):
        print(
            f"{bcolors.FAIL}[-] No hosts appear to be up in the specified range. Are you sure you provided correct IPs. . .? Exiting\n")
        print(f"---------------------------------{bcolors.RESET}\n")
        exit(3)
    # STEP 3 – Join results of normal and stealth scan
    all_up_hosts = host_discovery_results.copy()
    for k, v in stealth_discovery_result.items():
        if k not in all_up_hosts:
            all_up_hosts[k] = v
    setTargets(all_up_hosts, is_overwrite)
    print(f"[+] Total unique hosts discovered: {len(all_up_hosts)}")
    if (len(all_up_hosts) == 0):
        print(f"{bcolors.FAIL}[-] No hosts appear to be up in the specified range. Are you sure you provided correct IPs. . .? Exiting\n")
        print(f"---------------------------------{bcolors.RESET}\n")
        exit(3)
    return all_up_hosts
