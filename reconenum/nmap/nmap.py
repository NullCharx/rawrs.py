import asyncio
import datetime
import json
import os
import subprocess
from types import NoneType

from core import context_manager
from core.config import bcolors
from core.context_manager import setTargets
from reconenum.nmap.parser import parse_host_discovery, parse_full_discovery


def run_nmap_scan(nmap_args: list, output_prefix="scan"):
    # Generate timestamp for unique file naming
    scandate = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

    # Define the XML output path
    xml_path = f"{context_manager.current_project}/scans/raw/xml/{output_prefix}-{scandate}.xml"
    gopath = subprocess.run(["go", "env", "GOPATH"], capture_output=True, text=True).stdout.strip()

    # Run nmap and save the output to the XML file
    try:
        print(f"[+] Running Nmap: {' '.join(['nmap'] + nmap_args + ['-oX', xml_path])}{bcolors.GRAY}")
        subprocess.run(["nmap"] + nmap_args + ["-oX", xml_path], capture_output=False, check=True)
        target= ''.join(nmap_args[1:]).replace("/","-",1)
        # Define JSON output path
        json_output_path =  f"./scans/raw/json/{output_prefix}_{target}.json"
        try:
            os.remove(json_output_path)
        except OSError:
            pass
        # Run nmap-formatter to convert XML to JSON
        result = subprocess.run(
            [f"{gopath}/bin/nmap-formatter", "json", xml_path, "-f", json_output_path],
            capture_output=False,
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
        # Optional: Clean up the temporary XML file if you don't need it anymore
        if os.path.exists(xml_path) and not output_prefix == "full_scan":
            os.remove(xml_path)



#Make host run both sylent and unsilent scans and aggregate them
def full_discovery(ip_range : list, isOverwrite : bool, config):

    print(f"{bcolors.OKCYAN}[+] Starting full discovery on {ip_range}...")

    # STEP 1 – Basic Host Discovery (ping scan)
    args = ["-sn"]
    args += ip_range
    host_discovery_results = run_nmap_scan(args, "host_discovery")
    if host_discovery_results.get("Host", []):
        host_discovery_results = parse_host_discovery(host_discovery_results, "host_discovery")
        print(f"{bcolors.OKCYAN}[+] Ping scan found {len(host_discovery_results)} hosts up.")
        print(f"{bcolors.RESET}---------------------------------{bcolors.OKCYAN}")

    # STEP 2 – Additional discovery for stealthy or filtered hosts
    args[0] = f"-sS"
    stealth_discovery_result = run_nmap_scan(args, "stealth_discovery")
    if stealth_discovery_result.get("Host", []):
        stealth_discovery_result = parse_host_discovery(stealth_discovery_result, "stealth_discovery")
        print(f"{bcolors.OKCYAN}[+] Stealth scan found {len(stealth_discovery_result)} hosts up.\n")
        print(f"{bcolors.RESET}---------------------------------{bcolors.OKCYAN}\n")
    elif not host_discovery_results.get("Host", []) and not stealth_discovery_result.get("Host", []):
        print(f"{bcolors.FAIL}[-] No hosts appear to be up in the specified range. Are you sure you provided correct IPs. . .? Exiting\n")
        print(f"---------------------------------{bcolors.RESET}\n")
        exit(3)

    # STEP 3 – Join results of normal and stealth scan
    all_up_hosts = host_discovery_results.copy()
    for k, v in stealth_discovery_result.items():
        if k not in all_up_hosts:
            all_up_hosts[k] = v
    setTargets(list(all_up_hosts.keys()), isOverwrite)
    print(f"[+] Total unique hosts discovered: {len(all_up_hosts)}\n")

    # STEP 4 – Port scan with service detection (-sVC)

    targets = list(all_up_hosts.keys())
    args = ["-sVC","-Pn"]
    args += targets
    full_scan = run_nmap_scan(args, "full_scan")
    full_scan = parse_full_discovery(full_scan)

    print(f"\n{bcolors.RESET}[✔] Full discovery completed.{bcolors.RESET}\n\n")