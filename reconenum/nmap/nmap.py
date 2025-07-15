import asyncio
import datetime
import json
import os
import subprocess
from core import context_manager


def run_nmap_scan(nmap_args: list, output_prefix="scan"):
    # Generate timestamp for unique file naming
    scandate = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

    # Define the XML output path
    xml_path = f"{context_manager.current_project}/scans/raw/{output_prefix}-{scandate}.xml"
    gopath = subprocess.run(["go", "env", "GOPATH"], capture_output=True, text=True).stdout.strip()

    # Run nmap and save the output to the XML file
    try:
        print(f"[+] Running Nmap: {' '.join(['nmap'] + nmap_args + ['-oX', xml_path])}")
        subprocess.run(["nmap"] + nmap_args + ["-oX", xml_path], capture_output=False, check=True)
        target= nmap_args[-1].replace("/","-",1)

        # Define JSON output path
        json_output_path = f"./scans/{output_prefix}_{target}.json"
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

        print(f"[+] Nmap scan successful. JSON output saved to: {json_output_path}")

        # Load JSON data
        with open(json_output_path, 'r') as file:
            json_data = json.load(file)

        return json_data

    except subprocess.CalledProcessError as e:
        print(f"[!] Error during scan or formatting: {e.stderr}")
        return None
    finally:
        # Optional: Clean up the temporary XML file if you don't need it anymore
        if os.path.exists(xml_path):
            os.remove(xml_path)



#Make host run both sylent and unsilent scans and aggregate them
def full_discovery(ip_range, config):

    # Firstly for all IPs (single list or CIDR) we:
    #Make a regular scan first, then get the relevant (host up) results
    #Make other scans, like syn scans, then get relevant results and compare to see if theres any host actively up but ignoring probes

    #Then, for all up Ips, we scan ports with servivce and vulnerability scans -sVC. For the gosts that ignore probes we must add the argument that does not ping before scanning.
    print(f"[+] Starting full discovery on {ip_range}...\n")

    # STEP 1 – Basic Host Discovery (ping scan)
    print("[*] Running basic host discovery (ping scan)...")
    ip_range.insert(0,f"-sn")
    basic_result = run_nmap_scan(ip_range, "host_discovery")
    del ip_range[0]
    print(ip_range)
    #Different parsers on outputparsers for diffo things
    for host in parse_nmap_output(basic_result):
        if host["status"] == "up":
            up_hosts_ping.add(host["ip"])

    print(f"[+] Ping scan found {len(up_hosts_ping)} hosts up.\n")

    # STEP 2 – Additional discovery with -Pn or -PS/PA for stealthy or filtered hosts
    print("[*] Running additional discovery scan (-Pn)...")
    stealth_args = f"-Pn -sn"
    stealth_result = run_nmap_scan(ip_range, stealth_args, "stealth_discovery")

    up_hosts_stealth = set()
    for host in parse_nmap_output(stealth_result):
        if host["status"] == "up":
            up_hosts_stealth.add(host["ip"])

    print(f"[+] Stealth scan found {len(up_hosts_stealth)} hosts up.\n")

    # STEP 3 – Union de resultados
    all_up_hosts = sorted(up_hosts_ping.union(up_hosts_stealth))
    print(f"[+] Total unique hosts discovered: {len(all_up_hosts)}\n")

    # STEP 4 – Port scan with service detection (-sVC)
    print("[*] Running service & vulnerability scan (-sVC)...")
    for ip in all_up_hosts:
        print(f"    ↳ Scanning {ip}...")
        # If host did NOT respond to ping, use -Pn
        if ip not in up_hosts_ping:
            svc_args = "-Pn -sVC"
        else:
            svc_args = "-sVC"

        run_nmap_scan(ip, svc_args, f"svc_scan_{ip.replace('/', '_')}")

    print("\n[✔] Full discovery completed.\n")