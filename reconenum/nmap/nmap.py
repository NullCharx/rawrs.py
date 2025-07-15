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

        # Define JSON output path
        json_output_path = f"./scans/{output_prefix}_{scandate}.json"

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


async def run_nmap_async(target):
    proc = await asyncio.create_subprocess_exec(
        "", "-sn", target, f"-oX ./{target}scan",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    #Run  nmap-formatter json ./{target}scan
    #then mv to
    stdout, stderr = await proc.communicate()
    return stdout.decode(), stderr.decode()

#Make host run both sylent and unsilent scans and aggregate them
def host_discovery(ip_range): return run_nmap_scan(["-sn"] + ip_range,"host_discovery")
def port_discovery(ip): return run_nmap_scan(["-sS", "-Pn", "-p-"] + ip, "port discovery")
def service_discovery(ip): return run_nmap_scan(["-sVC"] + ip, "service_discovery")