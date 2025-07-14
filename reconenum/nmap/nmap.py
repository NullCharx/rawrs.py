import asyncio
import datetime
import json
import os
import subprocess
import tempfile


def run_nmap_scan(nmap_args: list, output_prefix="scan"):
    # Create temp XML output file
    xml_output = tempfile.NamedTemporaryFile(suffix=".xml", delete=False)
    xml_path = xml_output.name
    gopath = subprocess.run(["go", "env", "GOPATH"], capture_output=True, text=True).stdout.strip()
    try:
        # 1. Run nmap with XML output
        print(nmap_args)
        print(f"[+] Running Nmap: {' '.join(nmap_args)}")
        subprocess.run(["nmap", "-oX", xml_path] + nmap_args, check=True)

        # 2. Use nmap-formatter to convert XML to JSON
        result = subprocess.run(
            [gopath + "/bin/nmap-formatter", "json", xml_path, f" > ./scans/{output_prefix}{datetime.datetime.now()}.json"],
            capture_output=True,
            text=True,
            check=True
        )
        print(xml_path)
        xml_output.close()

        json_data = json.loads(result.stdout)
        print(f"[+] Scan successful. Hosts found: {len(json_data.get('hosts', []))}")
        return json_data

    except subprocess.CalledProcessError as e:
        print(f"[!] Error during scan or formatting: {e.stderr}")
        return None
    finally:
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

def host_discovery(ip_range): return run_nmap_scan(["-sn"] + ip_range,"host_discovery")
def port_discovery(ip): return run_nmap_scan(["-sS", "-Pn", "-p-"] + ip)
def service_discovery(ip): return run_nmap_scan(["-sV", "-sC"] + ip)