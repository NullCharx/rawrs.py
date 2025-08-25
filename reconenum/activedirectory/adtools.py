import json
import subprocess
from pathlib import Path
from platform import machine

from core import context_manager
from core.config import bcolors
from reconenum.nmap.nmaptools import run_nmap_scan
from reconenum.smb.smbtools import run_smb_full_enum


def run_kerbrute_user_enum(domain, userlist_path, dc_ip, output_dir=None):
    """
    Uses Kerbrute to enumerate valid users in a domain.
    """
    output_dir = Path(output_dir or context_manager.current_project) / "scans" / "kerbrute"
    output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / f"kerbrute_{domain}.txt"
    cmd = [
        "kerbrute",
        "userenum",
        "--dc", dc_ip,
        "--domain", domain,
        "--users", str(userlist_path),
        "--outputfile", str(output_file)
    ]

    print(f"[i] Running Kerbrute to enumerate users in {domain} against {dc_ip}...")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"[+] Kerbrute finished. Results saved to {output_file}")
    else:
        print(f"[!] Kerbrute failed: {result.stderr}")

    # Optional: parse results into a dict
    users = []
    if output_file.exists():
        with open(output_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    users.append(line)
    return {"task": "kerbrute_enum", "domain": domain, "dc": dc_ip, "users_found": users}


def run_asrep_roast(dc_ip, domain, userlist_path, output_dir=None):
    """
    Checks for AS-REP roastable accounts
    Saves extracted AS-REP hashes to a file.
    """
    output_dir = Path(output_dir) or Path(context_manager.current_project)  / "scans" / "asrep"
    output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / f"asrep_{domain}.txt"
    cmd = [
        "GetNPUsers.py",  # from Impacket
        f"{domain}/",     # the domain
        "-dc-ip", dc_ip,
        "-usersfile", str(userlist_path),
        "-format", "hashcat",
        "-outputfile", str(output_file)
    ]

    print(f"[i] Checking for AS-REP roastable accounts in {domain} against {dc_ip}...")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"[+] AS-REP check finished. Hashes saved to {output_file}")
    else:
        print(f"[!] AS-REP check failed: {result.stderr}")

    # Optional: parse results into a dict
    hashes = []
    if output_file.exists():
        with open(output_file) as f:
            for line in f:
                line = line.strip()
                if line and "$krb5asrep$" in line:
                    hashes.append(line)
    return {"task": "asrep_roast", "domain": domain, "dc": dc_ip, "hashes_found": hashes}

def adtips(args):

    print(f"{bcolors.WARNING}[i] There is a difference between attacking an AD using the IP or the FQDN"
          f"\n usually using the FQDN the auth will default to Kerberos first, while the IP will default to NTLM instead.{bcolors.RESET}\n")
    print(f"{bcolors.WARNING}[i] Remember that the visible Windows machine is NOT the target! The AD is on the internal network"
          f"targetable after compromising that visible AD joing machine! {bcolors.RESET}\n")
    print(f"{bcolors.WARNING}[i] Most actions reiquire an autehnticated account. Kerbrute can be used to bruteforce"
          f"valid users.{bcolors.RESET}\n")
    print(f"{bcolors.WARNING}[i] There might be times where you don't need to crack a hash to use it in a ticket. This is "
          f"known as pass-the-hash{bcolors.RESET}\n")

def get_fqdn(dc_ip, domain=None, username=None, password=None, verbose=0):
    """
    Attempt to resolve the FQDN of a target AD domain controller.
    Tries multiple techniques and compares results.
    Only returns a list if mismatches are found.
    """
    import subprocess
    import re
    import dns.resolver

    fqdn_results = []
    print(f"{bcolors.WARNING}[i] There is a difference between attacking an AD using the IP or the FQDN"
          f"\n usually using the FQDN the auth will default to Kerberos first, while the IP will default to NTLM instead.{bcolors.RESET}\n")

    print(f"{bcolors.WARNING}[i] There are various methods to extract a fqdn:.{bcolors.RESET}\n")
    # Helper to append if value exists
    def try_append(value, method_name):
        if value:
            fqdn_results.append((method_name, value))
            if verbose: print(f"[{method_name}] FQDN found: {value}")

    # 1. CrackMapExec
    try:
        print(f"{bcolors.WARNING}[i]Netexec (formerly known as CME) can return the FQDN in the shape of (name:machinename) (domain:domain.name), the FQDN being: macinename.domain.name{bcolors.OKCYAN}")
        print(f"\n{bcolors.WARNING}[i]If it fails, credentials might be needed, although this is usually not necessary on a domain-joint machine{bcolors.OKCYAN}")

        print(f"\n{bcolors.FAIL}[!]Parsing of netexec not implemented. Printing nmap output on screen instead.{bcolors.RESET}")
        cmd = ["netexec", "smb", dc_ip]
        print(f"\n{bcolors.OKGREEN}[i]Running f{''.join(cmd)}{bcolors.OKCYAN}")
        proc = subprocess.run(cmd, capture_output=False, text=True)

    except Exception:
        pass

    # 1. Enum4linux

    try:

        # Check for existing enum4linux-ng JSON
        json_file = Path(context_manager.current_project) / "scans" / "smb" / f"enum4linux_{dc_ip}.json"
        fqdn_from_file = None
        print(f"{bcolors.WARNING}[i] Enum4linux is another great tool to enumerate samba, including FQDN and machine name when applicable.{bcolors.OKCYAN}")
        print(f"{bcolors.WARNING}[i] If  you ran enum4linux before the result file will be checked immediately{bcolors.OKCYAN}")

        if json_file.exists():
            with open(json_file, "r") as f:
                data = json.load(f)
                # Attempt to get FQDN under smb_domain_info -> FQDN
                fqdn_from_file = data.get("smb_domain_info", {}).get("FQDN")
                machine_name_from_file = data.get("smb_domain_info", {}).get("NetBIOS computer name")
            if fqdn_from_file:
                try_append(f"{machine_name_from_file}.{fqdn_from_file}", "Enum4LinuxJSON")
            print(f"{bcolors.FAIL}[*]FQDN From JSON. Skipping command\n.{bcolors.RESET}")

        # Only run CME if JSON didn't provide FQDN
        if not fqdn_from_file:
            run_smb_full_enum(dc_ip,verbose)
            with open(json_file, "r") as f:
                data = json.load(f)
                # Attempt to get FQDN under smb_domain_info -> FQDN
                fqdn_from_file = data.get("smb_domain_info", {}).get("FQDN")
                machine_name_from_file = data.get("smb_domain_info", {}).get("NetBIOS computer name")
            if fqdn_from_file:
                try_append(f"{machine_name_from_file}.{fqdn_from_file}", "Enum4LinuxJSON")
    except Exception:
        pass

    # 2. Nmap ldap-rootdse
    try:
        print(f"{bcolors.WARNING}[i] Nmap has a script that can extract the FQDN via LDAP, if its available in the DC{bcolors.OKCYAN}")

        print(f"{bcolors.FAIL}[!]Parsing of ladp-rootsde not implemented. Printing nmap output on screen instead.{bcolors.RESET}")
        run_nmap_scan(dc_ip,["-Pn", "-p", "389",  "--script=ldap-rootdse"],verbose+3,"ad_fqdn")
        #TODO future version: Check what the script returns and parse it
    except Exception:
        pass

    # 3. OpenSSL certificate
    try:
        print(f"{bcolors.WARNING}[i] When a SSL certificate is signed correctly, it might have the FQDN embedded {bcolors.OKCYAN}")

        print(f"{bcolors.FAIL}[!]Parsing of ssl certificate not implemented. Printing nmap output on screen instead.{bcolors.RESET}")
        cmd = ["openssl", "s_client", "-connect", f"{dc_ip}:636", "-showcerts"]
        proc = subprocess.run(cmd, capture_output=True, text=False, input="\n")
        #TODO future version: Check what the cmd returns and parse it

    except Exception:
        pass

    # 4. nslookup / PTR
    try:
        print(f"{bcolors.WARNING}[i] If the Domain Controller also acts as DNS server, querying the Domain Controller IP will return its FQDN {bcolors.OKCYAN}")

        print(f"{bcolors.FAIL}[!]Parsing of nslookup not implemented. Printing nmap output on screen instead.{bcolors.RESET}")
        cmd = ["nslookup", dc_ip]
        proc = subprocess.run(cmd, capture_output=False, text=True)
        #TODO future version: Check what the cmd returns and parse it

    except Exception:
        pass

    # 5. NetBIOS / WINS
    try:
        print(f"{bcolors.WARNING}[i] NetBIOS machine and domain name usually match the FQDN of a machine for domain-joint machines{bcolors.OKCYAN}")

        print(f"{bcolors.FAIL}[!]Parsing of ladp-rootsde not implemented. Printing nmap output on screen instead.{bcolors.RESET}")
        cmd = ["nmblookup", "-A", dc_ip]
        proc = subprocess.run(cmd, capture_output=False, text=True)
        #TODO future version: Check what the cmd returns and parse it

    except Exception:
        pass

    # Check for consistency
    unique_fqdns = set(f[1] for f in fqdn_results)
    if len(unique_fqdns) > 1:
        print("\n[!] FQDN mismatch detected:")
        for method, fqdn in fqdn_results:
            print(f"  {method}: {fqdn}")
        return list(unique_fqdns)
    else:
        print(f"[+] FQDN consistent across methods: {unique_fqdns.pop()}")
        return []
