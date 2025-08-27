import json
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import dns.resolver

import dns.resolver
import dns.query

from rawrs.core import context_manager
from rawrs.core.globaldata import bcolors
from rawrs.reconenum.parser import parse_dig_command


def standard_ip_query(targets, nameserver=None):
    """
    Perform a standard DNS query for the given domain and record type.
    :param targets: List of target domains or IPs.
    :param nameserver: Optional DNS server to use.
    :return: None
    """
    output_dir = Path(context_manager.current_project) / "scans" / "dns"
    output_dir.mkdir(parents=True, exist_ok=True)

    nameserverarg = ["-n", nameserver] if nameserver else ["-n", "8.8.8.8"]

    for target in targets:
        safestring = target.replace("://", "_").replace("/", "_")
        output_path = output_dir / f"dnsstdquery_{safestring}.json"
        cmd = ["dnsrecon", "-t", "std", "-d", target, "-j", str(output_path)] + nameserverarg

        print(f"{bcolors.WARNING}[i] Running dnsrecon: {' '.join(cmd)}{bcolors.OKCYAN}")
        try:
            subprocess.run(cmd, check=True)
            print(f"[+] Finished scanning {target}")
        except subprocess.CalledProcessError as e:
            print(f"[!] Error scanning {target}: {e}")

def is_dns_server(address):
    try:
        # Attempt to resolve a known domain using the provided address
        print(f"{bcolors.WARNING}[i] This script checks, making an standard resolve query, if the ip given is a domain name Server.")

        dns.query.udp(dns.message.make_query('google.com', dns.rdatatype.A), address)
        return True
    except Exception:
        return False

def check_zone_transfer(targets, nameserver=None):
    """
    Checks the ns of a target domain for zone transfer.
    NOTE: I intended to make an option to directly check a dnsserver for zone transfer, but it is not implemented yet
    SINCE i dont know how a successful zone transfer looks like and i can't possibly test in a controlled environment.
    :param targets: List of target domains or IPs.
    :return: None
    """
    output_dir = Path(context_manager.current_project) / "results"
    dnszonetransferdata = {}

    nameserverarg = ["-n", nameserver] if nameserver else ["-n", "8.8.8.8"]
    print(targets)
    for target in targets:
        parsedurl = urlparse(target)
        if parsedurl.hostname:
            target = parsedurl.hostname
        safestring = target.replace("://", "_").replace("/", "_")
        output_path = output_dir / f"dns_ztransfer{safestring}.json"
        cmd = ["dig", "@" + nameserver, target,"axfr"]

        print(f"[+] Scanning {target} with dnsrecon via {nameserver} nameserver...\n")
        print(f"{bcolors.WARNING}[i] Running dig: {' '.join(cmd)}{bcolors.OKCYAN}")

        try:
            result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE)
            print(f"[+] Finished scanning {target}")
        except subprocess.CalledProcessError as e:
            print(f"[!] Error scanning {target}: {e}")

        if result.returncode != 0:
            print(f"{bcolors.WARNING}[!] Cannot perform unauthed {target} under {nameserver}{bcolors.RESET}")
        else:
            dnszonetransferdata[str(target)] = {"nameserver": nameserver,
                                           "dump": parse_dig_command(result.stdout.decode("utf-8"))}

    with open(output_dir / "dns_zone_transfer_list.json", "w") as f:
        json.dump(dnszonetransferdata, f, indent=2)
