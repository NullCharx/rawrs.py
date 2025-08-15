import subprocess
from pathlib import Path

import dns.resolver

import dns.resolver
import dns.query

from core import context_manager


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

        print(f"[+] Scanning {target} with dnsrecon...")
        try:
            subprocess.run(cmd, check=True)
            print(f"[+] Finished scanning {target}")
        except subprocess.CalledProcessError as e:
            print(f"[!] Error scanning {target}: {e}")

def is_dns_server(address):
    try:
        # Attempt to resolve a known domain using the provided address
        dns.query.udp(dns.message.make_query('google.com', dns.rdatatype.A), address)
        return True
    except Exception:
        return False

def check_zone_transfer(targets, nameserver=None, isdnsservertarget = False):
    """
    Checks the ns of a target domain for zone transfer.
    NOTE: I intended to make an option to directly check a dnsserver for zone transfer, but it is not implemented yet
    SINCE i dont know how a successful zone transfer looks like and i can't possibly test in a controlled environment.
    :param targets: List of target domains or IPs.
    :return: None
    """
    output_dir = Path(context_manager.current_project) / "results" / "dns_zone_transfer_results.json"
    output_dir.mkdir(parents=True, exist_ok=True)

    nameserverarg = ["-n", nameserver] if nameserver else ["-n", "8.8.8.8"]

    for target in targets:
        safestring = target.replace("://", "_").replace("/", "_")
        output_path = output_dir / f"dnsstdquery_{safestring}.json"
        cmd = ["dnsrecon", "-t", "std", "-d", target, "-j", str(output_path)] + nameserverarg

        print(f"[+] Scanning {target} with dnsrecon via {nameserver} nameserver...\n")
        try:
            subprocess.run(cmd, check=True)
            print(f"[+] Finished scanning {target}")
        except subprocess.CalledProcessError as e:
            print(f"[!] Error scanning {target}: {e}"