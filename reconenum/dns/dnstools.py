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

        print(f"[+] Scanning {target} with dnsrecon via {nameserver} nameserver...\n")
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



def enumerate_subdomains(domain, subdomain_list):
    found_subdomains = []
    for subdomain in subdomain_list:
        full_domain = f"{subdomain}.{domain}"
        try:
            dns.resolver.resolve(full_domain, 'A')
            found_subdomains.append(full_domain)
        except Exception:
            continue
    return found_subdomains



def query_dns_records(domain, record_type):
    try:
        records = dns.resolver.resolve(domain, record_type)
        return [str(record) for record in records]
    except Exception as e:
        return str(e)



def reverse_dns_lookup(ip_address):
    try:
        reverse_name = dns.reversename.from_address(ip_address)
        domain_name = dns.resolver.resolve(reverse_name, 'PTR')
        return [str(name) for name in domain_name]
    except Exception as e:
        return str(e)



def get_soa_record(domain):
    try:
        soa_record = dns.resolver.resolve(domain, 'SOA')
        return [str(record) for record in soa_record]
    except Exception as e:
        return str(e)


def enumerate_subdomains(domain, subdomain_list):
    found_subdomains = []
    for subdomain in subdomain_list:
        full_domain = f"{subdomain}.{domain}"
        try:
            dns.resolver.resolve(full_domain, 'A')
            found_subdomains.append(full_domain)
        except Exception:
            continue
    return found_subdomains
