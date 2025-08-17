import ipaddress

from core.config import bcolors
from core.context_manager import setcurrentenvproject, loadProjectContextOnMemory
from reconenum.dns.dnstools import standard_ip_query, check_zone_transfer
from reconenum.parser import parse_ip_inputs, filter_domains, dns_std_aggregator, parse_dns_list


def standard_dns_query(args):
    """
    Perform a standard DNS query for the given domain and record type.
    :param args: Argparse Namespace with at least: targets, nameserver (optional), auto, verbose, project.
    """
    setcurrentenvproject(args)
    loadProjectContextOnMemory()

    if args.verbose > 2:
        print(args)
        print(f"[recon:dns std] project={args.project} verbose={args.verbose}")

    # Get target domains from targets
    parsedtargetips = parse_ip_inputs(args.targets, args.auto, args.verbose, True, True)

    if not args.nameserver:
        dnsquery = standard_ip_query(parsedtargetips)
    else:
        # First try parsing as IP addresses
        parsednameserver = parse_ip_inputs(args.nameserver, args.auto, args.verbose, True)
        if parsednameserver:
            dnsquery = standard_ip_query(parsedtargetips, parsednameserver[0])
        else:
            print(f"{bcolors.FAIL}[!] Invalid nameserver provided: {args.nameserver}. Execution can't continue.{bcolors.RESET}")
            exit(1)
        dns_std_aggregator(parsedtargetips)

def zone_transfer(args):
    """Uses dnsrecon to bruteforce subdomains using a wordlist. And also searches on subdomains on bing"""
    setcurrentenvproject(args)
    loadProjectContextOnMemory()
    print(args)

    if args.verbose > 2:
        print(args)
        print(f"[recon:dns zone transfer check] project={args.project} verbose={args.verbose}")
    parsedtargetips = parse_ip_inputs(args.targets, args.auto, args.verbose, True, True)

    if not args.nameserver:
        dnsquery = check_zone_transfer(parsedtargetips)
    else:
        # First try parsing as IP addresses
        parsednameserver = parse_ip_inputs(args.nameserver, args.auto, args.verbose, True)
        if parsednameserver:
            dnsquery = check_zone_transfer(parsedtargetips, parsednameserver[0])
        else:
            print(
                f"{bcolors.FAIL}[!] Invalid nameserver provided: {args.nameserver}. Execution can't continue.{bcolors.RESET}")
            exit(1)


def dns_domain_discovery(args):
    """Uses dnsrecon to bruteforce subdomains using a wordlist. And also searches on subdomains on bing. Bruteforces TLD on the base domain."""
    setcurrentenvproject(args)
    loadProjectContextOnMemory()

    if args.verbose > 2:
        print(args)
        print(f"[recon:dns domain tools] project={args.project} verbose={args.verbose}")
    parsedtargetips = parse_ip_inputs(args.targets, args.auto, args.verbose)  # Get target arg
    print("This tool would use dnsrecon to brutefoce TLDs on the base domain, and then bruteforce subdomains with a wordlist, and search for subdomains on bing.")

def reverse_lookup(args):
    """Reverse DNS lookup for IPs or CIDRs"""
    setcurrentenvproject(args)
    loadProjectContextOnMemory()
    print(args)

    if args.verbose > 2:
        print(args)
        print(f"[recon:dns reverse ] project={args.project} verbose={args.verbose}")
    parsedtargetips = parse_ip_inputs(args.targets, args.auto, args.verbose)  # Get target arg
    print("This tool would perform reverse DNS lookups for the given IPs or CIDRs.")

def initdnsscanargparser(recon_sub, commonparser):
    p_dns = recon_sub.add_parser("dns", parents=[commonparser], help="DNS analysis tools")
    dns_subparsers = p_dns.add_subparsers(dest="tool", metavar="[TOOL]", required=True)

    # --- Standard scan (SOA, NS, A, AAAA, MX, SRV)
    p_regularscanner = dns_subparsers.add_parser("scan", parents=[commonparser],
                                                 help="Standard query for SOA, NS, A, AAAA, MX and SRV records.")
    p_regularscanner.add_argument("targets", nargs="*", help="Target IP(s), CIDR(s) or domain(s), or use --auto")
    p_regularscanner.add_argument("nameserver", nargs=1, help="Target IP(s) or CIDR(s) of the nameserver to use for the query")
    p_regularscanner.add_argument("--auto", action="store_true",
                                  help="Use IPs from the project nmap scanned targets, if any")
    p_regularscanner.add_argument("-o", "--overwrite", action="store_true",
                                  help="Overwrite targets from previous fingerprint scans on the same project. Default appends new IPs")
    p_regularscanner.set_defaults(func=standard_dns_query)

    # --- DNS Bruteforce
    p_bruteforce = dns_subparsers.add_parser("subdomains", parents=[commonparser],
                                             help="Bruteforces TLD on the base domain. For every TLD. bruteforces subdomains with wordlists, searches for subdomains on bing.")
    p_bruteforce.add_argument("domain", help="Target domain")
    p_bruteforce.add_argument("-w", "--wordlist", required=True, help="Wordlist file for subdomains")
    p_bruteforce.add_argument("--nameserver", nargs=1, help="Optional nameserver to use")
    p_bruteforce.set_defaults(func=dns_domain_discovery)
    p_bruteforce.add_argument("--auto", action="store_true",
                                  help="Use IPs from the project nmap scanned targets, if any")
    p_bruteforce.add_argument("-o", "--overwrite", action="store_true",
                                  help="Overwrite targets from previous fingerprint scans on the same project. Default appends new IPs")
    p_bruteforce.set_defaults(func=standard_dns_query)

    # --- Reverse Lookup
    p_reverse = dns_subparsers.add_parser("reverse", parents=[commonparser],
                                          help="Reverse DNS lookup for IPs or CIDRs")
    p_reverse.add_argument("targets", nargs="*", help="Target IP(s) or CIDR(s)")
    p_reverse.add_argument("--auto", action="store_true",
                                  help="Use IPs from the project nmap scanned targets, if any")
    p_reverse.add_argument("-o", "--overwrite", action="store_true",
                                  help="Overwrite targets from previous fingerprint scans on the same project. Default appends new IPs")
    p_reverse.set_defaults(func=reverse_lookup)

    # --- Zone Transfer
    p_zonetransfer = dns_subparsers.add_parser("ztransfer", parents=[commonparser],
                                               help="Attempt DNS zone transfer (AXFR)")
    p_zonetransfer.add_argument("targets", nargs="*",help="Target domain")
    p_zonetransfer.add_argument("nameserver", nargs=1, help="Nameserver to attempt zone transfer against")
    p_zonetransfer.add_argument("--auto", action="store_true",
                                  help="Use IPs from the project nmap scanned targets, if any")
    p_zonetransfer.add_argument("-o", "--overwrite", action="store_true",
                                  help="Overwrite targets from previous fingerprint scans on the same project. Default appends new IPs")
    p_zonetransfer.set_defaults(func=zone_transfer)
