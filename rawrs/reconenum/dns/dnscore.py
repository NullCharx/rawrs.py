from rawrs.core.globaldata import bcolors
from rawrs.core.context_manager import setcurrentenvproject, loadProjectContextOnMemory
from rawrs.reconenum.dns.dnstools import standard_ip_query, check_zone_transfer
from rawrs.reconenum.parser import parse_ip_inputs, dns_std_aggregator


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
    print(f"\n{bcolors.YELLOW}[i]DNS servers can give extra information about the target, such as subdomains, IPs, and more. "
          f"This scan checks for some standard ports and records: SOA, NS, A, AAAA, MX and SRV.{bcolors.RESET}")
    print(f"{bcolors.YELLOW}[i] Enterprises usually run on-premise authoritative DNS servers for internal names,"
          f"and less often for external names, otherwise they are managed by cloud providers (like Cloudfare, AWS...) {bcolors.RESET}")
    print(f"{bcolors.YELLOW}[i] The targets from which to get info must be domains, not IPs. A reverse lookup (IP->DNS) is another query{bcolors.RESET}\n")

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

    print(f"\n{bcolors.YELLOW}[i]Zone transfers are DNS operations to copy the contents between two authoritative DNS servers.")
    print(f"\n[i] A misconfigured DNS server may allow unauthorized or unauthenticated zone transfers, exposing sensitive information about the domain, such as subdomains, IP addresses, and other DNS records.{bcolors.RESET}")
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
    print(f"\n{bcolors.YELLOW}[i] Various bruteforcing operations might be performed on the base domain, such as bruteforcing TLDs or subdomains with a wordlist. {bcolors.RESET}")
    print(f"\n{bcolors.YELLOW}[i] This can cause instability or service disruptions or be noisy in in-real-life scenarios {bcolors.RESET}")
    print(f"\n{bcolors.YELLOW}[i] Another way is via OSINT, like searching or bruteforcing subdomains via the internet (a search engine).{bcolors.RESET}")

    if args.verbose > 2:
        print(args)
        print(f"[recon:dns domain tools] project={args.project} verbose={args.verbose}")
    parsedtargetips = parse_ip_inputs(args.targets, args.auto, args.verbose)  # Get target arg
    print("This tool would use dnsrecon to brutefoce TLDs on the base domain, and then bruteforce subdomains with a wordlist, and search for subdomains on bing.")

def reverse_lookup(args):
    """Reverse DNS lookup for IPs or CIDRs"""
    print(f"\n{bcolors.YELLOW}[i] Reverse lookups can be useful in certain situations well all the info available is the domain name. {bcolors.RESET}")

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
    p_regularscanner.add_argument("targets", nargs="*", help="Target domains to resolve.")
    p_regularscanner.add_argument("nameserver", nargs=1, help="Target IP of the nameserver to use for the query")
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
    p_bruteforce.set_defaults(func=dns_domain_discovery)

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

