def initdnsscanargparser(recon_sub, commonparser):
    p_dns = recon_sub.add_parser("dns", parents=[commonparser], help="DNS analysis tools")
    dns_subparsers = p_dns.add_subparsers(dest="tool", metavar="[TOOL]", required=True)

    # fingerprint: run whatweb (and possibly Wappalyzer)
    p_fingerprint = dns_subparsers.add_parser("fuzz", parents=[commonparser],
                                              help="Run whatweb to fingerprint web technologies")
    p_fingerprint.add_argument("targets", nargs="*", help="Target IP(s), CIDR(s) or domain(s), or use --auto")
    p_fingerprint.set_defaults(func=what_wapp_fingerprint)
    p_fingerprint.add_argument("--auto", action="store_true",
                               help="Use IPs from the project nmap scanned targets, if any")
    p_fingerprint.add_argument(
        "-o", "--overwrite",
        action="store_true",
        help="Overwrite targets from previous fingerprint scans on the same project. (Default appends any new IP to the list of targets)"
    )

#standard scan, bruteforce and bing lookup, reverse lookup, zonetransfer, and tld (against target) and if anything use the other methods