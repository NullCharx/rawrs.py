from core import context_manager
from core.context_manager import setcurrentenvproject, loadProjectContextOnMemory
from reconenum.parser import parse_ip_inputs, parse_webtechresults, parse_web_targets, aggregate_webvulns, parse_fuzzer
from reconenum.nmap.nmap import parsealivehosts
from reconenum.web.fuzzer import run_fuzzing
from reconenum.web.webtechanalyzer import whatwebexecutor
from reconenum.web.webvulnanalyzer import run_wpscan_scan, run_wapiti_scan, run_nikto_scan


# whatweb and wappalizer should be aggregated together. Then wappity, then recursive fuzzing, then vulns

def what_wapp_fingerprint(args):
    """
    Perform target fingerprinting with whatweb
    :param args: args that include the IP or host targets or a flag to perform it on the nmap scanned targets, if any
    :return:
    """
    setcurrentenvproject(args)
    loadProjectContextOnMemory()

    if args.verbose > 2:
        print(args)
        print(f"[recon:web fingerprint] project={args.project} verbose={args.verbose}")
    subargs = parse_ip_inputs(args.targets,args.auto,args.verbose) #Get target arg
    alivetargets = parsealivehosts(subargs, args.overwrite, args.verbose)  # List of alive targets
    parsedwebtargets = parse_web_targets(alivetargets,subargs)
    if args.verbose > 2:
        print(f"parsed web targets for fingerprint: {parsedwebtargets}")
    whatwebresults = whatwebexecutor(parsedwebtargets) #Scan. Only return web targets that were actually scanned
    #Whatweb
    finalwebtechresults = parse_webtechresults(whatwebresults, f"{context_manager.current_project}/results/whatweb_aggregated.json", args.overwrite)


def webvuln(args):
    """
    Perform target vulnerability assesment via wapiti, and nikto
    :param args: args that include the IP or host targets or a flag to perform it on the nmap scanned targets, if any
    :return:
    """
    setcurrentenvproject(args)
    loadProjectContextOnMemory()

    if args.verbose > 2:
        print(args)
        print(f"[recon:web fingerprint] project={args.project} verbose={args.verbose}")
    subargs = parse_ip_inputs(args.targets,args.auto,args.verbose) #Get target arg
    alivetargets = parsealivehosts(subargs, args.overwrite, args.verbose)  # List of alive targets
    parsedtargets = parse_web_targets(alivetargets,subargs)
    print(parsedtargets)
    if args.verbose > 2:
        print(f"parsed web targets for fingerprint: {parsedtargets}")
    #Make wapiti and nikto return the correct dicts to parse
    run_wapiti_scan(parsedtargets)
    run_nikto_scan(parsedtargets)

    aggregate_webvulns(None,parsedtargets)
def cmsscan(args):
    """
    Scan given targets for CMS (Wordpress, drupal) vulnerabilities
    :param args: args that include the IP or host targets or a flag to perform it on the nmap scanned targets, if any. The target should include the path to the root of the CMS. If not given it will be asumed to be '/'
    :return:
    """

    #Add username and password dict options and then check for authenticated attacks (wpscan)
    setcurrentenvproject(args)
    loadProjectContextOnMemory()

    if args.verbose > 2:
        print(args)
        print(f"[recon:web vuln] project={args.project} verbose={args.verbose}")
    subargs = parse_ip_inputs(args.targets,args.auto,args.verbose) #Get target arg
    wpscanoutput = run_wpscan_scan(args)
    parsedcmsouput = a #a
    #droopescanoutput = run_droopescan_scan(args)

def basicfuzzing(args):
    """
    Perform directory fuzzing with two common dictionaries and fzzf
    """
    setcurrentenvproject(args)
    loadProjectContextOnMemory()
    print(args)

    if args.verbose > 2:
        print(args)
        print(f"[recon:web fingerprint] project={args.project} verbose={args.verbose}")
    subargs = parse_ip_inputs(args.targets,args.auto,args.verbose) #Get target arg
    alivetargets = parsealivehosts(subargs, args.overwrite, args.verbose)  # List of alive targets
    parsedtargets = parse_web_targets(alivetargets,subargs)
    run_fuzzing(parsedtargets,args) #Perform fuzzing
    parse_fuzzer(None,parsedtargets) #Generate summary

def initwebscanargparser(recon_sub, commonparser):
    # Main "web" command parser
    p_web = recon_sub.add_parser("web", parents=[commonparser], help="Web fingerprinting and vulnerability scan tools")
    web_subparsers = p_web.add_subparsers(dest="tool", metavar="[TOOL]", required=True)

    # fingerprint: run whatweb (and possibly Wappalyzer)
    p_fingerprint = web_subparsers.add_parser("fingerprint", parents=[commonparser], help="Run whatweb to fingerprint web technologies")
    p_fingerprint.add_argument("targets", nargs="*", help="Target IP(s), CIDR(s) or domain(s), or use --auto")
    p_fingerprint.set_defaults(func=what_wapp_fingerprint)
    p_fingerprint.add_argument("--auto", action="store_true", help="Use IPs from the project nmap scanned targets, if any")
    p_fingerprint.add_argument(
        "-o", "--overwrite",
        action="store_true",
        help="Overwrite targets from previous fingerprint scans on the same project. (Default appends any new IP to the list of targets)"
    )
    # vulnerability assessment (automatic front facing with wapiti, other vulns with nikto
    p_vuln = web_subparsers.add_parser("vuln", parents=[commonparser], help="Run wapiti, nikto, and applicable CMS scanners (e.g., WPScan, Droopescan) on selected web targets")
    p_vuln.add_argument("targets", nargs="*",help="Target IP(s), domain(s), or CIDR(s). Supports scheme://ip:port format. Use --auto to pull from scanned project targets.")
    p_vuln.set_defaults(func=webvuln)
    p_vuln.add_argument("--auto", action="store_true",help="Use IPs from the current project's Nmap-scanned targets (if available)")
    p_vuln.add_argument(
        "--cookie", metavar="COOKIE",
        help="Session cookie to use for authenticated scanning"
    )
    p_vuln.add_argument(
        "--auth", metavar="USER:PASS",
        help="Basic authentication for targets requiring login"
    )
    p_vuln.add_argument(
        "-o", "--overwrite",
        action="store_true",
        help="Overwrite targets from previous fingerprint scans on the same project. (Default appends any new IP to the list of targets)"
    )

    p_cms = web_subparsers.add_parser("cms", parents=[commonparser], help="Run applicable CMS scanners (e.g., WPScan, Droopescan) on selected web targets. Targets should have the path to the CMS root or else '/' will be asumed")
    p_cms.add_argument("targets", nargs="*",
                        help="Target IP(s), domain(s), or CIDR(s). Supports scheme://ip:port/path/to/cms format. Use --auto to pull from scanned project targets."
                             " Path to CMS asumed to be '/' otherwise")
    p_cms.set_defaults(func=cmsscan)
    p_cms.add_argument("--auto", action="store_true",
                        help="Use IPs from the current project's Nmap-scanned targets (if available)")
    p_cms.add_argument(
        "--cookies", metavar="COOKIE",
        help="Session cookies to use in wpscan. Format:  cookie1=value1[; cookie2=value2 ...]"
    )
    p_cms.add_argument(
        "--auth", metavar="LOGIN:PASS",
        help="Basic authentication for targets or pages requiring login. Format user:password"
    )
    p_cms.add_argument(
        "--userdict",
        help="Dictionary of usernames to bruteforce in login scenarios"
    )
    p_cms.add_argument(
        "--passdict",
        help="Dictionary of passwords to bruteforce in login scenarios. Default is rockyou.txt or none if its not found"
    )

    p_fuzz = web_subparsers.add_parser("fuzz", parents=[commonparser],
                                      help="Fuzz thetarget web application with common directories and files")
    p_fuzz.add_argument("targets", nargs="*",
                       help="Target IP(s), domain(s), or CIDR(s). Supports scheme://ip:port/path/to/cms format. Use --auto to pull from scanned project targets."
                            " Path to CMS asumed to be '/' otherwise")
    p_fuzz.set_defaults(func=basicfuzzing)
    p_fuzz.add_argument("--auto", action="store_true",
                       help="Use IPs from the current project's Nmap-scanned targets (if available)")
    p_fuzz.add_argument("--common", action="store_true",
                       help="Skipp fuzzy finding and use a common dict for fuzzing.")
    p_fuzz.add_argument("--wordlist",
                       help="Skipp fuzzy finding and use the dictionary path specified")
    p_fuzz.add_argument("--matchcode", nargs="*", type=str, default="all",
                       help="Specified status codes to match. Default is anything but the filtered codes (404)")
    p_fuzz.add_argument("--header", nargs=1, type=str,
                       help="Append a custom header to the fuzzing requests. The program does not verify the header format, so use it at your own risk. "
                            "Example: 'X-My-Header: value'")
    p_fuzz.add_argument(
        "-o", "--overwrite",
        action="store_true",
        help="Overwrite targets from previous fingerprint scans on the same project. (Default appends any new IP to the list of targets)"
    )
    # Probably a whatweb parser and add technologies and versions to the context

    #If technologies returns wordpress -> wpscan
    #If technologies returns drupal-> droopescan
    #
    # Vulnerabilities to use (Searchsploit, rapid 7 and for exploits github mainly)
    #Prompt the user to search for manual vulnrable inpouts, url encodings, SQLi...
    #Complete scan that chains everything!!!