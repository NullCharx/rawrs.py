from urllib.parse import urlparse

from core import context_manager
from core.context_manager import setcurrentenvproject, getTargetsContext, loadProjectContextOnMemory
from reconenum.nmap.nmap import checkalivehosts
from reconenum.parser import parse_ip_inputs, target_web_sorter, parse_whatweb_results
from reconenum.web.webtechanalyzer import whatwebexecutor


# whatweb and wappalizer should be aggregated together. Then wappity, then recursive fuzzing, then vulns

def  cmd_recon_web(args):
    """
    Perform a full analysis on
    :param args: args that include the IP or host targets or a flag to perform it on the nmap scanned targets, if any
    :return:
    """
    setcurrentenvproject(args)
    loadProjectContextOnMemory()

    if args.verbose > 2:
        print(f"[recon:web full] project={args.project} verbose={args.verbose}")
    subargs = parse_ip_inputs(args.targets, args.auto, args.verbose)
    print("YOHOOO ALL SUMMER BLOW OUT")

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
    alivetargets = checkalivehosts(subargs,args.overwrite,args.verbose)
    parsedtargets = target_web_sorter(list(alivetargets.keys())) #Parse web identified targets
    if args.verbose > 2:
        print(f"parsed web targets for fingerprint: {parsedtargets}")
    parsedtargets = whatwebexecutor(parsedtargets) #Scan. Only return web targets that were actually scanned
    #Whatweb
    finalwhatwebresults = parse_whatweb_results(parsedtargets,f"{context_manager.current_project}/results/whatweb_aggregated.json", args.overwrite)

def webvuln(args):
    """
    Perform target vulnerability assesment via wapiti, nikto and wpscan / droopescan if applicable
    :param args: args that include the IP or host targets or a flag to perform it on the nmap scanned targets, if any
    :return:
    """
    setcurrentenvproject(args)
    loadProjectContextOnMemory()

    if args.verbose > 2:
        print(args)
        print(f"[recon:web vuln] project={args.project} verbose={args.verbose}")
    subargs = parse_ip_inputs(args.targets,args.auto,args.verbose) #Get target arg
    #run_wapiti_scan(subargs)


def basicfuzzing(args):
    """
    Perform directory fuzzing with two common dictionaries and fzzf
    """
    setcurrentenvproject(args)
    loadProjectContextOnMemory()
    print(args)

    if args.verbose > 2:
        print(f"[recon:web vuln] project={args.project} verbose={args.verbose}")
    subargs = parse_ip_inputs(args.targets, args.auto, args.verbose)  # Get target arg


def initwebscanargparser(recon_sub, commonparser):
    # Main "web" command parser
    p_web = recon_sub.add_parser("web", parents=[commonparser], help="Web fingerprinting and vulnerability scan tools")
    web_subparsers = p_web.add_subparsers(dest="tool", metavar="[TOOL]", required=True)

    # completescan: run all tools
    p_complete = web_subparsers.add_parser("completescan", parents=[commonparser], help="Run all available tools to perform a complete web scan of the targets")
    p_complete.add_argument("targets", nargs="*", help="Target IP(s), CIDR(s) or domain(s), or use --auto")
    p_complete.set_defaults(tool=cmd_recon_web)
    p_complete.add_argument("--auto", action="store_true", help="Use IPs from the project nmap scanned targets, if any")
    p_complete.add_argument(
        "-o", "--overwrite",
        action="store_true",
        help="Overwrite targets from previous scans on the same project. (Default appends any new IP to the list of targets)"
    )
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
    # vulnerability assessment (automatic front facing with wapiti, other vulns with nikto. wpscan and droppescan are also ran on the root or an
    p_vuln = web_subparsers.add_parser("vuln", parents=[commonparser], help="Run wapiti, nikto, and applicable CMS scanners (e.g., WPScan, Droopescan) on selected web targets")
    p_vuln.add_argument("targets", nargs="*",help="Target IP(s), domain(s), or CIDR(s). Supports scheme://ip:port format. Use --auto to pull from scanned project targets.")
    p_vuln.add_argument("cmspath", nargs="*",
        help=(
            "Optional CMS root paths for specific targets. Format: <target>/<cms_path>, "
            "e.g., 192.168.1.10/blog or example.com/wp. Each entry must match a host from the 'targets' list "
            "(or resolved via --auto). If omitted for a target, '/' is assumed."
        ))
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

    # Probably a whatweb parser and add technologies and versions to the context
        #
        # Nikto 2 (Check robots txt, source code credentials etc)
        #
        #If technologies returns wordpress -> wpscan
        #If technologies returns drupal-> droopescan
        #
        # Vulnerabilities to use (Searchsploit, rapid 7 and for exploits github mainly)
        #Prompt the user to search for manual vulnrable inpouts, url encodings, SQLi...
        #Complete scan that chains everything!!!