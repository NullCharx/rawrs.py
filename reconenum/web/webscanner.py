from urllib.parse import urlparse

from core.context_manager import setcurrentenvproject, getTargetsContext, loadProjectContextOnMemory
from reconenum.parser import parse_ip_inputs, target_web_sorter, parse_whatweb_results
from reconenum.web.whatwebxecutor import whatwebexecutor


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
    subargs = parse_ip_inputs(args.targets, args.auto)
    print("YOHOOO ALL SUMMER BLOW OUT")

def what_wapp_fingerprint(args):
    """
    Perform target fingerprinting with whatweb and wappalizer
    :param args: args that include the IP or host targets or a flag to perform it on the nmap scanned targets, if any
    :return:
    """
    setcurrentenvproject(args)
    loadProjectContextOnMemory()
    print(args)

    if args.verbose > 2:
        print(f"[recon:web fingerprint] project={args.project} verbose={args.verbose}")
    subargs = parse_ip_inputs(args.targets,args.auto) #Get target arg
    parsedtargets = target_web_sorter(subargs) #Parse web enabled targets
    if args.verbose > 2:
        print(f"parsed web targets for fingerprint: {parsedtargets}")
    whatwebexecutor(parsedtargets)
    #Whatweb
    finalwhatweb = parse_whatweb_results(parsedtargets)

    #wappalizer
    #aggregate results

def initwebscanargparser(recon_sub, commonparser):
    # Main "web" command parser
    p_web = recon_sub.add_parser("web", parents=[commonparser], help="Web fingerprinting and vulnerability scan tools")
    web_subparsers = p_web.add_subparsers(dest="tool", metavar="[TOOL]", required=True)

    # completescan: run all tools
    p_complete = web_subparsers.add_parser("completescan", parents=[commonparser], help="Run all available tools to perform a complete web scan of the targets")
    p_complete.add_argument("targets", nargs="*", help="Target IP(s), CIDR(s) or domain(s), or use --auto")
    p_complete.set_defaults(tool=cmd_recon_web)
    p_complete.add_argument("--auto", action="store_true", help="Use IPs from the project nmap scanned targets, if any")

    # fingerprint: run whatweb (and possibly Wappalyzer)
    p_fingerprint = web_subparsers.add_parser("fingerprint", parents=[commonparser], help="Run whatweb to fingerprint web technologies")
    p_fingerprint.add_argument("targets", nargs="*", help="Target IP(s), CIDR(s) or domain(s), or use --auto")
    p_fingerprint.set_defaults(func=what_wapp_fingerprint)
    p_fingerprint.add_argument("--auto", action="store_true", help="Use IPs from the project nmap scanned targets, if any")




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