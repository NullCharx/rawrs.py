from rawrs.core import context_manager
from rawrs.core.staticdata import bcolors
from rawrs.core.context_manager import setcurrentenvproject, loadProjectContextOnMemory
from rawrs.reconenum.parser import parse_ip_inputs, parse_webtechresults, parse_web_targets, aggregate_webvulns, \
    parse_fuzzer, ip_cleaner
from rawrs.reconenum.nmap.nmaptools import parsealivehosts
from rawrs.reconenum.fuzzer import run_directory_fuzzing
from rawrs.reconenum.web.webtechanalyzer import whatwebexecutor
from rawrs.reconenum.web.webvulnanalyzer import run_wpscan_scan, run_wapiti_scan, run_nikto_scan


# whatweb and wappalizer should be aggregated together. Then wappity, then recursive fuzzing, then vulns

def what_wapp_fingerprint(args):
    """
    Perform target fingerprinting with whatweb
    :param args: args that include the IP or host targets or a flag to perform it on the nmap scanned targets, if any
    :return:
    """
    setcurrentenvproject(args)
    loadProjectContextOnMemory()

    print(f"\n{bcolors.YELLOW}[i] Web fingerprinting is the process of identifying the technologies used by a web application, such as web servers, frameworks, and libraries."
          f".{bcolors.RESET}")
    print(f"\n{bcolors.YELLOW}[i] Fingerprinting can provide potential technologies with flaws or vulnerabilites that can be exploited under the right conditions .{bcolors.RESET}")
    if args.verbose > 2:
        print(args)
        print(f"[recon:web fingerprint] project={args.project} verbose={args.verbose}")

    print(f"\n{bcolors.YELLOW}[i] Firstly let's check which of the provided targets is alive and has a web on one of its ports .{bcolors.RESET}")
    print(f"{bcolors.YELLOW}[i] Usually when done manually you can check the output of the nmap scan and then target specific ports with http or https services..{bcolors.RESET}")

    subargs = parse_ip_inputs(args.targets,args.auto,args.verbose) #Get target arg
    alivetargets = parsealivehosts(ip_cleaner(subargs), args.overwrite, args.verbose)  # List of alive targets
    #With the alive targets, filter out dead hosts or those with no web on them
    parsedwebtargets = parse_web_targets(alivetargets,subargs, args.verbose)
    if args.verbose > 2:
        print(f"parsed web targets for fingerprint: {parsedwebtargets}")

    print(f"\n{bcolors.YELLOW}[i] After filtering out non-web targets, run whatweb. .{bcolors.RESET}")

    whatwebresults = whatwebexecutor(parsedwebtargets, args.verbose) #Scan. Only return web targets that were actually scanned
    #Whatweb
    finalwebtechresults = parse_webtechresults(whatwebresults, f"{context_manager.current_project}/results/whatweb_aggregated.json", args.overwrite)
    print(f"\n{bcolors.YELLOW}[i] This script uses whatweb but the browser extension wappalyzer is also recommended to use manually, as well as reading through the sourcecode of the target.{bcolors.RESET}")


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
        print(f"[recon:web vuln] project={args.project} verbose={args.verbose}")
    subargs = parse_ip_inputs(args.targets,args.auto,args.verbose) #Get target arg
    alivetargets = parsealivehosts(ip_cleaner(subargs), args.overwrite, args.verbose)  # List of alive targets
    parsedtargets = parse_web_targets(alivetargets,subargs)
    if args.verbose > 2:
        print(f"parsed web targets for fingerprint: {parsedtargets}")
    #Make wapiti and nikto return the correct dicts to parse
    print(webtips[0])

    print(f"\n{bcolors.YELLOW}[i] Always research vulnerabilities and exploits for target systems and versions for yourself too!{bcolors.OKCYAN}\n")
    print(webtips[3])

    run_wapiti_scan(parsedtargets,False,args.verbose)
    run_nikto_scan(parsedtargets)

    aggregate_webvulns(parsedtargets)

def cmsscan(args):
    """
    Scan given targets for CMS (Wordpress, drupal) vulnerabilities
    :param args: args that include the IP or host targets or a flag to perform it on the nmap scanned targets, if any. The target should include the path to the root of the CMS. If not given it will be asumed to be '/'
    :return:
    """

    #Add username and password dict options and then check for authenticated attacks (wpscan)
    setcurrentenvproject(args)
    loadProjectContextOnMemory()
    print(
        f"\n{bcolors.YELLOW}[i] Wpscan is the tool to scan wordpress installations. The script runs a very comprehensive scan, but some other tools are worth checking manually.")
    print(f"{bcolors.WARNING}[i] Certain vulnerabilities pertain not the server itself, but to the CMS (Content Management System) used!")
    print(f"\n{bcolors.WARNING}[i] Scripts and misconfigurations available for the CMS can potentially be used to infiltrate a target system")
    print(f"\n{bcolors.WARNING}[i] Most times you will find yourself getting access to a regular user (a blogger, a customer), and then find a way"
          f"to escalate to either the CMS admin or to the server itself via CMS scripts or other web or core CMS misconfigurations/vulnerabilities!")
    print(f"{bcolors.YELLOW}[i] If you manage to escalate to admin, check the php editor and change a script that loads (or can be for loaded/reloaded) into the page to run arbitrary code{bcolors.OKCYAN}[")

    if args.verbose > 2:
        print(args)
        print(f"[recon:web cms] project={args.project} verbose={args.verbose}")
    subargs = parse_ip_inputs(args.targets,args.auto,args.verbose) #Get target arg
    wpscanoutput = run_wpscan_scan(subargs, args.verbose, args.auth, args.cookies, args.userdict, args.passdict)
    #Don't parse wpscan ouput;
def basicfuzzing(args):
    """
    Perform directory fuzzing with two common dictionaries and fzzf
    """
    setcurrentenvproject(args)
    loadProjectContextOnMemory()

    if args.verbose > 2:
        print(args)
        print(f"[recon:web fingerprint] project={args.project} verbose={args.verbose}")
    print(f"{bcolors.YELLOW}[i] Fuzzing can be interesting to find public directories that might not be reachable from the front pages.{bcolors.RESET}")

    print(f"\n{bcolors.YELLOW}[i] Firstly let's check which of the provided targets is alive and has a web on one of its ports .{bcolors.RESET}")
    print(f"{bcolors.YELLOW}[i] Usually when done manually you can check the output of the nmap scan and then target specific ports with http or https services..{bcolors.RESET}")

    subargs = parse_ip_inputs(args.targets,args.auto,args.verbose) #Get target arg
    alivetargets = parsealivehosts(ip_cleaner(subargs), args.overwrite, args.verbose)  # List of alive targets
    parsedtargets = parse_web_targets(alivetargets,subargs)

    print(f"\n{bcolors.YELLOW}[i] After filtering out non-web targets, run fuff. .{bcolors.RESET}")
    run_directory_fuzzing(parsedtargets, args) #Perform fuzzing
    parse_fuzzer(parsedtargets,None,args.overwrite,args.verbose) #Generate summary

webtips = [f"\n{bcolors.YELLOW}[i] While programs like nikto might grab interesting info themselves, {bcolors.WARNING}checking the source code{bcolors.YELLOW} of pages and checking manually is always a good idea\n"
           f"[i] Remember that while automated vulnerability tools might be a good start, there are various options not used in this script, as well as some flaws that might not appear on the scans the first time",
f"\n{bcolors.YELLOW}[i] If nmap returns {bcolors.WARNING}POST as a permitted http method{bcolors.YELLOW}, or if it is permitted in a subpage of the domain, its as easy as uploading any arbitrary file, like a reverse shell. This can be checked with curl or one of the nmap http scripts which is used in the -sC option, among others",
f"\n{bcolors.YELLOW}[i] Check {bcolors.WARNING}input elements{bcolors.YELLOW} of the web, like login, search or file upload forms or URL parameters."
          f"\n\n      - This include checking for {bcolors.WARNING}SQL injections{bcolors.YELLOW}, specially in places that might make unsanitized queries to databases (login forms, search forms)"
          f"\n      Also {bcolors.WARNING}RCE{bcolors.YELLOW} that might end up running arbitrary scripts on the server side."
          f"\n\n      - Poorly configured {bcolors.WARNING}upload forms{bcolors.YELLOW} that might let arbitrary files be uploaded under certain circumstances."
          f"\n\n      - Certain {bcolors.WARNING}url parameters{bcolors.YELLOW} (after the url, like: ?paremeter1=value1&paremeter2=value2&paremeter3=value3...) might be vulnerable to injection too if input is not properly sanitzed before being given to whatever is behind"
          f"\n              Take into account that some characters in URLS are formatted differently (and usually handled automatically by the browser) like '.' and '/'"
          f"\n              You can try using {bcolors.WARNING}php wrappers{bcolors.YELLOW} to gain access to or upload files."
          f"\n\n      - Use password making tools like cewl or dictionaries like {bcolors.WARNING}rockyou.txt{bcolors.YELLOW} for passwords. In OSCP a password is very likely to be found in that dictionary if it has to be bruteforced."
          f"\n\n      - Use tools like {bcolors.WARNING}hydra{bcolors.YELLOW} to perform the bruteforce.",
f"\n{bcolors.YELLOW}[i] For others like Drupal or moodle, you can use other tools like Droopescan..",
           f"\n{bcolors.YELLOW}[i] Remember that while the {bcolors.WARNING}root of a webpage (usually the first scanned path) might not have a certain vulnerability or misconfiguration, some other subpage might! {bcolors.YELLOW} i.e the root might not have POST as accepted method, but some subpage might!{bcolors.RESET}"
           ]
def texttipsweb(args):
    for tip in webtips:
        print(tip)

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

    p_tip = web_subparsers.add_parser("tips", parents=[commonparser],
                                       help="Some other tips and actions that can be done manually")
    p_tip.set_defaults(func=texttipsweb)


    #If technologies returns wordpress -> wpscan
    #If technologies returns drupal-> droopescan
    #
    # Vulnerabilities to use (Searchsploit, rapid 7 and for exploits github mainly)
    #Prompt the user to search for manual vulnrable inpouts, url encodings, SQLi...
    #Complete scan that chains everything!!!