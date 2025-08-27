from rawrs.core.globaldata import bcolors
from rawrs.core.context_manager import setcurrentenvproject, loadProjectContextOnMemory
from rawrs.reconenum.ftp.ftptools import run_ftp_anon_check
from rawrs.reconenum.parser import parse_ftp_list, parse_ip_inputs


def initftpscanargparser(recon_sub, commonparser):
    p_ftp = recon_sub.add_parser("ftp", parents=[commonparser], help="ftp data gathering")
    ftp_subparsers = p_ftp.add_subparsers(dest="tool", metavar="[TOOL]", required=True)

    # --- Standard scan (SOA, NS, A, AAAA, MX, SRV)
    p_ftpanonlogin = ftp_subparsers.add_parser("anon", parents=[commonparser],
                                                 help="Checks if the target(s) allow anonymous SSH login")
    p_ftpanonlogin.add_argument("targets", nargs="*", help="Target IP(s), CIDR(s) or domain(s), or use --auto")
    p_ftpanonlogin.add_argument("--auto", action="store_true",
                                  help="Use IPs from the project nmap scanned targets, if any")
    p_ftpanonlogin.add_argument("-o", "--overwrite", action="store_true",
                                  help="Overwrite targets from previous fingerprint scans on the same project. Default appends new IPs")
    p_ftpanonlogin.set_defaults(func=check_ftp_anon)

    p_tips = ftp_subparsers.add_parser("tips", parents=[commonparser],
                                                 help="Tips for ftp")
    p_tips.set_defaults(func=ftptips)

def check_ftp_anon(args):
    """Check ftp anon login on an ip"""
    setcurrentenvproject(args)
    loadProjectContextOnMemory()
    print(args)

    if args.verbose > 2:
        print(args)
        print(f"[recon:ftp anon] project={args.project} verbose={args.verbose}")

    print(f"\n{bcolors.YELLOW}[i]Sometimes FTP allows anonymous login, which can be used to gather information about the server and its files. "
          f".{bcolors.RESET}")
    parsedips = parse_ip_inputs(args.targets, args.auto, args.verbose)
    parsedtargets = parse_ftp_list(parsedips, args.auto)
    run_ftp_anon_check(parsedtargets)


def ftptips(args):
    print(f"\n{bcolors.YELLOW}[i] If anon login is enabled, check all the folders and files available, they might have valuable information")
