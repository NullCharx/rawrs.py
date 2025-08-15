import argparse

from core.context_manager import setcurrentenvproject, loadProjectContextOnMemory
from reconenum.dns.dnscore import initdnsscanargparser
from reconenum.nmap.nmap import full_discovery
from reconenum.parser import parse_ip_inputs
from reconenum.web.webscanner import initwebscanargparser


def initreconenumsubparsers(menusubparser, commonparser):
    """
    Parsers for the reconsubtool
    :param menusubparser: The main subparser
    :param commonparser:  The parser with the common options (project, verbosity)
    :return:
    """
    p_recon = menusubparser.add_parser(
        "recon",
        help="Port/service scans & protocol-specific enumeration",
        description=(
            "Scan subtool for ports, services, and protocols.\n\n"
            "Examples:\n"
            "  rawrs.py recon nmapscan -o 192.168.1.0/24\n"
            "  rawrs.py recon nmapscan 192.168.1.1,192.168.1.2\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    recon_sub = p_recon.add_subparsers(dest="recon_cmd", required=True)

    # fullscan
    p_full = recon_sub.add_parser(
        "nmapscan",
        parents=[commonparser],
        help="Host, port and service discovery (-sVC). For single IP or list / CIDR via normal and stealth scan"
    )
    p_full.add_argument(
        "-o", "--overwrite",
        action="store_true",
        help="Overwrite targets from previous scans on the same project. (Default appends any new IP to the list of targets)"
    )
    p_full.add_argument(
        "targets",
        help="single IP or IP range in CIDR or comma-separated list of IPs"
    )
    p_full.set_defaults(func=cmd_recon_nmapscan)

    # protocol submenus
    initwebscanargparser(recon_sub, commonparser)

    initdnsscanargparser(recon_sub, commonparser)


    p_smb = recon_sub.add_parser("smb", parents=[commonparser], help="SMB-specific enumeration")
    p_smb.set_defaults(func=cmd_recon_smb)

    p_ssh = recon_sub.add_parser("ssh", parents=[commonparser], help="SSH version/key gathering")
    p_ssh.set_defaults(func=cmd_recon_ssh)

    p_ftp = recon_sub.add_parser("ftp", parents=[commonparser], help="FTP login/anon checks")
    p_ftp.set_defaults(func=cmd_recon_ftp)

def \
        cmd_recon_nmapscan(args):
    """
    Performs a full nmap scan and saves the results to context on the the IPs specified on range
    :param args: args that include the IP or host targets
    :return:
    """
    setcurrentenvproject(args)
    loadProjectContextOnMemory()

    if args.verbose > 2:
        print(f"[recon:nmapscan] targets={args.targets} overwrite={args.overwrite}")
    subargs = parse_ip_inputs(args.targets, verbose=args.verbose)
    full_discovery(subargs, args.verbose, args.overwrite)



def cmd_recon_smb(args):
    setcurrentenvproject(args)
    loadProjectContextOnMemory()

    if args.verbose > 2:
        print(f"[recon:web] project={args.project} verbose={args.verbose}")


def cmd_recon_dns(args):
    setcurrentenvproject(args)
    loadProjectContextOnMemory()
    if args.verbose > 2:
        print(f"[recon:web] project={args.project} verbose={args.verbose}")


def cmd_recon_ssh(args):
    setcurrentenvproject(args)
    loadProjectContextOnMemory()
    if args.verbose > 2:
        print(f"[recon:web] project={args.project} verbose={args.verbose}")

def cmd_recon_ftp(args):
    setcurrentenvproject(args)
    loadProjectContextOnMemory()
    if args.verbose > 2:
        print(f"[recon:web] project={args.project} verbose={args.verbose}")
