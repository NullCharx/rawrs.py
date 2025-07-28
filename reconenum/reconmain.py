import argparse

from core.context_manager import setcurrentenvproject
from reconenum.nmap.nmap import full_discovery
from reconenum.parser import parse_ip_inputs


def initreconenumsubparsers(menusubparser, commonparser):
    # ===================== RECON =====================
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
    p_web = recon_sub.add_parser("web", parents=[commonparser], help="Web fingerprinting")
    p_web.set_defaults(func=cmd_recon_web)

    p_smb = recon_sub.add_parser("smb", parents=[commonparser], help="SMB-specific enumeration")
    p_smb.set_defaults(func=cmd_recon_smb)

    p_dns = recon_sub.add_parser("dns", parents=[commonparser], help="DNS analysis tools")
    p_dns.set_defaults(func=cmd_recon_dns)

    p_ssh = recon_sub.add_parser("ssh", parents=[commonparser], help="SSH version/key gathering")
    p_ssh.set_defaults(func=cmd_recon_ssh)

    p_ftp = recon_sub.add_parser("ftp", parents=[commonparser], help="FTP login/anon checks")
    p_ftp.set_defaults(func=cmd_recon_ftp)

def cmd_recon_nmapscan(args):
    setcurrentenvproject(args)

    if args.verbose > 2:
        print(f"[recon:nmapscan] targets={args.targets} overwrite={args.overwrite}")
    subargs = parse_ip_inputs(args.targets)
    full_discovery(subargs, args.verbose, args.targets)

def  cmd_recon_web(args):
    setcurrentenvproject(args)

    if args.verbose > 2:
        print(f"[recon:web] project={args.project} verbose={args.verbose}")
    subargs = parse_ip_inputs(args.targets)


def cmd_recon_smb(args):
    setcurrentenvproject(args)
    if args.verbose > 2:
        print(f"[recon:web] project={args.project} verbose={args.verbose}")


def cmd_recon_dns(args):
    setcurrentenvproject(args)
    if args.verbose > 2:
        print(f"[recon:web] project={args.project} verbose={args.verbose}")


def cmd_recon_ssh(args):
    setcurrentenvproject(args)
    if args.verbose > 2:
        print(f"[recon:web] project={args.project} verbose={args.verbose}")

def cmd_recon_ftp(args):
    setcurrentenvproject(args)
    if args.verbose > 2:
        print(f"[recon:web] project={args.project} verbose={args.verbose}")
