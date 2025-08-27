from rawrs.core.context_manager import setcurrentenvproject, loadProjectContextOnMemory
from rawrs.reconenum.nmap.nmaptools import full_discovery
from rawrs.reconenum.parser import parse_ip_inputs


def initnmapscanargparser(recon_sub, commonparser):
    p_nmap = recon_sub.add_parser("nmap", parents=[commonparser], help="nmap port and ip enumeration")
    nmap_subparsers = p_nmap.add_subparsers(dest="tool", metavar="[TOOL]", required=True)

    p_full = nmap_subparsers.add_parser(
        "scan",
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

def cmd_recon_nmapscan(args):
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
