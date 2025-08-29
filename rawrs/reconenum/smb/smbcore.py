from rawrs.core.staticdata import bcolors
from rawrs.core.context_manager import setcurrentenvproject, loadProjectContextOnMemory
from rawrs.reconenum.parser import parse_ip_inputs, parse_smb_list
from rawrs.reconenum.smb.smbtools import run_smb_anon_check, run_smb_full_enum


def smb_std_enum(args):
    """Check ftp anon login on an ip"""
    setcurrentenvproject(args)
    loadProjectContextOnMemory()
    print(args)

    if args.verbose > 2:
        print(args)
        print(f"[recon:ftp anon] project={args.project} verbose={args.verbose}")

    parsedips = parse_ip_inputs(args.targets, args.auto, args.verbose)
    parsedtargets = parse_smb_list(parsedips, args.auto)


    print(f"\n{bcolors.YELLOW}[i] Sometimes SMB  allows anonymous login, which can be used to gather information about the server and its files. "
          f".{bcolors.RESET}")
    print(f"\n{bcolors.YELLOW}[i] This script tries to connec to IPC$. There might be shares that explictly disallow anonymous login. {bcolors.OKCYAN}")
    run_smb_anon_check(parsedtargets,5,  args.verbose, args.auto)

    print(f"\n{bcolors.YELLOW}[i] Enum4linux-ng is a great tool to enumerate SMB servers. It uses a lot of techniques to gather information about the target, including null sessions, shares, users, groups, policies, etc. {bcolors.RESET}")
    print(f"\n{bcolors.YELLOW}[i] This script runs enum4linux-ng with -A option, which is a comprehensive scan. It might be noisy and take some time, depending on the target. {bcolors.OKCYAN}")
    print(f"\n{bcolors.WARNING}[i] It also performs RID cycling, which might cause account lockouts if the target has such policies in a real life scenario. Use with caution. {bcolors.OKCYAN}")
    print(f"\n{bcolors.WARNING}[i] If unsure, ask the client or your manager before running a scan. In a OSCP scenario, scanning in an exhaustive manner and being noisy is preferred.{bcolors.OKCYAN}\n")
    run_smb_full_enum(parsedtargets, args.verbose)

    #TODO parser and aggregator for enum4linux-ng output


def initsmbscanargparser(recon_sub, commonparser):
    # Main "web" command parser
    p_smb = recon_sub.add_parser("smb", parents=[commonparser], help="smb recon and enum tools")
    smb_subparsers = p_smb.add_subparsers(dest="tool", metavar="[TOOL]", required=True)

    # fingerprint: run whatweb (and possibly Wappalyzer)
    p_smbanonlogin = smb_subparsers.add_parser("enum", parents=[commonparser],
                                              help="Check")
    p_smbanonlogin.add_argument("targets", nargs="*", help="Target IP(s), CIDR(s) or domain(s), or use --auto")
    p_smbanonlogin.add_argument("--auto", action="store_true",
                                  help="Use IPs from the project nmap scanned targets, if any")
    p_smbanonlogin.add_argument("-o", "--overwrite", action="store_true",
                                  help="Overwrite targets from previous fingerprint scans on the same project. Default appends new IPs")
    p_smbanonlogin.set_defaults(func=smb_std_enum)
