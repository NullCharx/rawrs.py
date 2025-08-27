from rawrs.core.globaldata import bcolors
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
    run_smb_anon_check(parsedtargets,args.auto, 5, args.verbose,)


    run_smb_full_enum(parsedtargets, args.verbose)


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
