import argparse

from core.context_manager import setcurrentenvproject, loadProjectContextOnMemory
from reconenum.dns.dnscore import initdnsscanargparser
from reconenum.ftp.ftpcore import initftpscanargparser
from reconenum.nmap.nmapcore import initnmapscanargparser
from reconenum.nmap.nmaptools import full_discovery
from reconenum.parser import parse_ip_inputs
from reconenum.ssh.sshcore import initsshscanargparser
from reconenum.web.webscanner import initwebscanargparser
from tunneling.tunnelcore import inittunnelscanargparser


#basicamente: Termina wp vulnerable parser
#Ternina el parser de dnsrecon zone tranfer
#ssh anon  logiun check
#ftp anon login check
#(haz los checks que tienes bbqq)


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
            "Scan subtool for ports, services, and protocols, inlcuding tools like dns checks, anon login checks and more\n\n"
            "Examples:\n"
            "  rawrs.py recon nmap scan -o 192.168.1.0/24\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    recon_sub = p_recon.add_subparsers(dest="recon_cmd", required=True)

    initnmapscanargparser(recon_sub, commonparser)

    # protocol submenus
    #finish web comments and others checl that the commands are printed for every subsection
    initwebscanargparser(recon_sub, commonparser)

    initdnsscanargparser(recon_sub, commonparser)

    initsshscanargparser(recon_sub, commonparser)

    initftpscanargparser(recon_sub, commonparser)



    p_smb = recon_sub.add_parser("smb", parents=[commonparser], help="SMB-specific enumeration")
    p_smb.set_defaults(func=cmd_recon_smb)

    p_win = recon_sub.add_parser("win", parents=[commonparser], help="Windows AD enumeration")
    p_win.set_defaults(func=cmd_recon_smb)





def cmd_recon_smb(args):
    setcurrentenvproject(args)
    loadProjectContextOnMemory()

    if args.verbose > 2:
        print(f"[recon:web] project={args.project} verbose={args.verbose}")


def cmd_recon_win(args):
    setcurrentenvproject(args)
    loadProjectContextOnMemory()

    if args.verbose > 2:
        print(f"[recon:web] project={args.project} verbose={args.verbose}")

