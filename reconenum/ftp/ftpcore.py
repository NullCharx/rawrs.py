
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
    p_ftpanonlogin.set_defaults(func=checkftp_anon)


def checkftp_anon():
    print("TODO")