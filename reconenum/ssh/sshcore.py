
def initsshscanargparser(recon_sub, commonparser):
    p_ssh = recon_sub.add_parser("ssh", parents=[commonparser], help="SSH data gathering")
    ssh_subparsers = p_ssh.add_subparsers(dest="tool", metavar="[TOOL]", required=True)

    # --- Standard scan (SOA, NS, A, AAAA, MX, SRV)
    p_sshanonlogin = ssh_subparsers.add_parser("anon", parents=[commonparser],
                                                 help="Checks if the target(s) allow anonymous SSH login")
    p_sshanonlogin.add_argument("targets", nargs="*", help="Target IP(s), CIDR(s) or domain(s), or use --auto")
    p_sshanonlogin.add_argument("--auto", action="store_true",
                                  help="Use IPs from the project nmap scanned targets, if any")
    p_sshanonlogin.add_argument("-o", "--overwrite", action="store_true",
                                  help="Overwrite targets from previous fingerprint scans on the same project. Default appends new IPs")
    p_sshanonlogin.set_defaults(func=checkssh_anon)


def checkssh_anon():
    print("TODO")