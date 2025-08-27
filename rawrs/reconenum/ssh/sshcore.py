from rawrs.core.staticdata import bcolors


def initsshscanargparser(recon_sub, commonparser):
    p_ssh = recon_sub.add_parser("ssh", parents=[commonparser], help="SSH data gathering")
    ssh_subparsers = p_ssh.add_subparsers(dest="tool", metavar="[TOOL]", required=True)

    # --- Standard scan (SOA, NS, A, AAAA, MX, SRV)
    p_sshanonlogin = ssh_subparsers.add_parser("tips", parents=[commonparser],
                                                 help="Shows some tips about SSH protocol")
    p_sshanonlogin.set_defaults(func=sshtips)


def sshtips():
    print(f"\n{bcolors.YELLOW}[i] Adding your own pubkey to the authorized_keys file of a compromised machine allows you to ssh to it without password. \n"
          f"     - The file can be crated but needs to have the correct permissions (check your own .ssh folder if in doubt\n\n ")
    print(f"\n[i] Search for a user private key. That way you can use it when ssh-ing (ssh -i) to impersonate them and access without"
          f"password. There are certain keywords like \"sha\", \"ed25519\", \"key\" that could potentially be searched, nt only"
          f"in the person's documents or .ssh folder, but also on mails (?) or backups (?) aka bad practices{bcolors.reset}\n\n")
