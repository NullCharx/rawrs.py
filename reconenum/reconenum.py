

def run(args, config):
    if not args:
        print('''
    Scan subtool for ports, services, and protocols.

    Discovery commands:
      rawrs.py reconenum hdiscovery [IP range]   Discover up hosts in an IP range
      rawrs.py reconenum pdiscovery [IP]         Discover open ports using various scans
      rawrs.py reconenum sdiscovery [IP]         Identify services and known vulnerabilities
      rawrs.py reconenum fdiscovery [IP range]   Full scan: hosts + ports + services

    Protocol submenus:
      rawrs.py reconenum smb                     SMB-specific enumeration
      rawrs.py reconenum dns                     DNS analysis tools
      rawrs.py reconenum ssh                     SSH version and key gathering
      rawrs.py reconenum ftp                     FTP login/anon checks
    ''')
        return

    subcommand = args[0]
    subargs = args[1:]

    if subcommand == "hdiscovery":
        host_discovery(subargs, config)
    elif subcommand == "pdiscovery":
        port_discovery(subargs, config)
    elif subcommand == "sdiscovery":
        service_discovery(subargs, config)
    elif subcommand == "fdiscovery":
        full_discovery(subargs, config)

    elif subcommand == "smb":
        smb_scan(subargs, config)
    elif subcommand == "dns":
        dns_scan(subargs, config)
    elif subcommand == "ftp":
        ftp_scan(subargs, config)
    elif subcommand == "ssh":
        ssh_scan(subargs, config)
    else:
        print(f"Unknown scan subcommand: {subcommand}")
