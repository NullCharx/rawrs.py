from reconenum.nmap.nmap import full_discovery
from reconenum.parser import parse_ip_inputs
from reconenum.web.webscanner import web_scan

helpmsg = '''
    Scan subtool for ports, services, and protocols.

      rawrs.py recon fullscan [IP range or list separated by commas]   Discover up hosts in an IP range; performs host discovery by various means, port detection and then service and common vuln detection on open ports.
      The default behaviour is to append new targets to already existing targets if multiple scans are performed. Use '-o' to overwrite existing targets.
      
      -o                                        Overwrite previous existing targets

    Protocol submenus:
      rawrs.py recon web                     web fingerprinting
      rawrs.py recon smb                     SMB-specific enumeration
      rawrs.py recon dns                     DNS analysis tools
      rawrs.py recon ssh                     SSH version and key gathering
      rawrs.py recon ftp                     FTP login/anon checks
      
    Examples:
    rawrs.py recon fullscan -o  192.168.1.0/24                                   Perform a fullscan on the provided CIDR. The detected hosts will overwrite any previosuly detected hosts.
    rawrs.py recon fullscan 192.168.1.1,192.168.1.2,192.168.1.3,192.168.1.4      Perform a fullscan on the provided list. Detected hosts will be appended to existing targets.
    '''

def run(args, config):
    if not args:
        print(helpmsg)
        return

    subcommand = args[0]
    subargs = args[1:]

    if subcommand == "fullscan":
        isoverwrite = False
        if not subargs:
            print(helpmsg)
            exit(1)
        if subargs[0] == '-o':
            del subargs[0]
            isoverwrite = True

        subargs = parse_ip_inputs(subargs)
        full_discovery(subargs, isoverwrite, config)


    elif subcommand == "web":
        tool = subargs[0]
        del subargs[0]
        web_scan(tool, subargs,config)

    elif subcommand == "dns":
        dns_scan(subargs, config)
    elif subcommand == "smb":
        smb_scan(subargs, config)
    elif subcommand == "ftp":
        ftp_scan(subargs, config)
    elif subcommand == "ssh":
        ssh_scan(subargs, config)
    else:
        print(f"Unknown scan subcommand: {subcommand}")
        print(helpmsg)



