import ipaddress
import re
from reconenum.nmap import parser
from reconenum.nmap import nmap
from reconenum.nmap.nmap import full_discovery

def run(args, config):
    if not args:
        print('''
    Scan subtool for ports, services, and protocols.

      rawrs.py enum fullscan [IP range or list separated by commas]   Discover up hosts in an IP range; performs host discovery by various means, port detection and then service and common vuln detection on open ports.
      The default behaviour is to append new targets to already existing targets if multiple scans are performed. Use '-o' to overwrite existing targets.
      
      -o                                        Overwrite previous existing targets

    Protocol submenus:
      rawrs.py reconenum smb                     SMB-specific enumeration
      rawrs.py reconenum smb                     SMB-specific enumeration
      rawrs.py reconenum dns                     DNS analysis tools
      rawrs.py reconenum ssh                     SSH version and key gathering
      rawrs.py reconenum ftp                     FTP login/anon checks
      
    Examples:
    rawrs.py enum fullscan -o  192.168.1.0/24                                   Perform a fullscan on the provided CIDR. The detected hosts will overwrite any previosuly detected hosts.
    rawrs.py enum fullscan 192.168.1.1,192.168.1.2,192.168.1.3,192.168.1.4      Perform a fullscan on the provided list. Detected hosts will be appended to existing targets.
    ''')
        return

    subcommand = args[0]
    subargs = args[1:]

    if subcommand == "fullscan":
        isoverwrite = False
        if subargs[0] == '-o':
            del subargs[0]
            isoverwrite = True

        subargs = parse_input(subargs)
        full_discovery(subargs, isoverwrite, config)


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



import ipaddress

def parse_input(input_string):
    """
    Takes a list with one element (e.g., a CIDR or comma-separated IPs)
    or multiple elements (e.g., plain IP strings), and returns a list of IPs.
    CIDRs are expanded into all contained IPs.
    """
    if isinstance(input_string, str):
        input_string = [input_string]

    ips = []

    for entry in input_string:
        # Split by comma in case of comma-separated entries
        parts = [p.strip() for p in entry.split(',') if p.strip()]
        for part in parts:
            #Return the CIDR
            if '/' in part:
                return [part]
            else:
                #Get the parsed list and try to parse it before adding
                try:
                    ip = ipaddress.ip_address(part)
                    ips.append(str(ip))
                except ValueError as e:
                    raise ValueError(f"Invalid IP address '{part}': {e}")
    return ips




