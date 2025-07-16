import ipaddress
import re
from reconenum.nmap import outputparser
from reconenum.nmap import nmap
from reconenum.nmap.nmap import full_discovery

nmapregex = re.compile(r"fullscan")




def run(args, config):
    if not args:
        print('''
    Scan subtool for ports, services, and protocols.

      rawrs.py reconenum fullscan [IP range or list separated by commas]   Discover up hosts in an IP range; performs host discovery by various means, port detection and then service and common vulnd etection on open ports

    Protocol submenus:
      rawrs.py reconenum smb                     SMB-specific enumeration
      rawrs.py reconenum dns                     DNS analysis tools
      rawrs.py reconenum ssh                     SSH version and key gathering
      rawrs.py reconenum ftp                     FTP login/anon checks
    ''')
        return

    subcommand = args[0]
    subargs = args[1:]

    if subcommand == "fullscan":
        subargs = parse_input(subargs)
        print(subargs)
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


'''
Parse CIDR notation IP list or single IP. If there is a list, CIDRS are ignored
'''
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




