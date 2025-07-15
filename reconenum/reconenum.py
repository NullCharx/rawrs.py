import ipaddress
import re
from reconenum.nmap import outputparser
from reconenum.nmap import nmap

nmapregex = re.compile(r"fullscan")


def full_discovery(subargs, config):
    pass


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
        print(subargs)
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
def parse_input(input_string):

    if len(input_string) == 1:
        parts = [p.strip() for p in input_string[0].split(',') if p.strip()]

        # Case: First element is CIDR or single IP is provided
        if len(parts) == 1 or '/' in parts[0]:
            return parts[0]
        # list of ips discarding any CIDR
        else:
            ips = []
            for p in parts:
                if '/' in p:
                    continue
                try:
                    ip = ipaddress.ip_address(p)
                    ips.append(str(ip))
                except ValueError as e:
                    raise ValueError(f"Invalid IP address '{p}': {e}")
            return ips
    else:
        ips = []
        for string in input_string:
            ips.append(string.replace(',', ''))
        return ips




