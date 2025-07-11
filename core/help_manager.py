# Manager for cli arguments (no TGUI)
import sys
general_help = '''
Really Awesome Recon and Scan Tool (RAWRS)

A tool intended to automate repetitive recon and scanning tasks,
especially focused on OSCP-style workflows.

Main subcommands:
  rawrs.py scan       -> Port and service scanning utilities
  rawrs.py tunnel     -> Tunneling and proxy setup
  rawrs.py osint      -> Passive information gathering
'''

main_arguments =  {
    "scan": '''
    Scan subtool for ports, services, and protocols.

    Discovery commands:
      rawrs.py scan hdiscovery [IP range]   Discover up hosts in an IP range
      rawrs.py scan pdiscovery [IP]         Discover open ports using various scans
      rawrs.py scan sdiscovery [IP]         Identify services and known vulnerabilities
      rawrs.py scan fdiscovery [IP range]   Full scan: hosts + ports + services

    Protocol submenus:
      rawrs.py scan smb                     SMB-specific enumeration
      rawrs.py scan dns                     DNS analysis tools
      rawrs.py scan ssh                     SSH version and key gathering
      rawrs.py scan ftp                     FTP login/anon checks
    ''',

    "tunnel": '''
    Tunneling subtool: Set up simple or advanced tunnels.

    Tunneling commands:
      rawrs.py tunnel direct [LPORT] [RIP] [RPORT]    Direct local→remote TCP tunnel
      rawrs.py tunnel reverse [LPORT] [RIP] [RPORT]   Reverse tunnel for callback shells
      rawrs.py tunnel proxy [LPORT] [RIP] [RPORT]     SSH-based SOCKS proxy
      rawrs.py tunnel ligolo                          Launch Ligolo tunneling agent
    ''',

    "osint": '''
    OSINT subtool: passive reconnaissance and info gathering.

    Commands:
      rawrs.py osint domain [DOMAIN]       Lookup DNS records, WHOIS, and leaks
      rawrs.py osint email [EMAIL]         Check breaches, Gravatar, public profiles
      rawrs.py osint ip [IP]               Enrich IPs with threat feeds, open ports
    '''
}
def mainarghelpmessage(command=None):
    if command is None or command not in main_arguments:
        print(general_help)
        exit(2)



def scanarguments(command=None):
    if command is None or command not in main_arguments:
        print(main_arguments.get(command))
