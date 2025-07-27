# Manager for cli arguments (no TGUI)
import sys

from reconenum import reconenum

general_help = '''
Really Awesome Recon and Scan Tool (RAWRS)

A tool intended to automate repetitive recon and scanning tasks,
especially focused on OSCP-style workflows.

Main subcommands:
  rawrs.py --gui      -> Launch the Terminal GUI mode (experimental)

  rawrs.py recon       -> Port and service scanning utilities
  rawrs.py tunnel     -> Tunneling pivoting and proxy setup
  rawrs.py transfer   -> Transfer tools between host and victim
  rawrs.py osint      -> Passive information gathering
'''


def mainarghelpmessage(command=None):
    if command is None or command not in command_map:
        print(general_help)
        exit(2)


command_map = {
    "enum": reconenum.run,
    "tunnel": print("awa"),
    "osint": print("awaawa"),
    # optionally add "add-host", "exit", etc.
}

a = {
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
