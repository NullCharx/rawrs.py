# Manager for cli arguments (no TGUI)
import sys

from reconenum import reconmain




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
