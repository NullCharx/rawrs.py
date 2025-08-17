from ftplib import FTP, error_perm
from pathlib import Path
from socket import socket
from urllib.parse import urlparse

from core import context_manager
from reconenum.parser import parse_ftp_port_or_scheme, parse_ftp_list


def run_ftp_anon(args):
    """
    Perform a check for ftp anon login
    :param targets: List of target domains or IPs.
    :param nameserver: Optional DNS server to use.
    :return: None
    """
    output_dir = Path(context_manager.current_project) / "scans" / "ftp"
    output_dir.mkdir(parents=True, exist_ok=True)

    parsedtargets =  parse_ftp_list(args.targets, args.auto)
    check_ftp_anon(parsedtargets)

def check_ftp_anon(targets, timeout=5):

    """
    Given a target list presupoed to have been parsed as (s)ftp://ip:port for a valid (s)ftp enabled target and port,
    check if it allows anonymous login.
    """
    for target in targets:
        parsed = urlparse(target)
        target = parsed.hostname
        port = parsed.port
        try:
            ftp = FTP()
            ftp.connect(target, port, timeout=timeout)
            ftp.login("anonymous", "anonymous@domain.com")  # standard anon login (passord not required)
            print(f"[+] {target}:{port} allows anonymous login")
            ftp.quit()
            return True
        except error_perm:
            print(f"[-] {target}:{port} does NOT allow anonymous login")
        except (socket.timeout, socket.error) as e:
            print(f"[!] {target}:{port} connection error: {e}")
        except Exception as e:
            print(f"[!] {target}:{port} unexpected error: {e}")
        return False