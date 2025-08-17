import json
from ftplib import FTP, error_perm
from lib2to3.fixes.fix_input import context
from pathlib import Path
from socket import socket
from urllib.parse import urlparse

from core import context_manager
from core.config import bcolors
from reconenum.parser import parse_ftp_port_or_scheme, parse_ftp_list


def run_ftp_anon_check(targets, timeout=5):

    """
    Given a target list presupoed to have been parsed as (s)ftp://ip:port for a valid (s)ftp enabled target and port,
    check if it allows anonymous login.
    """
    output_dir = Path(context_manager.current_project) / "results"
    output_dir.mkdir(parents=True, exist_ok=True)
    anonlogintargets = {}
    for target in targets:
        parsed = urlparse(target)
        target = parsed.hostname
        port = parsed.port
        try:
            ftp = FTP()
            ftp.connect(target, port, timeout=timeout)
            ftp.login("anonymous", "anonymous@domain.com")  # standard anon login (passord not required)
            print(f"{bcolors.OKGREEN}[+] {target}:{port} allows anonymous login{bcolors.RESET}")
            ftp.quit()
            anonlogintargets[f"{target}:{port}"] = True
        except error_perm:
            print(f"{bcolors.OKBLUE}[-] {target}:{port} does NOT allow anonymous login{bcolors.RESET}")
            anonlogintargets[f"{target}:{port}"] = False
        except socket.timeout as e:
            print(f"{bcolors.WARNING}[!] {target}:{port} connection error: {e}{bcolors.RESET}")
            anonlogintargets[f"{target}:{port}"] = False
        except Exception as e:
            print(f"{bcolors.WARNING}[!] {target}:{port} unexpected error: {e}{bcolors.RESET}")
            anonlogintargets[f"{target}:{port}"] = False

    with open(output_dir / "ftp_anon_login_list.json", "w") as f:
        json.dump(anonlogintargets, f, indent=2)