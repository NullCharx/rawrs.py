import json
import subprocess
from ftplib import FTP, error_perm
from pathlib import Path
from socket import socket
from urllib.parse import urlparse

from rawrs.core import context_manager
from rawrs.core.globaldata import bcolors


def run_ftp_anon_check(targets, timeout=5):

    """
    Given a target list presupoed to have been parsed as (s)ftp://ip:port for a valid (s)ftp enabled target and port,
    check if it allows anonymous login.
    """
    output_dir = Path(context_manager.current_project) / "results"
    output_dir.mkdir(parents=True, exist_ok=True)
    anonlogintargets = {}
    for target in targets:
        print(f"\n{bcolors.YELLOW}[i] Trying ftp {target} with anonymous:password...{bcolors.OKCYAN}")

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



def run_enum4linux_ng(targets, username="", password="", domain="", workgroup="", shares_wordlist=None, timeout=300, verbose=False):
    """
    Run enum4linux-ng against a list of SMB targets.
    Each target should be formatted as smb://ip:port.
    Performs full enumeration (-A -R -d).
    Saves per-target JSON results into results/smb/[IP]_smb_full_enum.json.
    """

    output_dir = Path(context_manager.current_project) / "results" / "smb"
    output_dir.mkdir(parents=True, exist_ok=True)
    results = {}

    for target in targets:
        print(f"\n{bcolors.YELLOW}[i] Running enum4linux-ng against {target}...{bcolors.OKCYAN}")

        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port if parsed.port else 445  # default SMB

        # Build base command
        cmd = ["enum4linux-ng", host, "-A", "-R", "-d", "-P", str(port)]

        if username:
            cmd += ["-u", username]
        if password:
            cmd += ["-p", password]
        if domain:
            cmd += ["-w", domain]
        if workgroup:
            cmd += ["-w", workgroup]
        if shares_wordlist:
            cmd += ["-s", shares_wordlist]
        out_file = output_dir / f"{host}_smb_full_enum.json"
        cmd += ["-oJ", str(out_file)]
        if verbose:
            cmd += ["-v"]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

            if result.returncode != 0:
                print(f"{bcolors.WARNING}[!] enum4linux-ng failed on {host}:{port}: {result.stderr.strip()}{bcolors.RESET}")
                results[f"{host}:{port}"] = None
                continue

            try:
                with open(out_file, "r") as f:
                    data = json.load(f)
                print(f"{bcolors.OKGREEN}[+] JSON results saved: {out_file}{bcolors.RESET}")
                results[f"{host}:{port}"] = data
            except Exception as e:
                print(f"{bcolors.WARNING}[!] Could not parse JSON for {host}:{port}: {e}{bcolors.RESET}")
                results[f"{host}:{port}"] = result.stdout

        except subprocess.TimeoutExpired:
            print(f"{bcolors.WARNING}[!] Timeout on {host}:{port} after {timeout}s{bcolors.RESET}")
            results[f"{host}:{port}"] = None
        except Exception as e:
            print(f"{bcolors.WARNING}[!] Unexpected error on {host}:{port}: {e}{bcolors.RESET}")
            results[f"{host}:{port}"] = None

    return results