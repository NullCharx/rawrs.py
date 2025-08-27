import subprocess
from pathlib import Path
from urllib.parse import urlparse
import socket

from impacket.smbconnection import SMBConnection

from rawrs.core import context_manager
from rawrs.core.globaldata import bcolors


def run_smb_anon_check(targets, timeout=5, verbose:int= 0, auto:bool=False):
    """
    Given a target list presupposed to have been parsed as smb://ip:port,
    check if it allows anonymous login.
    """
    output_dir = Path(context_manager.current_project) / "scans" / "smb"
    output_dir.mkdir(parents=True, exist_ok=True)

    anonlogintargets = {}
    for target in targets:
        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port or 445  # default SMB port
        print(f"\n{bcolors.YELLOW}[i] Trying smb {host}:{port} with anonymous credentials. here are some commands use to login anonimously:...")
        print(f"\n{bcolors.WARNING}[i] smbclient -L //{host}:{port}")
        print(f"\n{bcolors.WARNING}[i] smbmap -H {host}:{port} -u "" -p """)
        print(f"\n{bcolors.WARNING}[i] cme smb {host}:{port} -u '' -p '' / netexec smb {target} -u '' -p '' {bcolors.OKCYAN}")

        try:
            # Impacket SMBConnection args: remoteName, remoteHost, sess_port, timeout
            smb = SMBConnection(remoteName=host, remoteHost=host, sess_port=port, timeout=timeout)
            smb.login('', '')  # anonymous = empty user/pass

            print(f"{bcolors.OKGREEN}[+] {host}:{port} allows anonymous login{bcolors.RESET}")
            anonlogintargets[f"{host}:{port}"] = True
            smb.logoff()

        except Exception as e:
            # Failures include STATUS_LOGON_FAILURE and timeouts
            if isinstance(e, socket.timeout):
                print(f"{bcolors.WARNING}[!] {host}:{port} connection timeout{bcolors.RESET}")
            else:
                print(f"{bcolors.FAIL}[-] {host}:{port} does NOT allow anonymous login ({e}){bcolors.RESET}")
            anonlogintargets[f"{host}:{port}"] = False

    return anonlogintargets


def run_smb_full_enum(targets,verbose : int =0):
    """
    Run full SMB enumeration (-A) on a list of targets using enum4linux-ng.
    Saves results into scans/smb folder.
    """
    output_dir = Path(context_manager.current_project) / "scans" / "fuzz"
    output_dir.mkdir(parents=True, exist_ok=True)

    results = {}
    for target in targets:
        parsed = urlparse(target)
        host = parsed.hostname or target

        cmd = [
            "enum4linux-ng",
            f"{host}", "-A",
            "-oJ", f"{context_manager.current_project}/scans/smb/enum4linux_{host}",
            "-R", "-C", "-v"]
        print(f"\n[*] Running enum4linux-ng: f{''.join(cmd)}")

        result = subprocess.run(cmd, capture_output=False if verbose>1 else True)
        if result.returncode != 0:
            print(f"[!] enum4linux-ng failed on {target}: {result.stderr.strip()}")
            return None

    return results

