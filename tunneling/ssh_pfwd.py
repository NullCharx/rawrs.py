import asyncio
import os

from core import context_manager
from core.config import bcolors
from reconenum.parser import get_user_and_home_from_path


async def start_local_forward(user: str, host: str, local_host: str = "localhost", local_port: int = 0, remote_host: str = "0.0.0.0", remote_port: int = 0, identity_file: str = None, password: str = None, ) -> asyncio.subprocess.Process:
    """
    Start a local SSH port forward (local port -> remote port).

    Arguments:
    - user: SSH username for the remote host.
    - host: SSH server to connect to.
    - remote_host: Remote host to forward to (from the perspective of SSH server).
    - remote_port: Remote port to forward.
    - local_host: Local interface to bind the forwarded port (default 127.0.0.1).
    - local_port: Local port to bind (0 for random available port).
    - port: SSH server port (default 22).
    - identity_file: Optional SSH private key file.
    - password: Optional path to a file containing the password.
    Returns:
    - asyncio.subprocess.Process running the SSH tunnel.

    Data Flow:
    Local Application -> Local Port -> SSH Tunnel -> Remote Host:Remote Port
    """
    cmd = ["ssh"]
    if identity_file:
        cmd += ["-i", identity_file]
    else:
        cmd += ["-i",f"{get_user_and_home_from_path(f'{context_manager.current_project}')}/.ssh/id_ed25519"]
    if password:
        if os.path.exists(password[0]):
            cmd = ["sshpass", f"-f{password[0]}"] + cmd
        else:
            print("[!] Password file not found, using password directly is not recommended! Aborting.")
            exit(1)
    cmd += ["-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3", "-o", "ExitOnForwardFailure=yes",
            "-nNT", "-L", f"{local_host[0]}:{local_port[0]}:{remote_host[0]}:{remote_port[0]}", f"{user[0]}@{host[0]}"]
    print(f"{bcolors.OKGREEN}Running a direct tunnel to {bcolors.BOLD}{bcolors.WARNING}{remote_host[0]} port {remote_port[0]}{bcolors.RESET}{bcolors.OKGREEN} with credentials {bcolors.BOLD}{bcolors.WARNING}{user[0]}@{host[0]}{bcolors.RESET}{bcolors.OKGREEN}. Use {bcolors.BOLD}{bcolors.WARNING}{local_host[0]}:{local_port[0]}{bcolors.RESET} {bcolors.OKGREEN} to contact whatever service is on the remote host.")
    print(f"command:                  {bcolors.RESET}{' '.join(cmd)}{bcolors.RESET}")
    print(f"{bcolors.UNDERLINE}{bcolors.BOLD}If nothing pops on the screen and the script doesn't exit, the tunnel is working!{bcolors.RESET}")

    process = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=os.environ.copy())
    await process.wait()
    return process




async def start_reverse_forward(user: str, host: str, pivot_intra: str, pivot_port: int = 0, local_host: str = "0.0.0.0", local_port: int = 0, identity_file: str = None, password: str = None, ) -> asyncio.subprocess.Process:
    """
    Start a local SSH port forward (local port -> remote port).

    Arguments:
    - user: SSH username for the remote host.
    - host: SSH server to connect to.
    - remote_host: Remote host to forward to (from the perspective of SSH server).
    - remote_port: Remote port to forward.
    - local_host: Local interface to bind the forwarded port (default 127.0.0.1).
    - local_port: Local port to bind (0 for random available port).
    - port: SSH server port (default 22).
    - identity_file: Optional SSH private key file.
    - password: Optional path to a file containing the password.
    Returns:
    - asyncio.subprocess.Process running the SSH tunnel.

    Data Flow:
    Local Application -> Local Port -> SSH Tunnel -> Remote Host:Remote Port
    """
    cmd = ["ssh"]
    if identity_file:
        cmd += ["-i", identity_file]
    else:
        cmd += ["-i",f"{get_user_and_home_from_path(f'{context_manager.current_project}')}/.ssh/id_ed25519"]
    if password:
        if os.path.exists(password[0]):
            cmd = ["sshpass", f"-f{password[0]}"] + cmd
        else:
            print("[!] Password file not found, using password directly is not recommended! Aborting.")
            exit(1)
    cmd += ["-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3", "-o", "ExitOnForwardFailure=yes", "-o", "GatewayPorts=yes",
            "-nNT", "-R", f"{pivot_intra[0]}:{pivot_port[0]}:{local_host[0]}:{local_port[0]}", f"{user[0]}@{host[0]}"]
    print(f"{bcolors.OKGREEN}Running a reverse tunnel that will forward any data reaching pivot {bcolors.BOLD}{bcolors.WARNING}{pivot_intra[0]} port {pivot_port[0]}{bcolors.RESET}{bcolors.OKGREEN} with credentials {bcolors.BOLD}{bcolors.WARNING}{user[0]}@{host[0]}{bcolors.RESET}{bcolors.OKGREEN} to attacker {bcolors.BOLD}{bcolors.WARNING}{local_host[0]} port{local_port[0]}{bcolors.RESET} {bcolors.OKGREEN} that will \"output\" whatever data is sent from the target host through the pivot to the local port, i.e a reverse shell.")
    print(f"command:                  {bcolors.RESET}{' '.join(cmd)}{bcolors.RESET}")
    print(f"{bcolors.WARNING}{bcolors.BOLD}If the parameters are correct but the forwarding still fails (especially if using 0.0.0.0 as pivot IP), you need to specify GatewayPorts=yes on sshd_config{bcolors.RESET}")
    print(f"{bcolors.UNDERLINE}{bcolors.BOLD}If nothing pops on the screen and the script doesn't exit, the tunnel is working!{bcolors.RESET}")

    process = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=os.environ.copy())
    await process.wait()
    return process


async def start_dynamic_socks(user: str, host: str, socks_host: str = "127.0.0.1", socks_port: int = 0, identity_file: str = None, password: str = None, updateconfig : bool = False) -> asyncio.subprocess.Process:
    """
    Start a dynamic SOCKS proxy via SSH (-D option).

    Arguments:
    - user: SSH username.
    - host: SSH server.
    - socks_host: Local interface to bind SOCKS proxy (default 127.0.0.1).
    - socks_port: Local port for SOCKS proxy (0 for random available port).
    - port: SSH server port (default 22).
    - identity_file: Optional SSH private key file.

    Returns:
    - asyncio.subprocess.Process running the SOCKS proxy.

    Data Flow:
    Application -> SOCKS Proxy -> SSH Tunnel -> Remote Network
    """
    cmd = ["ssh"]
    if identity_file:
        cmd += ["-i", identity_file]
    else:
        cmd += ["-i", f"{get_user_and_home_from_path(f'{context_manager.current_project}')}/.ssh/id_ed25519"]
    if identity_file:
        cmd += ["-i", identity_file]
    if password:
        if os.path.exists(password):
            cmd = ["sshpass", f"-f{password}"] + cmd
        else:
            cmd = ["sshpass", f"-p{password}"] + cmd
    cmd += ["-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3", "-o", "ExitOnForwardFailure=yes",
            "-vvv", "-nNT", "-D", f"{socks_host[0]}:{socks_port[0]}", f"{user[0]}@{host[0]}"]

    if updateconfig:
        # Update proxychains configuration if requested
        proxychains_conf = f"/etc/proxychains.conf"
        if os.path.exists(proxychains_conf):
            with open(proxychains_conf, 'r') as file:
                lines = file.readlines()

            with open(proxychains_conf, "w") as file:
                file.writelines(lines[:-1])
                file.write(f"\n[ProxyList]\n# Add your dynamic forward here\nsocks5 {socks_host[0]} {socks_port[0]}\n")
            print(f"{bcolors.OKGREEN}Updated proxychains configuration to use SOCKS proxy at {socks_host[0]}:{socks_port[0]}{bcolors.RESET}")
        else:
            print(f"{bcolors.WARNING}Proxychains configuration file not found, skipping update.{bcolors.RESET}")

    print(f"{bcolors.OKGREEN}Running a reverse dynamic tunne that will forward any data sent via proxychains through {socks_host[0]} port {socks_port[0]}{bcolors.RESET}{bcolors.OKGREEN} with credentials {bcolors.BOLD}{bcolors.WARNING}{user[0]}@{host[0]}{bcolors.RESET}{bcolors.OKGREEN}, masking the data flow as if it was coming from the pivot machine.")
    print(f"command:                  {bcolors.RESET}{' '.join(cmd)}{bcolors.RESET}")
    print(f"{bcolors.UNDERLINE}{bcolors.BOLD}Need to add the following line to /etc/proxychains.conf if you didnt already:\n"
          f"socks5 {socks_host} {socks_port[0]} {bcolors.RESET[0]}")

    return await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=os.environ.copy())