import asyncio
import os

async def start_local_forward(user: str, host: str, remote_host: str, remote_port: int, local_host: str = "127.0.0.1", local_port: int = 0, port: int = 22, identity_file: str = None, password: str = None) -> asyncio.subprocess.Process:
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

    Returns:
    - asyncio.subprocess.Process running the SSH tunnel.

    Data Flow:
    Local Application -> Local Port -> SSH Tunnel -> Remote Host:Remote Port
    """
    cmd = ["ssh", "-p", str(port)]
    if identity_file:
        cmd += ["-i", identity_file]
    if password:
        if os.path.exists(password):
            cmd = ["sshpass", f"-f{password}"] + cmd
        else:
            cmd = ["sshpass", f"-p{password}"] + cmd
    cmd += ["-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3", "-o", "ExitOnForwardFailure=yes",
            "-nNT", "-L", f"{local_host}:{local_port}:{remote_host}:{remote_port}", f"{user}@{host}"]
    return await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=os.environ.copy())

async def start_remote_forward(user: str, host: str, local_target: str, local_port: int, remote_host: str = "127.0.0.1", remote_port: int = 0, port: int = 22, identity_file: str = None, password: str = None) -> asyncio.subprocess.Process:
    """
    Start a remote SSH port forward (remote port -> local port).

    Arguments:
    - user: SSH username for the remote host.
    - host: SSH server to connect to.
    - local_target: Local machine or service to expose.
    - local_port: Local port to forward.
    - remote_host: Remote interface to bind (default 127.0.0.1).
    - remote_port: Remote port to bind (0 for random available port).
    - port: SSH server port (default 22).
    - identity_file: Optional SSH private key file.

    Returns:
    - asyncio.subprocess.Process running the SSH tunnel.

    Data Flow:
    Remote Client -> Remote Port -> SSH Tunnel -> Local Target:Local Port
    """
    cmd = ["ssh", "-p", str(port)]
    if identity_file:
        cmd += ["-i", identity_file]
    if password:
        if os.path.exists(password):
            cmd = ["sshpass", f"-f{password}"] + cmd
        else:
            cmd = ["sshpass", f"-p{password}"] + cmd
    cmd += ["-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3", "-o", "ExitOnForwardFailure=yes",
            "-nNT", "-R", f"{remote_host}:{remote_port}:{local_target}:{local_port}", f"{user}@{host}"]
    return await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=os.environ.copy())

async def start_dynamic_socks(user: str, host: str, socks_host: str = "127.0.0.1", socks_port: int = 0, port: int = 22, identity_file: str = None, password: str = None) -> asyncio.subprocess.Process:
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
    cmd = ["ssh", "-p", str(port)]
    if identity_file:
        cmd += ["-i", identity_file]
    if password:
        if os.path.exists(password):
            cmd = ["sshpass", f"-f{password}"] + cmd
        else:
            cmd = ["sshpass", f"-p{password}"] + cmd
    cmd += ["-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3", "-o", "ExitOnForwardFailure=yes",
            "-N", "-D", f"{socks_host}:{socks_port}", f"{user}@{host}"]
    return await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=os.environ.copy())