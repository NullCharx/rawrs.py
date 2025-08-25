
import asyncio
import os
import platform

async def start_ligolo_proxy(listen: str = "0.0.0.0:11601", selfcert: bool = True, extra_args: list = None) -> asyncio.subprocess.Process:
    cmd = ["ligolo-proxy", "-l", listen]
    if selfcert:
        cmd += ["-selfcert"]
    if extra_args:
        cmd += extra_args
    return await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=os.environ.copy())

async def create_ligolo_tun(tun_name: str = "ligolo") -> None:
    if platform.system() != "Linux":
        return
    proc = await asyncio.create_subprocess_exec("ip", "tuntap", "add", tun_name, "mode", "tun", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out, err = await proc.communicate()
    if proc.returncode != 0 and "exists" not in out.decode() and "exists" not in err.decode():
        raise RuntimeError(f"Failed to create TUN: {err.decode()}")
    proc = await asyncio.create_subprocess_exec("ip", "link", "set", tun_name, "up", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out, err = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to set TUN up: {err.decode()}")

async def add_ligolo_route(cidr: str, tun_name: str = "ligolo", via: str = None) -> None:
    if platform.system() != "Linux":
        return
    cmd = ["ip", "route", "add", cidr, "dev", tun_name] if not via else ["ip", "route", "add", cidr, "via", via, "dev", tun_name]
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out, err = await proc.communicate()
    if proc.returncode != 0 and all(x not in out.decode() + err.decode() for x in ["File exists", "exists", "RTNETLINK"]):
        raise RuntimeError(f"Failed to add route {cidr}: {err.decode()}")