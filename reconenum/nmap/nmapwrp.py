import asyncio
import subprocess


async def run_nmap_async(target):
    proc = await asyncio.create_subprocess_exec(
        "nmap", "-sn", target, f"-oX ./{target}scan",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    #Run  nmap-formatter json ./{target}scan
    #then mv to
    stdout, stderr = await proc.communicate()
    return stdout.decode(), stderr.decode()