import os
import subprocess



def whatwebexecutor(targets) -> list:
    """
    Calls whatweb executable with given targets- It can be a single target, or a list of targets.
    The list of targets can also be the projects target context to perform the --auto whatweb scan
    :param targets: IP, list of IPS or project target context
    :return: a list with the target ips and ports that were scan to parse after
    """
    scannedlist = []
    if len(targets) > 1:
        for target in targets:
            services = targets.get(target, [])
            if services:
                for service in services:
                    if service.get("Service",[]) == "http" or service.get("Service",[]) == "https":
                        port=service.get("port",[])
                        try:
                            os.remove(f"./scans/whatweb/{''.join(target)}:{port}.json")
                        except:
                            pass

                        scannedlist.append(f"{target}:{port}")
                        status = subprocess.run(
                            ["whatweb", "-v", "-a 3", f"{target}:{port}",
                             f"--log-json=./scans/whatweb/{''.join(target)}:{port}.json"],
                            stderr=subprocess.PIPE, capture_output=False, check=True)
                        if status.stderr:
                            print(status.stderr.decode())
                            os.remove(f"./scans/whatweb/{''.join(target)}:{port}.json")
            else:
                scannedlist.append(target)
                status=subprocess.run(
                        ["whatweb", "-v", "-a 3", f"{target}", f"--log-json=./scans/whatweb/{''.join(target)}.json"],
                        stderr=subprocess.PIPE,capture_output=False, check=True)
                if status.stderr:
                    print(status.stderr.decode())
                    os.remove(f"./scans/whatweb/{''.join(target)}.json")
    else:
        scannedlist.append(targets[0])
        subprocess.run(["whatweb","-v","-a 3"] + targets + [f"--log-json=./scans/whatweb/{''.join(targets)}.json"], capture_output=False, check=True)
    return scannedlist

