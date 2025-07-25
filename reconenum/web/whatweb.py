import os
import subprocess



def whatwebexecutor(targets):
    """
    Calls whatweb executable with given targets- It can be a single target, or a list of targets.
    The list of targets can also be the projects target context to perform the --auto whatweb scan
    :param targets: IP, list of IPS or project target context
    :return:
    """
    print(targets)
    print("\n")
    if len(targets) > 1:
        for target in targets:
            services = targets.get(target, [])
            if services:
                for service in services:
                    if service.get("Service",[]) == "http" or service.get("Service",[]) == "https":
                        port=service.get("port",[])
                        try:
                            os.remove(f"./results/whatweb/{''.join(target)}:{port}.json")
                        except:
                            continue

                        status = subprocess.run(
                            ["whatweb", "-v", "-a 3", f"{target}:{port}",
                             f"--log-json=./results/whatweb/{''.join(target)}:{port}.json"],
                            stderr=subprocess.PIPE, capture_output=False, check=True)
                        if status.stderr:
                            print(status.stderr.decode())
                            os.remove(f"./results/whatweb/{''.join(target)}:{port}.json")
            else:
                status=subprocess.run(
                        ["whatweb", "-v", "-a 3", f"{target}", f"--log-json=./results/whatweb/{''.join(target)}.json"],
                        stderr=subprocess.PIPE,capture_output=False, check=True)
                if status.stderr:
                    print(status.stderr.decode())
                    os.remove(f"./results/whatweb/{''.join(target)}.json")
    else:
        subprocess.run(["whatweb","-v","-a 3"] + targets + [f"--log-json=./results/whatweb/{''.join(targets)}.json"], capture_output=False, check=True)
