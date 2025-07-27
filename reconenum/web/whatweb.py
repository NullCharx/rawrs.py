import os
import subprocess

from reconenum.parser import parse_whatweb_results


#make the web target parser, call it from outside here and pass it in to every web method
def whatwebexecutor(targets):
    """
    Calls whatweb executable with given targets- It can be a single target, or a list of targets.
    The list of targets can also be the projects target context to perform the --auto whatweb scan.
    Programatically it can check for any service web port on the target list but it for quickness web
    ports should be checked outside here

    :param targets: IP, list of IPS or project target context
    :return:
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
    parse_whatweb_results(scannedlist)




