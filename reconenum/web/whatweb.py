import os
import subprocess

from core import context_manager


#make the web target parser, call it from outside here and pass it in to every web method
def whatwebexecutor(targets):
    """
    Calls whatweb executable with given targets- It can be a single target, or a list of targets.
    The list of targets can also be the projects target context to perform the --auto whatweb scan.
    Programatically it can check for any service web port on the target list but it for quickness web
    ports should be checked outside here

    :param targets: Web-parsed IPs
    :return:
    """
    if len(targets) > 1:
        for target in targets:
            status = subprocess.run(
                ["whatweb", "-v", "-a 3", f"{target}",
                 f"--log-json={context_manager.current_project}/scans/whatweb/{''.join(target)}.json"],
                stderr=subprocess.PIPE, capture_output=False, check=True)
            if status.stderr:
                print(status.stderr.decode())
                os.remove(f"{context_manager.current_project}/scans/whatweb/{''.join(target)}.json")
    else:
        status = subprocess.run(["whatweb", "-v", "-a 3"] + targets + [
            f"--log-json={context_manager.current_project}/scans/whatweb/{''.join(targets)}.json"],
                                stderr=subprocess.PIPE, capture_output=False, check=True)
        if status.stderr:
            print(status.stderr.decode())
            os.remove(f"{context_manager.current_project}/scans/whatweb/{''.join(targets[0])}.json")