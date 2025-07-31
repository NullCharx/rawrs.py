import os
import subprocess
from core import context_manager


#use system program instead pf pythonas its very linted
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
            target = ''.join(target)
            safestring = ""
            if "http" in target:
                safestring = "http:" + target[8:]
            elif "https" in target:
                safestring = "https:" + target[8:]
            else:
                safestring = target

            try:
                with open(f"{context_manager.current_project}/scans/webtech/whatweb_{safestring}.json", 'w') as file:
                    file.write("")
            except FileExistsError:
                pass

            status = subprocess.run(
                ["whatweb", "-v", "-a 3", f"{target}",
                 f"--log-json={context_manager.current_project}/scans/webtech/whatweb_{safestring}.json"],
                stderr=subprocess.PIPE, capture_output=False, check=True)
            if status.stderr:
                print(status.stderr.decode())
                os.remove(f"{context_manager.current_project}/scans/webtech/whatweb_{safestring}.json")
                targets.remove(target)
    else:
        status = subprocess.run(["whatweb", "-v", "-a 3"] + targets + [
            f"--log-json={context_manager.current_project}/scans/webtech/whatweb_{''.join(targets[0])}.json"],
                                stderr=subprocess.PIPE, capture_output=False, check=True)
        if status.stderr:
            print(status.stderr.decode())
            os.remove(f"{context_manager.current_project}/scans/webtech/whatweb_{''.join(targets[0])}.json")
