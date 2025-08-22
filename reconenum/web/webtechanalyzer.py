import os
import subprocess
from core import context_manager
from core.config import bcolors


#use system program instead pf pythonas its very linted
#make the web target parser, call it from outside here and pass it in to every web method
def whatwebexecutor(targets):
    """
    Calls whatweb executable with given targets- It can be a single target, or a list of targets.
    The list of targets can also be the projects target context to perform the --auto whatweb scan.
    Programatically it can check for any service web port on the target list but it for quickness web
    ports should be checked outside here

    :param targets: Web-parsed IPs
    :return: web targets that were able to be scanned, as not all http detected ports might actually have a webserver behing them
    """
    validtargets = []
    for target in targets:
        #Check if the target has a protocol scheme and remove the slahes off of it that would
        #make the path error (since slashes are used to indicate vertical FS movement)
        safestring = ""
        if "http" in target:
            safestring = "http:" + target[8:]
        elif "https" in target:
            safestring = "https:" + target[9:]
        else:
            safestring = target
        try:
            with open(f"{context_manager.current_project}/scans/webtech/whatweb_{safestring}.json", 'w+') as file:
                file.write("")
        except Exception as e:
            print(f"Exception opening {safestring}.json: {e}")
            pass
        wwcmd = ["whatweb", "-v", "-a 3", f"{target}",
             f"--log-json={context_manager.current_project}/scans/webtech/whatweb_{safestring}.json"]

        print(f"{bcolors.WARNING}[i] Running whatweb: {' '.join(wwcmd)}{bcolors.OKCYAN}")

        status = subprocess.run(
            wwcmd,
            stderr=subprocess.PIPE, capture_output=False, check=True)
        if status.stderr:
            print(status.stderr.decode())
            os.remove(f"{context_manager.current_project}/scans/webtech/whatweb_{safestring}.json")
        else:
            validtargets.append(target)
    return validtargets