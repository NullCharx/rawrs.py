import os
import subprocess
import tempfile


def whatwebexecutor(targets):
    #check if the base parser is called??
    print(targets)
    print(' '.join(targets))
    if len(targets) > 1:
        for target in targets:

            status=subprocess.run(
                    ["whatweb", "-v", "-a 3", f"{target}", f"--log-json=./results/whatweb/{''.join(target)}.json"],
                    stderr=subprocess.PIPE,capture_output=False, check=True)
            if status.stderr:
                print(status.stderr.decode())
                os.remove(f"./results/whatweb/{''.join(target)}.json")
    else:
        print("wewew")
        subprocess.run(["whatweb","-v","-a 3"] + targets + [f"--log-json=./results/whatweb/{''.join(targets)}.json"], capture_output=False, check=True)
