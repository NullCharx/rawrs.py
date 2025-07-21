import os
import subprocess


def whatwebexecutor(targets):
    print(os.getcwd())
    subprocess.run(["whatweb","-v","-a 3"] + targets + [f"--log-json=./results/whatweb/{''.join(targets)}.json"], capture_output=False, check=True)
