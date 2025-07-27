import os
import random
import argparse
import shutil
import subprocess
import sys
from pathlib import Path

from core import context_manager
from core.config import bcolors, load_global_config, save_global_config
from core.project_manager.projects import create_project, checkdirectoryisproject
from reconenum.nmap.nmap import cmd_recon_fullscan

splash = ["""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⡇⠀⠀⠀⠀⠚⠉⠈⠓⣦⡀⠀⠀⠀⠀⠀⠀⡿⠀⠀⠀⠀⠀⢻⡄⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠖⠋⠉⠀⠈⠙⠳⣄⠀⠀⠀⠀⠀⠀⠈⣷⠀⠀⠀⠀⠀⢸⠇⠀⠀⠀⠀⠀⠈⠃⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠞⠁⠀⠀⠀⠀⠀⠀⠀⠙⢧⡀⠀⠀⣀⡠⠀⠙⣇⠀⠀⠀⠀⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣠⠤⠴⠿⠒⠒⠒⠒⠒⠒⠒⠶⠤⠤⠬⣷⣄⣀⠈⠀⠀⠀⠹⣆⠀⠀⠀⠃⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠴⠚⠋⠁⠀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠓⠶⢤⣄⡿⠀⡴⠣⠔⠛⠗⠶⠀⢀⣀⣄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠛⠁⠀⢀⣤⣶⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣶⣶⣄⡀⠀⠀⠈⠙⠳⣧⣤⠴⠒⠚⠋⠉⠉⠉⠙⠳⢶⣄⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡼⠋⠀⠀⠀⠀⠺⣿⡿⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠿⣿⣿⡄⠀⠀⠀⠀⠀⠙⢶⣄⠀⠀⠀⠀⠀⠀⠀⠀⠹⣧
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠛⠁⠀⠀⠀⠀⠀⠀⠀⠙⢷⡄⠀⠀⠀⠀⠀⠀⠀⢻
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣦⠀⠀⠀⠀⠀⠀⢸
⠀⠀⠀⢀⠀⢠⡄⠀⠀⢠⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢧⠀⠀⠀⠀⠀⣿
⠀⠀⠀⣾⠇⠀⢣⠀⠀⣼⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣶⣶⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣧⠀⠀⠀⢰⠇
⠀⠀⣼⠟⠀⢀⢸⡆⢀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠺⠋⠹⣿⣿⡟⠻⠖⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⣶⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⡆⠀⢠⡟⠀
⠀⢰⠃⢀⠈⠀⡾⡇⣸⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠛⠛⣿⣿⣿⠻⠶⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣇⢠⡟⠀⠀
⠀⣼⠀⠀⢀⣠⠾⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⢸⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠊⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠏⠀⠀⠀
⢠⡏⢀⣴⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡼⠲⠶⢶⣶⣒⣒⠒⠲⢶⣒⢒⣶⡶⢤⣄⣀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀
⠈⢀⡾⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠀⠀⠀⠀⠀⠈⠉⠉⠙⠒⠛⠛⠓⠒⠒⠒⠛⠛⠛⠒⠒⠒⠚⢻⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡾⠀⠀⠀⠘
⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠉⠀
⢸⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢽⢦⣀⡀⠀⣀⣴⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⠇⠀⠀⠀⣄
⢸⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣤⡀⠀⠀⢀⡿⠀⠀⠠⠄⠀
⢸⡄⠀⢀⣴⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠟⠿⣦⣀⣸⠁⠀⠀⠀⠀⢠
⢸⣷⡾⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡄⠀⠀⠀⠀⠈⣻⠇⠀⠀⠀⠀⠀⠀
⠘⠿⣆⠀⠀⠀⠀⠀⣠⣶⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠘⢿⣦⠀⠀⢀⡴⠋⠀⠀⠀⠀⠀⠀⢀
⠀⠀⠘⢧⡀⠀⣠⣾⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣷⡀⠀⠀⠀⠀⠙⣷⣤⠟⠁⠀⠀⠀⢠⡄⠀⣠⡟
⠀⠀⠀⠀⠙⢾⣟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⡄⠀⠀⣠⡴⢛⣥⡀⠀⠀⠀⣀⣸⣯⢄⣥⣶
⠀⠀⠀⠀⠀⠀⠈⠙⠲⢦⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣨⡿⠖⠛⠉⠀⠀⣀⣤⣀⣙⠙⠉⠉⠉⠉⠉⠋
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠛⠓⠲⠶⠶⠦⠤⣤⣤⣀⡀⠀⠀⠀⠀⠀⣀⣀⣀⣀⣀⣀⣠⡤⠴⠶⠶⠚⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠳⣄⡀⠀⠀⠀⠀
⠀⠀⠀⠀⣀⡀⠺⣆⠀⠀⠀⣀⣄⠀⠀⠀⠀⠀⠀⠀⢀⣠⣾⠷⠖⠚⠛⠋⣩⣽⣿⣿⣷⣦⡀⣀⡀⠀⠀⠀⢀⡀⠀⠀⠀⠐⠒⠦⢤⣍⣅⡂⠀⠠⠀⠈⠩⠿⠶⠶⠆
⠀⠀⠀⠀⠀⠈⢀⣈⣃⣀⡞⠁⢈⡇⠲⠛⠋⠉⠉⢰⠟⠁⣟⢀⣀⣀⣤⣴⣿⢽⠟⠛⠻⣿⠇⠀⠉⠳⠦⣴⡟⠙⢷⣄⡀⠀⠀⠀⠀⣀⣀⡈⠛⣂⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢠⡴⠋⠋⠉⢉⣿⡀⢿⣁⠈⠁⠢⠀⣴⠋⠀⢠⡟⠛⠛⠶⠶⣾⡟⢸⣆⠀⠀⠘⣧⠀⠀⠀⠀⠈⣷⣄⣸⠛⠛⠓⢦⣍⠉⠉⠉⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢀⡰⣿⡵⢛⣦⡄⠈⠉⠁⠀⠙⢷⣄⣠⡼⠃⠀⠀⣼⠇⠀⠀⠀⠀⠀⠀⢸⣿⡆⠀⠀⠘⣦⡀⣀⡴⠟⠉⠘⠛⠃⣠⡠⣴⣽⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠘⠳⠿⠥⠤⢾⡏⠀⠀⠀⠀⠈⠙⡇⠀⠀⣰⡿⠀⠀⠀⠀⠀⠀⠀⢰⡿⢹⣆⠀⠀⣼⠋⠉⠀⠀⠀⠀⣷⣄⣈⣹⣶⡿⠇⠀⠈⠛⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
""", """
                                                                                 
                                                                                 
                             @@@@@@@                                 
                           @@@     @@                                
                          @@         @                               
                                   @@@@@@@@                          
                @@@@  @@@@@@               @@@@                      
              @@@   @@@@@@@@                   @ @@@@@@@@@@          
             @@                           @@@@@@          @@         
           @@    @@        @                  @@@@ @        @        
          @@    @   @@@@@@   @                      @        @       
          @    @  @@@@@@@@@  @                       @       @       
         @    @   @@@@@@@@@@  @               @@      @      @       
         @    @  @@@@@@@@@@@  @             @@         @    @        
        @     @  @@@@@@@@@@@  @          @@             @  @         
      @@@@    @  @@@@@@@@@@@  @       @@                @ @@         
   @@@        @  @@@@@@@@@@@  @    @@                    @           
   @          @   @@@@@@@@@          @@@@@@@@@@@@@@      @           
 @@           @@   @@@@@@@   @                           @           
 @              @           @                            @           
 @                @@@@@@@@@@@@@@                        @            
@                  @    @@@      @                      @            
@                  @@     @@@@@                        @             
 @  @               @@@@@      @                @      @             
 @@                 @            @                @  @@              
  @      @          @@      @@   @          @       @@               
   @   @@            @  @@     @@@           @     @                 
    @@@               @@       @@      @      @ @@@                  
       @@@              @@@@@@@              @@@                     
         @@@@@@                         @@@@@                        
              @@@@@@@@@@@@@@@@@@@@@@@@@@                             
"""]


def cmd_recon_web(args):
    if args.verbose < 2:
        print(f"[recon:web] project={args.project} verbose={args.verbose}")

def cmd_recon_smb(args):
    if args.verbose < 2:
        print(f"[recon:smb] project={args.project}")

def cmd_recon_dns(args):
    if args.verbose < 2:
        print(f"[recon:dns] project={args.project}")

def cmd_recon_ssh(args):
    if args.verbose < 2:
        print(f"[recon:ssh] project={args.project}")

def cmd_recon_ftp(args):
    if args.verbose < 2:
        print(f"[recon:ftp] project={args.project}")

def cmd_tunnel(args):
    if args.verbose < 2:
        print("[tunnel] (placeholder)")

def cmd_transfer(args):
    if args.verbose < 2:
        print("[transfer] (placeholder)")

def cmd_osint(args):
    if args.verbose < 2:
        print(f"[osint] target={args.target}")

def cmd_gui(args):
    if args.verbose < 2:
        print("[gui] launching... (placeholder)")



# -------------------------------------------------
# Parser builder
# -------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    mainparser = argparse.ArgumentParser(
        prog="rawrs.py",
        description="A tool to automate repetitive recon and scanning tasks (OSCP-style).",
    )
    menusubparser = mainparser.add_subparsers(dest="command", required=True)

    # -------- shared/common options for most subtools --------
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--project", default="cwd", help="Project name to operate on. (Default asumes scrip is ran inside a rawrs.py project folder)")
    common.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity")

    # ===================== GUI =====================
    p_gui = menusubparser.add_parser("gui", help="Launch TUI/GUI mode")
    p_gui.set_defaults(func=cmd_gui)

    # ===================== RECON =====================
    p_recon = menusubparser.add_parser(
        "recon",
        help="Port/service scans & protocol-specific enumeration",
        description=(
            "Scan subtool for ports, services, and protocols.\n\n"
            "Examples:\n"
            "  rawrs.py recon fullscan -o 192.168.1.0/24\n"
            "  rawrs.py recon fullscan 192.168.1.1,192.168.1.2\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    recon_sub = p_recon.add_subparsers(dest="recon_cmd", required=True)

    # fullscan
    p_full = recon_sub.add_parser(
        "fullscan",
        parents=[common],
        help="Host, port and service discovery (-sVC)."
    )
    p_full.add_argument(
        "-o", "--overwrite",
        action="store_true",
        help="Overwrite previous existing targets instead of appending"
    )
    p_full.add_argument(
        "targets",
        help="IP range in CIDR or comma-separated list of IPs"
    )
    p_full.set_defaults(func=cmd_recon_fullscan)

    # protocol submenus
    p_web = recon_sub.add_parser("web", parents=[common], help="Web fingerprinting")
    p_web.set_defaults(func=cmd_recon_web)

    p_smb = recon_sub.add_parser("smb", parents=[common], help="SMB-specific enumeration")
    p_smb.set_defaults(func=cmd_recon_smb)

    p_dns = recon_sub.add_parser("dns", parents=[common], help="DNS analysis tools")
    p_dns.set_defaults(func=cmd_recon_dns)

    p_ssh = recon_sub.add_parser("ssh", parents=[common], help="SSH version/key gathering")
    p_ssh.set_defaults(func=cmd_recon_ssh)

    p_ftp = recon_sub.add_parser("ftp", parents=[common], help="FTP login/anon checks")
    p_ftp.set_defaults(func=cmd_recon_ftp)

    # ===================== TUNNEL =====================
    p_tunnel = menusubparser.add_parser("tunnel", parents=[common], help="Tunneling, pivoting, proxies")
    # you can add tunnel subcommands here with p_tunnel.add_subparsers(...)
    p_tunnel.set_defaults(func=cmd_tunnel)

    # ===================== TRANSFER =====================
    p_transfer = menusubparser.add_parser("transfer", parents=[common], help="Transfer tools/files")
    p_transfer.set_defaults(func=cmd_transfer)

    # ===================== OSINT =====================
    p_osint = menusubparser.add_parser("osint", parents=[common], help="Passive info gathering")
    p_osint.add_argument("--target", required=True)
    p_osint.set_defaults(func=cmd_osint)

    return mainparser

def init_environment(config):
    print(f"{bcolors.OKCYAN}Checking dependencies.{bcolors.RESET}")
    if not shutil.which("go"):
        print(f"{bcolors.FAIL}[-] Go is not installed or not in PATH. Trying to install.{bcolors.RESET}")
        try:
            result = subprocess.run(
                ["apt", "install", "golang"],
                capture_output=False,
            )
        except Exception:
            print(f"{bcolors.FAIL}[!] Golang couldn't be installed. Please manually install go as its needed by some subtools.{bcolors.RESET}")
            exit(1)
    #go and nmap-formatter
    try:
        env = os.environ.copy()
        env["CC"] = "/usr/bin/gcc"
        result = subprocess.run(
            ["go", "install", "github.com/vdjagilev/nmap-formatter/v3@latest"],
            capture_output=True,
            text=True,
            env=env,
            check=True
        )
        print(f"{bcolors.OKGREEN}[+] nmap-formatter installed succesfully or already installed.{result.stdout}{bcolors.RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{bcolors.FAIL}[!] Failed to install Go package:\n{e.stderr}{bcolors.RESET}")
        exit(1)
    except FileNotFoundError:
        print(f"{bcolors.FAIL}[!] Go is not installed or not in PATH.{bcolors.RESET}")
        exit(1)
    context_manager.projects_path = Path(config["projects_dir"])

    #Seclists
    if not os.path.exists("/usr/share/wordlists/SecLists") and not os.path.exists("/usr/share/SecLists"):
        print(f"{bcolors.FAIL}[!] Seclists wasn't detected on common locations. Installing on /usr/share/SecLists.{bcolors.RESET}")
        if not shutil.which("git"):
            print(f"{bcolors.FAIL}[-] git is not installed or not in PATH. Trying to install.{bcolors.RESET}")
            try:
                result = subprocess.run(
                    ["apt", "install", "git"],
                    capture_output=False,
                )
            except Exception:
                print(f"{bcolors.FAIL}[!] Git couldn't be installed. Please manually install git as its needed to insall SecLists.{bcolors.RESET}")
                exit(1)
        try:
            result = subprocess.run(
                ["git", "clone", "https://github.com/danielmiessler/SecLists.git"],
                capture_output=False,
                cwd="/usr/share/"
            )
        except Exception:
            print(f"{bcolors.FAIL}[!] Git couldn't be installed. Please manually install git as its needed to install SecLists.{bcolors.RESET}")
            exit(1)
    else:
        print(f"{bcolors.OKGREEN}[+] SecList detected. Checking and installing updates. . .{bcolors.RESET}")
        try:
            result = subprocess.run(
                ["git", "pull"],
                capture_output=False,
                cwd="/usr/share/SecLists"
            )
        except Exception:
            print(f"{bcolors.FAIL}[!] Git couldn't be installed. Please manually install git as its needed to insall SecLists.{bcolors.RESET}")
            exit(1)

    #Dirb
    if not shutil.which("dirb"):
        try:
            result = subprocess.run(
                ["apt", "install", "dirb"],
                capture_output=False,
            )
        except Exception:
            print(f"{bcolors.FAIL}[!] Dirb couldn't be installed. Please manually dirb go as its needed by some subtools.{bcolors.RESET}")
            exit(1)
    else:
        print(f"{bcolors.OKGREEN}[+] Dirb installed{bcolors.RESET}")

    #ffuf
    if not shutil.which("ffuf"):
        try:
            result = subprocess.run(
                ["apt", "install", "ffuf"],
                capture_output=False,
            )
        except Exception:
            print(f"{bcolors.FAIL}[!] ffuf couldn't be installed. Please manually install ffuf go as its needed by some subtools.{bcolors.RESET}")
            exit(1)
    else:
        print(f"{bcolors.OKGREEN}[+] ffuf installed{bcolors.RESET}")

    #fzf
    if not shutil.which("fzf"):
        try:
            result = subprocess.run(
                ["apt", "install", "fzf"],
                capture_output=False,
            )
        except Exception:
            print(f"{bcolors.FAIL}[!] fzf couldn't be installed. Please manually install fzf go as its needed by some subtools.{bcolors.RESET}")
            exit(1)
    else:
        print(f"{bcolors.OKGREEN}[+] fzf installed{bcolors.RESET}")

    if not shutil.which("wapiti"):
        try:
            result = subprocess.run(
                ["apt", "install", "wapiti"],
                capture_output=False,
            )
        except Exception:
            print(f"{bcolors.FAIL}[!] wapiti couldn't be installed. Please manually install wapiti go as its needed by some subtools.{bcolors.RESET}")
            exit(1)
    else:
        print(f"{bcolors.OKGREEN}[+] wapiti installed{bcolors.RESET}")

    #Create default project
    if not checkdirectoryisproject("cwd"):
        create_project(config["default_project"], config)

# -------------------------------------------------
# Main
# -------------------------------------------------
def main():
    #Splash
    print(f"{bcolors.OKBLUE}{bcolors.BOLD}{random.choice(splash)}{bcolors.ENDC}")
    print(f"{bcolors.OKBLUE}Really Awesome Recon And Scan tool (RAWRS) 0.2.a{bcolors.ENDC}")

    #Check sudo
    if os.getuid() != 0:
        print(
            f"{bcolors.FAIL}Due to the nature of some commands (like nmap stealth scan) this script needs to be ran as sudo{bcolors.RESET}")
        exit(10)

    #Init current environment
    config = load_global_config()
    init_environment(config)
    save_global_config(config)
    print(f"\n{bcolors.OKCYAN}[+] Toolkit environment is ready.{bcolors.RESET}")
    print(f"______________________________________________________________________")

    #Build supbparsers
    parser = build_parser()
    args = parser.parse_args(sys.argv[1:])

    # Dispatch arguments
    if hasattr(args, "func"):
        return args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()