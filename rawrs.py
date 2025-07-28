import os
import random
import argparse
import shutil
import subprocess
import sys
from pathlib import Path

from core import context_manager
from core.config import bcolors, load_global_config, save_global_config
from core.context_manager import setcurrentenvproject
from core.project_manager.projects import create_project, checkdirectoryisproject
from reconenum.reconmain import initreconenumsubparsers, cmd_recon_nmapscan

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


def cmd_tunnel(args):
    setcurrentenvproject(args)
    if args.verbose < 2:
        print("[tunnel] (placeholder)")

def cmd_transfer(args):
    setcurrentenvproject(args)
    if args.verbose < 2:
        print("[transfer] (placeholder)")

def cmd_osint(args):
    setcurrentenvproject(args)
    if args.verbose < 2:
        print(f"[osint] target={args.target}")

def cmd_gui(args):
    setcurrentenvproject(args)
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
    common.add_argument("--project", default="cwd", help="Path to project to operate on. (Default asumes script is ran inside a rawrs.py project folder)")
    common.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity")

    # ===================== GUI =====================
    p_gui = menusubparser.add_parser("gui", parents=[common], help="Launch TUI/GUI mode")
    p_gui.set_defaults(func=cmd_gui)

    # ============ PORT / SERVICE ENUM ============

    initreconenumsubparsers(menusubparser, common)

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
def preparse_verbose(argv):
    """Parse ONLY -v/--verbose before the full parser exists."""
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("-v", "--verbose", action="count", default=0)
    # parse_known_args ignore the rest safely
    args, _ = pre.parse_known_args(argv)
    if not args.verbose:
        return 0
    return args.verbose

def init_environment(verbosity,config):
    if verbosity > 2:
        print(f"{bcolors.OKCYAN}Checking dependencies.{bcolors.RESET}")
    if not shutil.which("go"):
        if verbosity > 2:
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
        if verbosity > 2:
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
        if verbosity > 2:
            print(f"{bcolors.FAIL}[!] Seclists wasn't detected on common locations. Installing on /usr/share/SecLists.{bcolors.RESET}")
        if not shutil.which("git"):
            if verbosity > 2:
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
        if verbosity > 2:
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
        if verbosity > 2:
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
        if verbosity > 2:
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
        if verbosity > 2:
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
        if verbosity > 2:
            print(f"{bcolors.OKGREEN}[+] wapiti installed{bcolors.RESET}")

    #Create default project
    if not checkdirectoryisproject("cwd"):
        create_project(config["default_project"], verbosity, config)

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

    # -------- pre-parse verbosity --------
    verbosity = preparse_verbose(sys.argv[1:])
    #Init current environment
    config = load_global_config()
    init_environment(verbosity,config)
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