import os
import shutil
import subprocess
import sys
from pathlib import Path

from core import context_manager
from core.commands_manager import mainarghelpmessage, command_map
from core.config import load_global_config, save_global_config
from core.project_manager.projects import create_project, checkpwdisproject
from core.config import bcolors
from rawrsgui import guimain


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
    if not checkpwdisproject():
        create_project(config["default_project"], config)

def laod_last_project_button(): print("a")
def load_default_project_button(): print("b")
def load_a_project_button(): print("c")
def make_new_project_button(): print("d")
def manage_projects_button(): print("manage")
def global_settings_button(): print("settings")
def exit_application(): exit()


if __name__ == "__main__":
    print(f"{bcolors.BOLD}Welcome to the Really Awesome Recon and Scan tool 0.a1! (Name pending){bcolors.RESET}")
    if os.getuid() != 0:
        print(f"{bcolors.FAIL}Due to the nature of some commands (like nmap stealth scan) this script needs to be ran as sudo{bcolors.RESET}")
        exit(10)
    config = load_global_config()
    init_environment(config)
    save_global_config(config)
    print(f"\n{bcolors.OKCYAN}[+] Toolkit environment is ready.{bcolors.RESET}")
    print(f"______________________________________________________________________")
    if len(sys.argv) > 1 and sys.argv[1] == "--gui":
        guimain()
    else:
        projectname = os.path.basename(os.getcwd())
        if checkpwdisproject():
            global current_project
            context_manager.current_project = os.getcwd()
            try:
                command = sys.argv[1]
                args = sys.argv[2:]
                command_map[command](args, config)
                mainarghelpmessage(sys.argv[1])
            except IndexError:
                mainarghelpmessage(None)
        else:
            print(f"\n{bcolors.FAIL}[-] Current folder is not a recognized project. Aborting{bcolors.RESET}")
            exit(1)
