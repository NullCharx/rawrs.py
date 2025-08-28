import json
import os
import shutil
import subprocess

from rawrs.core.staticdata import bcolors, GLOBAL_CONFIG_PATH, DEFAULT_CONFIG
from rawrs.core.project_manager import checkdirectoryisproject, create_project


# Globally used elements such as terminal colors, config info and config path

def load_global_config():
    """
    Load the global config file or create one if not eisting
    :return: The global config file contents or the default config data if not existent
    """
    print(GLOBAL_CONFIG_PATH)
    if GLOBAL_CONFIG_PATH.exists():
        with open(GLOBAL_CONFIG_PATH, "r") as f:
            return json.load(f)
    else:
        print(f"{bcolors.OKCYAN}[*] Creating initial config...{bcolors.RESET}")
        save_global_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG

def save_global_config(config):
    """
    Save global config currently stored in memory in the config file
    :param config: Configuration data to save
    :return:
    """
    with open(GLOBAL_CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)

def init_dependencies(verbosity, config):
    """
    Checks dependencies, creates the default project
    :param verbosity:
    :param config:
    :return:
    """
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
    #context_manager.projects_path = Path(config["projects_dir"])

    if not shutil.which("wordlists"):
        if verbosity > 2:
            print(f"{bcolors.FAIL}[-] wordlists is not installed or not in PATH. Trying to install.{bcolors.RESET}")
        try:
            result = subprocess.run(
                ["apt", "install", "wordlists"],
                capture_output=False,
            )
        except Exception:
            print(f"{bcolors.FAIL}[!] wordlists couldn't be installed. Please manually install go as its needed by some subtools.{bcolors.RESET}")
            exit(1)
    else:
        if verbosity > 2:
            print(f"{bcolors.OKGREEN}[+] wordlists installed{bcolors.RESET}")

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

        if os.path.exists("/usr/share/wordlists/"):
            try:
                result = subprocess.run(
                    ["ln", "-s", "/usr/share/SecLists", "SecLists.lst"],
                    capture_output=False,
                    cwd="/usr/share/wordlists/"
                )
            except Exception:
                print(
                    f"{bcolors.FAIL}[!] Error soft linking seclists to /etc/share/wordlists/. This might cause errors {bcolors.RESET}")

    else:
        if verbosity > 2:
            print(f"{bcolors.OKGREEN}[+] SecList detected. Checking and installing updates. . .{bcolors.RESET}")
        try:
            result = subprocess.run(
                ["git", "reset", "HEAD", "--hard"],
                capture_output=False,
                cwd="/usr/share/SecLists"
            )
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

    if not shutil.which("ruby"):
        if verbosity > 2:
            print(f"{bcolors.FAIL}[-] Ruby is not installed or not in PATH. Trying to install.{bcolors.RESET}")
        try:
            result = subprocess.run(
                ["apt", "install", "ruby"],
                capture_output=False,
            )
        except Exception:
            print(f"{bcolors.FAIL}[!] Ruby couldn't be installed. Please manually install go as its needed by some subtools.{bcolors.RESET}")
            exit(1)
    else:
        if verbosity > 2:
            print(f"{bcolors.OKGREEN}[+] ruby installed{bcolors.RESET}")

    if not shutil.which("wpscan"):
        if verbosity > 2:
            print(f"{bcolors.FAIL}[-] wpscan is not installed or not in PATH. Trying to install.{bcolors.RESET}")
        try:
            result = subprocess.run(
                ["apt", "install", " build-essentials libxml2 libxml2-dev libxslt1-dev ruby-dev  libgmp-dev zlib1g-devlibcurl4=7.88.1-10+deb12u14 libcurl4-openssl-dev"]
            )

            result = subprocess.run(
                ["gem", "install", "wpscan activesupport"],
                capture_output=False,
            )

        except Exception:
            print(
                f"{bcolors.FAIL}[!] wpscan couldn't be installed. Please manually install go as its needed by some subtools."
                f"Try the following commands manually:"
                f"sudo apt install build-essential libxml2 libxml2-dev libxslt1-dev ruby-dev libgmp-dev zlib1g-dev libcurl4=7.88.1-10+deb12u14 libcurl4-openssl-dev"
                f"sudo gem install wpscan activesupport\n{bcolors.RESET}")
            exit(1)
        else:
            if verbosity > 2:
                print(f"{bcolors.OKGREEN}[+] wpscan installed{bcolors.RESET}")
        result = subprocess.run(
            ["wpscan", "--update"]
        )
    if not shutil.which("dnsrecon"):
        if verbosity > 2:
            print(f"{bcolors.FAIL}[-] dnsrecon is not installed or not in PATH. Trying to install.{bcolors.RESET}")
        try:
            result = subprocess.run(
                ["apt", "install", "dnsrecon"],
                capture_output=False,
            )
        except Exception:
            print(f"{bcolors.FAIL}[!] dnsrecon couldn't be installed. Please manually install go as its needed by some subtools.{bcolors.RESET}")
            exit(1)
    else:
        if verbosity > 2:
            print(f"{bcolors.OKGREEN}[+] dnsrecon installed{bcolors.RESET}")

    if not shutil.which("proxychains"):
        if verbosity > 2:
            print(f"{bcolors.FAIL}[-] proxychains is not installed or not in PATH. Trying to install.{bcolors.RESET}")
        try:
            result = subprocess.run(
                ["apt", "install", "proxychains"],
                capture_output=False,
            )
        except Exception:
            print(f"{bcolors.FAIL}[!] proxychains couldn't be installed. Please manually install go as its needed by some subtools.{bcolors.RESET}")
            exit(1)
    else:
        if verbosity > 2:
            print(f"{bcolors.OKGREEN}[+] proxychains installed{bcolors.RESET}")
    if not shutil.which("enum4linux-ng"):
        if verbosity > 2:
            print(f"{bcolors.FAIL}[-] enum4linux-ng is not installed or not in PATH. Trying to install.{bcolors.RESET}")
        try:
            result = subprocess.run(
                ["apt", "install", "enum4linux-ng"],
                capture_output=False,
            )
        except Exception:
            print(f"{bcolors.FAIL}[!] enum4linux-ng couldn't be installed. Please manually install go as its needed by some subtools.{bcolors.RESET}")
            exit(1)
    else:
        if verbosity > 2:
            print(f"{bcolors.OKGREEN}[+] enum4linux-ng installed{bcolors.RESET}")

    if not shutil.which("netexec"):
        if verbosity > 2:
            print(f"{bcolors.FAIL}[-] netexecis not installed or not in PATH. Trying to install.{bcolors.RESET}")
        try:
            result = subprocess.run(
                ["apt", "install", "netexec"],
                capture_output=False,
            )
        except Exception:
            print(
                f"{bcolors.FAIL}[!] netexec couldn't be installed. Please manually install go as its needed by some subtools.{bcolors.RESET}")
            exit(1)
    else:
        if verbosity > 2:
            print(f"{bcolors.OKGREEN}[+] netexec installed{bcolors.RESET}")

    #Create default project
    if not checkdirectoryisproject("cwd"):
        create_project(config["default_project"], verbosity, config)
