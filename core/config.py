import json
import platform
from pathlib import Path

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    YELLOW = '\033[33m'
    GRAY = '\033[38;5;235m'


GLOBAL_CONFIG_PATH = Path("config.json")
DEFAULT_CONFIG = {
    "os": platform.system(),
    "projects_dir": "projects",
    "default_project": "default_project",
    "last_project": "default_project",
    "debug_verbose":True
}

def load_global_config():
    """Load the global config file or create one if not eisting"""
    if GLOBAL_CONFIG_PATH.exists():
        with open(GLOBAL_CONFIG_PATH, "r") as f:
            return json.load(f)
    else:
        print(f"{bcolors.OKCYAN}[*] Creating initial config...{bcolors.RESET}")
        save_global_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG

def save_global_config(config):
    """Save current global config to file"""
    with open(GLOBAL_CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)
