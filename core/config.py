import json
import platform
from pathlib import Path
from core.globalvars import bcolors

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
