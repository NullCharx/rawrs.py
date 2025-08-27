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


GLOBAL_CONFIG_PATH = Path(f"{Path(__file__).resolve().parent.parent.parent}/config.json")
DEFAULT_CONFIG = {
    "os": platform.system(),
    "projects_dir": "projects",
    "default_project": "default_project",
    "last_project": "default_project",
}
