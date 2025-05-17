from core.config import load_global_config, save_global_config
from core.projects import init_environment
from core.globalvars import bcolors
import prompt_toolkit as pt

def main():
    print(f"{bcolors.BOLD}Welcome to OSCPTFM 0.a1! (Name pending){bcolors.RESET}")
    config = load_global_config()
    init_environment(config)
    save_global_config(config)
    print(f"\n{bcolors.OKCYAN}[+] Toolkit environment is ready.{bcolors.RESET}")
    print(f"______________________________________________________________________")

    #

if __name__ == "__main__":
    main()
