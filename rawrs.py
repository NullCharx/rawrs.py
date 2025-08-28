import os
import random
import argparse
import shutil
import subprocess
import sys

from rawrs.core.environment_manager import load_global_config, save_global_config, init_dependencies
from rawrs.core.staticdata import bcolors
from rawrs.core.context_manager import setcurrentenvproject, loadProjectContextOnMemory
from rawrs.core.project_manager import create_project, checkdirectoryisproject
from rawrs.osint.osintcore import cmd_osint
from rawrs.reconenum.reconmain import initreconenumsubparsers
from rawrs.transfer.transfercore import inittransferscanargparser
from rawrs.tunneling.tunnelcore import inittunnelscanargparser

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






def cmd_gui(args):
    """
    Handler for the Terminal UI launcher
    :param args: arguments to be passed to the UI
    :return:
    """
    setcurrentenvproject(args)
    loadProjectContextOnMemory()
    if args.verbose < 2:
        print("[gui] launching... (placeholder)")

# -------------------------------------------------
# Parser builder
# -------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    """
    Builds the main application parser as well as calling the building
    methods for the subparsers of all the tools in a clean modular way
    :return: The main argument parser with all the subparsers added and set
    """

    # Main parser object
    mainparser = argparse.ArgumentParser(
        prog="Really Awesome Recon and Scan tool",
        description="A learning tool to automate repetitive recon and scanning tasks (OSCP-style).",
    )
    menusubparser = mainparser.add_subparsers(dest="command", required=True)

    # ========== COMMON OPTIONS FOR SUBTOOLS ==========
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--project", default="cwd", help="Path to project to operate on. (Default assumes script is ran inside a rawrs.py project folder)")
    common.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity")

    # ============ PORT / SERVICE ENUM ============
    initreconenumsubparsers(menusubparser, common)

    # ===================== TUNNEL =====================

    inittunnelscanargparser(menusubparser, common)

    # ===================== TRANSFER =====================
    inittransferscanargparser(menusubparser,common)

    # ===================== OSINT =====================
    p_osint = menusubparser.add_parser("osint", parents=[common], help="Passive info gathering")
    p_osint.add_argument("--target", required=True)
    p_osint.set_defaults(func=cmd_osint)


    # ===================== GUI =====================
    p_gui = menusubparser.add_parser("gui", parents=[common], help="Launch TUI/GUI mode")
    p_gui.set_defaults(func=cmd_gui)


    return mainparser


def preparse_verbose(argv):
    """
    Parse ONLY -v/--verbose before the full parser exists.
    This is so the verbosity level can be used for initialization messages,
    before the main parser is initialized
    :param argv: all the entry arguments
    :return: the value of the verbose option (the more "v"s the higher)
    """
    #Pre parser object
    pre = argparse.ArgumentParser(add_help=False)

    #This will only parse the target -v argument without removing it from the arguments
    #So it can be safely consumed by the main parser again
    pre.add_argument("-v", "--verbose", action="count", default=0)
    args, _ = pre.parse_known_args(argv)
    if not args.verbose:
        return 0
    return args.verbose



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

    # ========== pre-parse verbosity ==========
    verbosity = preparse_verbose(sys.argv[1:])

    # ========== Init current environment ==========
    config = load_global_config()
    init_dependencies(verbosity, config)
    save_global_config(config)
    print(f"\n{bcolors.OKCYAN}[+] Toolkit environment is ready.{bcolors.RESET}")
    print(f"______________________________________________________________________")

    # ========== Build tool subparsers and parse the input==========
    parser = build_parser()
    args = parser.parse_args(sys.argv[1:])

    # Dispatch arguments
    if hasattr(args, "func"):
        return args.func(args)
    else:
        return parser.print_help()


if __name__ == "__main__":
    main()