import os
import shutil
import subprocess
import sys
from pathlib import Path

from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.widgets import Label, Button
from prompt_toolkit.layout import Layout, HSplit, VSplit, Dimension, Window
from prompt_toolkit.application import Application
from prompt_toolkit.styles import Style

from core import context_manager
from core.commands_manager import mainarghelpmessage, command_map
from core.config import load_global_config, save_global_config
from core.context_manager import current_project
from core.project_manager.projects import create_project, project_folders, checkpwdisproject
from core.config import bcolors

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
        print(f"{bcolors.OKGREEN}[+] nmap-formatter installed succesfully or already installed:\n{result.stdout}{bcolors.RESET}")
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

def handle_and_exit(label, handler_func):
    handler_func()
    app.exit(result=label)

buttons = [
    [ Button("Load last", lambda: handle_and_exit("Load last", laod_last_project_button)),
      Button("Load", lambda: handle_and_exit("Load", load_a_project_button)),
      Button("Create new", lambda: handle_and_exit("Create new", make_new_project_button))],
    [ Button("Manage", lambda: handle_and_exit("Manage", manage_projects_button)),
      Button("Settings", lambda: handle_and_exit("Settings", global_settings_button)),
      Button("Exit", lambda: handle_and_exit("Exit", exit_application))]
]

button_row = 0
button_col = 0

def main_menUI(config):
    text = FormattedText([
        ('', "Choose a command:\n\n"),
        ('', "- Load last: load the last opened project: "),
        ('class:highlight', f"{config.get('last_project')}\n"),
        ('', "- Load: choose an existing project to load\n"),
        ('', "- Create new: start a new project\n\n"),
        ('', "- Manage: manage existing projects\n"),
        ('', "- Settings: global preferences\n"),
        ('', "- Exit: close the program"),
    ])

    # Manual dialog-style layout
    layout = HSplit([
        Window(height=1, char=" "),
        Label(text=text),
        Window(height=1, char=" "),
        VSplit(buttons[0], padding=3, align="CENTER"),
        Window(height=1, char=" "),
        VSplit(buttons[1], padding=3, align="CENTER"),
        Window(height=1, char=" "),
    ], width=Dimension(preferred=80))

    style = Style.from_dict({
        "highlight": "fg:#ffaf00 bold",
        "dialog": "bg:#1c1c1c fg:#ffffff",
    })

    kb = KeyBindings()

    @kb.add('left')
    def izquierda(event):
        global button_row, button_col
        if button_col > 0:
            button_col -= 1
        enfocar_boton(event)

    @kb.add('right')
    def derecha(event):
        global button_row, button_col
        if button_col < len(buttons[button_row]) - 1:
            button_col += 1
        enfocar_boton(event)

    @kb.add('up')
    def arriba(event):
        global button_row, button_col
        if button_row > 0:
            button_row -= 1
            button_col = min(button_col, len(buttons[button_row]) - 1)
        enfocar_boton(event)

    @kb.add('down')
    def abajo(event):
        global button_row, button_col
        if button_row < len(buttons) - 1:
            button_row += 1
            button_col = min(button_col, len(buttons[button_row]) - 1)
        enfocar_boton(event)

    def enfocar_boton(event):
        btn = buttons[button_row][button_col]
        event.app.layout.focus(btn)

    global app
    app = Application(
        layout=Layout(layout),
        full_screen=True,
        style=style,
        key_bindings=kb
    )

def guimain():
    main_menUI(config)
    result = app.run()
    print(f"Result = {result}")

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
