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
from core.project_manager.projects import create_project, project_folders, checkpwdisproject
from core.config import bcolors

def init_environment(config):
    print(f"{bcolors.OKCYAN}Checking dependencies.{bcolors.RESET}")
    if not shutil.which("go"):
        print(f"{bcolors.FAIL}[-] Go is not installed or not in PATH. Please install go as its needed by some subtools.{bcolors.RESET}")
    else:
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
            print(f"{bcolors.FAIL}[!] Failed to install Go package:\n{e.stderr}{bcolors.RESET}")
            exit(1)
        except FileNotFoundError:
            print(f"{bcolors.FAIL}[-] Go is not installed or not in PATH.{bcolors.RESET}")
            exit(1)
    context_manager.projects_path = Path(config["projects_dir"])
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
    config = load_global_config()
    init_environment(config)
    save_global_config(config)
    print(f"\n{bcolors.OKCYAN}[+] Toolkit environment is ready.{bcolors.RESET}")
    print(f"______________________________________________________________________")
    if len(sys.argv) == 1:
        guimain()
    else:
        print("Headless mode")
        projectname = os.path.basename(os.getcwd())
        if checkpwdisproject():
            context_manager.current_project = os.getcwd()
        else:
            exit(1)

        command = sys.argv[1]
        args = sys.argv[2:]
        mainarghelpmessage(sys.argv[1])

        command_map[command](args, config)
