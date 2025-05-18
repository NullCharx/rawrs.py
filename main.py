from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.widgets import Dialog, Label, Button, Box
from prompt_toolkit.layout import Layout, HSplit, VSplit, Dimension
from prompt_toolkit.application import Application
from prompt_toolkit.styles import Style

from core.config import load_global_config, save_global_config
from project_manager.projects import init_environment
from core.globalvars import bcolors

def laod_last_project_button():
    print("a")

def load_default_project_button():
    print("b")

def load_a_project_button():
    print("c")

def make_new_project_button():
    print("d")

def manage_projects_button():
    print("manage")

def global_settings_button():
    print("settings")

def exit_application():
    exit()
def handle_and_exit(label, handler_func):
    handler_func()
    app.exit(result=label)

def main_menUI(config):
    # Styled multi-part text
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

    # Dialog with vertical stacking
    top_buttons = Box(
        VSplit([
            Button("Load last", lambda: handle_and_exit("Load last", laod_last_project_button)),
            Button("Load", lambda: handle_and_exit("Load", load_a_project_button)),
            Button("Create new", lambda: handle_and_exit("Create new", make_new_project_button)),
        ], padding=3),
        width=Dimension(preferred=60),
        style="class:button-box"
    )

    bottom_buttons = Box(
        VSplit([
            Button("Manage", lambda: handle_and_exit("Manage", manage_projects_button)),
            Button("Settings", lambda: handle_and_exit("Settings", global_settings_button)),
            Button("Exit", lambda: handle_and_exit("Exit", exit_application)),
        ], padding=3),
        width=Dimension(preferred=60),
        style="class:button-box"
    )

    dialog = Dialog(
        title="Main menu",
        body=HSplit([
            Label(text=text),
            top_buttons,
            bottom_buttons
        ], padding=1),
        width=Dimension(preferred=80),  # Set dialog width
        with_background=True,
    )
    # Styles
    style = Style.from_dict({
        "highlight": "fg:#ffaf00 bold",
        "dialog": "bg:#1c1c1c fg:#ffffff",
    })

    global app
    app = Application(
        layout=Layout(dialog),
        full_screen=True,
        style=style,
    )


def main():
    print(f"{bcolors.BOLD}Welcome to OSCPTFM 0.a1! (Name pending){bcolors.RESET}")
    config = load_global_config()
    init_environment(config)
    save_global_config(config)
    print(f"\n{bcolors.OKCYAN}[+] Toolkit environment is ready.{bcolors.RESET}")
    print(f"______________________________________________________________________")
    main_menUI(config)
    result = app.run()
    print(f"Result = {result}")

if __name__ == "__main__":
    main()

