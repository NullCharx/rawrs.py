import json
import os
from pathlib import Path

from core.config import bcolors

"""Load and save"""

project_folders = ["results", "scans","tunnels"]
required_files = ['notes.md', 'context.json']


def create_project(name, config):
    """Create a project folder with default structure."""
    projects_folder = Path(config["projects_dir"])
    project_path = projects_folder / name
    if not projects_folder.exists():
        print(f"{bcolors.WARNING}[+] Creating projects folder {projects_folder} in this location:{bcolors.RESET}")
        projects_folder.mkdir()
    if not project_path.exists():
        print(f"{bcolors.WARNING}[+] Creating project: {name}{bcolors.RESET}")
        project_path.mkdir()
        for folder in project_folders:
            (project_path / folder).mkdir()
            if folder == "scans":
                (project_path / folder / "nmap").mkdir()
                (project_path / folder / "nmap"/"xml").mkdir()
                (project_path / folder / "nmap"/"json").mkdir()
                (project_path / folder / "whatweb").mkdir()

        (project_path / "notes.md").write_text("# Project Notes\n")
        context = {
            "targets": [],
            "tunnels": [],
            "notes": f"Auto-created project: {name}"
        }
        with open(project_path / "context.json", "w") as f:
            json.dump(context, f, indent=2)
    else:
        print(f"{bcolors.WARNING}[+] Project '{name}' already exists.{bcolors.RESET}")

def checkdirectoryisproject(path):
    directory = ""
    if path == "cwd":
        directory = Path(os.getcwd())
    elif not os.path.isdir(path):
        return False
    else:
        directory = Path(path)
    # Check if each project folder exists in the target directory
    for project in project_folders:
        if not (directory / project).is_dir():  # Check if project folder exists
            return False  # Return False if any folder is missing
    for file in required_files:
        if not (directory / file).is_file():
            return False  # Return False if any required file is missing

    return True  # Return True if all project folders and files exist



'''
list_projects()

delete_project(name)

load_context(project_name) (loads the volatile data that needs to be on memory like targets, scans, tunnels...)

save_context(project_name, context) (Saves the volatile data that needs to be on memory like targets, scans, tunnels...)

switch_project(name)
'''
