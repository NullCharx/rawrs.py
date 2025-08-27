import json
import os
from pathlib import Path

from rawrs.core.config import bcolors

# Required base folders and files for the project
project_folders = ["results", "scans","tunnels"]

required_files = ['notes.md', 'context.json']


def create_project(name, verbosity, config):
    """
    Create a project folder with default structure
    :param name: name of the project
    :param verbosity: verbosity level
    :param config: global config data
    :return:
    """
    projects_folder = Path(config["projects_dir"])
    project_path = projects_folder / name
    #If a projects folder doeesnt exist in the current location, create it by default
    if not projects_folder.exists():
        if verbosity > 2:
            print(f"{bcolors.WARNING}[+] Creating projects folder {projects_folder} in this location:{bcolors.RESET}")
        projects_folder.mkdir()
    #and if the project folder with the specified name doesnt exist, create it as well
    if not project_path.exists():
        if verbosity > 2:
            print(f"{bcolors.WARNING}[+] Creating project: {name}{bcolors.RESET}")
        project_path.mkdir()
        for folder in project_folders:
            (project_path / folder).mkdir()
            if folder == "scans":
                (project_path / folder / "nmap").mkdir()
                (project_path / folder / "nmap"/"xml").mkdir()
                (project_path / folder / "nmap"/"json").mkdir()
                (project_path / folder / "webtech").mkdir()
                (project_path / folder / "fuzz").mkdir()
                (project_path / folder / "cms").mkdir()
                (project_path / folder / "dns").mkdir()
                (project_path / folder / "ftp").mkdir()
                (project_path / folder / "ssh").mkdir()
                (project_path / folder / "smtp").mkdir()
                (project_path / folder / "snmp").mkdir()
                (project_path / folder / "smb").mkdir()
                (project_path / folder / "win").mkdir()
        (project_path / "notes.md").write_text("# Project Notes\n")
        context = {
            "targets": [],
            "tunnels": [],
            "notes": f"Auto-created project: {name}"
        }
        with open(project_path / "context.json", "w") as f:
            json.dump(context, f, indent=2)
    else:
        #Do nothing
        if verbosity > 2:
            print(f"{bcolors.WARNING}[+] Project '{name}' already exists.{bcolors.RESET}")

def checkdirectoryisproject(path) -> bool:
    """
    Check if a given path is a rawrs.py folder
    :param path: path to check, including "cwd" to check the current directory
    :return:
    """
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
'''
