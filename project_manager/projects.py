import json
from pathlib import Path
from core.globalvars import bcolors

"""Load and save"""

project_folders = ["results", "scans","tunnels"]

def create_project(name, config):
    """Create a project folder with default structure."""
    project_path = Path(config["projects_dir"]) / name
    if not project_path.exists():
        print(f"{bcolors.WARNING}[+] Creating project: {name}{bcolors.RESET}")
        project_path.mkdir()
        for folder in project_folders:
            (project_path / folder).mkdir()
            if folder == "scans":
                (project_path / folder / "raw").mkdir()

        (project_path / "notes.md").write_text("# Project Notes\n")
        context = {
            "targets": [],
            "tunnels": [],
            "notes": f"Auto-created project: {name}"
        }
        with open(project_path / "context.json", "w") as f:
            json.dump(context, f, indent=2)
    else:
        print(f"{bcolors.FAIL}[+] Project '{name}' already exists.{bcolors.RESET}")


'''
list_projects()

delete_project(name)

load_context(project_name) (loads the volatile data that needs to be on memory like targets, scans, tunnels...)

save_context(project_name, context) (Saves the volatile data that needs to be on memory like targets, scans, tunnels...)

switch_project(name)
'''
