import json
from pathlib import Path
from core.globalvars import bcolors

"""Load and save"""
def init_environment(config):
    """Create main projects dir and default project if needed."""
    projects_path = Path(config["projects_dir"])
    projects_path.mkdir(exist_ok=True)
    create_project(config["default_project"], config)

def create_project(name, config):
    """Create a project folder with default structure."""
    project_path = Path(config["projects_dir"]) / name
    if not project_path.exists():
        print(f"{bcolors.WARNING}[+] Creating project: {name}{bcolors.RESET}")
        project_path.mkdir()
        (project_path / "results").mkdir()
        (project_path / "tunnels").mkdir()
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

load_context(project_name)

save_context(project_name, context)

switch_project(name)
'''
