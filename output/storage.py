import json
import platform
from pathlib import Path

# Global configuration
CONFIG = {
    "os": platform.system(),
    "projects_dir": Path("projects"),
    "default_project": "default_project"
}


def init_environment():
    """Set up initial project environment."""
    print(f"[+] Detected operating system: {CONFIG['os']}")

    # Create the projects directory if it doesn't exist
    CONFIG["projects_dir"].mkdir(exist_ok=True)

    # Create default project if it doesn't exist
    default_path = CONFIG["projects_dir"] / CONFIG["default_project"]
    if not default_path.exists():
        print(f"[+] Creating default project: {CONFIG['default_project']}")
        default_path.mkdir()
        (default_path / "results").mkdir()
        (default_path / "tunnels").mkdir()
        (default_path / "notes.md").write_text("# Project Notes\n")

        context = {
            "targets": [],
            "tunnels": [],
            "notes": "Automatically created default project"
        }
        with open(default_path / "context.json", "w") as f:
            json.dump(context, f, indent=2)
    else:
        print(f"[+] Default project already exists.")


def main():
    init_environment()
    print("\n[+] Environment is ready. You can now start working with your toolkit!")


if __name__ == "__main__":
    main()
