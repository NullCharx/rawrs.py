import json
import os
from pathlib import Path

from rawrs.core.environment import bcolors, GLOBAL_CONFIG_PATH
from rawrs.core.project_manager.projects import checkdirectoryisproject

#Manager for session - volatile data, such as targets, for each project.
#THe context is saved so that consectuive runs of commands dont redo everything

#projects_path = ""
current_project = "" #Current runtime project

targets = []
tunnels = []

def loadProjectContextOnMemory ():
    """
    Load the current project memory context from its file
    """
    getTargetsContext()
    getTunnelsContext()

def saveProjectContextFromMemory ():
    """
    Save the current project memory context on the file
    """
    global targets, tunnels
    saveTargetContext (targets)
    saveTunnelContext (tunnels)

def getTargetsContext ():
    """
    Load the current project targets context from its file
    """
    global targets
    with open(f'{current_project}/context.json', 'r') as file:
        data = json.load(file)  # Parse the JSON file into a Python dictionary
    targets = data['targets']

def getTunnelsContext ():
    """
    Load the current project tunnels context from its file
    """
    global tunnels
    if not tunnels:
        with open(f'{current_project}/context.json', 'r') as file:
            data = json.load(file)  # Parse the JSON file into a Python dictionary
        tunnels = data['tunnels']

def setTargets(listoftargets : dict, overwrite : bool = False):
    """
    Save to both ctx file and memory of the current project the targets given
    :param listoftargets: list of targets
    :param overwrite: whether to overwrite targets or add the list to the already existing (removing duplicates)
    :return:
    """
    savedtargetlist = list(targets)
    writtentargetlsit = list(listoftargets.keys())
    if overwrite:
        saveTargetContext(writtentargetlsit) #Overwrite
    else:
        saveTargetContext(list(set(savedtargetlist + writtentargetlsit)))  # Combine and remove duplicates

def saveTargetContext (targetCtx):
    """
    Save the current project target context into its file and on memory
    :param targetCtx: target context
    """
    global targets
    targets = targetCtx

    with open(f'{current_project}/context.json', 'r') as file:
        data = json.load(file)  # Parse the JSON file into a Python dictionary
    data['targets'] = targets

    # Write the modified data back to context.json
    with open(f'{current_project}/context.json', 'w') as file:
        json.dump(data, file, indent=4)  # Writing back with indentation for readability

def getNmapAggregatedData():
    with open(f'{current_project}/results/nmap_aggregated_scan.json', 'r') as file:
        return json.load(file)  # Parse the JSON file into a Python dictionary

def saveTunnelContext (tunnelCtx):
    """
    Save the current project tunnel context into its file and on memory
    :param tunnelCtx: tunnel context
    """
    global tunnels
    tunnels = tunnelCtx

    with open(f'{current_project}/context.json', 'r') as file:
        data = json.load(file)  # Parse the JSON file into a Python dictionary
    data['tunnels'] = tunnels

    # Write the modified data back to context.json
    with open(f'{current_project}/context.json', 'w') as file:
        json.dump(data, file, indent=4)  # Writing back with indentation for readability

def setcurrentenvproject(args):
    """
    Set the current project on memory and last project on config
    :param args:
    :return:
    """
    with open(GLOBAL_CONFIG_PATH, "r") as f:
        file_content = json.load(f)
    global current_project
    if args.project is None or args.project == "cwd":
        if checkdirectoryisproject("cwd"):
            current_project = os.getcwd()
        else:
            print(f"\n{bcolors.FAIL}[-] Current folder is not a recognized project. Aborting{bcolors.RESET}")
            exit(1)
    else:
        if checkdirectoryisproject(args.project):
            current_project = Path(Path(args.project).resolve())
        else:
            print(f"\n{bcolors.FAIL}[-] Path {args.project} is not a recognized project. Aborting{bcolors.RESET}")
            exit(1)
    print(current_project)
    file_content.update({"last_project": current_project})
