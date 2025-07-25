import json

projects_path = ""
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

def setTargets(listoftargets : list, overwrite : bool = False):
    """
    Save to both ctx file and memory of the current project the targets given
    listoftargets: list of targets
    overwrite: whether to overwrite targets or add the list to the already existing (removing duplicates)
    """
    if overwrite:
        saveTargetContext(listoftargets) #Overwrite
    else:
        saveTargetContext(list(set(targets + listoftargets)))  # Combine and remove duplicates

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