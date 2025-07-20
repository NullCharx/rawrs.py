import json

projects_path = ""
current_project = "" #Current runtime project


targets = []
tunnels = []


def saveContext ():
    with open(f'{current_project}/context.json', 'r') as file:
        data = json.load(file)  # Parse the JSON file into a Python dictionary
    data['targets'] = targets
    data['tunnels'] = tunnels

    # Write the modified data back to context.json
    with open(f'{current_project}/context.json', 'w') as file:
        json.dump(data, file, indent=4)  # Writing back with indentation for readability


def setTargets(listoftargets : list, overwrite : bool = False):
    global targets
    if overwrite:
        targets = listoftargets
    else:
        targets = list(set(targets + listoftargets))  # Combine and remove duplicates

    saveContext()
