import json

from core import context_manager
from core.context_manager import current_project, saveTargetContext
from reconenum.web.whatweb import whatwebexecutor


def web_scan(subargs,config):
    if not subargs or len(subargs) == 0:
        print('''
        Scan subtool for web gathering

          rawrs.py enum web  [ARGUMENTS] <options>
          
          [ARGUMENTS] can be either an ip, list of IPs or CIDR or one of the following:
          
          -auto                                     Use the IPs gathered on a enum fullscan run if there are any, else error.
        
        Examples:
          rawrs.py reconenum web --auto             web fingerprinting of the IPs gathered during a fullscan
          rawrs.py reconenum web 192.168.1.1        web fingerprinting of 192.168.1.1
          rawrs.py reconenum web 192.168.1.1:44     web fingerprinting of 192.168.1.1 specifying an uncommon port

        ''')
        return
    else:
        whatwebexecutor(subargs)



def extract_http_services():
    # Load full scan results
    with open("./results/nmap_aggregated_scan.json", "r") as f:
        full_scan = json.load(f)

    global current_project
    # Load context with plain IPs
    with open(f"{context_manager.current_project}/context.json", "r") as f:
        context = json.load(f)
    targets = context.get("targets", [])

    http_services = {}
    print("UEUEUEUUE")#FALLA DE AQUI PABAJO UWU
    for ip in targets:

        services = []
        for port in full_scan[ip].get("ports", []):
            service_name = port.get("service", {}).get("name", "")
            if service_name in ["http", "https"]:
                services.append({
                    "Service": service_name,
                    "port": str(port.get("port"))
                })

        if services:
            http_services[ip] = services
        print("YUWYAYAYAY")
        saveTargetContext(http_services)
