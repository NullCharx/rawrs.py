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
        # Nikto 2 (Check robots txt, source code credentials etc)
        # Vulnerabilities to use (Searchsploit, rapid 7 and for exploits github mainly)
        #Prompt the user to search for manual vulnrable inpouts, url encodings, SQLi...
