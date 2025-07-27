import json

from core import context_manager
from core.context_manager import current_project, saveTargetContext, loadProjectContextOnMemory
from reconenum.parser import parse_ip_inputs, parse_whatweb_results, parse_web_targets
from reconenum.web.whatweb import whatwebexecutor


def web_scan(tool,subargs,config):
    if not subargs or len(subargs) == 0:
        print('''
        Scan subtool for web gathering

          rawrs.py enum web [TOOL] [ARGUMENTS] <options>
          
          [TOOL] can be:
          completescan                              Run all available tools to perform a complete web scan of the targets
          fingerprint                               Run whatweb on the targets to enumeate technologies used
        
          [ARGUMENT] can be either an ip, list of IPs or CIDR or one of the following:
          --auto                                     Use the IPs gathered on a enum fullscan run if there are any, else error.
        
        
        Examples:
          rawrs.py reconenum web fingerprint --auto             web fingerprinting of the IPs gathered during a fullscan. THis will detect services marked as "http" or "https" and launch whatweb with the corresponding port
          rawrs.py reconenum web fingerprint 192.168.1.1        web fingerprinting of 192.168.1.1
          rawrs.py reconenum web fingerprint 192.168.1.1:44     web fingerprinting of 192.168.1.1 specifying an uncommon port

        ''')
        return
    else:
        argument = None
        if subargs[-1].startswith("--") or subargs[0].startswith("-"):
            argument = subargs[0]
            del subargs[0]

        if tool == "fingerprint" or tool == "completescan":
            if argument and argument == "--auto":
                loadProjectContextOnMemory()
                subargs = context_manager.targets
            else:
                subargs = parse_ip_inputs(subargs)
            parse_web_targets(subargs)
            whatwebexecutor(subargs)

        if tool == "whatever" or tool == "completescan":
            pass

        # Probably a whatweb parser and add technologies and versions to the context
        #
        # Nikto 2 (Check robots txt, source code credentials etc)
        #
        #If technologies returns wordpress -> wpscan
        #If technologies returns drupal-> droopescan
        #
        # Vulnerabilities to use (Searchsploit, rapid 7 and for exploits github mainly)
        #Prompt the user to search for manual vulnrable inpouts, url encodings, SQLi...
        #Complete scan that chains everything!!!