import json

from core.context_manager import current_project
from reconenum.web.whatweb import whatwebexecutor


def web_scan(subargs,config):
    if not subargs or len(subargs) == 0:
        print('''
        Scan subtool for web gathering

          rawrs.py enum web  [ARGUMENTS] <options>
          
          [ARGUMENTS] can be either an ip, list of IPs or CIDR or one of the following:
          
          -auto                                     Use the IPs gathered on a enum fullscan run if there are any, else error.
          --dicpath [PATH]                          path to a dictionary for fuzzing purposes. If not used seclist directory-list-2.3-medium.txt and dirb common.txt will be used instead.
        Examples:
          rawrs.py reconenum web --auto             web fingerprinting of the IPs gathered during a fullscan
          rawrs.py reconenum web 192.168.1.1        web fingerprinting of 192.168.1.1
          rawrs.py reconenum web 192.168.1.1:44     web fingerprinting of 192.168.1.1 specifying an uncommon port

        ''')
        return
    else:
        whatwebexecutor(subargs)