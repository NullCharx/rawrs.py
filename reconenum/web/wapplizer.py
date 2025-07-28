

#!/usr/bin/env python
# from  gokulapap/wappalyzer-cli
import requests
from Wappalyzer import Wappalyzer, WebPage

from core import context_manager
from core.config import bcolors


def find_version(versions):
    return versions[0] if versions else "None"

def find_techs(url, newline):
    file = f"{context_manager.current_project}/webtech/wappalizer.json"
    output_file = open(f"{context_manager.current_project}/webtech/wappalizer.json", 'a')

    #Correct the url if necessary
    if '.' in url and not url.startswith('http'):
        try:
            url = requests.head('http://' + url, allow_redirects=True).url
        except Exception:
            print(f"{bcolors.FAIL}[-] Some error occurred while resolving{bcolors.RESET}")
            return

    try:
        webpage = WebPage.new_from_url(url)
        wappalyzer = Wappalyzer.latest()
        techs = wappalyzer.analyze_with_versions_and_categories(webpage)
    except Exception:
        print(f"{bcolors.FAIL}[-] ERROR SCANNING WITH WAPPALIZER {bcolors.RESET}")

    header = f"\n {bcolors.OKGREEN}[+] TECHNOLOGIES [{url.upper()}] {bcolors.RESET}:\n"
    print(header)
    if output_file:
        output_file.write(header)

    for tech, data in techs.items():
        category = data['categories'][0]
        version = find_version(data['versions'])
        line = f"{category} : {tech} [version: {version}]"
        print(line)
        if output_file:
            output_file.write(line + '\n')

    if output_file:
        output_file.close()

    if newline:
        print()
