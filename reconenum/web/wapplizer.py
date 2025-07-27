#!/usr/bin/env python
# from  gokulapap/wappalyzer-cli
from Wappalyzer import Wappalyzer, WebPage
import argparse
from core.config import bcolors
def find_version(a):
    if not a:
        return 'nil'
    else:
        return a[0]

def wappalyzer_tech_and_version(targetlist):
    for url in targetlist:
        try:
            webpage = WebPage.new_from_url(url)
            wappalyzer = Wappalyzer.latest()
            techs = wappalyzer.analyze_with_versions_and_categories(webpage)
        except Exception:
            print(f"{bcolors.FAIL}[-] ERROR SCANNING WITH WAPPALIZER {bcolors.RESET}")

        nurl = url.split("//")[1].rstrip("/")

        print(f"\n {bcolors.OKGREEN}[+] TECHNOLOGIES [{nurl.upper()}] {bcolors.RESET}:\n")

        for i in techs:
            print(f"{techs[i]['categories'][0]} : {i} [version: {find_version(techs[i]['versions'])}]")
            if j :
                j.write(f"{techs[i]['categories'][0]} : {i} [version: {find_version(techs[i]['versions'])}]\n");
        if nl == True:
            print("\n")
        else:
            pass
