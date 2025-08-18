import os
import shutil
import subprocess
import sys
from pathlib import Path

from core import context_manager

def run_wapiti_scan(args, disable_ssl=False):
    output_dir = Path(context_manager.current_project) / "scans" / "webtech"
    output_dir.mkdir(parents=True, exist_ok=True)
    validtargets = []

    for target in list(args):
        # Ensure URL has scheme
        if not target.startswith("http"):
            target_url = "http://" + target
        else:
            target_url = target

        # Make file path safe
        safestring = target_url.replace("://", "_").replace("/", "_")
        output_path = output_dir / f"wapiti_{safestring}.json"

        try:
            with open(output_path, 'w+') as file:
                file.write("")
        except Exception as e:
            print(f"[!] Exception opening {output_path.name}: {e}")
            continue

        cmd = [
            "wapiti", "-u", target_url,
            "--scope", "domain",
            "--depth", "5",
            "--max-links-per-page", "100",
            "--format", "json",
            "--output", str(output_path),
            "--flush-session", "--color"
        ]

        if disable_ssl:
            cmd.append("--no-ssl-check")

        print(f"[+] Running Wapiti on {target_url}...")

        try:
            result = subprocess.run(cmd, stderr=subprocess.PIPE, capture_output=False, check=True)

            # If Wapiti produces any stderr output, consider scan failed and remove output file
            if result.stderr:
                print(result.stderr.decode())
                if output_path.exists():
                    output_path.unlink()
            else:
                # No stderr, assume valid target
                validtargets.append(target)

        except subprocess.CalledProcessError as e:
            print(f"[!] Wapiti scan failed on {target_url}: {e}")
            if output_path.exists():
                output_path.unlink()
    return validtargets

def run_nikto_scan(args, force_ssl=False):
    output_dir = Path(context_manager.current_project) / "scans" / "webtech"
    output_dir.mkdir(parents=True, exist_ok=True)

    validtargets = []

    for target in list(args):
        # Ensure scheme
        if not target.startswith("http"):
            target_url = "http://" + target
        else:
            target_url = target

        # Parse scheme and hostname
        scheme, hostname = target_url.split("://", 1)

        # Make filename-safe version
        safestring = target_url.replace("://", "_").replace("/", "_")
        output_path = output_dir / f"nikto_{safestring}.json"

        try:
            with open(output_path, "w+") as f:
                f.write("")
        except Exception as e:
            print(f"[!] Failed to create output file for {target}: {e}")
            continue

        # Base command
        cmd = [
            "nikto",
            "-host", target_url,
            "-Format", "json",
            "-output", str(output_path),
            "-ask", "no",
            "-nointeractive",
            "-Display", "EPV",           # Errors, Progress, Verbose
            "-followredirects",
            "-Tuning", "1234567890abcde",  # Full tuning set
        ]

        if force_ssl or scheme == "https":
            cmd.append("-ssl")

        print(f"[+] Running Nikto on {target_url}...")


        result = subprocess.run(cmd, stderr=subprocess.PIPE, capture_output=False, check=False)
        if result.returncode == 1:
            validtargets.append(target)
        if result.stderr:
            print(result.stderr.decode())
            os.remove(output_path)
            print(f"[!] Nikto scan failed on {target_url}")

    return validtargets

def run_wpscan_scan(args, auth : str = None, cookies : str = None, pathuserdict : str = None, pathpassdict : str = None):
    output_dir = Path(context_manager.current_project) / "scans" / "cms"
    output_dir.mkdir(parents=True, exist_ok=True)
    valid_targets = []

    for target in args:
        if not target.startswith("http"):
            target_url = "http://" + target
        else:
            target_url = target


        full_url = target_url.rstrip("/")

        safestring = full_url.replace("://", "_").replace("/", "_")
        output_path = output_dir / f"wpscan_{safestring}.json"

        wpscan_cmd = [
            "wpscan",
            "--url", str(target_url),

            "--enumerate", "ap,at,u,tt,cb,dbe,m",
            "--plugins-detection", "aggressive",
            "--plugins-version-detection", "aggressive",
            "--random-user-agent",
            "--disable-tls-checks",
            "--max-threads", "50",
            "--detection-mode", "aggressive",
            "--no-update",
            "--output", str(output_path),
            "--format", "json",
        ]
        if auth:
            wpscan_cmd.append("--http-auth")
            wpscan_cmd.append(args.httpauth)
        if cookies:
            wpscan_cmd.append("cookie-string")
            wpscan_cmd.append(args.cookies)
        if pathuserdict:
            wpscan_cmd.append("--usernames")
            wpscan_cmd.append(args.userdict)
        if pathpassdict:
            wpscan_cmd.append("--passwords")
            wpscan_cmd.append(args.passdict)
        print(f"[+] Running WPScan on {full_url}... (This might take a while!)")

        try:
            subprocess.run(wpscan_cmd,capture_output=True, check=True)
            valid_targets.append(full_url)
        except subprocess.CalledProcessError as e:
            print(f"[!] WPScan failed on {full_url}: {e}")

        print(f"[+] Wpscan on {full_url} done. You might want to manually check other options such as username and password bruteforcing")

    return valid_targets

'''
def run_droopescan_scan(args):
    output_dir = Path(context_manager.current_project) / "scans" / "webtech"
    output_dir.mkdir(parents=True, exist_ok=True)

    valid_targets = []

    cms_list = ["drupal", "joomla", "moodle", "silverstripe"]

    for target in args.targets:
        if not target.startswith("http"):
            target_url = "http://" + target
        else:
            target_url = target

        full_url = target_url.rstrip("/")
        print(shutil.which("droopescan"))
        for cms in cms_list:
            safestring = f"{cms}_" + full_url.replace("://", "_").replace("/", "_")
            output_path = output_dir / f"droopescan_{safestring}.json"

            cmd = [
                shutil.which("droopescan"),
                "scan", cms,
                "--url", full_url,
                "--enumerate", "a",
                "--number", "all",
                "--output", "json",
                "--output-file", str(output_path)
            ]

            print(f"[+] Running Droopescan ({cms}) on {full_url}...")

            try:
                subprocess.run(cmd, stderr=subprocess.PIPE, capture_output=False, check=True)
                valid_targets.append((cms, full_url))
            except subprocess.CalledProcessError as e:
                print(f"[!] Droopescan failed for {cms} at {full_url}: {e}")
                if output_path.exists():
                    os.remove(output_path)

    return valid_targets
'''


