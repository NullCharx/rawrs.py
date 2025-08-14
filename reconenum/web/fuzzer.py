from core import context_manager
import subprocess
from pathlib import Path

def run_fuzzing(targets, args):
    """Fuzzes targets.
    Modes:
      1. --common   => use fixed common dictionary.
      2. --wordlist => use provided dictionary path.
      3. Default    => fzf selection from /usr/share/wordlists.
    """
    output_dir = Path(context_manager.current_project) / "scans" / "fuzz"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Pick the wordlist based on args
    if args.common:
        # Fixed path for common dictionary
        wordlist = "/usr/share/SecLists/Discovery/Web-Content/raft-medium-directories.txt"
    elif args.wordlist:
        # Use provided dictionary
        wordlist = args.wordlist
    else:
        # fzf interactive picker
        print("[*] No wordlist specified, opening fzf...")
        try:
            wordlist = fuzzyfind_dictionaries()
            if not wordlist:
                print("[!] No wordlist selected, aborting fuzzing.")
                return []
        except subprocess.CalledProcessError as e:
            print(f"[!] fzf selection failed: {e}")
            return []

    print(f"[+] Using wordlist: {wordlist}")
    valid_targets = []

    for target in targets:
        if not target.startswith("http"):
            target_url = "http://" + target
        else:
            target_url = target

        safestring = target_url.replace("://", "_").replace("/", "_")
        output_path = output_dir / f"fuzzing_{safestring}.txt"

        cmd = [
            "ffuf",
            "-u", f"{target_url}/FUZZ",
            "-w", wordlist,
            "-o", str(output_path),
            "-of", "json",
            "-fc", "404",  # Exclude 404 responses
            "-recursion",  # Enabling recursion
            "-recursion-depth", "3",  # Setting recursion depth
            "-maxtime-job", "60",  # Setting maximum time for each job
            "-p", "10",  # Setting number of concurrent requests
        ]
        if args.matchcode:
            cmd.append("-mc")
            cmd.append(args.matchcode)
        if args.header:
            cmd.append("-H")
            cmd.append(args.header)

        print(f"[+] Running fuzzing on {target_url}...")

        try:
            subprocess.run(cmd, stderr=subprocess.PIPE, capture_output=False, check=True)
            valid_targets.append(target_url)
        except subprocess.CalledProcessError as e:
            print(f"[!] Fuzzing failed on {target_url}: {e}")

    return valid_targets


def fuzzyfind_dictionaries():
    result = subprocess.run(
        [
            "bash", "-c",
            "find -L /usr/share/wordlists -type f | "
            "fzf --preview 'head -n 20 {}' --preview-window=down:wrap"
        ],
        capture_output=False,
        text=True,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    wordlist = result.stdout.strip()
    return wordlist

#Check the web sorter, then:
#Check the whatweb context to run it on the desired ports
#Here use the ffuf +fzf thing and it is done!
