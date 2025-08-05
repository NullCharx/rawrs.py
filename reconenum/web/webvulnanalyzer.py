import subprocess
from pathlib import Path


def run_wapiti_scan(
    target_url,
    output_dir="results/wapiti",
    depth=5,
    delay=1,
    user_agent=None,
    cookie=None,
    proxy=None,
    auth=None,
    ssl_verify=True,
    modules=None  # list of modules, or None for --all
):
    """
    Run a full Wapiti scan on the given target.

    Args:
        target_url (str): The full URL to scan (must include scheme).
        output_dir (str): Directory to store Wapiti reports.
        depth (int): Crawl depth.
        delay (int): Delay between requests (in seconds).
        user_agent (str): Custom User-Agent.
        cookie (str): Cookie string.
        proxy (str): Proxy URL.
        auth (str): "username:password" format.
        ssl_verify (bool): Whether to verify SSL certificates.
        modules (list): Specific Wapiti modules to run, or None for all.

    Returns:
        int: Exit code of the subprocess.
    """
    report_path = Path(output_dir)
    report_path.mkdir(parents=True, exist_ok=True)

    cmd = [
        "wapiti",
        "-u", target_url,
        "--format", "json",
        "--output", str(report_path / "report.json"),
        "--scope", "page",
        "--max-depth", str(depth),
        "--max-links-per-page", "100",
        "--timeout", "30",
        "--delay", str(delay)
    ]

    if not ssl_verify:
        cmd.append("--no-ssl-check")

    if modules:
        cmd += ["--module", ",".join(modules)]
    else:
        cmd.append("--all")

    if user_agent:
        cmd += ["--user-agent", user_agent]

    if cookie:
        cmd += ["--cookie", cookie]

    if proxy:
        cmd += ["--proxy", proxy]

    if auth:
        cmd += ["--auth", auth]

    print(f"[+] Launching Wapiti: {' '.join(cmd)}")

    result = subprocess.run(cmd)
    return result.returncode