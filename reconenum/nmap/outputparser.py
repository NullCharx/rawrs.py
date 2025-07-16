


def show_host_discovery_results(data: dict):
    hosts = data.get("Host", [])
    print(f"[+] Hosts discovered: {len(hosts)}\n")

    for host in hosts:
        addr_info = next((a for a in host.get("HostAddress", []) if a["AddressType"] == "ipv4"), None)
        hostname_info = host.get("HostNames", {}).get("HostName", [])
        hostname = hostname_info[0]["Name"] if hostname_info else "N/A"
        status = host.get("Status", {}).get("State", "unknown")
        reason = host.get("Status", {}).get("Reason", "n/a")
        vendor = addr_info.get("Vendor", "") if addr_info else ""

        print(f"  - {addr_info['Address']:<15} ({hostname})  →  {status.upper()} (reason: {reason}){' [' + vendor + ']' if vendor else ''}")

def parse_hostnames(nmap_json: dict) -> dict[str, list[str]]:
    """Return a dict of IP -> list of hostnames."""
    result = {}
    for host in nmap_json.get("Host", []):
        ip = host.get("HostAddress", [{}])[0].get("Address")
        names = [hn.get("Name") for hn in host.get("HostNames", {}).get("HostName", [])]
        if ip and names:
            result[ip] = names
    return result