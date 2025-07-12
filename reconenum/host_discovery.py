import nmap3

def host_discovery(args, config):
    if not args:
        print("Usage: rawrs.py scan hdiscovery <ip-range>")
        return

    ip_range = args[0]
    print(f"[*] Scanning live hosts in {ip_range}...")

    nm = nmap3.Nmap().
    # -sn = ping scan (no ports), fast host discovery
    nm.scan(hosts=ip_range, arguments='-sn')

    hosts = nm.all_hosts()
    if not hosts:
        print("[!] No hosts found.")
        return

    print(f"[+] {len(hosts)} host(s) found:")
    for host in hosts:
        state = nm[host].state()
        print(f"    {host} - {state}")
