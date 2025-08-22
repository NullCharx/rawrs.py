from reconenum.nmap.nmaptools import parsealivehosts
from reconenum.parser import parse_ip_inputs


def smb_vulns(args):
    """
    Scan SMB services for known vulnerabilities (MS17-010, etc).

    Steps:
      - Parse targets
      - Run crackmapexec with vuln modules
      - Aggregate results

    Usage:
        smb vulns -t 192.168.1.0/24
    """
    subargs = parse_ip_inputs(args.targets, args.auto, args.verbose)
    alivetargets = parsealivehosts(subargs, args.overwrite, args.verbose)
    parsedtargets = parse_smb_targets(alivetargets, subargs)

    results = crackmapexec_smbexecutor(parsedtargets, "vulns", args.user, args.password, args.domain)

    aggregate_smbvulns(
        results,
        f"{context_manager.current_project}/results/smb_vulns.json",
        args.overwrite,
    )
