from core.parsers.target import parse_ip_inputs, parsealivehosts, parse_smb_targets
from core.parsers.smb import parse_smbshares, parse_smbusers, aggregate_smbvulns
from core.executors.smb import (
    smbmapexecutor,
    smbclientexecutor,
    enum4linuxexecutor,
    crackmapexec_smbexecutor,
)
from core.context import context_manager


def smb_shares(args):
    """
    Enumerate SMB shares on given targets.

    Steps:
      - Parse targets
      - Run smbmap / smbclient
      - Aggregate results into JSON

    Usage:
        smb shares -t 192.168.1.10 -u user -p pass
    """
    subargs = parse_ip_inputs(args.targets, args.auto, args.verbose)
    alivetargets = parsealivehosts(subargs, args.overwrite, args.verbose)
    parsedtargets = parse_smb_targets(alivetargets, subargs)

    # run share enumeration tools
    results = smbmapexecutor(parsedtargets, args.user, args.password, args.domain)
    results += smbclientexecutor(parsedtargets, args.user, args.password, args.domain)

    # aggregate results
    parse_smbshares(
        results,
        f"{context_manager.current_project}/results/smb_shares.json",
        args.overwrite,
    )


def smb_users(args):
    """
    Enumerate SMB/AD users from targets.

    Steps:
      - Parse targets
      - Run enum4linux / crackmapexec
      - Aggregate into user list

    Usage:
        smb users -t 192.168.1.10 -u user -p pass
    """
    subargs = parse_ip_inputs(args.targets, args.auto, args.verbose)
    alivetargets = parsealivehosts(subargs, args.overwrite, args.verbose)
    parsedtargets = parse_smb_targets(alivetargets, subargs)

    results = enum4linuxexecutor(parsedtargets, args.user, args.password, args.domain)
    results += crackmapexec_smbexecutor(parsedtargets, "users", args.user, args.password, args.domain)

    parse_smbusers(
        results,
        f"{context_manager.current_project}/results/smb_users.json",
        args.overwrite,
    )


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
