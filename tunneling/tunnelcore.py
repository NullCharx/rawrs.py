import asyncio


from core.context_manager import setcurrentenvproject, loadProjectContextOnMemory, current_project
from tunneling.ssh_pfwd import start_local_forward, start_reverse_forward


def inittunnelscanargparser(general_parser, commonparser):
    p_tunnel = general_parser.add_parser("tun", parents=[commonparser], help="SSH and ligolo tunnels")
    tunnel_subparsers = p_tunnel.add_subparsers(dest="tool", metavar="[TOOL]", required=True)
    # --- Loal forward
    p_directforward = tunnel_subparsers.add_parser("direct", parents=[commonparser],
                                                   help="Directo portforward to reach a target machine through a pivot SSH server")
    p_directforward.add_argument("user", nargs=1, help="User on the pivot machine")
    p_directforward.add_argument("pivot", nargs=1, help="IP or hostname of the pivot machine")
    p_directforward.add_argument("localtarget", nargs=1,
                                 help="IP or hostname of the local machine visible to the pivot")
    p_directforward.add_argument("localport", nargs=1, help="Local port on the local machine to bind")
    p_directforward.add_argument("remotetarget", nargs=1, help="Target IP or hostname to reach through the pivot")
    p_directforward.add_argument("remoteport", nargs=1, help="Remote port on the target machine to reach")
    p_directforward.set_defaults(func=local_forward)
    p_directforward.add_argument("--identity", nargs=1,
                                  help="Path to an identity file to use for the SSH connection with the pivot machine")
    p_directforward.add_argument("--credentials", nargs=1,
                                  help="A file with the password to use for the SSH connection with the pivot machine. Directly using the password aborts the script.")
    p_directforward.set_defaults(func=local_forward)

    # --- Reverse forward
    p_reverseforward = tunnel_subparsers.add_parser("reverse", parents=[commonparser],
                                                   help="Reverse forward on the pivot that allows data fro, the target machine to be sent to the attacker machine through the pivot SSH server")
    p_reverseforward.add_argument("user", nargs=1, help="User on the pivot machine")
    p_reverseforward.add_argument("host", nargs=1,
                                 help="IP of the pivot machine visible to the attacker to which the SSH connection will be made")
    p_reverseforward.add_argument("pivotip", nargs=1,
                                 help="IP of the pivot machine visible to internal targets to which listening will be made")
    p_reverseforward.add_argument("pivotport", nargs=1, help="Port on the pivot machine to bind")
    p_reverseforward.add_argument("localtarget", nargs=1, help="Target of attacker IP visible to the pivot")
    p_reverseforward.add_argument("localport", nargs=1, help="Local port on the attacker machine to bind")
    p_reverseforward.set_defaults(func=local_forward)
    p_reverseforward.add_argument("--identity", nargs=1,
                                  help="Path to an identity file to use for the SSH connection with the pivot machine")
    p_reverseforward.add_argument("--credentials", nargs=1,
                                  help="A file with the password to use for the SSH connection with the pivot machine. Directly using the password aborts the script.")
    p_reverseforward.set_defaults(func=reverse_forward)

def local_forward(args):
    """
    Start a local SSH port forward (local port -> remote port).

    """
    setcurrentenvproject(args)
    loadProjectContextOnMemory()

    if args.verbose > 2:
      print(args)
      print(f"[recon:ssh diret] project={args.project} verbose={args.verbose}")

    # Get target domains from targets
    asyncio.run(start_local_forward(args.user, args.pivot, args.localtarget,args.localport, args.remotetarget, args.remoteport,args.identity,args.credentials))

def reverse_forward(args):
    """
    Start a local SSH port forward (local port -> remote port).

    """
    setcurrentenvproject(args)
    loadProjectContextOnMemory()

    if args.verbose > 2:
      print(args)
      print(f"[recon:ssh diret] project={args.project} verbose={args.verbose}")

    # Get target domains from targets
    asyncio.run(start_reverse_forward(args.user, args.host, args.pivotip, args.pivotport, args.localtarget, args.localport,args.identity,args.credentials))
