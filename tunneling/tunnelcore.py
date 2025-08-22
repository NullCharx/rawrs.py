import asyncio

from core.config import bcolors
from core.context_manager import setcurrentenvproject, loadProjectContextOnMemory, current_project
from tunneling.ssh_pfwd import start_local_forward, start_reverse_forward, start_dynamic_socks


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

    # --- Dynamic proxy forward
    p_dynamicforward = tunnel_subparsers.add_parser("dynamic", parents=[commonparser],
                                                   help="Reverse forward on the pivot that allows data fro, the target machine to be sent to the attacker machine through the pivot SSH server")
    p_dynamicforward.add_argument("user", nargs=1, help="User on the pivot machine")
    p_dynamicforward.add_argument("host", nargs=1,
                                 help="IP of the pivot machine visible to the attacker to which the SSH connection will be made")
    p_dynamicforward.add_argument("localtarget", nargs=1, help="Local IP of the attacker machine to which the dynamic forward will be bound. Should be either 127.0.0.1 (socks locally available) or 0.0.0.0 (any connection to the port will be proxfied to the pivot. Useful for chaining or sharing)")
    p_dynamicforward.add_argument("localport", nargs=1, help="Local port on the attacker machine to bind")
    p_dynamicforward.set_defaults(func=local_forward)
    p_dynamicforward.add_argument("--identity", nargs=1,
                                  help="Path to an identity file to use for the SSH connection with the pivot machine")
    p_dynamicforward.add_argument("--credentials", nargs=1,
                                  help="A file with the password to use for the SSH connection with the pivot machine. Directly using the password aborts the script.")
    p_dynamicforward.add_argument("--autoconfig", action="store_true",
                                  help="Whether the script should try to adjust the proxychains configuration automatically. If not set, the user should manually adjust the proxychains configuration to use the dynamic forward port.")
    p_dynamicforward.set_defaults(func=dynamic_forward)

def local_forward(args):
    """
    Start a local SSH port forward (local port -> remote port).

    """
    setcurrentenvproject(args)
    loadProjectContextOnMemory()

    if args.verbose > 2:
      print(args)
      print(f"[recon:ssh diret] project={args.project} verbose={args.verbose}")

    print(f"\n{bcolors.YELLOW}[i] Local tunnels create an SSH connection from attacker to target. Remember that this tunnel is not bidirectional {bcolors.OKCYAN}")
    print(f"\n{bcolors.YELLOW}[i] Meaning that any connection outbound created from the target will probably not succeed through the same tunnel {bcolors.OKCYAN}")

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
      print(f"[recon:ssh reverse] project={args.project} verbose={args.verbose}")

    print(f"\n{bcolors.YELLOW}[i] Reverse  tunnels create an SSH connection from target to attacker. Remember that this tunnel is not bidirectional {bcolors.OKCYAN}")
    print(f"\n{bcolors.YELLOW}[i] Meaning that any connection outbound created from the attacker will not succeed through the same tunnel{bcolors.OKCYAN}")

    # Get target domains from targets
    asyncio.run(start_reverse_forward(args.user, args.host, args.pivotip, args.pivotport, args.localtarget, args.localport,args.identity,args.credentials))


def dynamic_forward(args):
    """
    Start a local SSH port forward (local port -> remote port).

    """
    setcurrentenvproject(args)
    loadProjectContextOnMemory()
    print(f"\n{bcolors.YELLOW}[i] Dynamic tunnels allow for bidirectional connection via a SOCKS proxy server and the proxychains application, without the need of specifying ports  {bcolors.OKCYAN}")
    print(f"\n{bcolors.YELLOW}[i] Although this kind of tunnels are flexible, some apps, like nmap, might not function properly when not working in a direct-connection basis with the target {bcolors.OKCYAN}")

    if args.verbose > 2:
      print(args)
      print(f"[recon:ssh dynamic] project={args.project} verbose={args.verbose}")

    # Get target domains from targets
    asyncio.run(start_dynamic_socks(args.user, args.host, args.localtarget, args.localport, args.identity,args.credentials, args.autoconfig))
