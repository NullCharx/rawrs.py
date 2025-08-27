from rawrs.core.globaldata import bcolors
from rawrs.core.context_manager import setcurrentenvproject, loadProjectContextOnMemory
from rawrs.transfer.transfertools import start_http_server, transftips


def pythonserver(args):
    """Check ftp anon login on an ip"""
    setcurrentenvproject(args)
    loadProjectContextOnMemory()

    if args.verbose > 2:
        print(args)
        print(f"[recon:ftp anon] project={args.project} verbose={args.verbose}")

    print(f"\n{bcolors.YELLOW}[i]This is one of the easiest way to transfer files to the target machine {bcolors.RESET}")

    start_http_server(args.port, args.folder)

def inittransferscanargparser(general_parser, commonparser):

    p_transfer = general_parser.add_parser("transf", parents=[commonparser], help="Data transfer to the the target machine")
    transf_subparsers = p_transfer.add_subparsers(dest="tool", metavar="[TOOL]", required=True)
    # --- Loal forward
    p_pythonserver = transf_subparsers.add_parser("pythonhttp", parents=[commonparser],
                                                   help="httpd python3 server started on the specified port and folder")
    p_pythonserver.add_argument("port", nargs=1, help="Local port to server on")
    p_pythonserver.add_argument("folder", nargs=1, help="Path to start the server on as the root (/) of the page")
    p_pythonserver.set_defaults(func=pythonserver)

    p_transfertips = transf_subparsers.add_parser("tips", parents=[commonparser],
                                                 help="Shows some tips about SSH protocol")
    p_transfertips.set_defaults(func=transftips)

