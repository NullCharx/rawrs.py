from rawrs.core.context_manager import setcurrentenvproject, loadProjectContextOnMemory


def cmd_osint(args):
    """
    Handler for the osint commands
    :param args: arguments to be passed to the osint subtool
    :return:
    """
    setcurrentenvproject(args)
    loadProjectContextOnMemory()

    if args.verbose < 2:
        print(f"[osint] target={args.target}")