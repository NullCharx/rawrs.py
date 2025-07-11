from nmap import nmap



class nmapWrapper:

    portScanner = None

    scripts = {
        'default': '-sC',  # Default scripts
        'safe': 'safe',  # Only safe scripts
        'vuln': 'vuln',  # Vulnerability detection
        'auth': 'auth',  # Authentication bypass / brute force
        'discovery': 'discovery',  # Service / host discovery
        'external': 'external',  # External info (whois, geoip, etc.)
        'malware': 'malware',  # Malware presence checks
        'exploit': 'exploit',  # Scripts that exploit known vulns

        # Specific service families
        'http': 'http-*',  # All HTTP-related scripts
        'ftp': 'ftp-*',  # All FTP-related scripts
        'ssh': 'ssh-*',  # All SSH-related scripts
        'smb': 'smb-*',  # All SMB-related scripts
        'dns': 'dns-*',  # All DNS-related scripts
        'mysql': 'mysql-*',  # MySQL-specific scripts
        'rdp': 'rdp-*',  # RDP-specific scripts

        # Mixed utility
        'brute': 'brute',  # General brute force attempts
        'banner': 'banner',  # Try to grab service banners
    }

    def __init__(self):
        try:
            nmap.PortScanner = nmap.PortScanner()
        except nmap.PortScannerError as e:
            print(e)
            print("nmap wasn't found on regular paths! Most reconenum functions won't work unless you specify a path in the settings menu")


    def regularPortScanning(self):
        print("A")
