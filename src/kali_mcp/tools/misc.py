from mcp.types import Tool
from ..tools.base import run_tool, require_target

TOOLS = [
    Tool(
        name="aircrack_ng",
        description=(
            "WiFi security auditing tool — cracks WEP, WPA/WPA2-PSK, and WPA3 keys from captured wireless traffic. "
            "Requires a .cap capture file containing the 4-way handshake (for WPA) or enough IVs (for WEP). "
            "For capturing handshakes and automating attacks, use wifite. For WPS attacks, use reaver. "
            "Output: cracked WiFi password/key on success."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "capture_file": {"type": "string", "description": "Path to .cap/.pcap capture file containing WPA handshake or WEP traffic"},
                "wordlist": {"type": "string", "description": "Path to wordlist for WPA cracking. Without this, only WEP cracking works."},
                "opts": {"type": "string", "description": "Additional aircrack-ng options (e.g. '-b AA:BB:CC:DD:EE:FF' to target specific BSSID)"},
            },
            "required": ["capture_file"],
        },
    ),
    Tool(
        name="responder",
        description=(
            "LLMNR, NBT-NS, and mDNS poisoner. Responds to name resolution requests on the local network "
            "and captures NTLMv2 password hashes from Windows systems. "
            "Use on internal network assessments to capture credentials when systems attempt to resolve names. "
            "Run on a network interface with an IP on the target subnet. "
            "Output: captured NTLMv2 hashes that can be cracked with hashcat (mode 5600)."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "interface": {"type": "string", "description": "Network interface to listen on (e.g. eth0, tun0). Must be on target network."},
                "opts": {"type": "string", "description": "Additional responder options (e.g. '-A' to analyze mode, '-w' to start WPAD server)"},
            },
            "required": ["interface"],
        },
    ),
    Tool(
        name="impacket",
        description=(
            "Collection of Python tools for Windows network protocols. Includes secretsdump (dump credentials remotely), "
            "psexec (remote command execution), wmiexec (WMI shell), GetNPUsers (AS-REP roasting), "
            "GetUserSPNs (Kerberoasting), and many more. "
            "Use for post-exploitation Windows/AD operations when you have credentials. "
            "Output: varies by module — dumped hashes, command output, or shell access."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "module": {"type": "string", "description": "Impacket module (e.g. secretsdump, psexec, wmiexec, GetNPUsers, GetUserSPNs, samrdump)"},
                "target": {"type": "string", "description": "Target IP or hostname"},
                "opts": {"type": "string", "description": "Module-specific options (e.g. 'domain/user:password@target' for authenticated access)"},
            },
            "required": ["module", "target"],
        },
    ),
    Tool(
        name="mimikatz",
        description=(
            "Windows post-exploitation tool for extracting plaintext passwords, NTLM hashes, Kerberos tickets, "
            "and PINs from memory (LSASS). "
            "Use on a compromised Windows system to dump credentials. "
            "Output: extracted credentials in structured format — usernames, domains, passwords/hashes."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "opts": {"type": "string", "description": "Mimikatz command (e.g. 'privilege::debug sekurlsa::logonpasswords' to dump logon passwords)"},
            },
            "required": [],
        },
    ),
    Tool(
        name="bettercap",
        description=(
            "Real-time MITM attack framework with modular caplets. Performs ARP spoofing, DNS spoofing, "
            "HTTP/HTTPS traffic manipulation, credential sniffing, and session hijacking. "
            "Use for man-in-the-middle attacks on a local network segment. "
            "Output: real-time captured credentials, session cookies, and traffic logs."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "iface": {"type": "string", "description": "Network interface to use (e.g. eth0, wlan0)"},
                "caplet": {"type": "string", "description": "Caplet file to load predefined attack workflows (e.g. 'http-ui', 'net.probe')"},
                "opts": {"type": "string", "description": "Additional bettercap options (e.g. '-eval \"net.probe on\"' for auto-discovery)"},
            },
            "required": [],
        },
    ),
    Tool(
        name="hash_identifier",
        description=(
            "Hash type identification tool. Analyzes a hash string and determines which algorithm(s) likely produced it "
            "(MD5, SHA1, SHA256, NTLM, bcrypt, etc.). "
            "Use BEFORE attempting to crack a hash — you must know the hash type to select the correct mode in hashcat "
            "or format in john. "
            "Output: list of possible hash types ranked by likelihood with the corresponding hashcat mode and john format."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "hash_str": {"type": "string", "description": "Hash string to identify (e.g. '5f4dcc3b5aa765d61d8327deb882cf99')"},
                "hashfile": {"type": "string", "description": "File containing hashes to identify (one per line)"},
            },
            "required": [],
        },
    ),
    Tool(
        name="cewl",
        description=(
            "Custom wordlist generator that spiders a website and extracts words from its content. "
            "Creates targeted password lists based on the vocabulary actually used by the target organization. "
            "Use to generate wordlists for password attacks when you have a target website. "
            "For generating wordlists from character sets and patterns (not website content), use crunch. "
            "Output: list of extracted words, optionally saved to a file for use with hydra, john, or hashcat."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target website URL to spider (e.g. http://example.com)"},
                "depth": {"type": "integer", "description": "How many links deep to spider from the starting URL (default: 2)"},
                "min_length": {"type": "integer", "description": "Minimum word length to include in output (default: 3)"},
                "outfile": {"type": "string", "description": "Output file path to save the generated wordlist"},
                "opts": {"type": "string", "description": "Additional cewl options (e.g. '--lowercase' for lowercase-only output)"},
            },
            "required": ["url"],
        },
    ),
    Tool(
        name="proxychains",
        description=(
            "Proxy wrapper — forces any TCP-based tool's connections through a chain of proxies "
            "(Tor, SOCKS4/5, HTTP proxies). Reads proxy configuration from /etc/proxychains4.conf. "
            "Use to route tools through a pivot host (after setting up chisel or SSH tunneling) or through Tor for anonymity. "
            "Wrap any command: proxychains nmap -sT target.com "
            "Output: the wrapped tool's normal output, plus proxy chain connection debug info."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Full command to run through proxychains (e.g. 'nmap -sT target.com' or 'curl http://internal.corp.local')"},
                "opts": {"type": "string", "description": "Additional proxychains options (e.g. '-f custom_proxychains.conf' for non-default config)"},
            },
            "required": ["command"],
        },
    ),
    Tool(
        name="wifite",
        description=(
            "Automated wireless attack tool. Handles the full WiFi cracking workflow: interface setup, target scanning, "
            "WPA handshake capture, WEP cracking, and WPS PIN attacks — all with minimal user interaction. "
            "Use as the primary wireless attack tool for streamlined WiFi security testing. "
            "For manual control over individual steps, use aircrack_ng directly. For WPS-specific attacks, use reaver. "
            "Output: real-time attack progress and recovered passwords."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "opts": {"type": "string", "description": "Additional wifite options. Default: --kill (disables interfering network services before starting)"},
            },
            "required": [],
        },
    ),
    Tool(
        name="reaver",
        description=(
            "WPS (WiFi Protected Setup) brute-force attack tool. Exploits the WPS PIN vulnerability "
            "to recover the WPA/WPA2 passphrase without needing a captured handshake. "
            "Use when the target AP has WPS enabled (many do by default). "
            "For full WiFi attack automation including WPA handshake capture, use wifite. "
            "Output: WPA PSK (password) and AP details on success, or PIN attempt progress."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "interface": {"type": "string", "description": "Wireless interface in monitor mode (e.g. wlan0mon)"},
                "bssid": {"type": "string", "description": "Target AP BSSID — MAC address of the access point (e.g. 'AA:BB:CC:DD:EE:FF')"},
                "channel": {"type": "string", "description": "Channel number the target AP is on (e.g. '6', '11')"},
                "opts": {"type": "string", "description": "Additional reaver options (e.g. '-vv' for very verbose, '-t 10' for timeout)"},
            },
            "required": ["interface", "bssid"],
        },
    ),
]

DISPATCH = {
    "aircrack_ng": lambda **kw: aircrack_ng(**kw),
    "responder": lambda **kw: responder(**kw),
    "impacket": lambda **kw: impacket(**kw),
    "mimikatz": lambda **kw: mimikatz(**kw),
    "bettercap": lambda **kw: bettercap(**kw),
    "hash_identifier": lambda **kw: hash_identifier(**kw),
    "cewl": lambda **kw: cewl(**kw),
    "proxychains": lambda **kw: proxychains(**kw),
    "wifite": lambda **kw: wifite(**kw),
    "reaver": lambda **kw: reaver(**kw),
}


def aircrack_ng(capture_file: str, wordlist: str = "", opts: str = "") -> str:
    if not capture_file:
        return "capture_file is required"
    cmd = ["aircrack-ng", capture_file]
    if wordlist:
        cmd.extend(["-w", wordlist])
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=600)


def responder(interface: str, opts: str = "") -> str:
    if not interface:
        return "interface is required"
    cmd = ["responder", "-I", interface]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=300)


def impacket(module: str, target: str, opts: str = "") -> str:
    if not module:
        return "impacket module is required"
    err = require_target(target)
    if err:
        return err
    script = f"impacket-{module}" if not module.startswith("impacket-") else module
    cmd = [script, target]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=120)


def mimikatz(opts: str = "") -> str:
    cmd = ["mimikatz"]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=60)


def bettercap(iface: str = "", caplet: str = "", opts: str = "") -> str:
    cmd = ["bettercap"]
    if iface:
        cmd.extend(["-iface", iface])
    if caplet:
        cmd.extend(["-caplet", caplet])
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=300)


def hash_identifier(hash_str: str = "", hashfile: str = "") -> str:
    if not hash_str and not hashfile:
        return "hash_str or hashfile is required"
    cmd = ["hash-identifier"]
    if hashfile:
        return run_tool(["hash-identifier", hashfile], timeout=30)
    return run_tool(cmd, timeout=30, input_data=hash_str)


def cewl(url: str, depth: int = 2, min_length: int = 3, outfile: str = "", opts: str = "") -> str:
    err = require_target(url)
    if err:
        return err
    cmd = ["cewl", url, "-d", str(depth), "-m", str(min_length)]
    if outfile:
        cmd.extend(["-w", outfile])
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=180)


def proxychains(command: str, opts: str = "") -> str:
    if not command:
        return "command is required"
    cmd = ["proxychains4"] + command.split()
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=300)


def wifite(opts: str = "--kill") -> str:
    cmd = ["wifite"]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=600)


def reaver(interface: str, bssid: str, channel: str = "", opts: str = "") -> str:
    if not interface or not bssid:
        return "interface and bssid are required"
    cmd = ["reaver", "-i", interface, "-b", bssid]
    if channel:
        cmd.extend(["-c", channel])
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=600)
