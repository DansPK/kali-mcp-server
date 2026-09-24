from mcp.types import Tool
from ..tools.base import run_tool, require_target

TOOLS = [
    Tool(
        name="nmap",
        description=(
            "Primary network scanner for host discovery, port scanning, service/version detection, and OS fingerprinting. "
            "Use this FIRST on any target to understand what's running. Returns open ports with service banners and detected OS. "
            "For fast bulk port scanning across many hosts, use masscan instead. "
            "For live host discovery on a local subnet, use arp_scan."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP, hostname, or CIDR range (e.g. 192.168.1.0/24)"},
                "ports": {"type": "string", "description": "Ports to scan (e.g. '22,80,443' or '1-1000'). Omit for top 1000 ports."},
                "opts": {"type": "string", "description": "Additional nmap options. Default: -sV -sC (version detection + safe scripts)"},
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="masscan",
        description=(
            "Ultra-fast asynchronous TCP port scanner. Use when you need to scan large IP ranges (entire subnets or the internet) for open ports. "
            "Much faster than nmap for bulk scanning but does NOT provide service/version detection. "
            "Typical workflow: masscan to find open ports, then nmap on those ports for details. "
            "Output: list of open ports with optional banner grab."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or CIDR range (e.g. 10.0.0.0/8, 192.168.1.0/24)"},
                "ports": {"type": "string", "description": "Ports to scan (default: 1-65535). Top ports: '80,443,22,21,25,3389,8080'"},
                "rate": {"type": "integer", "description": "Packets per second. Default 1000. Increase for faster scans, decrease to avoid network disruption."},
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="netcat",
        description=(
            "TCP/UDP connection utility — connect to services, create listeners, transfer files, or spawn shells. "
            "Use for quick service banner grabs, port connectivity tests, or setting up reverse/bind shells. "
            "For structured service enumeration, prefer nmap. For raw packet analysis, use tcpdump/tshark."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Target host IP or hostname to connect to"},
                "port": {"type": "string", "description": "Port number (e.g. '80', '4444')"},
                "connect": {"type": "boolean", "description": "true = connect to host:port (default), false = listen on port for incoming connections"},
            },
            "required": ["host", "port"],
        },
    ),
    Tool(
        name="tcpdump",
        description=(
            "Real-time packet capture on a network interface. Use for live traffic monitoring, debugging connectivity, "
            "or capturing evidence of network activity. For deeper protocol analysis and display filtering, use tshark. "
            "Output: raw packet headers (IP, TCP/UDP, payload snippets). Requires root/privileged access."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "interface": {"type": "string", "description": "Network interface to capture on (default: eth0). Use 'any' for all interfaces."},
                "count": {"type": "integer", "description": "Number of packets to capture before exiting (default: 50)"},
                "filt": {"type": "string", "description": "BPF filter expression (e.g. 'tcp port 80', 'host 192.168.1.1', 'icmp')"},
            },
            "required": [],
        },
    ),
    Tool(
        name="arp_scan",
        description=(
            "ARP-based host discovery on a local network segment. Sends ARP requests and identifies live hosts by MAC address and vendor. "
            "Use for initial reconnaissance of a local subnet — faster and more reliable than nmap ping scans on the same LAN. "
            "Output: IP address, MAC address, and OUI vendor name for each responding host."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP range or CIDR (e.g. 192.168.1.0/24, 10.0.0.1-254)"},
                "iface": {"type": "string", "description": "Network interface to use (auto-detected if omitted)"},
                "opts": {"type": "string", "description": "Additional arp-scan options"},
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="onesixtyone",
        description=(
            "Fast SNMP scanner — discovers SNMP-enabled devices and tests community strings. "
            "Use when you suspect SNMP is running (port 161 UDP) and want to find readable community strings "
            "(public, private, or custom). Much faster than snmpwalk for initial discovery. "
            "Output: list of IPs with their valid community strings and system descriptions."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "community": {"type": "string", "description": "Community string to test (default: 'public'). Use a file path for multiple strings."},
                "opts": {"type": "string", "description": "Additional onesixtyone options"},
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="dnsrecon",
        description=(
            "DNS enumeration tool — performs zone transfers, brute-force subdomain discovery, reverse lookups, "
            "and DNS record enumeration (A, AAAA, MX, NS, SOA, TXT, SRV). "
            "Use when you have a domain and need to map its DNS footprint. "
            "For passive subdomain discovery across many sources, prefer subfinder. "
            "Output: DNS records organized by type with associated IPs and hostnames."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain (e.g. example.com)"},
                "opts": {"type": "string", "description": "DNS record types to enumerate (default: '-t std'). Use '-t axfr' for zone transfer attempt."},
            },
            "required": ["domain"],
        },
    ),
    Tool(
        name="tshark",
        description=(
            "Command-line Wireshark — captures and deeply analyzes network traffic with full protocol dissection. "
            "Use for detailed traffic analysis, extracting specific protocol fields, or analyzing pcap files. "
            "Superior to tcpdump for protocol decoding and display filters. Can read pcap files or capture live. "
            "Output: detailed packet summaries with protocol-specific fields."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "iface": {"type": "string", "description": "Network interface for live capture (default: eth0)"},
                "count": {"type": "integer", "description": "Number of packets to capture (default: 50)"},
                "read_file": {"type": "string", "description": "Read from pcap file instead of live capture (e.g. capture.pcap)"},
                "filt": {"type": "string", "description": "Capture filter (e.g. 'tcp port 80', 'host 10.0.0.1')"},
                "opts": {"type": "string", "description": "Additional tshark options or display filters (e.g. '-Y http.request')"},
            },
            "required": [],
        },
    ),
]

DISPATCH = {
    "nmap": lambda **kw: nmap(**kw),
    "masscan": lambda **kw: masscan(**kw),
    "netcat": lambda **kw: netcat(**kw),
    "tcpdump": lambda **kw: tcpdump(**kw),
    "arp_scan": lambda **kw: arp_scan(**kw),
    "onesixtyone": lambda **kw: onesixtyone(**kw),
    "dnsrecon": lambda **kw: dnsrecon(**kw),
    "tshark": lambda **kw: tshark(**kw),
}


def nmap(target: str, ports: str = "", opts: str = "-sV -sC") -> str:
    err = require_target(target)
    if err:
        return err
    cmd = ["nmap"]
    if opts:
        cmd.extend(opts.split())
    if ports:
        cmd.extend(["-p", ports])
    cmd.append(target)
    return run_tool(cmd, timeout=300)


def masscan(target: str, ports: str = "1-65535", rate: int = 1000) -> str:
    err = require_target(target)
    if err:
        return err
    cmd = ["masscan", target, "-p", ports, "--rate", str(rate)]
    return run_tool(cmd, timeout=300)


def netcat(host: str, port: str, connect: bool = True) -> str:
    err = require_target(host)
    if err:
        return err
    cmd = ["nc", "-v"]
    if connect:
        cmd.append(host)
        cmd.append(port)
    else:
        cmd.extend(["-l", "-p", port])
    return run_tool(cmd, timeout=30)


def tcpdump(interface: str = "eth0", count: int = 50, filt: str = "") -> str:
    cmd = ["tcpdump", "-i", interface, "-c", str(count), "-n"]
    if filt:
        cmd.append(filt)
    return run_tool(cmd, timeout=60)


def arp_scan(target: str, iface: str = "", opts: str = "") -> str:
    err = require_target(target)
    if err:
        return err
    cmd = ["arp-scan", target]
    if iface:
        cmd.extend(["--interface", iface])
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=60)


def onesixtyone(target: str, community: str = "public", opts: str = "") -> str:
    err = require_target(target)
    if err:
        return err
    cmd = ["onesixtyone", "-c", community, target]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=60)


def dnsrecon(domain: str, opts: str = "-t std") -> str:
    err = require_target(domain)
    if err:
        return err
    cmd = ["dnsrecon", "-d", domain]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=120)


def tshark(iface: str = "eth0", count: int = 50, read_file: str = "", filt: str = "", opts: str = "") -> str:
    cmd = ["tshark"]
    if read_file:
        cmd.extend(["-r", read_file])
    else:
        cmd.extend(["-i", iface, "-c", str(count)])
    if filt:
        cmd.extend(["-f", filt])
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=60)
