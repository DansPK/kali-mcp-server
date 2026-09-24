from mcp.types import Tool
from ..tools.base import run_tool, require_target

TOOLS = [
    Tool(
        name="enum4linux",
        description=(
            "Windows/Samba enumeration tool. Extracts user lists, shares, groups, password policies, "
            "and OS information from SMB services (ports 139/445). "
            "Use for Windows domain reconnaissance without authentication. "
            "For more advanced AD enumeration with credentials, use crackmapexec or impacket modules. "
            "Output: structured enumeration data including RID-cycled user lists and accessible shares."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname of Windows/Samba server"},
                "opts": {"type": "string", "description": "Additional enum4linux options (e.g. '-a' for all enumeration)"},
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="searchsploit",
        description=(
            "Command-line interface to the Exploit Database. Search for public exploit code by software name, "
            "version, CVE number, or vulnerability description. "
            "Use after identifying software versions (from nmap, whatweb, etc.) to find available exploits. "
            "Output: exploit title, path, and sometimes the exploit file content. "
            "Pair with msf_search for Metasploit module equivalents."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search term, CVE ID (e.g. 'CVE-2017-0144'), or software name (e.g. 'vsftpd 2.3.4')"},
                "opts": {"type": "string", "description": "Additional searchsploit options (e.g. '-m 12345' to mirror/copy an exploit to current dir)"},
            },
            "required": ["query"],
        },
    ),
    Tool(
        name="subfinder",
        description=(
            "Passive subdomain discovery using multiple online sources (certificate transparency, search engines, DNS datasets). "
            "No direct DNS queries — completely passive and undetectable. "
            "Use for initial domain reconnaissance to map external attack surface. "
            "For active DNS brute-force and zone transfers, use dnsrecon. For deeper OSINT, use amass. "
            "Output: list of discovered subdomains."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain (e.g. example.com). Do NOT include subdomains."},
                "opts": {"type": "string", "description": "Additional subfinder options (e.g. '-all' for all sources, '-o output.txt')"},
            },
            "required": ["domain"],
        },
    ),
    Tool(
        name="amass",
        description=(
            "Comprehensive network mapping and attack surface discovery using OSINT and active techniques. "
            "Discovers subdomains, IP ranges, ASNs, and related domains. "
            "Use for deep domain mapping — combines passive (OSINT) and active (DNS brute-force) methods. "
            "More thorough than subfinder but slower. Use subfinder for quick passive-only results. "
            "Output: discovered assets with their sources and relationships."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain (e.g. example.com)"},
                "mode": {"type": "string", "description": "Mode: 'enum' for subdomain enumeration (default), 'intel' for OSINT on IP ranges/ASNs"},
                "opts": {"type": "string", "description": "Additional amass options (e.g. '-active' to enable active DNS brute-force)"},
            },
            "required": ["domain"],
        },
    ),
    Tool(
        name="exiftool",
        description=(
            "Read, write, and edit metadata embedded in files — images, PDFs, Office documents, audio, video. "
            "Use to extract hidden information: GPS coordinates from photos, author names from documents, "
            "software versions from PDFs, or creation timestamps. "
            "Output: all metadata fields with their values. Can also strip or modify metadata."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "filepath": {"type": "string", "description": "Path to the file to analyze (image, PDF, document, etc.)"},
                "opts": {"type": "string", "description": "Additional exiftool options (e.g. '-all=' to strip all metadata)"},
            },
            "required": ["filepath"],
        },
    ),
    Tool(
        name="theHarvester",
        description=(
            "OSINT tool for harvesting emails, names, subdomains, IPs, and URLs from public sources "
            "(Google, Bing, LinkedIn, Shodan, PGP key servers, and 20+ others). "
            "Use for early reconnaissance to identify employee email patterns, exposed services, and related domains. "
            "Output: organized results by source — emails, hosts, IPs, and URLs."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain (e.g. example.com)"},
                "source": {"type": "string", "description": "Data source to query. 'all' uses all available sources. Options: google, linkedin, shodan, hunter, etc."},
                "limit": {"type": "integer", "description": "Maximum results per source (default: 100). Lower if getting rate-limited."},
                "opts": {"type": "string", "description": "Additional theHarvester options"},
            },
            "required": ["domain"],
        },
    ),
    Tool(
        name="smbclient",
        description=(
            "SMB/CIFS client — connects to Windows file shares for browsing, downloading, and uploading files. "
            "Use to access SMB shares with or without credentials (anonymous/null session). "
            "For SMB vulnerability scanning, use nmap or crackmapexec. For automated share enumeration, use enum4linux. "
            "Output: directory listings, file contents, or confirmation of upload/download."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "share": {"type": "string", "description": "Share name (e.g. 'C$', 'IPC$', 'shared'). Leave empty to list shares."},
                "user": {"type": "string", "description": "Username for authentication. Omit for anonymous/null session."},
                "password": {"type": "string", "description": "Password for authentication"},
                "command": {"type": "string", "description": "SMB command to execute (e.g. 'ls' to list, 'get file.txt' to download)"},
                "opts": {"type": "string", "description": "Additional smbclient options"},
            },
            "required": ["target"],
        },
    ),
]

DISPATCH = {
    "enum4linux": lambda **kw: enum4linux(**kw),
    "searchsploit": lambda **kw: searchsploit(**kw),
    "subfinder": lambda **kw: subfinder(**kw),
    "amass": lambda **kw: amass(**kw),
    "exiftool": lambda **kw: exiftool(**kw),
    "theHarvester": lambda **kw: theHarvester(**kw),
    "smbclient": lambda **kw: smbclient(**kw),
}


def enum4linux(target: str, opts: str = "") -> str:
    err = require_target(target)
    if err:
        return err
    cmd = ["enum4linux", target]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=180)


def searchsploit(query: str, opts: str = "") -> str:
    if not query:
        return "search query is required"
    cmd = ["searchsploit", query]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=60)


def subfinder(domain: str, opts: str = "") -> str:
    err = require_target(domain)
    if err:
        return err
    cmd = ["subfinder", "-d", domain]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=120)


def amass(domain: str, mode: str = "enum", opts: str = "") -> str:
    err = require_target(domain)
    if err:
        return err
    cmd = ["amass", mode, "-d", domain]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=300)


def exiftool(filepath: str, opts: str = "") -> str:
    if not filepath:
        return "filepath is required"
    cmd = ["exiftool", filepath]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=60)


def theHarvester(domain: str, source: str = "all", limit: int = 100, opts: str = "") -> str:
    err = require_target(domain)
    if err:
        return err
    cmd = ["theHarvester", "-d", domain, "-b", source, "-l", str(limit)]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=120)


def smbclient(target: str, share: str = "", user: str = "", password: str = "", command: str = "", opts: str = "") -> str:
    err = require_target(target)
    if err:
        return err
    cmd = ["smbclient"]
    if share:
        cmd.append(f"//{target}/{share}")
    if user:
        cmd.extend(["-U", user])
    if password:
        cmd.append(f"--password={password}")
    if command:
        cmd.extend(["-c", command])
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=60)
