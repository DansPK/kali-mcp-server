import asyncio
import functools
import os
import sys
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import MCPError
from mcp.types import (
    Tool,
    TextContent,
    ListToolsResult,
    CallToolResult,
    CallToolRequestParams,
    ListToolsRequest,
)

from kali_mcp.tools import network, web, password, recon, misc, metasploit, evasion, forensics, post_exploit

server = Server("kali-mcp")
AUTH_TOKEN: str = ""

ALL_TOOLS: list[Tool] = [
    # ===================== NETWORK (8) =====================
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

    # ===================== WEB (11) =====================
    Tool(
        name="sqlmap",
        description=(
            "Automated SQL injection detection, exploitation, and data extraction. "
            "Use when you find a URL parameter that may be injectable. Handles detection, database fingerprinting, "
            "data dumping, and even OS shell access via SQLi. "
            "Output: confirms injectable parameters, database type/version, and extracted data. "
            "For command injection (not SQL), use commix. For XSS, use xsser."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL with parameters (e.g. 'http://example.com/page.php?id=1')"},
                "opts": {"type": "string", "description": "Additional options. Default: --batch --random-agent (non-interactive with random user-agent)"},
            },
            "required": ["url"],
        },
    ),
    Tool(
        name="nikto",
        description=(
            "Web server vulnerability scanner — checks for 6700+ known issues: outdated server software, "
            "dangerous files/CGIs, default credentials, and server misconfigurations. "
            "Use early in web recon to find low-hanging vulnerabilities. Does NOT exploit — only reports. "
            "For modern CVE-based scanning, use nuclei. For WordPress-specific, use wpscan. "
            "Output: categorized list of findings with severity."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Target host or IP (e.g. 192.168.1.10 or example.com)"},
                "port": {"type": "string", "description": "Web server port (default: 80). Use 443 for HTTPS."},
                "opts": {"type": "string", "description": "Additional nikto options (e.g. '-ssl' for HTTPS, '-Tuning 9' for SQLi tests)"},
            },
            "required": ["host"],
        },
    ),
    Tool(
        name="gobuster",
        description=(
            "Fast multi-mode brute-force tool: directory/files (dir), DNS subdomains (dns), virtual hosts (vhost), and fuzzing. "
            "Use for discovering hidden paths and subdomains. Written in Go — faster than dirb. "
            "For pure directory brute-force, dirb is simpler. For parameter/header fuzzing, use ffuf. "
            "Output: discovered paths/subdomains with HTTP status codes."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL (e.g. http://example.com). Include http:// or https://"},
                "wordlist": {"type": "string", "description": "Path to wordlist file (e.g. /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt)"},
                "mode": {"type": "string", "description": "Mode: dir (directories/files), dns (subdomains), vhost (virtual hosts), fuzz (default: dir)"},
                "opts": {"type": "string", "description": "Additional gobuster options (e.g. '-x php,html,txt' for extensions)"},
            },
            "required": ["target", "wordlist"],
        },
    ),
    Tool(
        name="dirb",
        description=(
            "Classic web content scanner using dictionary-based attacks to find hidden directories and files. "
            "Simpler than gobuster — good for quick scans with built-in wordlists. "
            "Use when you want a straightforward directory scan without configuring many options. "
            "Output: list of found paths with HTTP response codes. Non-recursive by default."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL (e.g. http://192.168.1.10)"},
                "wordlist": {"type": "string", "description": "Wordlist path. Default: /usr/share/wordlists/dirb/common.txt"},
                "opts": {"type": "string", "description": "Additional dirb options (e.g. '-X .php,.txt' for specific extensions)"},
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="wpscan",
        description=(
            "Dedicated WordPress security scanner. Enumerates installed plugins, themes, users, "
            "and checks for known vulnerabilities in all of them. "
            "Use ONLY when the target is confirmed to be WordPress (verify with whatweb first). "
            "Output: WordPress version, vulnerable plugins/themes with CVE references, enumerated usernames."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target WordPress site URL (e.g. https://blog.example.com)"},
                "opts": {"type": "string", "description": "Additional wpscan options (e.g. '--enumerate u,p,t' for users, plugins, themes)"},
            },
            "required": ["url"],
        },
    ),
    Tool(
        name="ffuf",
        description=(
            "Extremely fast web fuzzer written in Go. Supports directory discovery, virtual host enumeration, "
            "GET/POST parameter fuzzing, header fuzzing, and more. "
            "Use for high-performance fuzzing tasks. Place 'FUZZ' keyword in the target URL where fuzzing should occur. "
            "For simpler directory scans, use gobuster or dirb. For HTTP parameter brute-force, wfuzz has more features. "
            "Output: matched URLs with status codes and response sizes."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL with FUZZ keyword (e.g. 'http://example.com/FUZZ' or 'http://example.com?param=FUZZ')"},
                "wordlist": {"type": "string", "description": "Path to wordlist file"},
                "match_code": {"type": "string", "description": "HTTP status codes to match, comma-separated (default: '200,301,302'). Use 'all' to see everything."},
                "opts": {"type": "string", "description": "Additional ffuf options (e.g. '-H \"Host: FUZZ.example.com\"' for vhost)"},
            },
            "required": ["target", "wordlist"],
        },
    ),
    Tool(
        name="nuclei",
        description=(
            "Modern template-based vulnerability scanner with thousands of community-maintained YAML templates. "
            "Detects CVEs, misconfigurations, exposed panels, default credentials, and more. "
            "Use as your primary vulnerability scanner after discovering services. Much faster and more current than nikto. "
            "Output: vulnerability name, severity, matched endpoint, and remediation reference."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL, IP, hostname, or file containing targets (one per line)"},
                "opts": {"type": "string", "description": "Template options. Default: '-severity medium,high,critical'. Add '-tags cve,oast' for CVE checks."},
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="whatweb",
        description=(
            "Passive web technology fingerprinting. Identifies CMS (WordPress, Joomla, Drupal), web frameworks, "
            "JavaScript libraries, analytics platforms, CDNs, server software, and more. "
            "Use FIRST on any web target to understand the tech stack before running specialized tools. "
            "Output: structured list of identified technologies with version numbers where available."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL or IP (e.g. https://example.com)"},
                "opts": {"type": "string", "description": "Additional whatweb options (e.g. '-a 3' for aggressive level)"},
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="wfuzz",
        description=(
            "Feature-rich web application brute-forcer. Fuzzes URLs, POST data, headers, cookies, and authentication. "
            "Use for parameter discovery, login brute-force, header injection testing, and custom fuzzing scenarios. "
            "More flexible than ffuf for complex fuzzing (multi-point injection, encoders, auth handling). "
            "Output: requests with their response codes, line/word/char counts."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL with FUZZ keyword (e.g. 'http://example.com/FUZZ')"},
                "wordlist": {"type": "string", "description": "Path to wordlist file"},
                "filter_code": {"type": "string", "description": "HTTP codes to HIDE from output (e.g. '404,500'). Helps reduce noise."},
                "opts": {"type": "string", "description": "Additional wfuzz options (e.g. '-d \"user=FUZZ&pass=FUZZ\"' for POST data fuzzing)"},
            },
            "required": ["target", "wordlist"],
        },
    ),
    Tool(
        name="xsser",
        description=(
            "Cross-Site Scripting (XSS) detection and exploitation framework. Tests for reflected, stored, and DOM-based XSS. "
            "Use when you find user input reflected in page output. Automatically encodes payloads to bypass filters. "
            "For general web vulnerability scanning, use nuclei or nikto. For SQL injection, use sqlmap. "
            "Output: identified XSS vectors with payload and injection point."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL with injectable parameter (e.g. 'http://example.com/search?q=test')"},
                "opts": {"type": "string", "description": "Additional xsser options. Default: --auto (automatic mode)"},
            },
            "required": ["url"],
        },
    ),
    Tool(
        name="commix",
        description=(
            "Automated OS command injection detection and exploitation tool. "
            "Tests for shell command injection in HTTP parameters, headers, cookies, and POST data. "
            "Use when sqlmap confirms the parameter is NOT SQL injectable but may still be vulnerable to command injection. "
            "Supports multiple injection techniques: results-based, blind, time-based. "
            "Output: confirms injection, shows OS type, and provides an interactive pseudo-shell on success."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL with injectable parameter (e.g. 'http://example.com/ping?ip=127.0.0.1')"},
                "opts": {"type": "string", "description": "Additional commix options. Default: --batch (non-interactive)"},
            },
            "required": ["url"],
        },
    ),

    # ===================== PASSWORD (4) =====================
    Tool(
        name="hydra",
        description=(
            "Fast network login brute-force tool supporting 50+ protocols (SSH, FTP, HTTP, RDP, SMB, MySQL, etc.). "
            "Use for testing password strength on network services. Specify the target service and provide user/password lists. "
            "For offline hash cracking, use john or hashcat instead. "
            "Output: found credentials in login:password format, or 'no valid credentials found'."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target host or IP"},
                "service": {"type": "string", "description": "Service name (e.g. ssh, ftp, http-post-form, rdp, smb, mysql)"},
                "userlist": {"type": "string", "description": "Single username OR path to user wordlist file"},
                "passlist": {"type": "string", "description": "Path to password wordlist file"},
                "opts": {"type": "string", "description": "Additional hydra options (e.g. '-t 4' for threads, '-V' for verbose)"},
            },
            "required": ["target", "service", "userlist", "passlist"],
        },
    ),
    Tool(
        name="john",
        description=(
            "John the Ripper — offline password hash cracker. Supports hundreds of hash formats with auto-detection. "
            "Use for cracking password hashes extracted from /etc/shadow, SAM databases, or captured network hashes. "
            "CPU-based — better for smaller hash sets or when GPU is unavailable. "
            "For GPU-accelerated cracking of large hash sets, prefer hashcat. "
            "Output: cracked passwords with their corresponding hashes."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "hashfile": {"type": "string", "description": "Path to file containing hashes (one per line or colon-separated)"},
                "wordlist": {"type": "string", "description": "Path to wordlist for dictionary attack (optional — uses brute-force if omitted)"},
                "fmt": {"type": "string", "description": "Force hash format (e.g. 'raw-md5', 'sha256crypt', 'nt'). Auto-detect if omitted."},
                "opts": {"type": "string", "description": "Additional john options (e.g. '--rules' for word mangling, '--show' to display cracked)"},
            },
            "required": ["hashfile"],
        },
    ),
    Tool(
        name="hashcat",
        description=(
            "World's fastest GPU-accelerated password cracker with 300+ hash type modes. "
            "Use for high-performance cracking of large hash sets. REQUIRES the mode number matching the hash type. "
            "For CPU-only or auto-detect cracking, use john instead. Use hash_identifier first if unsure of hash type. "
            "Output: cracked hashes with their plaintext passwords. Status lines show cracking speed and progress."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "hashfile": {"type": "string", "description": "Path to file containing hashes"},
                "wordlist": {"type": "string", "description": "Path to wordlist file"},
                "mode": {"type": "integer", "description": "Hash type mode number. Key values: 0=MD5, 100=NTLM, 1000=SHA1, 1400=SHA256, 1800=sha512crypt"},
                "opts": {"type": "string", "description": "Additional hashcat options (e.g. '-r rules/best64.rule' for rules, '--show' for results)"},
            },
            "required": ["hashfile", "wordlist"],
        },
    ),
    Tool(
        name="crunch",
        description=(
            "Wordlist generator — creates custom password lists based on character sets, length ranges, and patterns. "
            "Use to generate targeted wordlists when you know password policy (min/max length, required characters). "
            "For generating wordlists from website content (password profiling), use cewl instead. "
            "Output: wordlist printed to stdout or written to a file."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "min_len": {"type": "integer", "description": "Minimum word length (e.g. 6)"},
                "max_len": {"type": "integer", "description": "Maximum word length (e.g. 8)"},
                "charset": {"type": "string", "description": "Character set to use (e.g. 'abc123!@#' or '0123456789' for numeric-only)"},
                "output": {"type": "string", "description": "Output file path to save generated wordlist"},
                "opts": {"type": "string", "description": "Additional crunch options (e.g. '-t @@@%%%' for pattern: 3 lowercase + 3 digits)"},
            },
            "required": ["min_len", "max_len"],
        },
    ),

    # ===================== RECON (7) =====================
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

    # ===================== METASPLOIT (6) =====================
    Tool(
        name="msfconsole",
        description=(
            "Metasploit Framework console — the primary interface for running exploit, auxiliary, post-exploitation, "
            "and payload modules. Use to execute exploits, scan with auxiliary modules, or run post-exploitation tasks. "
            "For generating standalone payloads without the console, use msfvenom. "
            "For searching modules without opening console, use msf_search. "
            "Output: module output, exploit results, or session information."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Metasploit command to run (e.g. 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 10.0.0.1; run')"},
                "resource_file": {"type": "string", "description": "Path to .rc resource script for multi-step automation (overrides command if set)"},
                "opts": {"type": "string", "description": "Additional commands to chain after the main command"},
            },
            "required": ["command"],
        },
    ),
    Tool(
        name="msfvenom",
        description=(
            "Metasploit payload generator — creates shellcode and executables from payloads. "
            "Use for generating standalone payloads (reverse shells, meterpreter, etc.) in various formats. "
            "For AV-evasion with encoding, encryption, and template injection, use evasive_payload instead. "
            "Output: generated payload in the requested format, or list of available payloads/encoders."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "payload": {"type": "string", "description": "Payload name (e.g. 'linux/x64/shell_reverse_tcp', 'windows/meterpreter/reverse_tcp')"},
                "lhost": {"type": "string", "description": "Listen host IP — where the payload connects back to"},
                "lport": {"type": "string", "description": "Listen port — which port the payload connects to"},
                "fmt": {"type": "string", "description": "Output format: raw, exe, dll, python, c, csharp, powershell, hex, js, vba, etc."},
                "encoder": {"type": "string", "description": "Encoder to use (e.g. 'x86/shikata_ga_nai'). Omit for no encoding."},
                "iterations": {"type": "integer", "description": "Number of encoding iterations (default: 1). More iterations = larger payload."},
                "platform": {"type": "string", "description": "Target platform: windows, linux, android, osx, solaris"},
                "arch": {"type": "string", "description": "Target architecture: x86, x64, armle, mipsle, ppc"},
                "template": {"type": "string", "description": "Path to executable to use as template (payload injected into it)"},
                "outfile": {"type": "string", "description": "Output file path to save generated payload"},
                "badchars": {"type": "string", "description": "Bad characters to avoid (e.g. '\\x00\\x0a\\x0d' for null, newline, carriage return)"},
                "opts": {"type": "string", "description": "Additional msfvenom options"},
            },
            "required": ["payload"],
        },
    ),
    Tool(
        name="msfdb",
        description=(
            "Metasploit database management. Controls the PostgreSQL database used by Metasploit for storing "
            "host data, service info, credentials, and loot from scans and exploits. "
            "Run 'init' before first use, 'start' to launch the DB, 'status' to check if running. "
            "Output: status messages about database state."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "DB command: init, start, stop, status, reinit, delete (default: status)"},
                "opts": {"type": "string", "description": "Additional msfdb options"},
            },
            "required": [],
        },
    ),
    Tool(
        name="msf_search",
        description=(
            "Search the Metasploit module database by keyword, CVE, platform, or module type. "
            "Use BEFORE opening msfconsole to find relevant modules for a target. "
            "Returns module paths, disclosure dates, ranks, and descriptions. "
            "After finding a module, use msf_info to see its options and requirements. "
            "Output: table of matching modules with full paths and metadata."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search keyword (e.g. 'smb', 'eternalblue', 'CVE-2021-34527', 'apache 2.4')"},
                "module_type": {"type": "string", "description": "Filter by module type: auxiliary, exploit, post, payload, encoder, nop"},
            },
            "required": ["query"],
        },
    ),
    Tool(
        name="msf_info",
        description=(
            "Display detailed information about a specific Metasploit module: description, available options, "
            "required settings, supported targets, and references. "
            "Use after msf_search to understand what a module does and what parameters it needs before running it. "
            "Output: module metadata, option table (name, current setting, required, description), and references."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "module_path": {"type": "string", "description": "Full module path (e.g. 'exploit/windows/smb/ms17_010_eternalblue', 'auxiliary/scanner/smb/smb_version')"},
            },
            "required": ["module_path"],
        },
    ),
    Tool(
        name="msf_resource",
        description=(
            "Execute a Metasploit resource script (.rc file) — batch automation for multi-step Metasploit operations. "
            "Use for running pre-written attack sequences, setting up multi-handlers, or automating complex module chains. "
            "Resource files contain msfconsole commands (one per line) executed sequentially. "
            "Output: combined output of all commands in the script."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "script_path": {"type": "string", "description": "Path to .rc resource script file"},
            },
            "required": ["script_path"],
        },
    ),

    # ===================== EVASION (5) =====================
    Tool(
        name="evasive_payload",
        description=(
            "Advanced payload crafter for anti-virus evasion. Applies multiple evasion layers: "
            "polymorphic encoding (shikata_ga_nai, xor), encryption (AES256, RC4), "
            "template injection into legitimate executables (putty, plink), process migration on execution, "
            "bad character avoidance, and obfuscation padding. "
            "Use INSTEAD of msfvenom when AV evasion is needed. Use msfvenom for simple/standard payload generation. "
            "Output: saved payload file path with size, plus any msfvenom warnings about the chosen configuration."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "payload": {"type": "string", "description": "Payload name (e.g. 'windows/x64/meterpreter/reverse_tcp', 'windows/meterpreter/reverse_https')"},
                "lhost": {"type": "string", "description": "Listen host IP — where the payload connects back"},
                "lport": {"type": "string", "description": "Listen port — which port the payload connects to"},
                "fmt": {"type": "string", "description": "Output format. Default: exe. Options: exe, dll, python, c, powershell, raw, vba"},
                "encoder": {"type": "string", "description": "Encoder name or 'auto'. Auto picks best encoder per architecture (shikata_ga_nai for x86, xor for x64)"},
                "iterations": {"type": "integer", "description": "Encoding iterations for polymorphism (default: 5). Higher = better evasion but larger payload."},
                "encrypt": {"type": "string", "description": "Encryption layer: aes256, rc4, xor. Adds another layer of obfuscation."},
                "encrypt_key": {"type": "string", "description": "Custom encryption key. Random if not specified."},
                "template": {"type": "string", "description": "Template executable to inject into. Use 'putty', 'plink', 'notepad', or path to custom exe."},
                "inject_process": {"type": "string", "description": "Process to migrate into on execution (e.g. 'explorer.exe', 'svchost.exe')"},
                "platform": {"type": "string", "description": "Target platform: windows (default), linux, android"},
                "arch": {"type": "string", "description": "Target architecture: x86, x64 (default), armle"},
                "badchars": {"type": "string", "description": "Characters to avoid in shellcode (default: '\\x00'). Add '\\x0a\\x0d' for HTTP payloads."},
                "obfuscate": {"type": "boolean", "description": "Enable extra obfuscation padding to inflate encoder space and evade signature detection"},
                "opts": {"type": "string", "description": "Additional raw msfvenom options (e.g. '--smallest' for minimum size)"},
            },
            "required": ["payload", "lhost", "lport"],
        },
    ),
    Tool(
        name="list_payloads",
        description=(
            "List all available msfvenom payloads with descriptions. Use BEFORE generating a payload to find "
            "the correct payload name for your target platform and connection type. "
            "Filter by platform (windows, linux, android), architecture (x86, x64), or keyword (reverse_tcp, bind, meterpreter). "
            "Output: table of payload names with descriptions, organized by platform."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "platform": {"type": "string", "description": "Filter by platform: windows, linux, android, osx, solaris, bsd"},
                "arch": {"type": "string", "description": "Filter by architecture: x86, x64, armle, mipsle, ppc, aarch64"},
                "keyword": {"type": "string", "description": "Keyword to search within payload names (e.g. 'reverse_tcp', 'meterpreter', 'bind', 'https')"},
            },
            "required": [],
        },
    ),
    Tool(
        name="list_encoders",
        description=(
            "List all available msfvenom encoders with their ranks and descriptions. "
            "Use to find the best encoder for your target architecture. "
            "Filter by platform or architecture to see relevant encoders only. "
            "Output: table of encoder names with ranks (excellent, great, good, normal, manual) and descriptions."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "platform": {"type": "string", "description": "Filter by platform: windows, linux, android"},
                "arch": {"type": "string", "description": "Filter by architecture: x86, x64"},
            },
            "required": [],
        },
    ),
    Tool(
        name="list_encryption",
        description=(
            "List available msfvenom encryption/encoding formats (aes256, rc4, xor, base64, etc.). "
            "Use to see what encryption options are available for payload generation. "
            "Output: list of supported encryption methods."
        ),
        inputSchema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    Tool(
        name="shellcode_to_exe",
        description=(
            "Convert raw shellcode from a file into a Windows executable. "
            "Use when you have shellcode from another source (Cobalt Strike, custom C code, or extracted from malware) "
            "and need to package it as an EXE for execution. "
            "Output: path to the generated executable file."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "shellcode_file": {"type": "string", "description": "Path to file containing raw shellcode bytes"},
                "arch": {"type": "string", "description": "Architecture of the shellcode: x86 (32-bit, default) or x64 (64-bit)"},
                "outfile": {"type": "string", "description": "Output executable path (default: auto-generated temp file)"},
            },
            "required": ["shellcode_file"],
        },
    ),

    # ===================== MISC: Wireless/Cred/MITM (5) =====================
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

    # ===================== FORENSICS (4) =====================
    Tool(
        name="binwalk",
        description=(
            "Firmware analysis tool — scans binary files for embedded file signatures, compressed data, "
            "and filesystem structures. Automatically extracts discovered files when using -e. "
            "Use for reverse engineering firmware images, IoT device binaries, or any blob that may contain embedded files. "
            "Output: offset map of discovered signatures and extracted file paths."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "filepath": {"type": "string", "description": "Path to firmware image or binary file to analyze"},
                "opts": {"type": "string", "description": "Additional binwalk options. Default: -e (extract embedded files). Use '-M' for recursive scan."},
            },
            "required": ["filepath"],
        },
    ),
    Tool(
        name="volatility",
        description=(
            "Memory forensics framework for analyzing RAM dumps. Extracts running processes, network connections, "
            "loaded DLLs, registry hives, injected code, and malware artifacts from memory images. "
            "Requires a memory profile matching the source OS version. "
            "Output: structured forensic data — process trees, network sockets, registry keys, or flagged anomalies."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "profile": {"type": "string", "description": "Memory profile matching the OS (e.g. 'Win7SP1x64', 'Win10x64_19041', 'Win2016x64')"},
                "image": {"type": "string", "description": "Path to memory dump file (.raw, .vmem, .mem)"},
                "plugin": {"type": "string", "description": "Plugin to run (e.g. pslist, pstree, netscan, malfind, cmdscan, hivelist, timeliner)"},
                "opts": {"type": "string", "description": "Additional volatility options (e.g. '-p PID' to filter by process ID)"},
            },
            "required": ["image", "plugin"],
        },
    ),
    Tool(
        name="foremost",
        description=(
            "File carving tool — recovers deleted files from disk images and raw data by searching for file headers, "
            "footers, and data structures. Supports common formats: images, documents, archives, executables. "
            "Use for data recovery from formatted drives, corrupted media, or when filesystem metadata is lost. "
            "Output: recovered files organized by type in the output directory."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "filepath": {"type": "string", "description": "Path to disk image or raw data file to carve"},
                "output_dir": {"type": "string", "description": "Output directory for recovered files (default: foremost_output)"},
                "opts": {"type": "string", "description": "Additional foremost options (e.g. '-t jpg,pdf,doc' to limit to specific file types)"},
            },
            "required": ["filepath"],
        },
    ),
    Tool(
        name="steghide",
        description=(
            "Steganography tool — hides data within image (JPEG, BMP) and audio (WAV, AU) files, "
            "or extracts hidden data from them. Uses passphrase-protected embedding. "
            "Use to detect hidden messages in files (CTF challenges) or to conceal data. "
            "Output: embedded file confirmation or extracted hidden content."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Operation: 'info' (check if file has hidden data), 'embed' (hide data), 'extract' (recover hidden data). Default: info"},
                "embed_file": {"type": "string", "description": "File to hide inside the cover file (for embed mode)"},
                "cover_file": {"type": "string", "description": "Cover image/audio file to hide data in (for embed) or stego file to analyze"},
                "stego_file": {"type": "string", "description": "Output stego file (for embed) or source stego file to extract from (for extract)"},
                "passphrase": {"type": "string", "description": "Passphrase used to embed or extract the hidden data"},
                "opts": {"type": "string", "description": "Additional steghide options"},
            },
            "required": [],
        },
    ),

    # ===================== POST-EXPLOIT (3) =====================
    Tool(
        name="crackmapexec",
        description=(
            "Swiss army knife for pentesting Windows/Active Directory environments. "
            "Enumerates and exploits SMB, WinRM, MSSQL, RDP, SSH, and FTP services across multiple hosts. "
            "Supports pass-the-hash, Kerberos auth, and module execution (lsassy, mimikatz, spider_plus, etc.). "
            "Use as the PRIMARY post-exploitation tool against Windows networks when you have credentials. "
            "For interactive WinRM shells, use evil_winrm. For detailed SMB enumeration, use enum4linux. "
            "Output: per-host results with authentication status, shares, logged-on users, and module output."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP, CIDR range, or hostname (e.g. 10.0.0.0/24, dc01.corp.local)"},
                "protocol": {"type": "string", "description": "Protocol to test. Default: smb. Options: smb, winrm, mssql, ssh, ftp, rdp, ldap"},
                "user": {"type": "string", "description": "Username or path to user file for authentication"},
                "password": {"type": "string", "description": "Password or path to password file for authentication"},
                "ntlm_hash": {"type": "string", "description": "NTLM hash for pass-the-hash authentication"},
                "module": {"type": "string", "description": "Module to execute on successful auth (e.g. 'lsassy' for LSASS dump, 'mimikatz', 'spider_plus' for share crawling)"},
                "opts": {"type": "string", "description": "Additional crackmapexec options (e.g. '--local-auth' for local accounts, '-k' for Kerberos)"},
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="evil_winrm",
        description=(
            "Windows Remote Management (WinRM) shell client. Provides an interactive PowerShell session "
            "on port 5985 (HTTP) or 5986 (HTTPS) with pass-the-hash support. "
            "Use when you have valid Windows credentials and WinRM is enabled (common on servers). "
            "For non-interactive WinRM command execution or multi-host testing, use crackmapexec with winrm protocol. "
            "Output: interactive PowerShell session output."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname with WinRM enabled"},
                "user": {"type": "string", "description": "Username (domain\\user or user@domain format)"},
                "password": {"type": "string", "description": "Password for authentication"},
                "ntlm_hash": {"type": "string", "description": "NTLM hash for pass-the-hash authentication (alternative to password)"},
                "port": {"type": "string", "description": "WinRM port (default: 5985 for HTTP, 5986 for HTTPS)"},
                "opts": {"type": "string", "description": "Additional evil-winrm options (e.g. '-s scripts/' for script directory, '-S' for SSL)"},
            },
            "required": ["target", "user"],
        },
    ),
    Tool(
        name="chisel",
        description=(
            "Fast TCP/UDP tunnel over HTTP/HTTPS — ideal for pivoting through firewalls and NAT. "
            "Single binary for both client and server. Encapsulates TCP connections inside HTTP WebSocket streams. "
            "Use to tunnel traffic from an internal network through a compromised host to your attack machine. "
            "Run server on your attack box, client on the pivot host with reverse port forwarding. "
            "Output: connection status and tunnel statistics."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Mode: 'server' (runs on attack box to accept connections) or 'client' (runs on pivot host to connect back)"},
                "server": {"type": "string", "description": "Server address for client mode (e.g. '10.10.10.1:8080' where attack box server is listening)"},
                "port": {"type": "string", "description": "Port. Server: listening port (default: 1080). Client: local SOCKS port."},
                "socks": {"type": "boolean", "description": "Enable SOCKS5 proxy on server side (server mode only)"},
                "opts": {"type": "string", "description": "Additional chisel options (e.g. '--fingerprint' to verify server identity)"},
            },
            "required": ["command"],
        },
    ),

    # ===================== MISC EXPANDED (5) =====================
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

TOOL_DISPATCH = {
    # Network
    "nmap": lambda **kw: network.nmap(**kw),
    "masscan": lambda **kw: network.masscan(**kw),
    "netcat": lambda **kw: network.netcat(**kw),
    "tcpdump": lambda **kw: network.tcpdump(**kw),
    "arp_scan": lambda **kw: network.arp_scan(**kw),
    "onesixtyone": lambda **kw: network.onesixtyone(**kw),
    "dnsrecon": lambda **kw: network.dnsrecon(**kw),
    "tshark": lambda **kw: network.tshark(**kw),
    # Web
    "sqlmap": lambda **kw: web.sqlmap(**kw),
    "nikto": lambda **kw: web.nikto(**kw),
    "gobuster": lambda **kw: web.gobuster(**kw),
    "dirb": lambda **kw: web.dirb(**kw),
    "wpscan": lambda **kw: web.wpscan(**kw),
    "ffuf": lambda **kw: web.ffuf(**kw),
    "nuclei": lambda **kw: web.nuclei(**kw),
    "whatweb": lambda **kw: web.whatweb(**kw),
    "wfuzz": lambda **kw: web.wfuzz(**kw),
    "xsser": lambda **kw: web.xsser(**kw),
    "commix": lambda **kw: web.commix(**kw),
    # Password
    "hydra": lambda **kw: password.hydra(**kw),
    "john": lambda **kw: password.john(**kw),
    "hashcat": lambda **kw: password.hashcat(**kw),
    "crunch": lambda **kw: password.crunch(**kw),
    # Recon
    "enum4linux": lambda **kw: recon.enum4linux(**kw),
    "searchsploit": lambda **kw: recon.searchsploit(**kw),
    "subfinder": lambda **kw: recon.subfinder(**kw),
    "amass": lambda **kw: recon.amass(**kw),
    "exiftool": lambda **kw: recon.exiftool(**kw),
    "theHarvester": lambda **kw: recon.theHarvester(**kw),
    "smbclient": lambda **kw: recon.smbclient(**kw),
    # Metasploit
    "msfconsole": lambda **kw: metasploit.msfconsole(**kw),
    "msfvenom": lambda **kw: metasploit.msfvenom(**kw),
    "msfdb": lambda **kw: metasploit.msfdb(**kw),
    "msf_search": lambda **kw: metasploit.search_module(**kw),
    "msf_info": lambda **kw: metasploit.show_module_info(**kw),
    "msf_resource": lambda **kw: metasploit.resource_script(**kw),
    # Evasion
    "evasive_payload": lambda **kw: evasion.craft_evasive_payload(**kw),
    "list_payloads": lambda **kw: evasion.list_payloads(**kw),
    "list_encoders": lambda **kw: evasion.list_encoders(**kw),
    "list_encryption": lambda **kw: evasion.list_encryption(**kw),
    "shellcode_to_exe": lambda **kw: evasion.shellcode_to_exe(**kw),
    # Misc
    "aircrack_ng": lambda **kw: misc.aircrack_ng(**kw),
    "responder": lambda **kw: misc.responder(**kw),
    "impacket": lambda **kw: misc.impacket(**kw),
    "mimikatz": lambda **kw: misc.mimikatz(**kw),
    "bettercap": lambda **kw: misc.bettercap(**kw),
    "hash_identifier": lambda **kw: misc.hash_identifier(**kw),
    "cewl": lambda **kw: misc.cewl(**kw),
    "proxychains": lambda **kw: misc.proxychains(**kw),
    "wifite": lambda **kw: misc.wifite(**kw),
    "reaver": lambda **kw: misc.reaver(**kw),
    # Forensics
    "binwalk": lambda **kw: forensics.binwalk(**kw),
    "volatility": lambda **kw: forensics.volatility(**kw),
    "foremost": lambda **kw: forensics.foremost(**kw),
    "steghide": lambda **kw: forensics.steghide(**kw),
    # Post-Exploit
    "crackmapexec": lambda **kw: post_exploit.crackmapexec(**kw),
    "evil_winrm": lambda **kw: post_exploit.evil_winrm(**kw),
    "chisel": lambda **kw: post_exploit.chisel(**kw),
}


async def handle_list_tools(ctx, _req: ListToolsRequest) -> ListToolsResult:
    return ListToolsResult(tools=ALL_TOOLS)


async def handle_call_tool(ctx, req: CallToolRequestParams) -> CallToolResult:
    handler = TOOL_DISPATCH.get(req.name)
    if not handler:
        return CallToolResult(
            content=[TextContent(type="text", text=f"[error] unknown tool: {req.name}")],
            is_error=True,
        )

    args = req.arguments or {}
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, functools.partial(handler, **args))
    return CallToolResult(content=[TextContent(type="text", text=str(result))])


def register_handlers() -> None:
    server.add_request_handler("tools/list", ListToolsRequest, handle_list_tools)
    server.add_request_handler("tools/call", CallToolRequestParams, handle_call_tool)


def register_auth_middleware() -> None:
    async def auth_middleware(ctx, call_next):
        if not AUTH_TOKEN:
            return await call_next(ctx)

        if ctx.method == "initialize":
            return await call_next(ctx)

        if ctx.method in ("tools/list", "tools/call"):
            raw_params = ctx.params or {}
            meta = raw_params.get("_meta", {}) if isinstance(raw_params, dict) else {}
            token = meta.get("auth_token", "")

            if token != AUTH_TOKEN:
                raise MCPError(
                    code=-32001,
                    message="Unauthorized: invalid or missing auth_token in _meta",
                )

        return await call_next(ctx)

    server.middleware.append(auth_middleware)


def main():
    global AUTH_TOKEN
    AUTH_TOKEN = os.environ.get("KALI_MCP_AUTH_TOKEN", "")

    for arg in sys.argv[1:]:
        if arg.startswith("--auth-token="):
            AUTH_TOKEN = arg.split("=", 1)[1]
        elif arg == "--auth-token" and sys.argv.index(arg) + 1 < len(sys.argv):
            AUTH_TOKEN = sys.argv[sys.argv.index(arg) + 1]

    register_handlers()
    register_auth_middleware()

    async def _run():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(),
            )

    asyncio.run(_run())


if __name__ == "__main__":
    main()
