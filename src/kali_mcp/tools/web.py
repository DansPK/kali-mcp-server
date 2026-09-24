from mcp.types import Tool
from ..tools.base import run_tool, require_target

TOOLS = [
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
]

DISPATCH = {
    "sqlmap": lambda **kw: sqlmap(**kw),
    "nikto": lambda **kw: nikto(**kw),
    "gobuster": lambda **kw: gobuster(**kw),
    "dirb": lambda **kw: dirb(**kw),
    "wpscan": lambda **kw: wpscan(**kw),
    "ffuf": lambda **kw: ffuf(**kw),
    "nuclei": lambda **kw: nuclei(**kw),
    "whatweb": lambda **kw: whatweb(**kw),
    "wfuzz": lambda **kw: wfuzz(**kw),
    "xsser": lambda **kw: xsser(**kw),
    "commix": lambda **kw: commix(**kw),
}


def sqlmap(url: str, opts: str = "--batch --random-agent") -> str:
    err = require_target(url)
    if err:
        return err
    cmd = ["sqlmap", "-u", url]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=300)


def nikto(host: str, port: str = "80", opts: str = "") -> str:
    err = require_target(host)
    if err:
        return err
    cmd = ["nikto", "-h", host, "-p", port]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=300)


def gobuster(target: str, wordlist: str, mode: str = "dir", opts: str = "") -> str:
    err = require_target(target)
    if err:
        return err
    if not wordlist:
        return "wordlist is required"
    cmd = ["gobuster", mode, "-u", target, "-w", wordlist]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=300)


def dirb(target: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", opts: str = "") -> str:
    err = require_target(target)
    if err:
        return err
    cmd = ["dirb", target, wordlist]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=300)


def wpscan(url: str, opts: str = "--random-user-agent") -> str:
    err = require_target(url)
    if err:
        return err
    cmd = ["wpscan", "--url", url]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=300)


def ffuf(target: str, wordlist: str, match_code: str = "200,301,302", opts: str = "") -> str:
    err = require_target(target)
    if err:
        return err
    if not wordlist:
        return "wordlist is required"
    cmd = ["ffuf", "-u", target, "-w", wordlist, "-mc", match_code]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=300)


def nuclei(target: str, opts: str = "-severity medium,high,critical") -> str:
    err = require_target(target)
    if err:
        return err
    cmd = ["nuclei", "-target", target]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=300)


def whatweb(target: str, opts: str = "") -> str:
    err = require_target(target)
    if err:
        return err
    cmd = ["whatweb", target]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=120)


def wfuzz(target: str, wordlist: str, filter_code: str = "", opts: str = "") -> str:
    err = require_target(target)
    if err:
        return err
    if not wordlist:
        return "wordlist is required"
    cmd = ["wfuzz", "-u", target, "-w", wordlist]
    if filter_code:
        cmd.extend(["--hc", filter_code])
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=300)


def xsser(url: str, opts: str = "--auto") -> str:
    err = require_target(url)
    if err:
        return err
    cmd = ["xsser", "-u", url]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=180)


def commix(url: str, opts: str = "--batch") -> str:
    err = require_target(url)
    if err:
        return err
    cmd = ["commix", "--url", url]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=300)
