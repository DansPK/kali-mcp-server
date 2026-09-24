from mcp.types import Tool
from ..tools.base import run_tool, require_target

TOOLS = [
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
]

DISPATCH = {
    "msfconsole": lambda **kw: msfconsole(**kw),
    "msfvenom": lambda **kw: msfvenom(**kw),
    "msfdb": lambda **kw: msfdb(**kw),
    "msf_search": lambda **kw: search_module(**kw),
    "msf_info": lambda **kw: show_module_info(**kw),
    "msf_resource": lambda **kw: resource_script(**kw),
}


def msfconsole(command: str, resource_file: str = "", opts: str = "") -> str:
    if not command:
        return "msfconsole command is required"
    cmd = ["msfconsole", "-q", "-x", f"{command}; exit"]
    if resource_file:
        cmd = ["msfconsole", "-q", "-r", resource_file]
    if opts:
        cmd[-1] = f"{command}; {opts}; exit"
    return run_tool(cmd, timeout=300)


def msfvenom(
    payload: str,
    lhost: str = "",
    lport: str = "",
    fmt: str = "raw",
    encoder: str = "",
    iterations: int = 1,
    platform: str = "",
    arch: str = "",
    template: str = "",
    outfile: str = "",
    badchars: str = "",
    opts: str = "",
) -> str:
    if not payload:
        return "payload is required (e.g. linux/x64/shell_reverse_tcp)"
    cmd = ["msfvenom", "-p", payload]
    if lhost:
        cmd.extend(["LHOST", lhost])
    if lport:
        cmd.extend(["LPORT", lport])
    if fmt:
        cmd.extend(["-f", fmt])
    if encoder:
        cmd.extend(["-e", encoder])
    if iterations > 1:
        cmd.extend(["-i", str(iterations)])
    if platform:
        cmd.extend(["--platform", platform])
    if arch:
        cmd.extend(["-a", arch])
    if template:
        cmd.extend(["-x", template])
    if outfile:
        cmd.extend(["-o", outfile])
    if badchars:
        cmd.extend(["-b", badchars])
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=120)


def msfdb(command: str = "status", opts: str = "") -> str:
    cmd = ["msfdb", command]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=30)


def search_module(query: str, module_type: str = "") -> str:
    if not query:
        return "search query is required"
    search_cmd = f"search {query}"
    if module_type:
        search_cmd += f" type:{module_type}"
    return run_tool(
        ["msfconsole", "-q", "-x", f"{search_cmd}; exit"],
        timeout=60,
    )


def show_module_info(module_path: str) -> str:
    if not module_path:
        return "module path is required"
    return run_tool(
        ["msfconsole", "-q", "-x", f"info {module_path}; exit"],
        timeout=30,
    )


def resource_script(script_path: str) -> str:
    if not script_path:
        return "resource script path is required"
    return run_tool(
        ["msfconsole", "-q", "-r", script_path],
        timeout=600,
    )
