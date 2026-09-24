from . import (
    network,
    web,
    password,
    recon,
    metasploit,
    evasion,
    forensics,
    post_exploit,
    misc,
)
from .base import run_bash

# Merge all tool definitions and dispatch tables from each module
ALL_TOOLS: list = []
TOOL_DISPATCH: dict = {}

for mod in (network, web, password, recon, metasploit, evasion, forensics, post_exploit, misc):
    ALL_TOOLS.extend(getattr(mod, "TOOLS", []))
    TOOL_DISPATCH.update(getattr(mod, "DISPATCH", {}))

# Add the meta tool (run_command) — defined here since it wraps run_bash directly
from mcp.types import Tool

ALL_TOOLS.append(
    Tool(
        name="run_command",
        description=(
            "Execute an allowlisted command on the Kali system. Use ONLY as a fallback when the specific tool "
            "you need is not available as a dedicated MCP tool. Runs through /bin/bash, so full shell syntax "
            "is supported: pipes (|), chaining (&& || ;), redirection (> >> <), and command substitution ($()). "
            "Safety: only known-safe binaries are permitted (nmap, dig, grep, cat, ls, ps, ss, whois, exiftool, "
            "searchsploit, etc. — an allowlist). Every binary in a chain, pipeline, or substitution must be "
            "allowlisted, and system-damaging commands (rm, dd, shutdown, mkfs, sudo, interpreters like python3, "
            "etc.) are rejected. Use the dedicated MCP tools for anything the allowlist refuses. "
            "Output: command stdout and stderr output."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command to execute (e.g. 'whois example.com', 'dig example.com ANY')"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default: 120, max: 600)"},
            },
            "required": ["command"],
        },
    ),
)
TOOL_DISPATCH["run_command"] = run_bash
