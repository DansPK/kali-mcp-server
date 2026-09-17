# AGENTS.md

## Project
Kali MCP — an MCP server exposing popular Kali Linux security tools to AI applications via the Model Context Protocol.

## Commands
- Install: `pip install -e .`
- Run: `python -m kali_mcp.server` or `kali-mcp`
- Run with auth: `KALI_MCP_AUTH_TOKEN=secret123 python -m kali_mcp.server`
- Auth: set `KALI_MCP_AUTH_TOKEN` env var or `--auth-token=...` flag. Client passes token via `_meta.auth_token` on each request. Unauthorized requests return error code -32001.

## Architecture
```
src/kali_mcp/
├── server.py          # MCP server entrypoint, tool registry, dispatch
└── tools/
    ├── base.py        # run_tool() — safe subprocess executor with timeout + blocked commands
    ├── network.py     # nmap, masscan, netcat, tcpdump, arp-scan, onesixtyone, dnsrecon, tshark
    ├── web.py         # sqlmap, nikto, gobuster, dirb, wpscan, ffuf, nuclei, whatweb, wfuzz, xsser, commix
    ├── password.py    # hydra, john, hashcat, crunch
    ├── recon.py       # enum4linux, searchsploit, subfinder, amass, exiftool, theHarvester, smbclient
    ├── metasploit.py  # msfconsole, msfvenom, msfdb, search, info, resource scripts
    ├── evasion.py     # evasive payload crafter, payload/encoder/encryption listers, shellcode→exe
    ├── forensics.py   # binwalk, volatility, foremost, steghide
    ├── post_exploit.py # crackmapexec, evil-winrm, chisel
    └── misc.py        # aircrack-ng, responder, impacket, mimikatz, bettercap, hash-identifier, cewl, proxychains, wifite, reaver
```

## Conventions
- All tool functions accept kwargs matching MCP inputSchema properties and return `str`.
- `run_tool()` in `base.py` is the single subprocess gateway — never call subprocess directly.
- `run_bash()` in `base.py` wraps `run_tool()` with `shlex.split()` for arbitrary command execution. Use only as fallback when no dedicated tool exists.
- `require_target()` in `base.py` validates target args aren't empty.
- Tool names use `snake_case` for function names but the MCP `Tool.name` is the snake_case key in TOOL_DISPATCH.
- Add new tools by: (1) creating the function in the appropriate tools/ module, (2) adding a `Tool(...)` definition and a `TOOL_DISPATCH` entry in server.py.
- Timeout defaults: most tools 120–300s, password cracking 600s, packet capture 60s.
- `BLOCKED_COMMANDS` set in `base.py` prevents dangerous shell commands from being executed.
