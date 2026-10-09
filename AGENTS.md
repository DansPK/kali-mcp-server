# AGENTS.md

## Project
Kali MCP — an MCP server exposing popular Kali Linux security tools to AI applications via the Model Context Protocol.

## Commands
- Install: `pip install -e .`
- Run: `python -m kali_mcp.server` or `kali-mcp`
- Docker: `docker build -t kali-mcp:latest .` then `docker run --rm -i kali-mcp:latest`
- Compose: `docker compose run --rm kali-mcp`
- Run with auth: `KALI_MCP_AUTH_TOKEN=secret123 python -m kali_mcp.server`
- Run over HTTP (env-driven): `KALI_MCP_TRANSPORT=http KALI_MCP_URL=http://HOST:PORT/mcp KALI_MCP_AUTH_TOKEN=secret123 python -m kali_mcp.server` — `http`/`https` alias `streamable-http`; `KALI_MCP_URL` supplies bind host/port.
- Auth: set `KALI_MCP_AUTH_TOKEN` env var or `--auth-token=...` flag. Client passes token via `_meta.auth_token` on each request, or via `Authorization: Bearer <token>` / `X-Auth-Token` headers on SSE/HTTP transports. Unauthorized requests return error code -32001.

## Architecture
```
src/kali_mcp/
├── server.py          # MCP server entrypoint, tool registry, dispatch
└── tools/
    ├── base.py        # run_tool() — safe subprocess executor; start_background() for daemons
    ├── network.py     # nmap, masscan, netcat, tcpdump, arp-scan, onesixtyone, dnsrecon, tshark
    ├── web.py         # sqlmap, nikto, gobuster, dirb, wpscan, ffuf, nuclei, whatweb, wfuzz, xsser, commix
    ├── password.py    # hydra, john, hashcat, crunch
    ├── recon.py       # enum4linux, searchsploit, subfinder, amass, exiftool, theHarvester, smbclient
    ├── metasploit.py  # msfconsole, msfvenom, msfdb, search, info, resource scripts
    ├── evasion.py     # evasive payload crafter, payload/encoder/encryption listers, shellcode→exe
    ├── forensics.py   # binwalk, volatility, foremost, steghide
    ├── post_exploit.py # crackmapexec, evil-winrm, chisel
    ├── misc.py        # aircrack-ng, responder, impacket, mimikatz, bettercap, hash-identifier, cewl, proxychains, wifite, reaver
    └── zap.py         # OWASP ZAP daemon REST API: spider, active scan, alerts, reports
```

## Conventions
- All tool functions accept kwargs matching MCP inputSchema properties and return `str`.
- `run_tool()` in `base.py` is the single subprocess gateway — never call subprocess directly.
- `run_bash()` in `base.py` wraps `run_tool()` with `shlex.split()` for arbitrary command execution. Use only as fallback when no dedicated tool exists.
- `start_background()` / `stop_background()` in `base.py` are the only sanctioned way to run long-lived daemons (used by ZAP). Never call `subprocess` directly outside `base.py`.
- `require_target()` in `base.py` validates target args aren't empty.
- Tool names use `snake_case` for function names but the MCP `Tool.name` is the snake_case key in TOOL_DISPATCH.
- Add new tools by: (1) creating the function in the appropriate tools/ module, (2) adding a `Tool(...)` to that module's `TOOLS` list and an entry in its `DISPATCH` dict. `tools/__init__.py` merges every module into `ALL_TOOLS` / `TOOL_DISPATCH`.
- `zap_*` tools need `zaproxy` + a Java 17/21 LTS JVM (ZAP 2.17 hangs on Java 25); the daemon is auto-started via `start_background()` and driven over its REST API.
- Streamable-HTTP uses `json_response=True` (`KALI_MCP_JSON_RESPONSE`) so tool results return as `application/json`; SSE frames have a 1 MiB per-event cap in httpx-sse/httpx2 clients that aborts large results with -32000. Optional `KALI_MCP_MAX_RESULT_BYTES` caps a single result (marker + overflow file), 0 = unlimited.
- Timeout defaults: most tools 120–300s, password cracking 600s, packet capture 60s.
- `BLOCKED_COMMANDS` set in `base.py` prevents dangerous shell commands from being executed.
