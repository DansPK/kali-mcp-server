# Kali MCP Client

Cross-platform client for the Kali MCP server. Works on **Windows**, **Linux**, and macOS.

## Files

| File | Platform | Purpose |
|------|----------|---------|
| `kali_mcp_client.py` | All | The client (stdio / SSE / Streamable HTTP) |
| `kali-client` | Linux/macOS | Bash launcher wrapper |
| `kali-client.bat` | Windows | Batch launcher wrapper |

## Setup

Requires Python 3.10+ and the `mcp` package:

```bash
pip install mcp
```

## Usage

### List available tools

```bash
# Linux / macOS
./kali-client --list

# Windows
kali-client.bat --list

# Or directly with Python (any OS)
python kali_mcp_client.py --list
```

### Call a tool (one-shot)

```bash
python kali_mcp_client.py --call nmap --kwargs '{"target": "127.0.0.1", "ports": "22,80"}'
```

Windows `cmd.exe` quoting (double quotes outside, escaped inside):

```bat
kali-client.bat --call nmap --kwargs "{\"target\": \"127.0.0.1\", \"ports\": \"22,80\"}"
```

PowerShell:

```powershell
python kali_mcp_client.py --call nmap --kwargs '{"target": "127.0.0.1"}'
```

### Interactive mode (default)

```bash
python kali_mcp_client.py
```

Interactive commands:

```
list                      List available tools
schema <tool>             Show a tool's arguments and description
call <tool> [json-args]   Call a tool, e.g. call nmap {"target": "127.0.0.1"}
help                      Show help
quit                      Exit
```

### Connect to a remote server

```bash
# SSE transport
python kali_mcp_client.py -t sse -u http://10.0.0.5:8080/sse --list

# Streamable HTTP transport
python kali_mcp_client.py -t streamable-http -u http://10.0.0.5:8080/mcp --list

# With auth token
python kali_mcp_client.py -t sse -u http://10.0.0.5:8080/sse --auth-token secret123 --list
```

Or use host/port shorthand (URL is derived: `http://HOST:PORT/sse` or `/mcp`):

```bash
python kali_mcp_client.py -t sse --host 10.0.0.5 --port 8080 --list
```

### Start the server first (for remote transports)

```bash
# On the Kali box:
KALI_MCP_AUTH_TOKEN=secret123 python -m kali_mcp.server -t sse -H 0.0.0.0 -p 8080
```

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KALI_MCP_AUTH_TOKEN` | *(empty)* | Auth token (same as `--auth-token`) |
| `KALI_MCP_TRANSPORT` | `stdio` | `stdio` \| `sse` \| `streamable-http` |
| `KALI_MCP_HOST` | `127.0.0.1` | Server host when `--url` is omitted |
| `KALI_MCP_PORT` | `8080` | Server port when `--url` is omitted |
| `KALI_MCP_PYTHON` | `python3` / `python` | Interpreter used by the launchers |
| `KALI_MCP_SERVER_DIR` | *(auto)* | Repo root for stdio PYTHONPATH setup |

## Auth behavior

- The token is sent as `_meta.auth_token` on every `tools/list` and `tools/call` request, matching the server's auth middleware (error `-32001` on mismatch).
- In **stdio** mode the client spawns the server itself and forwards the token via `--auth-token`, so they always match.
- In **sse / streamable-http** mode the server must be started with the same token (`KALI_MCP_AUTH_TOKEN` or `--auth-token`).

## Timeouts

Client-side call timeout defaults to 600s (`--timeout`), matching the server's
longest tool timeouts (password cracking 600s).
