# Kali MCP

An [MCP](https://modelcontextprotocol.io) server that exposes **75 security tools**, including Kali utilities, source-code scanners, API tests, and OWASP ZAP, to AI applications.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![MCP 1.x](https://img.shields.io/badge/mcp-1.x-green)

---

## Features

- **75 tools** across 13 categories, all callable by name through the MCP `tools/list` / `tools/call` protocol.
- **Three transports** — `stdio` (default), `sse`, and `streamable-http`.
- **Optional token auth** via `_meta.auth_token` or HTTP headers, with TLS support.
- **Safe execution layer** — every subprocess goes through one gateway with allow/deny lists, required-argument validation, and per-tool timeouts.
- **OWASP ZAP integration** — auto-started headless daemon driven over its REST API (spider, active scan, alerts, reports).
- **Container-ready** — `Dockerfile`, `docker-compose.yml`, and `docker-run.sh`.

---

## Requirements

- Python **3.10+**
- Kali Linux, or any system with the corresponding CLI tools installed and on `$PATH`
- For `zap_*` tools: `zaproxy` plus a **Java 17/21 LTS** JVM (ZAP 2.17 hangs on Java 25)

---

## Installation

### Local

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

This installs the `kali-mcp` entrypoint and pins `mcp>=1.9,<2` (the server uses the MCP 1.x API).

### Docker

Prerequisites: Git, Bash, a running Docker Engine or Docker Desktop, and internet access to Docker Hub, `kali.download`, PyPI, and npm. Use an Intel/AMD machine, or a Docker installation configured to emulate **linux/amd64**. On Windows, run these commands in WSL2 with Docker integration enabled.

Run from the repository root:

```bash
# Check that this shell can access the Docker daemon.
docker info

git clone https://github.com/DansPK/kali-mcp-server.git
cd kali-mcp-server

# Build kali-mcp:latest for linux/amd64.
./docker-run.sh build

# Optional: tag the built image as kali-worker:1.0.
./docker-run.sh release
```

If you already have the repository, skip `git clone` and run the helper from your checkout. No host Python environment or Kali tool installation is required for the Docker build.

The image targets **linux/amd64 only**. ZAP and Java 21 are included in every build; no `INSTALL_ZAP` flag is needed. A first build downloads about **1.6 GB of apt packages**, plus the base image, Python scanners, and Newman. Apt packages alone occupy about **6 GB** after installation; allow at least **20 GB of free Docker storage** for image layers and build cache. Downloads and image export can take many minutes. Subsequent builds reuse cached layers.

`release` tags the current built image as **`kali-worker:1.0`**; it does not run verification or push to a registry. You can run the built image without the optional release tag using `./docker-run.sh run` (stdio MCP).

To build directly with detailed Docker output, use the same platform and image tag:

```bash
docker build --platform linux/amd64 --progress=plain -t kali-mcp:latest .
```

The Kali last-release base is pinned by digest and uses `kali-last-snapshot` from `kali.download`. The Dockerfile replaces the base image's duplicate Kali source and avoids mirror-selector redirects. Python/npm tool versions are pinned; installed package versions are recorded in `/opt/kali-versions/`. Kali's snapshot repository advances at the next release, so future builds can resolve different apt versions.

Build troubleshooting:

- **Docker unavailable:** run `docker info` to see whether the daemon is stopped or your shell lacks access to its socket. Start Docker or correct socket access, then retry.
- **Download failure:** check connectivity to the service named in the error, then rerun `./docker-run.sh build`. Completed layers remain cached.
- **Long export/unpack step:** the security-tool image is large; Docker can spend several minutes exporting layers after installation finishes. Check Docker storage if the step fails with a disk-space error.

Kali's Amass launcher downloads address datasets for real operations when absent. Help/version commands skip that download.

The helper and Compose persist scanner caches in `kali-mcp-cache` and Nuclei templates in `kali-nuclei-templates`. Runtime internet access is allowed for vulnerability databases, rules, and templates. These volumes are disposable caches, not reports. Neither credentials nor caches are committed to Git.

To scan your own project, mount it into the container and use that container path in MCP arguments:

```bash
docker run --rm -i --platform linux/amd64 \
  -v "$PWD/project:/workspace:ro" kali-worker:1.0
# MCP: semgrep {"path":"/workspace"}
# MCP: gitleaks {"path":"/workspace"}
# MCP: trivy {"path":"/workspace"}
```

---

## Quickstart

### stdio (default)

```bash
python -m kali_mcp.server          # or: kali-mcp
```

The server speaks MCP over stdin/stdout — use this when the MCP client spawns the process itself.

### Network transport

Run the server on a socket so remote clients can connect:

```bash
# Streamable HTTP (recommended for remote clients) — endpoint: http://HOST:PORT/mcp
python -m kali_mcp.server -t streamable-http -H 0.0.0.0 -p 8080

# SSE legacy transport — endpoint: http://HOST:PORT/sse
python -m kali_mcp.server -t sse -H 0.0.0.0 -p 8080

# With auth + HTTPS
python -m kali_mcp.server -t streamable-http -H 0.0.0.0 -p 8443 \
  --auth-token secret123 --ssl-certfile cert.pem --ssl-keyfile key.pem
```

Or configure entirely from the environment:

```bash
export KALI_MCP_TRANSPORT=http
export KALI_MCP_URL=http://192.168.1.5:8080/mcp
export KALI_MCP_AUTH_TOKEN=secret123
python -m kali_mcp.server
```

Verify it is up:

```bash
curl -s -X POST http://127.0.0.1:8080/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Authorization: Bearer secret123' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

---

## Transports

| Transport | Flag | Endpoint | Use when |
|---|---|---|---|
| `stdio` | `-t stdio` | stdin/stdout | The client launches the server process (Claude Desktop, most editors) |
| `streamable-http` | `-t streamable-http` | `/mcp` | Remote/shared server, multiple clients, easiest to firewall |
| `sse` | `-t sse` | `/sse` (GET) + `/messages/` (POST) | Legacy remote clients that only speak SSE |

---

## Configuration

### CLI flags

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--host`, `-H` | `KALI_MCP_HOST` | `127.0.0.1` | Bind address (`0.0.0.0` for all interfaces) |
| `--port`, `-p` | `KALI_MCP_PORT` | `8080` | Listening port |
| `--url` | `KALI_MCP_URL` | *(empty)* | Bind host/port derived from this URL (e.g. `http://192.168.1.5:8080/mcp`); the flag overrides `--host`/`--port` |
| `--transport`, `-t` | `KALI_MCP_TRANSPORT` | `stdio` | `stdio` \| `sse` \| `streamable-http` (aliases: `http`, `https` → `streamable-http`) |
| `--auth-token` | `KALI_MCP_AUTH_TOKEN` | *(empty)* | Require this token on every request |
| `--ssl-certfile` | `KALI_MCP_SSL_CERTFILE` | *(empty)* | PEM certificate for HTTPS |
| `--ssl-keyfile` | `KALI_MCP_SSL_KEYFILE` | *(empty)* | PEM private key for HTTPS |

### Response framing / large results

Over Streamable HTTP the server replies to request/response calls with
`Content-Type: application/json`, **not** an SSE frame. This matters because
clients built on httpx-sse / httpx2 cap a single SSE event at 1 MiB
(`DEFAULT_MAX_EVENT_SIZE_BYTES = 1048576`); a tool result bigger than that
aborts the call with `-32000 "...exceeded the 1048576 byte limit"`. A JSON
reply has no per-event cap, so arbitrarily large results (e.g.
`nuclei -jsonl`) are delivered intact. SSE is reserved for
progress/notifications, which this server does not emit. The legacy `/sse`
transport is inherently event-framed, so prefer Streamable HTTP for large
results.

| Env var | Default | Description |
|---|---|---|
| `KALI_MCP_JSON_RESPONSE` | `true` | Return request responses as `application/json` (avoids the SSE 1 MiB cap). Set `false` only for SSE-only clients. |
| `KALI_MCP_MAX_RESULT_BYTES` | `0` (unlimited) | Optional safety net: cap a single tool result. On overflow the leading bytes are returned with a `…[truncated: N of M bytes]` marker and the full output is written to a file on the server. |

### ZAP-specific

| Env var | Default | Description |
|---|---|---|
| `KALI_ZAP_HOST` | `127.0.0.1` | ZAP daemon bind/connect address |
| `KALI_ZAP_PORT` | `8090` | ZAP daemon port |

---

## Client configuration

### Claude Desktop / stdio clients

```json
{
  "mcpServers": {
    "kali": {
      "command": "/path/to/kali-mcp-server/.venv/bin/python",
      "args": ["-m", "kali_mcp.server"]
    }
  }
}
```

### OpenCode (remote, with auth)

```json
{
  "mcp": {
    "kali": {
      "type": "remote",
      "url": "http://127.0.0.1:8080/mcp",
      "headers": { "Authorization": "Bearer secret123" },
      "enabled": true
    }
  }
}
```

### Docker

```json
{
  "mcpServers": {
    "kali": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "--privileged", "kali-mcp:latest"]
    }
  }
}
```

Some tools (`nmap`, `masscan`, `tcpdump`) need network capabilities. The helper grants `NET_ADMIN` and `NET_RAW`; physical wireless devices and GPU access require host-specific configuration.

With auth:

```json
{
  "mcpServers": {
    "kali": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "--privileged", "-e", "KALI_MCP_AUTH_TOKEN=secret123", "kali-mcp:latest"]
    }
  }
}
```

### Docker Compose

```bash
KALI_MCP_AUTH_TOKEN=secret123 docker compose run --rm kali-mcp
```

---

## Authentication (optional)

Enable token auth with the env var or flag:

```bash
KALI_MCP_AUTH_TOKEN=secret123 python -m kali_mcp.server
kali-mcp --auth-token=secret123
```

Clients may authenticate in either of two ways:

1. **Per-request `_meta`** (works on every transport):

   ```json
   {
     "jsonrpc": "2.0",
     "id": 1,
     "method": "tools/call",
     "params": {
       "name": "nmap",
       "arguments": { "target": "127.0.0.1" },
       "_meta": { "auth_token": "secret123" }
     }
   }
   ```

2. **HTTP headers** (SSE / Streamable HTTP only) — handy for clients that only support custom headers:

   - `Authorization: Bearer <token>`
   - `X-Auth-Token: <token>`

Unauthorized requests are rejected with MCP error code `-32001`. When no token is configured, all requests are accepted.

---

## Tools

75 tools across 13 categories — see [TOOLS.md](TOOLS.md) for details.

| Category | Tools |
|---|---|
| Network | nmap, masscan, netcat, tcpdump, arp_scan, onesixtyone, dnsrecon, tshark, naabu |
| Web | sqlmap, nikto, gobuster, dirb, wpscan, ffuf, nuclei, whatweb, wfuzz, xsser, commix, httpx_probe, testssl |
| Source | semgrep, gitleaks, trivy |
| API | schemathesis, newman |
| OWASP ZAP | zap_start, zap_stop, zap_status, zap_spider, zap_active_scan, zap_scan, zap_alerts, zap_report |
| Password | hydra, john, hashcat, crunch |
| Recon | enum4linux, searchsploit, subfinder, amass, exiftool, theHarvester, smbclient |
| Metasploit | msfconsole, msfvenom, msfdb, msf_search, msf_info, msf_resource |
| Evasion | evasive_payload, list_payloads, list_encoders, list_encryption, shellcode_to_exe |
| Forensics | binwalk, volatility, foremost, steghide |
| Post-Exploit | crackmapexec, evil_winrm, chisel |
| Misc | aircrack_ng, responder, impacket, mimikatz, bettercap, hash_identifier, cewl, proxychains, wifite, reaver |
| Meta | run_command |

---

## OWASP ZAP

The `zap_*` tools drive a headless [OWASP ZAP](https://www.zaproxy.org/) daemon over its REST API (stdlib only — no extra Python dependency). The daemon is auto-started on first use and reused across calls.

```bash
# Install ZAP (Kali/Ubuntu)
apt install zaproxy

# ZAP 2.17 needs a Java 17/21 LTS JVM; it hangs on Java 25.
apt install openjdk-21-jre-headless
```

The server auto-selects a 17/21 JVM if present. Typical workflow:

```
zap_scan   { "url": "http://target" }     # spider + active scan + findings
zap_alerts { "risk": "High" }             # review findings
zap_report { "template": "traditional-html" }
zap_stop                                   # free resources when done
```

`zap_report` supports `traditional-html`, `traditional-md`, `modern`, `high-level-report`, and `sarif-json`. (ZAP 2.17's `traditional-json`/`traditional-xml` templates are broken when alerts exist.)

> Only use `zap_active_scan` / `zap_scan` against systems you are authorized to test.

---

## Architecture

```
src/kali_mcp/
├── server.py          # Entrypoint: CLI/transports, tool registry, dispatch, auth middleware
└── tools/
    ├── base.py        # run_tool() subprocess gateway + start_background() for daemons
    ├── network.py     # Network scanning, packet capture, DNS/SNMP enumeration
    ├── web.py         # Web vulnerability scanning, fuzzing, injection tools
    ├── source.py      # Semgrep, Gitleaks, Trivy
    ├── api.py         # Schemathesis, Newman
    ├── password.py    # Brute-force, hash cracking, wordlist generation
    ├── recon.py       # OSINT, SMB/DNS enumeration, metadata extraction
    ├── metasploit.py  # Full Metasploit Framework integration
    ├── evasion.py     # AV evasion payload crafting and enumeration
    ├── forensics.py   # Memory analysis, file carving, steganography
    ├── post_exploit.py # AD pentesting, WinRM shells, pivoting
    ├── misc.py        # Wireless attacks, credential capture, MITM
    └── zap.py         # OWASP ZAP daemon REST API: spider, scan, alerts, reports
```

Each tool module exports a `TOOLS` list and a `DISPATCH` dict; `tools/__init__.py` merges them into `ALL_TOOLS` / `TOOL_DISPATCH`.

### Compatibility notes

- `volatility` uses Volatility 3's `vol` CLI: pass `image` and a namespaced `plugin` such as `windows.pslist`. The old `profile` argument is removed; symbols may need downloads or local setup.
- `hash_identifier` uses non-interactive `hashid` with the same `hash_str` / `hashfile` arguments. The older interactive `hash-identifier` program fails when stdin closes.
- `mimikatz` lists installed Windows resources. Passing execution options returns an error; Windows execution is outside this Linux container.
- Failed commands retain stdout/stderr and set MCP `isError`. Gitleaks findings remain successful scan results with redacted JSON. Schemathesis/Newman failing checks return an error plus their report.
- New wrappers parse quoted `opts` into argument lists and use bounded timeouts. `httpx_probe` calls `httpx-toolkit`, avoiding the Python `httpx` executable name conflict.

---

## Safety

- Only one subprocess gateway (`run_tool()` / `run_bash()` in `base.py`); long-lived daemons use `start_background()`.
- `run_command` enforces an **allowlist** of safe binaries; destructive commands (`rm`, `dd`, `shutdown`, `mkfs`, interpreters, …) are rejected.
- A denylist runs as defense-in-depth across chains, pipes, and substitutions.
- Required arguments are validated, and every tool has a timeout (30s–900s).
- Optional token auth rejects unauthorized requests.

---

## Disclaimer

This tool is intended for authorized security testing and educational purposes only.
Users are responsible for complying with all applicable laws and regulations.
Unauthorized use of security tools against systems you do not own or have explicit
permission to test is illegal.

## License

MIT
