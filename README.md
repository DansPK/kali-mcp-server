# Kali MCP

Kali MCP exposes **75 security tools** to AI applications through the [Model Context Protocol (MCP)](https://modelcontextprotocol.io). It supports network and web scanning, source-code analysis, API testing, forensics, and OWASP ZAP workflows.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![MCP 1.x](https://img.shields.io/badge/mcp-1.x-green)

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quickstart](#quickstart)
- [Client configuration](#client-configuration)
- [Configuration](#configuration)
- [Available tools](#available-tools)
- [Project structure](#project-structure)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Responsible use](#responsible-use)
- [License](#license)

## Features

- 75 MCP tools across 13 categories.
- Stdio, Streamable HTTP, and legacy SSE transports.
- Optional token authentication and HTTPS support.
- Subprocess timeouts, argument validation, and command restrictions for the shell fallback.
- Headless OWASP ZAP integration for crawling, scanning, alerts, and reports.
- An AMD64 Kali Docker image with isolated Python environments and Java 21.

## Requirements

| Deployment | Requirements |
| --- | --- |
| Docker | Git, Bash, Docker Engine or Docker Desktop, and internet access for image builds |
| Local | Python 3.10+, Kali Linux or the required CLI tools installed on `PATH` |
| Local ZAP | `zaproxy` and a Java 17 or 21 JVM |

The Docker image targets **linux/amd64**. Other architectures require AMD64 emulation. On Windows, run the helper in WSL2 with Docker integration enabled.

Allow at least **20 GB of free Docker storage** for the image and build cache. First builds download roughly 1.6 GB of apt packages plus the base image and Python/npm dependencies, and can take many minutes. Scanners may also download vulnerability databases, rules, or datasets at runtime.

## Installation

Clone the repository:

```bash
git clone https://github.com/DansPK/kali-mcp-server.git
cd kali-mcp-server
```

### Docker

Confirm Docker is accessible, then build the image:

```bash
docker info
./docker-run.sh build
```

This creates `kali-mcp:latest`. To build directly with detailed output:

```bash
docker build --platform linux/amd64 --progress=plain -t kali-mcp:latest .
```

Optionally create the `kali-worker:1.0` tag:

```bash
./docker-run.sh release
```

`release` tags the current image; it does not run verification or push to a registry. Installed package versions are recorded inside the image under `/opt/kali-versions/`. The base image is pinned by digest, but Kali snapshot packages can change between releases.

### Local

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

This installs the `kali-mcp` entrypoint and the MCP Python dependency (`mcp>=1.9,<2`). Install the security tools you need separately; the Python package does not install their executables.

## Quickstart

### Stdio

Stdio is the default transport for both local and Docker deployments. An MCP client launches the process and communicates through stdin/stdout.

```bash
# Docker
./docker-run.sh run

# Local
kali-mcp
```

The equivalent Docker command is:

```bash
docker run --rm -i --platform linux/amd64 \
  --cap-add=NET_ADMIN --cap-add=NET_RAW \
  kali-mcp:latest
```

Keep `-i` enabled for stdio. The helper also persists scanner caches and Nuclei templates in Docker volumes. Compose uses stdio as well:

```bash
docker compose run --rm kali-mcp
```

### Streamable HTTP

Run the container on host port **8096**:

```bash
docker run --rm --name kali-mcp-http --platform linux/amd64 \
  -p 8096:8080 \
  --cap-add=NET_ADMIN --cap-add=NET_RAW \
  -e KALI_MCP_AUTH_TOKEN=change-me \
  kali-mcp:latest \
  -t streamable-http -H 0.0.0.0 -p 8080
```

Connect your client to **`http://localhost:8096/mcp`** with `Authorization: Bearer change-me`. Replace `change-me` with your own token. The container listens on port 8080; Docker publishes it on host port 8096.

For a local installation:

```bash
KALI_MCP_AUTH_TOKEN=change-me kali-mcp \
  -t streamable-http -H 0.0.0.0 -p 8096
```

### Transport reference

| Transport | Flag | Endpoint |
| --- | --- | --- |
| Stdio | `-t stdio` (default) | stdin/stdout |
| Streamable HTTP | `-t streamable-http` or `-t http` | `/mcp` |
| Legacy SSE | `-t sse` | `/sse` and `/messages/` |

For HTTPS, pass `--ssl-certfile cert.pem --ssl-keyfile key.pem` with a network transport. The `https` transport alias alone does not enable TLS.

## Client configuration

For clients that accept an `mcpServers` configuration, launch the Docker image over stdio:

```json
{
  "mcpServers": {
    "kali": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i", "--platform", "linux/amd64",
        "--cap-add=NET_ADMIN", "--cap-add=NET_RAW",
        "kali-mcp:latest"
      ]
    }
  }
}
```

For a local stdio server, use the absolute path to `.venv/bin/python` as the command and `["-m", "kali_mcp.server"]` as its arguments.

For HTTP clients, configure the URL `http://localhost:8096/mcp` and the authentication header used above. Client-specific configuration formats may differ.

The repository includes a command-line client. After local installation, list tools on the HTTP server:

```bash
python client/kali_mcp_client.py \
  -t streamable-http -u http://localhost:8096/mcp \
  --auth-token change-me --list
```

See [client/README.md](client/README.md) for interactive usage and tool calls.

## Configuration

CLI arguments override the corresponding environment defaults. `--url` overrides the bind host and port; its path does not change the `/mcp` endpoint.

| CLI argument | Environment variable | Default |
| --- | --- | --- |
| `--transport`, `-t` | `KALI_MCP_TRANSPORT` | `stdio` |
| `--host`, `-H` | `KALI_MCP_HOST` | `127.0.0.1` |
| `--port`, `-p` | `KALI_MCP_PORT` | `8080` |
| `--url`, `-u` | `KALI_MCP_URL` | Unset |
| `--auth-token` | `KALI_MCP_AUTH_TOKEN` | Unset |
| `--ssl-certfile` | `KALI_MCP_SSL_CERTFILE` | Unset |
| `--ssl-keyfile` | `KALI_MCP_SSL_KEYFILE` | Unset |

`KALI_MCP_URL` supplies the bind host/port when `KALI_MCP_HOST` and `KALI_MCP_PORT` are unset. Network services inside Docker must bind to `0.0.0.0` to accept connections through published ports.

### Authentication

When a token is configured, `tools/list` and `tools/call` requests must authenticate using one of:

- HTTP header: `Authorization: Bearer <token>` or `X-Auth-Token: <token>`.
- Request metadata on any transport: `params._meta.auth_token`.

Missing or incorrect tokens return MCP error code `-32001`. Without a configured token, authentication is disabled. The bundled client supports `--auth-token` for all transports.

### Results and ZAP

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `KALI_MCP_JSON_RESPONSE` | `true` | Use JSON responses for Streamable HTTP; avoids SSE event-size limits in some clients |
| `KALI_MCP_MAX_RESULT_BYTES` | `0` | Cap a tool result in bytes; `0` is unlimited. Overflow includes a truncation marker and a server-side file containing the full result |
| `KALI_ZAP_HOST` | `127.0.0.1` | ZAP daemon address |
| `KALI_ZAP_PORT` | `8090` | ZAP daemon port |

ZAP starts automatically when needed and is reused across calls. Use `zap_stop` to shut it down. The Docker image includes ZAP and Java 21.

## Available tools

See [TOOLS.md](TOOLS.md) for the complete tool reference.

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

### Scan local files with Docker

Mount your project and pass its container path to tools such as `semgrep`, `gitleaks`, or `trivy`:

```bash
docker run --rm -i --platform linux/amd64 \
  -v "$PWD/project:/workspace:ro" kali-mcp:latest
```

For example, call `semgrep` with `{"path":"/workspace"}`. Files referenced by tool arguments must exist in the server's filesystem.

Volatility uses the Volatility 3 `vol` CLI with namespaced plugins such as `windows.pslist`. Mimikatz lists packaged Windows resources; execution requires Windows. Physical wireless devices, GPUs, and Windows/AD workflows require additional environment-specific setup.

## Project structure

```text
src/kali_mcp/
├── server.py       # CLI, transports, authentication, and MCP handlers
└── tools/          # Tool schemas, argument builders, and execution gateway
client/             # Cross-platform MCP command-line client
docker/             # Pinned dependencies and container launcher adjustments
Dockerfile          # AMD64 Kali image
docker-compose.yml  # Stdio service and cache volumes
docker-run.sh       # Build, run, release-tag, and Compose helper
TOOLS.md            # Tool reference
```

## Troubleshooting

| Problem | Action |
| --- | --- |
| Docker is unavailable | Run `docker info`; start the daemon or correct socket access |
| Build downloads fail | Check access to Docker Hub, `kali.download`, PyPI, and npm, then rerun the build |
| Image export takes a long time | Allow several minutes for large layers and check free Docker storage |
| HTTP client cannot connect | Check the published port, `-t streamable-http`, and the container's `-H 0.0.0.0` setting |
| Tool reports an authentication error | Match the client token to the server's configured token |
| Local tool executable is missing | Install the corresponding utility and make it available on `PATH`, or use Docker |
| Stdio client hangs | Keep Docker stdin open with `-i` and configure the process in an MCP client |

Some tools need network capabilities; the helper grants `NET_ADMIN` and `NET_RAW`. Amass downloads address datasets on first use for actual operations; help and version commands skip those downloads.

## Contributing

Open an issue for bugs or feature requests, or submit a pull request with a description of the change. Follow [AGENTS.md](AGENTS.md) for repository conventions.

New tool wrappers belong in the appropriate module under `src/kali_mcp/tools/`. Register each schema in its module's `TOOLS` list and its handler in `DISPATCH`. Run subprocesses through the execution helpers in `tools/base.py`.

## Responsible use

Use Kali MCP only on systems you own or have explicit permission to assess. Users are responsible for complying with applicable laws and regulations.

## License

Licensed under the [MIT License](LICENSE).
