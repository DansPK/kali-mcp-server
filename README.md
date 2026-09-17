# Kali MCP

An MCP server exposing 58 popular Kali Linux security tools to AI applications via the [Model Context Protocol](https://modelcontextprotocol.io).

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Usage

```bash
# Direct
python -m kali_mcp.server

# Via entrypoint
kali-mcp
```

Configure in your MCP client (e.g. Claude Desktop, OpenCode):

```json
{
  "mcpServers": {
    "kali": {
      "command": "python",
      "args": ["-m", "kali_mcp.server"]
    }
  }
}
```

## Tools

58 tools across 10 categories. See [TOOLS.md](TOOLS.md) for the full list.

| Category | Tools |
|---|---|
| Network | nmap, masscan, netcat, tcpdump, arp_scan, onesixtyone, dnsrecon, tshark |
| Web | sqlmap, nikto, gobuster, dirb, wpscan, ffuf, nuclei, whatweb, wfuzz, xsser, commix |
| Password | hydra, john, hashcat, crunch |
| Recon | enum4linux, searchsploit, subfinder, amass, exiftool, theHarvester, smbclient |
| Metasploit | msfconsole, msfvenom, msfdb, msf_search, msf_info, msf_resource |
| Evasion | evasive_payload, list_payloads, list_encoders, list_encryption, shellcode_to_exe |
| Forensics | binwalk, volatility, foremost, steghide |
| Post-Exploit | crackmapexec, evil_winrm, chisel |
| Misc | aircrack_ng, responder, impacket, mimikatz, bettercap, hash_identifier, cewl, proxychains, wifite, reaver |

## Requirements

- Python 3.10+
- Kali Linux (or any system with the corresponding CLI tools installed)
- Tools must be installed and available on `$PATH`

## Architecture

```
src/kali_mcp/
├── server.py          # MCP server entrypoint, tool registry, dispatch
└── tools/
    ├── base.py        # Safe subprocess executor with timeout + blocked commands
    ├── network.py     # Network scanning, packet capture, DNS/SNMP enumeration
    ├── web.py         # Web vulnerability scanning, fuzzing, injection tools
    ├── password.py    # Brute-force, hash cracking, wordlist generation
    ├── recon.py       # OSINT, SMB/DNS enumeration, metadata extraction
    ├── metasploit.py  # Full Metasploit Framework integration
    ├── evasion.py     # AV evasion payload crafting and enumeration
    ├── forensics.py   # Memory analysis, file carving, steganography
    ├── post_exploit.py # AD pentesting, WinRM shells, pivoting
    └── misc.py        # Wireless attacks, credential capture, MITM
```

## Safety

- Commands run with configurable timeouts (30s–600s depending on tool)
- Dangerous system commands (`rm`, `dd`, `shutdown`, etc.) are blocked
- Target validation ensures required parameters are not empty

## License

MIT
