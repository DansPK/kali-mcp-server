# Kali MCP Tools

59 security tools exposed via MCP for AI-assisted pentesting.

---

## Network (8)

| Tool | Description |
|---|---|
| `nmap` | Network discovery, port scanning, service/OS detection |
| `masscan` | Ultra-fast TCP port scanner |
| `netcat` | TCP/IP Swiss Army knife — connect, listen, tunnel |
| `tcpdump` | Real-time packet capture and analysis |
| `arp_scan` | ARP discovery and host fingerprinting |
| `onesixtyone` | Fast SNMP scanner and community string brute-force |
| `dnsrecon` | DNS enumeration — zone transfers, brute-force, record discovery |
| `tshark` | CLI Wireshark — capture and analyze traffic with display filters |

## Web (11)

| Tool | Description |
|---|---|
| `sqlmap` | Automated SQL injection detection and exploitation |
| `nikto` | Web server vulnerability scanner |
| `gobuster` | Directory, file, DNS, and vhost brute-force |
| `dirb` | Dictionary-based web content scanner |
| `wpscan` | WordPress vulnerability scanner |
| `ffuf` | Fast web fuzzer (dirs, vhosts, params) |
| `nuclei` | Template-based vulnerability scanner |
| `whatweb` | Web technology fingerprinting |
| `wfuzz` | Web application brute-forcer |
| `xsser` | XSS scanner and exploitation framework |
| `commix` | Automated command injection exploitation |

## Password (4)

| Tool | Description |
|---|---|
| `hydra` | Network login brute-forcer (50+ protocols) |
| `john` | John the Ripper — hash cracker (hundreds of formats) |
| `hashcat` | GPU-accelerated password cracker (300+ hash types) |
| `crunch` | Custom wordlist generator |

## Recon (7)

| Tool | Description |
|---|---|
| `enum4linux` | Windows/Samba enumeration — users, shares, groups |
| `searchsploit` | Exploit Database CLI search |
| `subfinder` | Passive subdomain discovery |
| `amass` | OSINT network mapping and asset discovery |
| `exiftool` | File metadata reader/writer |
| `theHarvester` | OSINT email and subdomain harvesting |
| `smbclient` | SMB/CIFS client — browse shares, upload/download |

## Metasploit (6)

| Tool | Description |
|---|---|
| `msfconsole` | Metasploit console — run modules and commands |
| `msfvenom` | Payload generator and encoder |
| `msfdb` | Database management (init, start, stop, status) |
| `msf_search` | Search modules by keyword and type |
| `msf_info` | Show module details and options |
| `msf_resource` | Execute .rc resource scripts |

## Evasion (5)

| Tool | Description |
|---|---|
| `evasive_payload` | Craft encoded, encrypted, template-injected payloads |
| `list_payloads` | List available msfvenom payloads |
| `list_encoders` | List available msfvenom encoders |
| `list_encryption` | List available encryption/encoding formats |
| `shellcode_to_exe` | Convert raw shellcode to Windows executable |

## Forensics (4)

| Tool | Description |
|---|---|
| `binwalk` | Firmware analysis — scan and extract embedded files |
| `volatility` | Memory forensics — analyze RAM dumps |
| `foremost` | File carving — recover deleted files |
| `steghide` | Steganography — embed/extract hidden data |

## Post-Exploitation (3)

| Tool | Description |
|---|---|
| `crackmapexec` | AD pentesting swiss army knife (SMB, WinRM, MSSQL, RDP) |
| `evil_winrm` | WinRM shell with pass-the-hash support |
| `chisel` | TCP tunnel over HTTP for pivoting |

## Misc (10)

| Tool | Description |
|---|---|
| `aircrack_ng` | WiFi security — crack WEP/WPA/WPA2 |
| `responder` | LLMNR/NBT-NS/mDNS poisoner — capture NTLMv2 hashes |
| `impacket` | Network protocol tools — secretsdump, psexec, wmiexec |
| `mimikatz` | Windows credential extraction from memory |
| `bettercap` | MITM attacks, network monitoring, manipulation |
| `hash_identifier` | Identify hash algorithm types |
| `cewl` | Wordlist generation from website content |
| `proxychains` | Proxy wrapper for any TCP connection |
| `wifite` | Automated wireless attack tool |
| `reaver` | WPS brute-force attack |

---

## Meta (1)

| Tool | Description |
|---|---|
| `run_command` | Execute arbitrary commands as a fallback when no dedicated tool is available |

---

**Total: 59 tools**
