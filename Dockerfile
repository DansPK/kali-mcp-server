FROM kalilinux/kali-rolling

LABEL description="Kali MCP Server — 67 security tools exposed via Model Context Protocol"

RUN echo "deb http://archive.kali.org/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list && \
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3 python3-pip python3-venv python3-setuptools python3-wheel \
    nmap masscan netcat-openbsd tcpdump arp-scan onesixtyone dnsrecon tshark \
    sqlmap nikto gobuster dirb wpscan ffuf nuclei whatweb wfuzz xsser commix \
    hydra john hashcat crunch \
    enum4linux exploitdb subfinder amass exiftool theharvester smbclient \
    metasploit-framework \
    binwalk foremost steghide \
    crackmapexec evil-winrm chisel \
    aircrack-ng responder python3-impacket impacket-scripts mimikatz \
    bettercap hash-identifier cewl proxychains4 wifite reaver \
    && rm -rf /var/lib/apt/lists/* && \
    pip3 install --break-system-packages --no-cache-dir volatility3

# Optionally bundle OWASP ZAP + a Java 17/21 LTS JVM for the zap_* tools.
# It is heavy (~400 MB), so it is opt-in:
#   docker build --build-arg INSTALL_ZAP=true -t kali-mcp:latest .
ARG INSTALL_ZAP=false
RUN if [ "$INSTALL_ZAP" = "true" ]; then \
        apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            zaproxy openjdk-21-jre-headless \
        && rm -rf /var/lib/apt/lists/*; \
    fi

WORKDIR /app
COPY . .
RUN pip3 install --break-system-packages --no-cache-dir .

ENTRYPOINT ["python3", "-m", "kali_mcp.server"]
