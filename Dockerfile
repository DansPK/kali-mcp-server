FROM kalilinux/kali-last-release@sha256:3ea545e38849417fc933514e117014b98aa42fd87d239177fa4c9874dcb73d5f

LABEL description="AMD64 Kali MCP worker — 75 security tools"

ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 \
    PATH=/opt/kali-mcp/bin:/opt/kali-scanners/bin:/usr/lib/jvm/java-21-openjdk-amd64/bin:$PATH \
    XDG_CACHE_HOME=/root/.cache \
    SEMGREP_SEND_METRICS=off

RUN test "$(dpkg --print-architecture)" = amd64 && \
    printf '%s\n' 'deb http://http.kali.org/kali kali-last-snapshot main contrib non-free non-free-firmware' > /etc/apt/sources.list && \
    apt-get -o Acquire::Retries=3 update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates python3 python3-pip python3-venv \
    git nodejs npm openssl file procps iproute2 iputils-ping bind9-dnsutils snmp wordlists \
    nmap masscan netcat-openbsd tcpdump arp-scan onesixtyone dnsrecon tshark \
    sqlmap nikto gobuster dirb wpscan ffuf nuclei whatweb wfuzz xsser commix \
    hydra john hashcat pocl-opencl-icd crunch \
    enum4linux exploitdb subfinder amass exiftool theharvester smbclient \
    metasploit-framework \
    binwalk foremost steghide \
    crackmapexec evil-winrm chisel \
    aircrack-ng responder python3-impacket impacket-scripts mimikatz \
    bettercap hash-identifier hashid cewl proxychains4 wifite reaver \
    zaproxy openjdk-21-jre-headless gitleaks trivy httpx-toolkit testssl.sh naabu && \
    mkdir -p /opt/kali-versions && \
    dpkg-query -W -f='${Package}\t${Version}\n' > /opt/kali-versions/apt.txt && \
    rm -rf /var/lib/apt/lists/*

COPY docker/scanner-requirements.txt /tmp/scanner-requirements.txt
RUN python3 -m venv /opt/kali-scanners && \
    /opt/kali-scanners/bin/pip install --no-cache-dir -r /tmp/scanner-requirements.txt && \
    /opt/kali-scanners/bin/pip check && \
    /opt/kali-scanners/bin/pip freeze > /opt/kali-versions/scanners.txt && \
    npm install --global newman@6.2.3 && \
    npm list --global --depth=0 > /opt/kali-versions/npm.txt && \
    npm cache clean --force

WORKDIR /app
COPY . .
RUN python3 -m venv /opt/kali-mcp && \
    /opt/kali-mcp/bin/pip install --no-cache-dir -c docker/server-requirements.txt . && \
    /opt/kali-mcp/bin/pip check && \
    /opt/kali-mcp/bin/pip freeze > /opt/kali-versions/server.txt && \
    python -c 'from kali_mcp.tools import ALL_TOOLS, TOOL_DISPATCH; names = [t.name for t in ALL_TOOLS]; assert len(names) == len(set(names)) == 75; assert set(names) == set(TOOL_DISPATCH)'

ENTRYPOINT ["python", "-m", "kali_mcp.server"]
