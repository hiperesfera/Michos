FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/opt/go
ENV GOBIN=/opt/go/bin
ENV PATH=$PATH:/opt/go/bin:/usr/local/go/bin

# Fix Kali repositories
RUN echo "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list && \
    echo "deb-src http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" >> /etc/apt/sources.list

# System utilities
RUN apt-get update --fix-missing && apt-get install -y --fix-missing \
    git python3 python3-pip python3-venv pipx whois curl wget vim sudo ssh \
    iputils-ping jq unzip golang-go ca-certificates chromium chromium-driver libcap2-bin \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Scanning, Fingerprinting, and OSINT
RUN apt-get update && apt-get install -y \
    nmap naabu masscan nikto whatweb wafw00f sslscan sslyze dnsx amass \
    theharvester recon-ng dnsrecon dnsenum fierce \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery / Modern Web Recon Suite
RUN apt-get update && apt-get install -y \
    nuclei httpx-toolkit subfinder \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN nuclei -update-templates -silent || true

# Web Proxies & Interceptors
RUN apt-get update && apt-get install -y \
    burpsuite zaproxy mitmproxy \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Injection, Exploitation, and Fuzzing
RUN apt-get update && apt-get install -y \
    sqlmap commix gobuster dirb dirbuster wfuzz ffuf feroxbuster \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Authentication / Password Attacks
RUN apt-get update && apt-get install -y \
    hydra medusa patator ncrack john hashcat \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Frameworks, SMB, and CMS Scanners
RUN apt-get update && apt-get install -y \
    metasploit-framework enum4linux dnsutils smbclient ldap-utils \
    wpscan joomscan \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Wordlists & Secret Scanners
RUN apt-get update && apt-get install -y \
    wordlists seclists cewl crunch trufflehog gitleaks \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Fallback installations for specific web tools
RUN apt-get update && \
    for pkg in arjun hakrawler gospider subjack getallurls ssrfmap nosqlmap fuxploider; do \
        apt-get install -y --no-install-recommends "$pkg" \
            && echo "OK: $pkg" || echo "MISSING (will fallback): $pkg"; \
    done && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# PyPI and Git fallbacks
RUN command -v arjun >/dev/null 2>&1 || pip3 install --no-cache-dir --break-system-packages arjun || true

RUN if ! command -v fuxploider >/dev/null 2>&1; then \
        mkdir -p /opt/tools && git clone --depth 1 https://github.com/almandin/fuxploider.git /opt/tools/fuxploider || true; \
        if [ -f /opt/tools/fuxploider/requirements.txt ]; then pip3 install --no-cache-dir --break-system-packages -r /opt/tools/fuxploider/requirements.txt || true; fi; \
        if [ -f /opt/tools/fuxploider/fuxploider.py ]; then chmod +x /opt/tools/fuxploider/fuxploider.py && ln -sf /opt/tools/fuxploider/fuxploider.py /usr/local/bin/fuxploider; fi; \
    fi

RUN if ! command -v ssrfmap >/dev/null 2>&1; then \
        mkdir -p /opt/tools && git clone --depth 1 https://github.com/swisskyrepo/SSRFmap.git /opt/tools/SSRFmap || true; \
        if [ -f /opt/tools/SSRFmap/requirements.txt ]; then pip3 install --no-cache-dir --break-system-packages -r /opt/tools/SSRFmap/requirements.txt || true; fi; \
        if [ -f /opt/tools/SSRFmap/ssrfmap.py ]; then chmod +x /opt/tools/SSRFmap/ssrfmap.py && ln -sf /opt/tools/SSRFmap/ssrfmap.py /usr/local/bin/ssrfmap; fi; \
    fi

RUN if ! command -v nosqlmap >/dev/null 2>&1; then \
        mkdir -p /opt/tools && git clone --depth 1 https://github.com/codingo/NoSQLMap.git /opt/tools/NoSQLMap || true; \
        if [ -f /opt/tools/NoSQLMap/requirements.txt ]; then pip3 install --no-cache-dir --break-system-packages -r /opt/tools/NoSQLMap/requirements.txt || true; fi; \
        if [ -f /opt/tools/NoSQLMap/nosqlmap.py ]; then chmod +x /opt/tools/NoSQLMap/nosqlmap.py && ln -sf /opt/tools/NoSQLMap/nosqlmap.py /usr/local/bin/nosqlmap; fi; \
    fi

# Git-cloned advanced web tools
RUN mkdir -p /opt/tools && cd /opt/tools && \
    for repo in \
        https://github.com/vladko312/SSTImap.git \
        https://github.com/dolevf/graphw00f.git \
        https://github.com/dolevf/graphql-cop.git \
        https://github.com/nikitastupin/clairvoyance.git \
        https://github.com/doyensec/inql.git \
        https://github.com/GerbenJavado/LinkFinder.git \
        https://github.com/m4ll0k/SecretFinder.git \
        https://github.com/xnl-h4ck3r/xnLinkFinder.git \
        https://github.com/ticarpi/jwt_tool.git \
        https://github.com/assetnote/kiterunner.git \
    ; do \
        name=$(basename "$repo" .git); \
        GIT_TERMINAL_PROMPT=0 git clone --depth 1 "$repo" "/opt/tools/$name" \
            && echo "OK: $name" || echo "FAILED (skipped): $repo"; \
    done

RUN for d in SSTImap clairvoyance LinkFinder SecretFinder xnLinkFinder jwt_tool; do \
        if [ -f /opt/tools/$d/requirements.txt ]; then \
            pip3 install --no-cache-dir -r /opt/tools/$d/requirements.txt --break-system-packages || true; \
        fi; \
    done

RUN if [ -d /opt/tools/kiterunner ]; then \
        cd /opt/tools/kiterunner && make build && ln -sf /opt/tools/kiterunner/dist/kr /usr/local/bin/kr; \
    else \
        echo "kiterunner not cloned, skipping build"; \
    fi

# Modern Go tools
RUN mkdir -p /opt/go/bin && \
    for mod in \
        github.com/hahwul/dalfox/v2@latest \
        github.com/projectdiscovery/katana/cmd/katana@latest \
        github.com/tomnomnom/waybackurls@latest \
        github.com/tomnomnom/qsreplace@latest \
        github.com/tomnomnom/gf@latest \
        github.com/tomnomnom/anew@latest \
        github.com/PentestPad/subzy@latest \
        github.com/lc/gau/v2/cmd/gau@latest \
    ; do \
        go install -v "$mod" && echo "OK: $mod" || echo "FAILED (skipped): $mod"; \
    done

# Assetnote wordlists
RUN mkdir -p /usr/share/wordlists/assetnote && cd /usr/share/wordlists/assetnote && \
    for url in \
        "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt" \
        "https://wordlists-cdn.assetnote.io/data/manual/2m-subdomains.txt" \
        "https://wordlists-cdn.assetnote.io/data/automated/httparchive_directories_1m_2024_05_28.txt" \
        "https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2024_05_28.txt" \
        "https://wordlists-cdn.assetnote.io/data/automated/httparchive_parameters_top_1m_2024_05_28.txt" \
    ; do \
        wget -q "$url" || echo "FAILED (skipped): $url"; \
    done

# Symlinks
RUN for entry in \
        "SSTImap/sstimap.py:sstimap" \
        "graphw00f/main.py:graphw00f" \
        "graphql-cop/graphql-cop.py:graphql-cop" \
        "LinkFinder/linkfinder.py:linkfinder" \
        "SecretFinder/SecretFinder.py:secretfinder" \
        "xnLinkFinder/xnLinkFinder/xnLinkFinder.py:xnLinkFinder" \
        "jwt_tool/jwt_tool.py:jwt_tool" \
    ; do \
        src="/opt/tools/${entry%%:*}"; dst="/usr/local/bin/${entry##*:}"; \
        if [ -f "$src" ]; then chmod +x "$src" && ln -sf "$src" "$dst" && echo "linked: $dst"; else echo "skipped (missing): $src"; fi; \
    done && \
    chmod +x /opt/tools/*/*.py 2>/dev/null || true

RUN if [ -x /usr/local/bin/kr ] && [ ! -e /usr/local/bin/kiterunner ]; then \
        ln -sf /usr/local/bin/kr /usr/local/bin/kiterunner && echo "kiterunner alias created"; \
    fi

RUN for bin in dalfox katana waybackurls qsreplace gf anew subzy gau hakrawler gospider subjack; do \
        if [ -x "/opt/go/bin/$bin" ]; then cp -f "/opt/go/bin/$bin" "/usr/local/bin/$bin"; fi; \
    done

# Critical Binaries Verification
RUN set -e; \
    echo "=== Verifying critical binaries ==="; \
    MISSING=""; \
    for bin in \
        nmap naabu masscan nikto whatweb wafw00f sslscan sslyze nuclei httpx-toolkit subfinder dnsx amass \
        sqlmap commix gobuster ffuf feroxbuster wfuzz dirb \
        hydra john hashcat medusa patator ncrack wpscan joomscan enum4linux msfconsole \
        cewl crunch theharvester recon-ng dnsrecon dnsenum fierce \
        trufflehog gitleaks dalfox katana waybackurls gau hakrawler gospider subjack subzy \
        arjun qsreplace gf anew sstimap nosqlmap ssrfmap fuxploider jwt_tool \
        linkfinder secretfinder xnLinkFinder graphw00f graphql-cop kr burpsuite zaproxy mitmproxy \
    ; do \
        if ! command -v "$bin" >/dev/null 2>&1; then \
            echo "MISSING CRITICAL: $bin"; MISSING="$MISSING $bin"; \
        fi; \
    done; \
    if [ -n "$MISSING" ]; then echo "BUILD FAILED: critical binaries missing:$MISSING"; exit 1; fi

# Network capabilities
RUN for bin in /usr/bin/nmap /usr/bin/masscan /usr/bin/naabu; do \
        if [ -x "$bin" ]; then setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$bin" || true; fi; \
    done

# Post-install data setup
RUN if [ -f /usr/share/wordlists/rockyou.txt.gz ] && [ ! -f /usr/share/wordlists/rockyou.txt ]; then gunzip -k /usr/share/wordlists/rockyou.txt.gz; fi
RUN wpscan --update --no-banner --disable-tls-checks 2>&1 | tail -5 || true

ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/go/bin

# MCP Kali Server
WORKDIR /opt
RUN git clone https://github.com/Wh0am123/MCP-Kali-Server.git
WORKDIR /opt/MCP-Kali-Server
RUN pip3 install --no-cache-dir -r requirements.txt --break-system-packages

RUN sed -i 's|^COMMAND_TIMEOUT = 180.*|COMMAND_TIMEOUT = int(os.environ.get("COMMAND_TIMEOUT", 600))|' server.py
ENV COMMAND_TIMEOUT=600

# Non-root user
RUN useradd -m -s /bin/bash mcpuser && \
    chown -R mcpuser:mcpuser /opt/MCP-Kali-Server && \
    chown -R mcpuser:mcpuser /opt/tools && \
    chown -R mcpuser:mcpuser /opt/go

RUN echo 'export PATH=$PATH:/opt/go/bin' >> /home/mcpuser/.bashrc

USER mcpuser
EXPOSE 5000

CMD ["python3", "server.py", "--ip", "0.0.0.0", "--port", "5000"]
