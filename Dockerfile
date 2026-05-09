FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive

# Fix Kali repositories and update
RUN echo "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list && \
    echo "deb-src http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" >> /etc/apt/sources.list

# System utilities
RUN apt-get update && apt-get install -y \
    git \
    python3 \
    python3-pip \
    python3-venv \
    whois \
    curl \
    wget \
    vim \
    sudo \
    ssh \
    net-tools \
    iputils-ping \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Scanning & fingerprinting
RUN apt-get update && apt-get install -y \
    nmap \
    nikto \
    whatweb \
    wafw00f \
    sslscan \
    sslyze \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Web proxies & interceptors
RUN apt-get update && apt-get install -y \
    burpsuite \
    zaproxy \
    mitmproxy \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Injection & exploitation
RUN apt-get update && apt-get install -y \
    sqlmap \
    commix \
    xsser \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Directory & content discovery
RUN apt-get update && apt-get install -y \
    gobuster \
    dirb \
    dirbuster \
    wfuzz \
    ffuf \
    feroxbuster \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Authentication attacks
RUN apt-get update && apt-get install -y \
    hydra \
    medusa \
    patator \
    ncrack \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# CMS scanners
RUN apt-get update && apt-get install -y \
    wpscan \
    joomscan \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Wordlists & recon
RUN apt-get update && apt-get install -y \
    wordlists \
    seclists \
    cewl \
    crunch \
    theharvester \
    recon-ng \
    dnsrecon \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /opt

# Clone the MCP Kali Server repository
RUN git clone https://github.com/Wh0am123/MCP-Kali-Server.git

# Set working directory to the cloned repo
WORKDIR /opt/MCP-Kali-Server

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt --break-system-packages

# Create a non-root user for running the server
RUN useradd -m -s /bin/bash mcpuser && \
    chown -R mcpuser:mcpuser /opt/MCP-Kali-Server

# Switch to non-root user
USER mcpuser

# Expose the default port (5000 according to the README)
EXPOSE 5000

# Set the correct entrypoint to run the Kali server
# Using 0.0.0.0 to accept connections from outside the container
CMD ["python3", "server.py", "--ip", "0.0.0.0", "--port", "5000"]
