FROM kalilinux/kali-rolling:latest

# Fix Kali repositories and update
RUN echo "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list && \
    echo "deb-src http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" >> /etc/apt/sources.list

# Update and install dependencies
RUN apt-get update && \
    apt-get install -y \
    git \
    python3 \
    python3-pip \
    python3-venv \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Update and install essential packages
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    vim \
    sudo \
    ssh \
    net-tools \
    iputils-ping \
    nmap \
    nikto \
    sqlmap \
    metasploit-framework \
    john \
    hashcat \
    aircrack-ng \
    wireshark \
    burpsuite \
    gobuster \
    dirb \
    hydra \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Update and install comprehensive Kali tools
RUN apt-get update && apt-get install -y \
    kali-tools-top10 \
    kali-tools-web \
    kali-tools-database \
    kali-tools-passwords \
    kali-tools-wireless \
    kali-tools-reverse-engineering \
    kali-tools-exploitation \
    kali-tools-social-engineering \
    kali-tools-sniffing-spoofing \
    kali-tools-post-exploitation \
    kali-tools-forensics \
    kali-tools-hardware \
    kali-tools-crypto-stego \
    kali-tools-vulnerability \
    kali-tools-web \
    kali-tools-information-gathering \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

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
CMD ["python3", "kali_server.py", "--ip", "0.0.0.0", "--port", "5000"]
