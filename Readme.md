![Michos](https://github.com/hiperesfera/Michos/raw/main/img/michos.png)

Penetration testing  often involves sensitive targets, data, and vulnerability details. Even though most cloud LLM providers exclude API traffic from model training by default, data still transits and is temporarily processed on third-party infrastructure. This could conflict with client data requirements, regulated environments, or even air-gapped environments where connectivity to external endpoints is not even possible. Running a model within your own compute infrastructure via [Ollama](https://ollama.com) ensures that all prompts, tool outputs, and findings stay entirely within your own infrastructure, eliminating external dependencies and the risk of data exposure.

In addition, adopting open-weight models democratises the power of advanced AI, whether you deploy them within your own compute infrastructure for privacy or in the cloud for scale. While proprietary models like [Mythos](https://red.anthropic.com/2026/mythos-preview/) or Claude Opus, as shown in the [benchmark](#results), currently deliver superior performance, open-weight alternatives are already highly capable. Their results can no longer be ignored; anyone can now build effective security agents, creating a dual-use reality that must be accounted for in every security strategy. Please do not miss the forest for the trees: do not get so distracted by the top-tier proprietary models that you ignore the very real, accessible threat of open-weight agents like Michos that any bad actor can easily build.


Oh, and why **Michos**? Consider it a playful parody of Mythos, as 'micho' is the [Galician](https://en.wikipedia.org/wiki/Galician_language) word for a kitten.


## How to use it

Launch the pentest agent against a target. The `OPENCODE_CONFIG` variable loads the Ollama provider, and `--file` injects the skill:

```bash
OPENCODE_CONFIG=.opencode.json opencode -m ollama/deepseek-v4-pro:cloud run "Target URL: http://zero.webappsecurity.com, Mode:pentest" --file skills/web-app-pentester.md
```

[View full DeepSeek-v4-pro report for zero.webappsecurity.com](results/webappsecurity/zero.webappsecurity.com-deepseek-v4-pro-report.md)

## High-level Architecture

A Docker-based setup that exposes Kali Linux penetration testing tools through an MCP server, enabling AI agents built with [OpenCode](https://opencode.ai), or other solutions, to perform security assessments and automated penetration testing leveraging Ollama local and cloud open-weight models. 

This project combines:

- **Kali Linux Docker Container**: Running essential penetration testing tools [Kali Docker image](https://hub.docker.com/repository/docker/hiperesfera/kali-mcp/) — see [full tool inventory](#appendix--kali-container-tool-inventory)
- **MCP Kali Server**: Exposing Kali tools via MCP ([Wh0am123/MCP-Kali-Server](https://github.com/Wh0am123/MCP-Kali-Server)). The [Kali Docker image](https://hub.docker.com/repository/docker/hiperesfera/kali-mcp/) ships ~65 penetration testing tools focused on web application security assessments. Every tool is accessible to the AI agent in one of two ways:
  - **Dedicated MCP functions** — ten of the most common tools have their own typed MCP tool with structured parameters: `nmap_scan`, `gobuster_scan`, `dirb_scan`, `nikto_scan`, `sqlmap_scan`, `metasploit_run`, `hydra_attack`, `john_crack`, `wpscan_analyze`, `enum4linux_scan`
  - **`execute_command`** — a generic MCP function that runs any arbitrary shell command inside the container, giving the agent access to every other tool in the image
- **OpenCode Agent**: An AI agent that can execute security tools and automate tasks based on the [`web-app-pentester.md`](https://github.com/hiperesfera/Michos/blob/main/skills/web-app-pentester.md) skill
- **Ollama**: Running open models locally or in the cloud, providing the LLM backend for the OpenCode agent

```mermaid
flowchart TD
    User(["👤 User"]) --> Agent

    subgraph Local["Local Machine"]
        Agent["OpenCode Agent"]
        MCP["client.py\nMCP Server"]

        subgraph OllamaC["Docker: ollama"]
            Ollama["Ollama"]
            LocalM["🖥️ Local\nllama3 · gemma · ..."]
            Ollama --> LocalM
        end

        subgraph KaliC["Docker: kali-mcp"]
            API["server.py\nFlask REST API :5000"]
            Tools["Kali Tools\nnmap · sqlmap · hydra\nnikto · gobuster · dirb · ..."]
        end

        Agent <-->|"HTTP REST :11434"| Ollama
        Agent <-->|"MCP protocol"| MCP
        MCP <-->|"HTTP REST :5000"| API
        API -->|"subprocess"| Tools
    end

    CloudM["☁️ Cloud Models\nqwen3.5:cloud · deepseek-v4-pro:cloud · kimi-k2.6:cloud"]

    Ollama -->|"API"| CloudM
    Tools --> Target(["Target\nWeb App"])

    style OllamaC fill:#d0e8f1,stroke:#2496ed,stroke-width:2px
    style KaliC fill:#d0e8f1,stroke:#2496ed,stroke-width:2px
    style Target fill:#f1948a,stroke:#e74c3c,color:#000
```
  
## How to build it

1. Install OpenCode

    `curl -fsSL https://opencode.ai/install | bash`

2. Clone this repo, it contains the [`web-app-pentester.md`](https://github.com/hiperesfera/Michos/blob/main/skills/web-app-pentester.md) skill, the [Kali Docker file](https://github.com/hiperesfera/Michos/blob/main/Dockerfile) and the [opencode configuration](https://github.com/hiperesfera/Michos/blob/main/opencode.json) to use Ollama

    `git clone https://github.com/hiperesfera/Michos`

3. Clone the MCP Kali Server and adjust timeouts

    `git clone https://github.com/Wh0am123/MCP-Kali-Server`

    Long-running tools like nmap, sqlmap, or hydra can exceed the default limits. Edit this variable:

    *MCP-Kali-Server/client.py* — line 27 (how long the client waits for an HTTP response):
    ```
    DEFAULT_REQUEST_TIMEOUT = 660  # seconds — keep ~60s above COMMAND_TIMEOUT
    ```

    **Note:** Keep `DEFAULT_REQUEST_TIMEOUT` a bit higher than `COMMAND_TIMEOUT`, so the HTTP connection does not drop before the server has a chance to return the command's output.

4. Build and run the Kali Docker image. Note that I am adding an extra option to manually adjust the MCP timeout in the *MCP-Kali-Server/server.py* so we can adjust that via env variable when running the container.
   
    ```
    RUN sed -i 's|^COMMAND_TIMEOUT = 180.*|COMMAND_TIMEOUT = int(os.environ.get("COMMAND_TIMEOUT", 600))|' server.py
    ENV COMMAND_TIMEOUT=600
    ```

    `docker build --tag 'kali-mcp' .`
   
    `docker run --cap-add NET_RAW --cap-add NET_ADMIN --rm -d --name kali-mcp -e COMMAND_TIMEOUT=300 -p 5000:5000 kali-mcp`
   
    Alternatively, you can pull it from my [Docker Hub](https://hub.docker.com/repository/docker/hiperesfera/kali-mcp/)
   
    `docker pull hiperesfera/kali-mcp`
   

5. Pull, configure and run the Ollama Docker image 

    `docker pull ollama/ollama`
   
    `docker run --rm -d --name ollama -p 11434:11434 ollama/ollama`


    Download the models into Ollama.

    `docker exec -it ollama ollama pull qwen3.5:cloud`
   
    `docker exec -it ollama ollama pull deepseek-v4-pro:cloud`
   
    `docker exec -it ollama ollama pull kimi-k2.6:cloud`

    `docker exec -it ollama ollama signin`


    Quick test using the [`opencode.json`](https://github.com/hiperesfera/Michos/blob/main/opencode.json) configuration example to load Ollama models

    `OPENCODE_CONFIG=.opencode.json opencode -m ollama/deepseek-v4-pro:cloud run "Which model are you running ?"`

    Response:
   
    > build · deepseek-v4-pro:cloud
    >
    > I'm running on deepseek-v4-pro:cloud (model ID: ollama/deepseek-v4-pro:cloud).

## Test Examples and LLM models benchmark

A curated list of vulnerable web applications is available in the [OWASP Vulnerable Web Applications Directory](https://vwad.owasp.org/). While many of these web apps can run in Docker on my local machine, I decided to use online  web apps for simplicity and real-world experience (external app, network latency, ISP blocks, etc.). There is a big caveat here: most of these web apps are likely part of the training for these models; in other words, the findings are things the model already knows or remembers. 

LLMs are trained on vast amounts of internet data, which includes CVE databases, exploit write-ups, GitHub repositories, and bug bounty reports. If an application or its underlying middleware has been publicly available and discussed before the model's knowledge cutoff date, the model already "knows" about it. In other words, when you point the agent at the target, it doesn't start with a blank slate. Its neural network strongly associates the target's software fingerprint with specific known vulnerabilities.

### How to defend against it?

This is exactly why this skill [`web-app-pentester.md`](https://github.com/hiperesfera/Michos/blob/main/skills/web-app-pentester.md) was built the way it is:

- State Separation (via Raw Extraction): Forcing the agent to write tool output to a file and read it back creates a hard execution break. This constrains the Agent to the live target's physical reality, preventing its predictive engine from hallucinating based on pre-trained memory.
  
- Strict Refusals: Explicitly instructing the model that "fabrication is strictly prohibited" and to clearly state if a tool produces no output helps override the model's tendency to please you with a "successful" hack. 

- Optimised Foundation Models: General chat models are designed to be helpful and conversational, making them highly prone to inventing exploits. Defending against contamination requires using models that are heavily fine-tuned for strict instruction-following and structured data extraction, such as DeepSeek-v4-pro.
  
### Vulnerable Web Applications

- https://brokencrystals.com/
- https://vulnbank.org/
- http://zero.webappsecurity.com/

### LLM Models

- claude-opus-4-7 (for comparison to proprietary model)
- deepseek-v4-pro
- kimi-k2.6
- qwen3.5

## Running Scans

Before each run, restart the Kali container to ensure a clean state and update tool databases:

```bash
docker stop kali-mcp
docker run --cap-add NET_RAW --cap-add NET_ADMIN --rm -d --name kali-mcp -e COMMAND_TIMEOUT=300 -p 5000:5000 kali-mcp
docker exec kali-mcp wpscan --update
```

Run the pentest skill against a target using Ollama cloud models. The `OPENCODE_CONFIG` variable loads the Ollama provider configuration:

```bash
OPENCODE_CONFIG=.opencode.json opencode -m ollama/kimi-k2.6:cloud run "Target URL: http://zero.webappsecurity.com, Mode:pentest" --file skills/web-app-pentester.md

OPENCODE_CONFIG=.opencode.json opencode -m ollama/qwen3.5:cloud run "Target URL: http://zero.webappsecurity.com, Mode:pentest" --file skills/web-app-pentester.md

OPENCODE_CONFIG=.opencode.json opencode -m ollama/deepseek-v4-pro:cloud run "Target URL: http://zero.webappsecurity.com, Mode:pentest" --file skills/web-app-pentester.md
```

For comparison against a proprietary model (requires Anthropic API key):

```bash
opencode -m anthropic/claude-opus-4-7 run "Target URL: http://zero.webappsecurity.com, Mode:pentest" --file skills/web-app-pentester.md
```

## Results

### Comprehensive Pentester Agent Model Comparison

| Model | `zero.webappsecurity.com` | `brokencrystals.com` | `vulnbank.org` | Overall Verdict & Technical Evaluation |
| :--- | :--- | :--- | :--- | :--- |
| **Claude Opus 4.7** | **18 Total**<br>🔴 Critical: 4<br>🟠 High: 5<br>🟡 Medium: 4<br>🟢 Low: 3<br>⚪ Info: 2<br><br>**Notable:** Detailed the public `/debug.txt` leak; explicitly verified Tomcat 401 behavior without credential hallucination. | **23 Total**<br>🔴 Critical: 7<br>🟠 High: 7<br>🟡 Medium: 6<br>🟢 Low: 3<br>⚪ Info: 0<br><br>**Notable:** Discovered 4 independent RCE vectors; successfully exfiltrated live Kubernetes ServiceAccount tokens. | **19 Total**<br>🔴 Critical: 5<br>🟠 High: 4<br>🟡 Medium: 4<br>🟢 Low: 6<br>⚪ Info: 0<br><br>**Notable:** Exploited SQLi for auth bypass, SSRF for internal secret exfiltration, and mass assignment for admin takeover. | **Top Tier.** Highly reliable, forensic-grade reporting.<br><br>**PoC Adherence: Excellent.** Retained strict forensic integrity with exact, raw HTTP requests and responses.<br><br>**Contamination Resistance: High.** Resisted training data memory; independently extracted live data. |
| **DeepSeek-v4-pro** | **7 Total**<br>🔴 Critical: 2<br>🟠 High: 2<br>🟡 Medium: 2<br>🟢 Low: 1<br>⚪ Info: 0<br><br>**Notable:** Flagged unauthenticated administrative panel access (`/admin/`) and `/debug.txt` exposure. | **13 Total**<br>🔴 Critical: 6<br>🟠 High: 4<br>🟡 Medium: 2<br>🟢 Low: 0<br>⚪ Info: 1<br><br>**Notable:** Escalated Local File Inclusion (LFI) to SSRF against the cloud metadata service to dump container hostnames. | **26 Total**<br>🔴 Critical: 10<br>🟠 High: 8<br>🟡 Medium: 5<br>🟢 Low: 3<br>⚪ Info: 0<br><br>**Notable:** Detailed Flask/SQLi remediation; identified and broke the weak 9-byte JWT secret. | **Strong.** Best for rapid triage and architectural remediation planning.<br><br>**PoC Adherence: Good.** Accurate PoCs and structural trace logs, though large output blocks were occasionally summarised.<br><br>**Contamination Resistance: High.** Proved execution by extracting live pod hostnames and environment specifics. |
| **Qwen 3.5** | **15 Total**<br>🔴 Critical: 3<br>🟠 High: 4<br>🟡 Medium: 3<br>🟢 Low: 2<br>⚪ Info: 3<br><br>**Notable:** Extracted raw HTML data tables exposing plaintext user passwords and SSNs. | **7 Total**<br>🔴 Critical: 3<br>🟠 High: 1<br>🟡 Medium: 2<br>🟢 Low: 1<br>⚪ Info: 0<br><br>**Notable:** Identified exposed `.env` and `.git` files, but missed deeper RCE exploitation chains. | **18 Total**<br>🔴 Critical: 4<br>🟠 High: 5<br>🟡 Medium: 3<br>🟢 Low: 2<br>⚪ Info: 4<br><br>**Notable:** Captured Werkzeug interactive debugger exposure and extracted raw backend database schema JSON. | **Solid Choice.** A capable reconnaissance assistant.<br><br>**PoC Adherence: Average.** Captures baseline vulnerabilities well, but occasionally omits full raw HTTP execution context.<br><br>**Contamination Resistance: Moderate.** Reliable for surface-level recon but misses deeper exploit chains. |
| **Kimi k2.6** | **18 Total**<br>🔴 Critical: 4<br>🟠 High: 5<br>🟡 Medium: 4<br>🟢 Low/Info: 5<br><br>**Notable:** Flagged the Admin Panel SSN leak and `/errors/errors.log` credential leaks. | **7 Total**<br>🔴 Critical: 4<br>🟠 High: 1<br>🟡 Medium: 1<br>🟢 Low: 1<br>⚪ Info: 0<br><br>**Notable:** Flagged the `/api/spawn` command injection endpoint and verified basic `.git` directory exposure. | **13 Total**<br>🔴 Critical: 4<br>🟠 High: 3<br>🟡 Medium: 3<br>🟢 Low: 0<br>⚪ Info: 3<br><br>**Notable:** Identified standard Werkzeug debug console endpoints and AI system prompt configuration exposures. | **Use with Caution.** Requires manual forensic verification.<br><br>**PoC Adherence: Fail.** Prioritises clean markdown over raw forensic data; reformats tool output, breaking the chain of evidence.<br><br>**Contamination Resistance: Low.** Relies heavily on semantic patterns of known vulnerable targets; prone to hallucination. |

More detailed results per web application can be found  under the [results](https://github.com/hiperesfera/Michos/results) folder

## Appendix — Kali Container Tool Inventory

### Scanning, Fingerprinting & OSINT
| Tool | Purpose |
|------|---------|
| `nmap` | Network/port scanner |
| `naabu` | Fast port scanner (ProjectDiscovery) |
| `masscan` | Mass IP port scanner |
| `nikto` | Web server vulnerability scanner |
| `whatweb` | Web technology fingerprinter |
| `wafw00f` | WAF detection |
| `sslscan` | SSL/TLS analysis |
| `sslyze` | SSL/TLS configuration analyzer |
| `dnsx` | DNS resolver & brute-forcer |
| `amass` | Attack surface mapping / subdomain enumeration |
| `theharvester` | Email, subdomain, IP OSINT |
| `recon-ng` | OSINT recon framework |
| `dnsrecon` | DNS enumeration |
| `dnsenum` | DNS enumeration |
| `fierce` | DNS reconnaissance |

### ProjectDiscovery Web Recon Suite
| Tool | Purpose |
|------|---------|
| `nuclei` | Template-based vulnerability scanner |
| `httpx` / `httpx-toolkit` | HTTP probing |
| `subfinder` | Subdomain discovery |
| `katana` | Web crawler |
| `dalfox` | XSS scanner |
| `gau` | Get all URLs (Wayback + Common Crawl) |
| `waybackurls` | Fetch URLs from Wayback Machine |
| `qsreplace` | Query string value replacer |
| `gf` | Pattern matching wrapper for grep |
| `anew` | Append new lines to files |
| `subzy` | Subdomain takeover checker |

### Web Proxies & Interceptors
| Tool | Purpose |
|------|---------|
| `burpsuite` | Web app security testing proxy |
| `zaproxy` | OWASP ZAP web proxy |
| `mitmproxy` | Intercepting proxy |

### Injection, Exploitation & Fuzzing
| Tool | Purpose |
|------|---------|
| `sqlmap` | SQL injection automation |
| `commix` | Command injection exploiter |
| `gobuster` | Directory/DNS/vhost brute-forcer |
| `dirb` | Web content scanner |
| `dirbuster` | Directory brute-forcer |
| `wfuzz` | Web fuzzer |
| `ffuf` | Fast web fuzzer |
| `feroxbuster` | Recursive content discovery |
| `sstimap` | SSTI detection & exploitation |
| `nosqlmap` | NoSQL injection |
| `ssrfmap` | SSRF detection & exploitation |
| `fuxploider` | File upload vulnerability scanner |
| `arjun` | HTTP parameter discovery |

### GraphQL & API Testing
| Tool | Purpose |
|------|---------|
| `graphw00f` | GraphQL fingerprinter |
| `graphql-cop` | GraphQL security auditor |
| `clairvoyance` | GraphQL introspection via fuzzing |
| `inql` | GraphQL security scanner (Burp extension) |
| `kiterunner` / `kr` | API endpoint brute-forcer |

### Web Crawling & URL Discovery
| Tool | Purpose |
|------|---------|
| `hakrawler` | Fast Go-based web crawler |
| `gospider` | Web spider |
| `linkfinder` | Endpoint/URL extractor from JS |
| `secretfinder` | Secret/key extractor from JS |
| `xnLinkFinder` | Link/parameter finder |

### Authentication & Password Attacks
| Tool | Purpose |
|------|---------|
| `hydra` | Network login brute-forcer |
| `medusa` | Parallel network logon auditor |
| `patator` | Multi-purpose brute-forcer |
| `ncrack` | Network authentication cracker |
| `john` | John the Ripper — password cracker |
| `hashcat` | GPU hash cracker |

### Exploitation Frameworks & Enumeration
| Tool | Purpose |
|------|---------|
| `msfconsole` | Metasploit Framework |
| `enum4linux` | SMB/NetBIOS enumeration |
| `smbclient` | SMB client |
| `wpscan` | WordPress vulnerability scanner |
| `joomscan` | Joomla vulnerability scanner |

### JWT & Subdomain Takeover
| Tool | Purpose |
|------|---------|
| `jwt_tool` | JWT analysis & exploitation |
| `subjack` | Subdomain takeover detection |

### Secret & Credential Scanning
| Tool | Purpose |
|------|---------|
| `trufflehog` | Secret/credential scanner |
| `gitleaks` | Git secret scanner |

### Wordlists
| Resource | Location |
|----------|---------|
| `rockyou.txt` | `/usr/share/wordlists/rockyou.txt` |
| SecLists | `/usr/share/seclists/` |
| Kali wordlists | `/usr/share/wordlists/` |
| Assetnote DNS | `/usr/share/wordlists/assetnote/best-dns-wordlist.txt` |
| Assetnote 2M subdomains | `/usr/share/wordlists/assetnote/2m-subdomains.txt` |
| Assetnote HTTP dirs | `/usr/share/wordlists/assetnote/httparchive_directories_1m_*.txt` |
| Assetnote API routes | `/usr/share/wordlists/assetnote/httparchive_apiroutes_*.txt` |
| Assetnote parameters | `/usr/share/wordlists/assetnote/httparchive_parameters_top_1m_*.txt` |
| `cewl` | Custom wordlist generator from target site |
| `crunch` | Pattern-based wordlist generator |
