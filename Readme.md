![Michos](https://github.com/hiperesfera/Michos/raw/main/img/michos.png)

Penetration testing  often involves sensitive targets, data, and vulnerability details. Even though most cloud LLM providers exclude API traffic from model training by default, data still transits and is temporarily processed on third-party infrastructure. This could conflict with client data requirements, regulated environments, or even air-gapped environments where connectivity to external endpoints is not even possible. Running a model locally via [Ollama](https://ollama.com) ensures that all prompts, tool outputs, and findings stay entirely within your own infrastructure, eliminating external dependencies and the risk of data exposure

In addition, by adopting open-weight models, we democratise the power of advanced AI, whether you deploy them locally for maximum privacy or in the cloud for greater scale. While there is a lot of hype surrounding proprietary models like [Mythos](https://red.anthropic.com/2026/mythos-preview/), the reality is that anyone can now build highly capable agents using open-weight alternatives. It is only a matter of time before these models reach parity with current top-tier proprietary offerings, creating a dual-use reality that must be accounted for in every security strategy.

Oh, and why **Michos**? Consider it a playful parody of Mythos, as 'micho' is the [Galician](https://en.wikipedia.org/wiki/Galician_language) word for a kitten.


## High-level Architecture

A Docker-based setup that exposes Kali Linux penetration testing tools through an MCP server, enabling AI agents built with [OpenCode](https://opencode.ai) to perform security assessments and automated penetration testing tasks leveraging Ollama local and cloud open-weight models. 

This project combines:

- **Kali Linux Docker Container**: Running essential penetration testing tools [Kali Docker image](https://hub.docker.com/repository/docker/hiperesfera/kali-mcp/)
- **MCP Kali Server**: Exposing Kali tools via MCP ([Wh0am123/MCP-Kali-Server](https://github.com/Wh0am123/MCP-Kali-Server))
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
  
## How to use it

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

This is exactly why this skill [`web-app-pentester-refined.md`](https://github.com/hiperesfera/Michos/blob/main/skills/web-app-pentester.md) was built the way it is:

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

