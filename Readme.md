
# Michos

![Michos](https://github.com/hiperesfera/Michos/raw/main/img/michos.png)

Penetration testing  often involves sensitive targets, data, and vulnerability details. Even though most cloud LLM providers exclude API traffic from model training by default, data still transits and is temporarily processed on third-party infrastructure. This could conflict with client data requirements, regulated environments, or even air-gapped environments where connectivity to external endpoints is not even possible. Running a model locally via Ollama ensures that all prompts, tool outputs, and findings stay entirely within your own infrastructure, with no external dependency or data exposure risk. 

Running a model locally via Ollama ensures that all prompts, tool outputs, and findings remain entirely within your own infrastructure, eliminating external dependencies and the risk of data exposure. By adopting open-weights models, we democratise the power of advanced AI, whether you deploy them locally for maximum privacy or in the cloud for greater scale. While there is a lot of hype surrounding proprietary models like Mythos, the reality is that anyone can now build highly capable agents using open-weight alternatives. It is only a matter of time before these models reach parity with the current top-tier proprietary offerings, creating a dual-use reality that must be factored into every modern security strategy.

Oh, and why **Michos**? Consider it a playful parody of Mythos, as 'micho' is the Galician word for a kitten.

## Kali Linux MCP Server for OpenCode Agent

A Docker-based setup that exposes Kali Linux penetration testing tools through an MCP server, enabling AI agents built with OpenCode to perform security assessments and automated penetration testing tasks leveraging Ollama local and cloud open-weight models.

## Overview

This project combines:

- **Kali Linux Docker Container**: Running essential penetration testing tools
- **MCP Kali Server**: Exposing Kali tools via API ([Wh0am123/MCP-Kali-Server](https://github.com/Wh0am123/MCP-Kali-Server))
- **OpenCode Agent**: An AI agent that can execute security tools and automate tasks based on a "Skill"
- **Ollama**: Running open models locally or in the cloud, providing the LLM backend for the OpenCode agent

## Architecture

![PlantUML model](https://img.plantuml.biz/plantuml/png/RP9DJyCm38Rl-HKMft7ek4zJjJ6GG82eQ8-zXCJhehf9b6PC4-A_awGTBO9R_Fhnnsjbqtlk_B4ZHhZtu0qurHmyIELGU6KqwrkbBNUy0s4wQpHgN_ep8KI0wuRmFmG-6S2jSH9TejThOsCxJdaEalS7bEoBJVZLAn7lEEp872LqHYBrLy1x457u2zRwpeWMNM9CakRGin6Svcqe2Yd-rSkYtWKHjas8QrssYcW59tpFkBLPo7hiFRfb9uT1GH61d_TusHLGelj0L-k581N4fJrVrphjaCewOUSLJvmKR8l7mFUfSE1dXjf0p2igxXhqSQ-mLgqJCmGitGVMcJGddUNZAM053rLLb6mCVzBJ6G8o74dfFRfW2oSucunU7b7Dev5G5nqNpdWZ3B4efLpSUPnxytPVLYm9by73jcD-KGQxR8DQXe_t3G00) 
  
## How to use it

1. Install OpenCode

    `curl -fsSL https://opencode.ai/install | bash`

2. Clone this repo
    
    `git clone https://github.com/hiperesfera/AI_Agent_Pentest`


3. Clone the MCP Kali Server and adjust timeouts

    `git clone https://github.com/Wh0am123/MCP-Kali-Server`

    Long-running tools like nmap, sqlmap, or hydra can exceed the default limits. Edit these two constants before building:
    
    *MCP-Kali-Server/server.py* — line 31 (how long the server waits for a command to finish):
    ```
    COMMAND_TIMEOUT = 600  # seconds — increase for slow scans (e.g. 1200)
    ```

    *MCP-Kali-Server/client.py* — line 27 (how long the client waits for an HTTP response):
    ```
    DEFAULT_REQUEST_TIMEOUT = 660  # seconds — keep ~60s above COMMAND_TIMEOUT
    ```

    > [!NOTE]
    > Keep `DEFAULT_REQUEST_TIMEOUT` a bit higher than `COMMAND_TIMEOUT`, so the HTTP connection does not drop before the server has a chance to return the command's output.

4. Build and run the Kali Docker image

    `docker build --tag 'kali-mcp' .`
    `docker run --cap-add NET_RAW --cap-add NET_ADMIN  --rm -d --name kali-mcp -p 5000:5000 kali-mcp`

5. Pull, configure and run the Ollama Docker image 

    `docker pull ollama/ollama`
    `docker run --rm -d --name ollama -p 11434:11434 ollama/ollama`


    6. Pull the models into Ollama.

    `docker exec -it ollama ollama pull qwen3.5:cloud`
    `docker exec -it ollama ollama pull deepseek-v4-pro:cloud`
    `docker exec -it ollama ollama pull kimi-k2.6:cloud`
    `docker exec -it ollama ollama signin`


Test Ollama model

>[!NOTE]
>Example using Ollama, refer to the opencode configuration example `opencode.json` to load local Ollama models
>
>`OPENCODE_CONFIG=.opencode.json opencode -m ollama/qwen3.5:cloud run ...`


`OPENCODE_CONFIG=.opencode.json opencode -m ollama/qwen3.5:cloud run "Which model are you running ?"`

Response: 
> build · qwen3.5:cloud
> I'm running on qwen3.5:cloud (model ID: ollama/qwen3.5:cloud).




## Test Examples and LLM models benchmark

A curated list of vulnerable web applications can be found in [OWASP Vulnerable Web Applications Directory](https://vwad.owasp.org/). While many of these web apps can run in Docker on my local machine, I decided to use online  web apps for simplicity and real-world experience (external app, network latency, ISP blocks, etc.):

### Vulnerable Web Applications

- https://brokencrystals.com/
- https://vulnbank.org/
- http://zero.webappsecurity.com/

### LLM Models

- claude-opus-4-7 (for comparison to proprietary model)
- deepseek-v4-pro
- kimi-k2.6
- qwen3.5






