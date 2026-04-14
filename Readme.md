# Kali Linux MCP Server for OpenCode Agent

A Docker-based setup that exposes Kali Linux penetration testing tools through an MCP server, enabling AI agents built with OpenCode to perform security assessments, and automated penetration testing tasks.

## Overview

This project combines:

- **Kali Linux Docker Container**: Running essential penetration testing tools
- **MCP Kali Server**: Exposing Kali tools via API ([Wh0am123/MCP-Kali-Server](https://github.com/Wh0am123/MCP-Kali-Server))
- **OpenCode Agent**: AI agent that can execute security tools and automate tasks
- **Ollama**: Running open models locally or in the cloud, providing the LLM backend for the OpenCode agent

###  Why Ollama ?

Penetration testing  often involves sensitive targets, data, and vulnerability details. Even though most cloud LLM providers exclude API traffic from model training by default, data still transits and is temporarily processed on third-party infrastructure. This could conflict with client data requirements, regulated environments, or even air-gapped environments where connectivity to external endpoints is not even possible. Running a model locally via Ollama ensures that all prompts, tool outputs, and findings stay entirely within your own infrastructure, with no external dependency or data exposure risk.


## Architecture

![PlantUML model](https://img.plantuml.biz/plantuml/png/LP11QyCm38Nl_XMYf-sGxbx6QEa66qjPM78C3EDedObi1KSjzDzNDemsHxtdx-d9srbiabCWG_Wh80p97_y41f_GYUTeZECmSSGeiFgQCEvvGDWTTUvZ7zlH4sr0TS5PAflrTHXMO6TWLPs-layux1jeCPqnzV4XkEbdBiDwkZpsiMPdgQ3gt5EVbZpiceyREggoO5_PZPWAdBr5Qo8Rh48b7-hwiDZ5nJRclouyLzLBRW0Ro7MRnCAEoMIfU7c1ckzTrpnzlxMTiYKZkxUhpHRZe3zx1G00) 
  
## How to use it

Clone the repo

`git clone https://github.com/hiperesfera/AI_Agent_Pentest`


Clone the MCP Kali Server and adjust timeouts

```
git clone https://github.com/Wh0am123/MCP-Kali-Server
```

Long-running tools like nmap, sqlmap, or hydra can exceed the default limits. Edit these two constants before building:

**`MCP-Kali-Server/server.py` — line 31** (how long the server waits for a command to finish):
```python
COMMAND_TIMEOUT = 600  # seconds — increase for slow scans (e.g. 1200)
```

**`MCP-Kali-Server/client.py` — line 27** (how long the client waits for an HTTP response):
```python
DEFAULT_REQUEST_TIMEOUT = 660  # seconds — keep ~60s above COMMAND_TIMEOUT
```

> [!NOTE]
> Keep `DEFAULT_REQUEST_TIMEOUT` a bit higher than `COMMAND_TIMEOUT` so the HTTP connection does not drop before the server has a chance to return the command's output.

Build and run the Kali Docker image

`docker build --tag 'kali-mcp' .`

`docker run --cap-add NET_RAW --cap-add NET_ADMIN  --rm -d --name kali-mcp -p 5000:5000 kali-mcp`

Pull, configure and run the Ollama Docker image 

`docker pull ollama/ollama`

`docker run --rm -d --name ollama -p 11434:11434 ollama/ollama`

> [!Important]
> This is not a local model; unfortunately, my laptop won't run anything with a 7B-parameter model. For testing purposes, I am using a cloud-hosted model


Pull qwen3.5:cloud and log in to Ollama.

`docker exec -it ollama ollama pull qwen3.5:cloud`

`docker exec -it ollama ollama signin`

List models available

`docker exec -it ollama ollama list`



Test Ollama model

`OPENCODE_CONFIG=.opencode.json opencode -m ollama/qwen3.5:cloud run "Which model are you running ?"`

Response: 
> build · qwen3.5:cloud
>
> I'm running on qwen3.5:cloud (model ID: ollama/qwen3.5:cloud).



Run the AI Agent pentest - quick test using OpenCode big-pickle 

`opencode -m opencode/big-pickle run "Target URL: http://zero.webappsecurity.com/, Mode:recon" --file agents/pentester-agent.md`

>[!NOTE]
>Example using Ollama, refer to the opencode configuration example `opencode.json` to load local Ollama models
>
>`OPENCODE_CONFIG=.opencode.json opencode -m ollama/qwen3.5:cloud run "Target URL: http://zero.webappsecurity.com/, Mode:passive" --file pentester-agent.md`


## Test Examples

### Open vulnerable web — zero.webappsecurity.com (recon)

Running the AI Agent on _recon_ mode against [zero.webappsecurity.com](http://zero.webappsecurity.com/), a publicly available intentionally vulnerable banking demo app, no local setup required.

`OPENCODE_CONFIG=./opencode.json opencode -m ollama/qwen3.5:cloud run "Target URL: http://zero.webappsecurity.com/, Mode:recon" --file pentester-agent.md`

Summary below, see [Results/zero-webappsecurity-recon.md](https://github.com/hiperesfera/AI_Agent_Pentest/blob/main/Results/zero-webappsecurity-recon.md) for the full report.

| ID | Finding | Severity | CVSS | Exploitability | Remediation Priority |
|----|---------|----------|------|----------------|---------------------|
| 1 | Unauthenticated Admin Access + Plaintext Credentials & SSNs | Critical | 9.8 | Trivial | Immediate |
| 2 | Error Log Publicly Accessible (logs usernames & passwords) | Critical | 8.6 | Trivial | Immediate |
| 3 | Backup File Exposes Server-Side Source Code (`/index.old`) | Critical | 8.2 | Trivial | Immediate |
| 4 | Dangerous HTTP Methods Enabled (PUT, DELETE, TRACE, PATCH) | High | 7.5 | Easy | High |
| 5 | Missing Security Headers (X-Frame-Options, CSP, HSTS, etc.) | High | 6.5 | Easy | High |
| 6 | Apache Server Status Page Exposed (`/server-status`) | Medium | 5.3 | Easy | Medium |
| 7 | CORS Wildcard (`Access-Control-Allow-Origin: *`) | Medium | 5.0 | Moderate | Medium |

---

### Local vulnerable targets — DVWA and OWASP Juice-Shop (pentest)

Results from a local test using DVWA and OWASP Juice-Shop docker image

`docker run --rm -it -p 80:80 vulnerables/web-dvwa`

`docker run --rm -p 127.0.0.1:3000:3000 bkimminich/juice-shop`

Running the AI Agent on _pentest_ mode against DVWA

`OPENCODE_CONFIG=.opencode.json opencode -m ollama/qwen3.5:cloud run "Target URL: http://172.17.0.2, Mode:pentest" --file pentester-agent.md`

Summary below, see [Results/report.md](https://github.com/hiperesfera/AI_Agent_Pentest/blob/main/Results/report.md) for the full report.

| ID | Finding | Severity | CVSS | Exploitability | Remediation Priority |
|----|---------|----------|------|----------------|---------------------|
| 1 | SQL Injection | Critical | 9.8 | Easy | Immediate |
| 2 | RCE via File Upload | Critical | 10.0 | Easy | Immediate |
| 3 | Command Injection | Critical | 9.8 | Easy | Immediate |
| 4 | Stored XSS | High | 7.2 | Easy | High |
| 5 | Reflected XSS | High | 7.3 | Easy | High |
| 6 | CSRF | High | 7.5 | Easy | High |
| 7 | Directory Listing | Medium | 4.3 | Easy | Medium |
| 8 | Missing Security Headers | Medium | 4.8 | Easy | Medium |
| 9 | Outdated Apache | Low | 3.7 | Medium | Low |


