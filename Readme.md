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

Build de Docker image

`docker build --tag 'kali-mcp' .`

Run the Docket image

`docker run --cap-add NET_RAW --cap-add NET_ADMIN  --rm -d --name kali-mcp -p 5000:5000 kali-mcp`

Run the AI Agent pentest - quick test using opencode big-pickle 

`opencode -m opencode/big-pickle run "Target URL: http://zero.webappsecurity.com/, Mode:recon" --file agents/pentester-agent.md`

>[!NOTE]
>Example using Ollama, refer to the opencode configuration example `opencode.json` to load local Ollama models
>
>`OPENCODE_CONFIG=.opencode.json opencode -m ollama/qwen3.5:cloud run "Target URL: http://TARGET-WEB-AP, Mode:pentest" --file pentester-agent.md`


## Test Example

Results from a local test using DVWA docker image

`docker run --rm -it -p 80:80 vulnerables/web-dvwa`

Running the AI Agent  on _pentest_ mode against DVWP

`OPENCODE_CONFIG=.opencode.json opencode -m ollama/qwen3.5:cloud run "Target URL: http://172.17.0.2, Mode:pentest" --file pentester-agent.md`

Results

Summary below, see [report.md](https://github.com/hiperesfera/AI_Agent_Pentest/blob/main/Results/report.md) for more details.

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


