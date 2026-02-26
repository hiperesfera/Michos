# Kali Linux MCP Server for OpenCode Agent

A Docker-based setup that exposes Kali Linux penetration testing tools through an MCP server, enabling AI agents built with OpenCode to perform security assessments, and automated penetration testing tasks.

## Overview

This project combines:
- **Kali Linux Docker Container**: Running essential penetration testing tools
- **MCP Kali Server**: Exposing Kali tools via API ([Wh0am123/MCP-Kali-Server](https://github.com/Wh0am123/MCP-Kali-Server))
- **OpenCode Agent**: AI agent that can execute security tools and automate tasks

## Architecture

![PlantUML model](https://img.plantuml.biz/plantuml/png/LP31IiH038RlUOeSxM7rBY9Rgk2oAnQtjtQHOHhNOMUICXE5VNkdqu9up9_lIqYsIKtKx-01F7qggc1qvo_5qKMoweG1-hU9k96Hi3uJwy0tzGxhb5nsMQiJchHqe7zjMZnI_A6OgM2dZrIAs-bQ3NmGQtoX6-yAlZVUOTtk_fnBJlv9Js8l58krG01b5pviDe_h8Bp7UN4RHSMAXpKjn29bugNhshltvsC7QpHt-uvYS6pya0yCmV2OvlFucXyXlZe1R8d7_9vV) 
  
## How to use it

Clone the repo

`git clone https://github.com/hiperesfera/AI_Agent_Pentest`

Build de Docker image

`docker build --tag 'kali-mcp' .`

Run the Docket image

`docker run --rm -d --name kali-mcp -p 5000:5000 kali-mcp`

Run the AI Agent penstest

`opencode -m opencode/big-pickle run "Target URL: http://TARGET-WEB-APP, Mode:recon" --file agents/pentester-agent.md`

Example using Ollama, refer to opencode configuration example `opencode.json` to load local Ollama models
`opencode -m ollama/qwen3.5:cloud run "Target URL: http://172.17.0.2, Mode:pentest" --file pentester-agent.md`



## How to use it

Results from a local test using DVWA docker image

`docker run --rm -it -p 80:80 vulnerables/web-dvwa`

Running the AI Agent  on _pentest_ mode against DVWP

`opencode -m opencode/big-pickle run "Target URL: http://172.17.0.2, Mode:pentest" --file pentester-agent.md`

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


