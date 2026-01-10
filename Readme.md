# Kali Linux MCP Server for OpenCode Agent

A Docker-based setup that exposes Kali Linux penetration testing tools through an MCP server, enabling AI agents built with OpenCode to perform security assessments, and automated penetration testing tasks.

## Overview

This project combines:
- **Kali Linux Docker Container**: Running essential penetration testing tools
- **MCP Kali Server**: Exposing Kali tools via API ([Wh0am123/MCP-Kali-Server](https://github.com/Wh0am123/MCP-Kali-Server))
- **OpenCode Agent**: AI agent that can execute security tools and automate tasks

## Architecture

ADD UML DIAGRAM HERE

  
## How to use it

Build de Docker image

`docker build --tag 'kali-mcp' .`

Run the Docket image

`docker run --rm -d --name kali-mcp -p 5000:5000 kali-mcp`

Run the AI Agent penstest

`opencode -m opencode/big-pickle run "Target URL: http://web-app-to-test, Mode:recon" --file pentester-agent.md`

