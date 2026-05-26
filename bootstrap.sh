#! /bin/bash

. bin/activate

# Build and run the Kali Docker container with all relevant tools, including the MCP server

docker build -t kali-mcp .
docker run --cap-add NET_RAW --cap-add NET_ADMIN --rm -d --name kali-mcp -e COMMAND_TIMEOUT=300 -p 5000:5000 kali-mcp

# Update wpscan
docker exec kali-mcp wpscan --update

# Pull and run the Ollama container
docker run --rm -d --name ollama -p 11434:11434 ollama/ollama

# Download models and signin
docker exec -it ollama ollama pull deepseek-v4-pro:cloud
docker exec -it ollama ollama pull kimi-k2.6:cloud
docker exec -it ollama ollama pull qwen3.5:cloud

# Sign to Ollama
docker exec -it ollama ollama signin

# Run the scan

OPENCODE_CONFIG=.opencode.json opencode -m ollama/kimi-k2.6:cloud run "Target URL: http://zero.webappsecurity.com, Mode:pentest" --file skills/web-app-pentester.md
