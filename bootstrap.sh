#! /bin/bash

. bin/activate

# Build and run the Kali Docker container with all relevant tools, including the MCP server
docker build -t kali-mcp .
docker run --cap-add=NET_RAW --cap-add=NET_ADMIN --rm -d --name kali-mcp -p 5000:5000 kali-mcp
docker exec kali-mcp wpscan --update

# Pull and run the Ollama container
docker run --rm -d --name ollama -p 11434:11434 ollama/ollama

# Download models and signin
docker exec -it ollama ollama pull deepseek-v4-pro:cloud
docker exec -it ollama ollama pull kimi-k2.6:cloud
docker exec -it ollama ollama pull qwen3.5:cloud
docker exec -it ollama ollama signin
