#! /bin/bash

# Start all containers (opencode stays idle for exec).
# Missing images are built (kali/opencode) or pulled (ollama); existing images are reused as-is.
# After editing a Dockerfile, rebuild explicitly: docker compose up -d --build
docker compose up -d

# Update wpscan
docker compose exec kali-server wpscan --update

# Sign in to Ollama (interactive; required before pulling :cloud models)
docker compose exec ollama ollama signin

# Download models
docker compose exec ollama ollama pull deepseek-v4-pro:cloud
docker compose exec ollama ollama pull kimi-k2.6:cloud
docker compose exec ollama ollama pull qwen3.5:cloud
docker compose exec ollama ollama pull nemotron-3-ultra:cloud
docker compose exec ollama ollama pull glm-5.2:cloud

# Print example scan + list-models commands
echo ""
echo "Init complete. Run a scan by exec-ing into the opencode container, e.g.:"
echo ""
echo 'docker exec opencode opencode -m ollama/deepseek-v4-pro:cloud run "Target URL: http://zero.webappsecurity.com, Mode:pentest" --file /app/skills/web-app-pentester.md'
echo ""
echo "List available models with: docker exec opencode opencode models"
echo ""
echo "Report lands in ./results. When finished, tear down with: docker compose down"
