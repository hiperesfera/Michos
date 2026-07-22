#! /bin/bash

# up --build doesn't pull image-only services, so pull ollama first
docker compose pull ollama

# Build and start all containers (opencode stays idle for exec)
docker compose up -d --build

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

# Print an example scan command
cat <<'EOF'

Init complete. Run a scan by exec-ing into the opencode container, e.g.:

  docker exec opencode opencode \
    -m ollama/deepseek-v4-pro:cloud \
    run "Target URL: http://zero.webappsecurity.com, Mode:pentest" \
    --file /app/skills/web-app-pentester.md

Report lands in ./results. When finished, tear down with: docker compose down
EOF
