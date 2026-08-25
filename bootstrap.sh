#! /bin/bash

# Start all containers (webui serves the scan UI on :8080).
# Missing images are built (kali/opencode-runner) or pulled (ollama); existing images are reused as-is.
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
docker compose exec ollama ollama pull kimi-k3:cloud

# Print how to launch scans
echo ""
echo "Init complete. Launch scans from the web UI at: http://localhost:8080"
echo ""
echo "Or from the CLI by exec-ing into the webui container, e.g.:"
echo ""
echo 'docker exec webui opencode -m ollama/deepseek-v4-pro:cloud run "Target URL: http://zero.webappsecurity.com, Mode:pentest" --file /app/skills/web-app-pentester.md'
echo ""
echo "List available models with: docker exec webui opencode models"
echo ""
echo "Report lands in ./results. When finished, tear down with: docker compose down"

# Wait for the web UI to respond, then open it in the default browser.
URL="http://localhost:8080"
echo ""
echo "Waiting for the web UI at $URL ..."
for _ in $(seq 1 30); do
  curl -sf -o /dev/null "$URL" && break
  sleep 1
done
if command -v xdg-open >/dev/null 2>&1; then
  xdg-open "$URL" >/dev/null 2>&1 &
elif command -v open >/dev/null 2>&1; then
  open "$URL" >/dev/null 2>&1 &
else
  echo "Open $URL in your browser."
fi
