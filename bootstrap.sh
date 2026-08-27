#! /bin/bash

# Start all containers (webui serves the scan UI on :8080).
# Missing images are built (kali/opencode-runner) or pulled (ollama); existing images are reused as-is.
# After editing a Dockerfile, rebuild explicitly: docker compose up -d --build
docker compose up -d

# Update wpscan
docker compose exec kali-server wpscan --update

# Start Ollama sign-in in the background and capture the link it prints.
# `ollama signin` shows a URL and waits until the user completes auth in the browser;
# we surface that URL as the "Log in to Ollama" button in the web UI.
echo "Starting Ollama sign-in..."
SIGNIN_LOG="$(mktemp)"
docker compose exec -T ollama ollama signin >"$SIGNIN_LOG" 2>&1 &
SIGNIN_PID=$!

# Poll the output for the sign-in URL, then inject it into the web UI container.
LOGIN_URL=""
for _ in $(seq 1 20); do
  LOGIN_URL="$(grep -oE 'https?://[^[:space:]]+' "$SIGNIN_LOG" | head -1)"
  [ -n "$LOGIN_URL" ] && break
  sleep 1
done
if [ -n "$LOGIN_URL" ]; then
  echo "Ollama sign-in link: $LOGIN_URL"
  OLLAMA_LOGIN_URL="$LOGIN_URL" docker compose up -d webui
else
  echo "Could not capture the Ollama sign-in link automatically. Raw output:"
  cat "$SIGNIN_LOG"
fi

# Wait for the web UI, then open it so the user can click "Log in to Ollama".
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

# Block until sign-in completes (user clicked the link), then pull the models.
echo ""
echo "Complete the Ollama sign-in via the 'Log in to Ollama' button; model download starts after..."
wait "$SIGNIN_PID"
rm -f "$SIGNIN_LOG"

# Sign-in done: flip the web UI button to the green "Logged into Ollama" state.
OLLAMA_LOGGED_IN=1 docker compose up -d webui

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
