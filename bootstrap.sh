#! /bin/bash

if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo "Error: Docker and Docker Compose are required. Install the Docker environment first." >&2
  exit 1
fi

docker compose up -d --build

docker compose exec kali-server wpscan --update

docker compose exec ollama ollama pull deepseek-v4-pro:cloud
docker compose exec ollama ollama pull qwen3.5:cloud
docker compose exec ollama ollama pull nemotron-3-ultra:cloud
docker compose exec ollama ollama pull glm-5.2:cloud
docker compose exec ollama ollama pull glm-5.3:cloud
docker compose exec ollama ollama pull kimi-k3:cloud
docker compose exec ollama ollama run deepseek-v4.1-flash:cloud

echo "Starting Ollama sign-in..."
SIGNIN_LOG="$(mktemp)"
docker compose exec -T ollama ollama signin >"$SIGNIN_LOG" 2>&1 &

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

rm -f "$SIGNIN_LOG"
echo ""
echo "Sign in to Ollama anytime via the 'Log in to Ollama' button at $URL"

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
