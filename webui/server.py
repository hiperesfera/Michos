#!/usr/bin/env python3
"""Minimal web UI to launch web-app-pentester scans, watch progress, and read the report.

Runs inside the opencode-runner image: it shells out to the `opencode` binary that is
already configured (MCP kali-server + ollama) and writes each scan into its own directory
under /results/webui so the generated report is easy to find. Stdlib only, single process."""

import base64
import html
import json
import os
import re
import signal
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONFIG_PATH = os.environ.get("OPENCODE_CONFIG", "/app/opencode.docker.json")
SKILL_FILE = "/app/skills/web-app-pentester.md"
LOGO_PATH = os.environ.get("LOGO_PATH", "/app/img/michos.png")
OLLAMA_LOGIN_URL = os.environ.get("OLLAMA_LOGIN_URL", "").strip()
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://ollama:11434")
KALI_SERVER = os.environ.get("KALI_SERVER", "http://kali-server:5000")
RESULTS_BASE = os.environ.get("RESULTS_BASE", "/results/webui")
MODES = ("passive", "recon", "pentest")
TIMINGS = ("paranoid", "polite", "normal", "aggressive")


def load_logo():
    """Embed the logo as a data URI so the page stays self-contained (no static route / volume)."""
    try:
        with open(LOGO_PATH, "rb") as fh:
            return "data:image/png;base64," + base64.b64encode(fh.read()).decode()
    except OSError:
        return ""

# scan_id -> {status, url, mode, model, outdir, logfile, returncode, started}
SCANS = {}
LOCK = threading.Lock()


def load_models():
    """Read the ollama model ids from the opencode config so the dropdown stays in sync."""
    try:
        with open(CONFIG_PATH) as fh:
            cfg = json.load(fh)
        names = cfg["provider"]["ollama"]["models"].keys()
        return ["ollama/" + n for n in names]
    except Exception:
        return []


MODELS = load_models()
LOGO_URI = load_logo()

# A :cloud model to probe Ollama's real auth state (see is_logged_in).
PROBE_MODEL = next((m[len("ollama/"):] for m in MODELS if m.endswith(":cloud")), "")

# Initial "Log in" button (rendered server-side). The logged-in/green state is decided
# live by the client polling /api/ollama-status, so it isn't baked into the page here.
if OLLAMA_LOGIN_URL.startswith(("http://", "https://")):
    LOGIN_BTN = ('<a class="login" href="%s" target="_blank" rel="noopener">Log in to Ollama</a>'
                 % html.escape(OLLAMA_LOGIN_URL, quote=True))
else:
    LOGIN_BTN = ""

# Cached result of the live auth probe. `ollama signin` exits 0 even when signed out, so we
# detect real login by calling /api/generate on a cloud model: 401 => signed out, 2xx => in.
_AUTH = {"logged_in": False, "ts": 0.0}
_AUTH_TTL = 15  # seconds between probes while still signed out


def is_logged_in():
    if _AUTH["logged_in"]:
        return True  # sticky once true, to avoid repeated cloud calls
    if not PROBE_MODEL or time.time() - _AUTH["ts"] < _AUTH_TTL:
        return False
    _AUTH["ts"] = time.time()
    body = json.dumps({"model": PROBE_MODEL, "prompt": "1", "stream": False,
                       "options": {"num_predict": 1}, "keep_alive": 0}).encode()
    req = urllib.request.Request(OLLAMA_HOST + "/api/generate", data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        urllib.request.urlopen(req, timeout=30).read()
        _AUTH["logged_in"] = True
    except urllib.error.HTTPError as e:
        _AUTH["logged_in"] = e.code != 401
    except Exception:
        _AUTH["logged_in"] = False
    return _AUTH["logged_in"]


def slug(url):
    host = re.sub(r"^\w+://", "", url).split("/")[0].split(":")[0]
    return re.sub(r"[^A-Za-z0-9.-]", "_", host) or "target"


def build_message(url, mode, timing, auth, auth2, maxtime):
    lines = [f"Target URL: {url}", f"Mode: {mode}", f"Timing: {timing}"]
    if auth:
        lines.append(f"Auth Header: {auth}")
    if auth2:
        lines.append(f"Auth Header (Secondary): {auth2}")
    lines.append(f"Max Time: {maxtime}")
    return "\n".join(lines)


def run_scan(scan_id, model, message, outdir):
    logpath = os.path.join(outdir, "scan.log")
    with open(logpath, "w") as log:
        log.write(f"$ opencode -m {model} run <message> --file {SKILL_FILE}\n\n{message}\n\n{'='*60}\n\n")
        log.flush()
        # start_new_session=True puts opencode in its own process group so cancel can kill
        # the whole session (agent + any children) with one signal.
        proc = subprocess.Popen(
            ["opencode", "-m", model, "run", message, "--file", SKILL_FILE],
            cwd=outdir, stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    with LOCK:
        SCANS[scan_id]["proc"] = proc
        SCANS[scan_id]["pid"] = proc.pid
    rc = proc.wait()
    with LOCK:
        SCANS[scan_id]["returncode"] = rc
        if SCANS[scan_id]["status"] != "cancelled":  # cancel_scan may have set this
            SCANS[scan_id]["status"] = "done" if rc == 0 else "failed"


# Upstream kali-server has no stop endpoint and ignores client disconnects, so a tool it is
# already running keeps going until COMMAND_TIMEOUT. server.py runs as PID 1 there with each
# tool as its child, so we kill every process except PID 1 and the killer shell itself.
KALI_KILL_CMD = (
    'me=$$; par=$PPID; '
    'for p in $(ls /proc 2>/dev/null | grep -E "^[0-9]+$"); do '
    '[ "$p" = 1 ] && continue; [ "$p" = "$me" ] && continue; [ "$p" = "$par" ] && continue; '
    'grep -qa server.py "/proc/$p/cmdline" 2>/dev/null && continue; '
    'kill -9 "$p" 2>/dev/null; done'
)


def kill_kali_tools():
    """Kill any in-flight tool command in the kali-server container via its /api/command route."""
    body = json.dumps({"command": KALI_KILL_CMD}).encode()
    req = urllib.request.Request(KALI_SERVER + "/api/command", data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        urllib.request.urlopen(req, timeout=15).read()
    except Exception:
        pass


def cancel_scan(scan):
    """Stop the scan: kill the opencode session, and any in-flight command in the Kali container."""
    with LOCK:
        scan["status"] = "cancelled"  # set first so run_scan won't overwrite with done/failed
    proc = scan.get("proc")
    if proc and proc.poll() is None:
        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGTERM)
            for _ in range(20):  # up to ~2s grace, then force
                if proc.poll() is not None:
                    break
                time.sleep(0.1)
            else:
                os.killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    kill_kali_tools()


def find_report(outdir):
    """The skill writes <domain>-<model>-report.md in its cwd; pick the newest .md that isn't the log."""
    mds = [f for f in os.listdir(outdir) if f.endswith(".md")]
    if not mds:
        return None
    mds.sort(key=lambda f: os.path.getmtime(os.path.join(outdir, f)), reverse=True)
    return os.path.join(outdir, mds[0])


ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")


def clean(text):
    """opencode emits ANSI colour codes and \\r spinner rewrites; strip them for the <pre> view."""
    text = ANSI_RE.sub("", text).replace("\r", "")
    return re.sub(r"\n{3,}", "\n\n", text)


def tail(path, limit=40000):
    try:
        with open(path, "r", errors="replace") as fh:
            data = fh.read()
        return data[-limit:]
    except OSError:
        return ""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        payload = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass  # quiet

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            return self._send(200, PAGE, "text/html; charset=utf-8")
        if self.path.split("?")[0] == "/api/ollama-status":
            return self._send(200, json.dumps({
                "logged_in": is_logged_in(),
                "login_url": OLLAMA_LOGIN_URL if OLLAMA_LOGIN_URL.startswith(("http://", "https://")) else "",
            }))
        m = re.match(r"^/api/scan/([\w.-]+)/(progress|report)/?$", self.path.split("?")[0])
        if m:
            scan_id, what = m.group(1), m.group(2)
            with LOCK:
                scan = SCANS.get(scan_id)
            if not scan:
                return self._send(404, json.dumps({"error": "unknown scan"}))
            if what == "progress":
                return self._send(200, json.dumps({
                    "status": scan["status"],
                    "log": clean(tail(os.path.join(scan["outdir"], "scan.log"))),
                }))
            report = find_report(scan["outdir"])
            if not report:
                return self._send(200, json.dumps({"found": False}))
            if self.path.endswith("download=1") or "download=1" in self.path:
                with open(report, "rb") as fh:
                    body = fh.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/markdown; charset=utf-8")
                self.send_header("Content-Disposition",
                                 f'attachment; filename="{os.path.basename(report)}"')
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                return self.wfile.write(body)
            return self._send(200, json.dumps({
                "found": True, "name": os.path.basename(report), "content": tail(report, 400000),
            }))
        return self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        cm = re.match(r"^/api/scan/([\w.-]+)/cancel/?$", self.path.split("?")[0])
        if cm:
            with LOCK:
                scan = SCANS.get(cm.group(1))
            if not scan:
                return self._send(404, json.dumps({"error": "unknown scan"}))
            if scan["status"] == "running":
                cancel_scan(scan)
            return self._send(200, json.dumps({"status": scan["status"]}))
        if self.path != "/api/scan":
            return self._send(404, json.dumps({"error": "not found"}))
        length = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self._send(400, json.dumps({"error": "invalid json"}))

        url = (data.get("url") or "").strip()
        mode = (data.get("mode") or "").strip()
        timing = (data.get("timing") or "normal").strip()
        model = (data.get("model") or "").strip()
        auth = (data.get("auth") or "").strip()
        auth2 = (data.get("auth2") or "").strip()
        maxtime = str(data.get("maxtime") or "600").strip()

        if not re.match(r"^https?://", url):
            return self._send(400, json.dumps({"error": "Target URL must start with http:// or https://"}))
        if mode not in MODES:
            return self._send(400, json.dumps({"error": "invalid mode"}))
        if timing not in TIMINGS:
            return self._send(400, json.dumps({"error": "invalid timing"}))
        if model not in MODELS:
            return self._send(400, json.dumps({"error": "invalid model"}))
        if not maxtime.isdigit():
            return self._send(400, json.dumps({"error": "Max Time must be an integer"}))

        scan_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + slug(url) + "-" + uuid.uuid4().hex[:6]
        outdir = os.path.join(RESULTS_BASE, scan_id)
        os.makedirs(outdir, exist_ok=True)
        message = build_message(url, mode, timing, auth, auth2, maxtime)

        with LOCK:
            SCANS[scan_id] = {
                "status": "running", "url": url, "mode": mode, "model": model,
                "outdir": outdir, "returncode": None,
                "started": datetime.now(timezone.utc).isoformat(),
            }
        threading.Thread(target=run_scan, args=(scan_id, model, message, outdir), daemon=True).start()
        return self._send(200, json.dumps({"scan_id": scan_id}))


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Michos</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { font: 15px/1.5 system-ui, sans-serif; margin: 0; background: #0f1216; color: #e6e6e6; }
  header { border-bottom: 1px solid #2a2f37; background: #151a21; }
  header .hdr { position: relative; max-width: 980px; margin: 0 auto; padding: 24px; }
  header .brand { background: #fff; border-radius: 12px; padding: 16px; text-align: center; }
  header .logo { height: 110px; }
  .login { padding: 9px 16px; background: #3b82f6; color: #fff; border-radius: 7px;
    font-weight: 600; text-decoration: none; font-size: 14px; }
  a.login:hover { background: #2f6fd6; }
  .login.loggedin { background: #14532d; color: #86efac; }
  main { max-width: 980px; margin: 0 auto; padding: 24px; }
  .card { background: #151a21; border: 1px solid #2a2f37; border-radius: 10px; padding: 20px; margin-bottom: 20px; }
  label { display: block; margin: 12px 0 4px; font-size: 13px; color: #9aa4b2; }
  input, select { width: 100%; padding: 9px 11px; background: #0f1216; color: #e6e6e6;
    border: 1px solid #2a2f37; border-radius: 7px; font: inherit; }
  .row { display: flex; gap: 16px; flex-wrap: wrap; }
  .row > div { flex: 1; min-width: 220px; }
  button { margin-top: 18px; padding: 10px 20px; background: #3b82f6; color: #fff; border: 0;
    border-radius: 7px; font: inherit; font-weight: 600; cursor: pointer; }
  button:disabled { opacity: .5; cursor: default; }
  .actions { display: flex; justify-content: space-between; align-items: center; margin-top: 18px; }
  .action-btns { display: flex; gap: 10px; align-items: center; }
  .actions button { margin-top: 0; }
  #cancel { background: #dc2626; }
  #cancel:hover:not(:disabled) { background: #b91c1c; }
  .badge { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 12px; font-weight: 600; }
  .running { background: #78500a; color: #fde68a; }
  .done { background: #14532d; color: #86efac; }
  .failed { background: #7f1d1d; color: #fecaca; }
  .cancelled { background: #374151; color: #d1d5db; }
  pre { background: #0b0e12; border: 1px solid #2a2f37; border-radius: 7px; padding: 14px;
    overflow: auto; max-height: 420px; font: 12.5px/1.5 ui-monospace, monospace; white-space: pre-wrap;
    word-break: break-word; }
  .hidden { display: none; }
  a { color: #60a5fa; }
  h2 { font-size: 15px; margin: 0 0 12px; }
  .md { line-height: 1.6; }
  .md h1, .md h2, .md h3, .md h4 { margin: 1.2em 0 .5em; line-height: 1.3; }
  .md h1 { font-size: 22px; border-bottom: 1px solid #2a2f37; padding-bottom: .3em; }
  .md h2 { font-size: 19px; border-bottom: 1px solid #2a2f37; padding-bottom: .2em; }
  .md h3 { font-size: 16px; } .md h4 { font-size: 14px; color: #c3cad6; }
  .md p { margin: .6em 0; } .md ul, .md ol { margin: .6em 0; padding-left: 1.4em; }
  .md li { margin: .2em 0; }
  .md code { background: #0b0e12; border: 1px solid #2a2f37; border-radius: 4px;
    padding: 1px 5px; font: 12.5px ui-monospace, monospace; }
  .md pre.code { background: #0b0e12; border: 1px solid #2a2f37; border-radius: 7px;
    padding: 14px; overflow-x: auto; }
  .md pre.code code { background: none; border: 0; padding: 0; }
  .md blockquote { margin: .6em 0; padding: .2em 1em; border-left: 3px solid #3b82f6; color: #9aa4b2; }
  .md hr { border: 0; border-top: 1px solid #2a2f37; margin: 1.2em 0; }
  .md table { border-collapse: collapse; margin: .8em 0; font-size: 13.5px;
    display: block; overflow-x: auto; }
  .md th, .md td { border: 1px solid #2a2f37; padding: 7px 10px; text-align: left; vertical-align: top; }
  .md th { background: #1b2129; }
  .md tbody tr:nth-child(even) { background: #12161c; }
  .tabs { display: flex; gap: 4px; border-bottom: 1px solid #2a2f37; margin-bottom: 20px; }
  .tab { padding: 10px 18px; background: none; border: 0; color: #9aa4b2; font: inherit;
    font-weight: 600; cursor: pointer; border-bottom: 2px solid transparent; }
  .tab.active { color: #e6e6e6; border-bottom-color: #3b82f6; }
  .tab:disabled { opacity: .4; cursor: default; }
  .panel { display: none; }
  .panel.active { display: block; }
</style></head>
<body>
<header>
  <div class="hdr">
    <div class="brand"><img src="%LOGO%" alt="Michos" class="logo"></div>
  </div>
</header>
<main>
  <div class="tabs">
    <button class="tab active" id="tabBtnScan" onclick="showTab('scan')">Scan</button>
    <button class="tab" id="tabBtnReport" onclick="showTab('report')" disabled>Report</button>
  </div>
  <div class="panel active" id="tabScan">
  <div class="card" id="formCard">
    <div class="row">
      <div><label>Target URL</label><input id="url" placeholder="https://example.com"></div>
      <div><label>Mode</label><select id="mode">
        <option value="passive">passive</option>
        <option value="recon">recon</option>
        <option value="pentest" selected>pentest</option>
      </select></div>
      <div><label>Timing</label><select id="timing" title="Like nmap -T: how fast to scan. Lower it if the target throws 429s.">
        <option value="paranoid">paranoid</option>
        <option value="polite">polite</option>
        <option value="normal" selected>normal</option>
        <option value="aggressive">aggressive</option>
      </select></div>
    </div>
    <div class="row">
      <div><label>Model</label><select id="model"></select></div>
      <div><label>Max Time (seconds)</label><input id="maxtime" type="number" value="600"></div>
    </div>
    <label>Auth Header (optional)</label>
    <input id="auth" placeholder="Authorization: Bearer eyJ...  or  Cookie: session=...">
    <label>Secondary Auth Header (optional, for access-control testing)</label>
    <input id="auth2" placeholder="second, lower-privilege identity">
    <div class="actions">
      <div id="loginSlot">%LOGIN%</div>
      <div class="action-btns">
        <button id="cancel" class="hidden">Cancel scan</button>
        <button id="start">Start scan</button>
      </div>
    </div>
    <p id="err" style="color:#fca5a5"></p>
  </div>

  <div class="card hidden" id="progCard">
    <h2>Progress <span id="badge" class="badge running">running</span>
      <span id="sid" style="color:#6b7280;font-size:12px"></span></h2>
    <pre id="log"></pre>
  </div>

  </div><!-- /tabScan -->

  <div class="panel" id="tabReport">
  <div class="card" id="repCard">
    <h2>Report: <span id="repName"></span>
      <a id="dl" style="font-size:13px;margin-left:10px">download .md</a></h2>
    <div id="report" class="md"></div>
  </div>
  </div><!-- /tabReport -->
</main>
<script>
const $ = id => document.getElementById(id);
const models = %MODELS%;
$("model").innerHTML = models.map(m => `<option value="${m}">${m}</option>`).join("")
  || '<option value="">(no models found)</option>';

let poll = null;
let currentScanId = null;

function setRunning(running) {
  $("start").disabled = running;
  $("cancel").classList.toggle("hidden", !running);
  $("cancel").disabled = false;
}

$("cancel").onclick = async () => {
  if (!currentScanId) return;
  $("cancel").disabled = true;
  try { await fetch(`/api/scan/${currentScanId}/cancel`, {method: "POST"}); } catch (e) {}
  // the next tick reflects the "cancelled" status and stops polling
};

function showTab(name) {
  if ($("tabBtnReport").disabled && name === "report") return;
  $("tabScan").classList.toggle("active", name === "scan");
  $("tabReport").classList.toggle("active", name === "report");
  $("tabBtnScan").classList.toggle("active", name === "scan");
  $("tabBtnReport").classList.toggle("active", name === "report");
}

$("start").onclick = async () => {
  $("err").textContent = "";
  const body = {
    url: $("url").value, mode: $("mode").value, timing: $("timing").value, model: $("model").value,
    maxtime: $("maxtime").value, auth: $("auth").value, auth2: $("auth2").value,
  };
  $("start").disabled = true;
  const r = await fetch("/api/scan", {method: "POST", body: JSON.stringify(body)});
  const j = await r.json();
  if (!r.ok) { $("err").textContent = j.error || "failed to start"; setRunning(false); return; }
  startWatching(j.scan_id);
};

function startWatching(id) {
  currentScanId = id;
  setRunning(true);
  $("progCard").classList.remove("hidden");
  $("tabBtnReport").disabled = true;
  showTab("scan");
  $("sid").textContent = id;
  try { localStorage.setItem("michos_scan", id); } catch (e) {}
  if (poll) clearInterval(poll);
  poll = setInterval(() => tick(id), 2000);
  tick(id);
}

// Re-attach to the last scan after a browser refresh (state lives on the server, not the page).
async function restore() {
  let id;
  try { id = localStorage.getItem("michos_scan"); } catch (e) {}
  if (!id) return;
  const r = await fetch(`/api/scan/${id}/progress`);
  if (!r.ok) { try { localStorage.removeItem("michos_scan"); } catch (e) {} return; }
  const j = await r.json();
  $("progCard").classList.remove("hidden");
  $("sid").textContent = id;
  $("badge").textContent = j.status;
  $("badge").className = "badge " + j.status;
  $("log").textContent = j.log || "(waiting for output...)";
  $("log").scrollTop = $("log").scrollHeight;
  if (j.status === "running") {
    currentScanId = id;
    setRunning(true);
    if (poll) clearInterval(poll);
    poll = setInterval(() => tick(id), 2000);
  } else {
    loadReport(id);
  }
}

async function tick(id) {
  const j = await (await fetch(`/api/scan/${id}/progress`)).json();
  const badge = $("badge");
  badge.textContent = j.status;
  badge.className = "badge " + j.status;
  const atBottom = $("log").scrollTop + $("log").clientHeight >= $("log").scrollHeight - 30;
  $("log").textContent = j.log || "(waiting for output...)";
  if (atBottom) $("log").scrollTop = $("log").scrollHeight;
  if (j.status !== "running") {
    clearInterval(poll); poll = null;
    setRunning(false);
    loadReport(id);
  }
}

async function loadReport(id) {
  const j = await (await fetch(`/api/scan/${id}/report`)).json();
  if (!j.found) return;
  $("repName").textContent = j.name;
  $("report").innerHTML = md2html(j.content);
  $("dl").href = `/api/scan/${id}/report?download=1`;
  $("tabBtnReport").disabled = false;
  showTab("report");
}

// --- tiny self-contained markdown renderer (headings, lists, tables, code, quotes, inline) ---
function escapeHtml(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
function inline(s) {
  const codes = [];
  s = s.replace(/`([^`]+)`/g, (m, c) => { codes.push(c); return "\\u0000" + (codes.length - 1) + "\\u0000"; });
  s = s.replace(/\\*\\*([^*]+)\\*\\*/g, "<strong>$1</strong>");
  s = s.replace(/\\*([^*]+)\\*/g, "<em>$1</em>");
  s = s.replace(/\\[([^\\]]+)\\]\\(([^)\\s]+)\\)/g, (m, t, u) =>
    '<a href="' + (/^(https?:|\\/|#)/.test(u) ? u : "#") + '" target="_blank" rel="noopener">' + t + "</a>");
  return s.replace(/\\u0000(\\d+)\\u0000/g, (m, n) => "<code>" + codes[n] + "</code>");
}
function splitRow(line) {
  return line.trim().replace(/^\\|/, "").replace(/\\|$/, "").split("|").map(c => c.trim());
}
function md2html(src) {
  const lines = src.replace(/\\r\\n?/g, "\\n").split("\\n");
  const out = []; let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (/^```/.test(line)) {
      const buf = []; i++;
      while (i < lines.length && !/^```/.test(lines[i])) { buf.push(lines[i]); i++; }
      i++;
      out.push('<pre class="code"><code>' + escapeHtml(buf.join("\\n")) + "</code></pre>"); continue;
    }
    if (/^\\s*([-*_])(\\s*\\1){2,}\\s*$/.test(line)) { out.push("<hr>"); i++; continue; }
    const h = line.match(/^(#{1,6})\\s+(.*)$/);
    if (h) { const n = h[1].length; out.push("<h" + n + ">" + inline(escapeHtml(h[2].trim())) + "</h" + n + ">"); i++; continue; }
    if (line.includes("|") && i + 1 < lines.length && lines[i + 1].includes("-") &&
        /^\\s*\\|?[\\s:|-]+\\|?\\s*$/.test(lines[i + 1])) {
      const header = splitRow(line); i += 2; const rows = [];
      while (i < lines.length && lines[i].includes("|") && lines[i].trim() !== "") { rows.push(splitRow(lines[i])); i++; }
      let t = "<table><thead><tr>" + header.map(c => "<th>" + inline(escapeHtml(c)) + "</th>").join("") + "</tr></thead><tbody>";
      for (const r of rows) t += "<tr>" + r.map(c => "<td>" + inline(escapeHtml(c)) + "</td>").join("") + "</tr>";
      out.push(t + "</tbody></table>"); continue;
    }
    if (/^\\s*>/.test(line)) {
      const buf = [];
      while (i < lines.length && /^\\s*>/.test(lines[i])) { buf.push(lines[i].replace(/^\\s*>\\s?/, "")); i++; }
      out.push("<blockquote>" + md2html(buf.join("\\n")) + "</blockquote>"); continue;
    }
    if (/^\\s*([-*+]|\\d+\\.)\\s+/.test(line)) {
      const ordered = /^\\s*\\d+\\.\\s+/.test(line); const buf = [];
      while (i < lines.length && /^\\s*([-*+]|\\d+\\.)\\s+/.test(lines[i])) { buf.push(lines[i].replace(/^\\s*([-*+]|\\d+\\.)\\s+/, "")); i++; }
      const tag = ordered ? "ol" : "ul";
      out.push("<" + tag + ">" + buf.map(it => "<li>" + inline(escapeHtml(it)) + "</li>").join("") + "</" + tag + ">"); continue;
    }
    if (line.trim() === "") { i++; continue; }
    const buf = [line]; i++;
    while (i < lines.length && lines[i].trim() !== "" &&
           !/^(#{1,6}\\s|```|\\s*>|\\s*([-*+]|\\d+\\.)\\s)/.test(lines[i])) { buf.push(lines[i]); i++; }
    out.push("<p>" + inline(escapeHtml(buf.join(" "))) + "</p>");
  }
  return out.join("\\n");
}

// Poll Ollama sign-in status so the button flips to green live (e.g. after bootstrap
// recreates the container as logged in) without needing a page refresh.
function renderLogin(s) {
  const slot = $("loginSlot");
  slot.innerHTML = "";
  let el;
  if (s.logged_in) {
    el = document.createElement("span");
    el.className = "login loggedin";
    el.textContent = "Logged into Ollama";
  } else if (s.login_url) {
    el = document.createElement("a");
    el.className = "login";
    el.href = s.login_url;
    el.target = "_blank";
    el.rel = "noopener";
    el.textContent = "Log in to Ollama";
  } else {
    return;
  }
  slot.appendChild(el);
}
async function pollLogin() {
  try { renderLogin(await (await fetch("/api/ollama-status")).json()); } catch (e) {}
}
pollLogin();
setInterval(pollLogin, 5000);

restore();
</script>
</body></html>"""

PAGE = PAGE.replace("%MODELS%", json.dumps(MODELS)).replace("%LOGO%", LOGO_URI).replace("%LOGIN%", LOGIN_BTN)


if __name__ == "__main__":
    os.makedirs(RESULTS_BASE, exist_ok=True)
    port = int(os.environ.get("PORT", "8080"))
    print(f"Pentest web UI on :{port}  (models: {len(MODELS)}, skill: {SKILL_FILE})", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
