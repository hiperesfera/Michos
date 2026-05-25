# MCP-Kali Diagnostic Skill

## Purpose

Verify that the Kali MCP server is reachable and that every tool configured in the provided Dockerfile is actually callable. Produces a single pass/fail table so you can see at a glance what's broken in the container environment before running any real assessments.

This skill performs **diagnostic checks only**. It does not exploit, scan, or attack any third-party target. Every check is either local (`127.0.0.1`, `--version`, `--help`, `which`) or against `scanme.nmap.org`, the public test target maintained by the Nmap project for exactly this purpose.

## How to use

Run the steps in order. Record the result of each step in the report template at the bottom. Stop only if step 1 fails — otherwise continue through every step so the final report shows the full picture.

## 1. Server health

Confirm the MCP server is reachable at all.

```text
server_health()

```

**Pass:** response indicates the server is up.
**Fail:** any error → stop here, the MCP server is not running or not reachable. Nothing else in this skill can succeed.

## 2. Dedicated MCP functions

Test the active dedicated functions with the minimum-impact invocation that still exercises the wrapper. Record success / failure / error message for each.

### 2.1 `nmap_scan`

```text
nmap_scan(target="scanme.nmap.org", scan_type="-sV", ports="80", additional_args="-Pn --top-ports 1")

```

Expect: any output containing port 80 state.

### 2.2 `gobuster_scan`

```text
gobuster_scan(url="[http://scanme.nmap.org](http://scanme.nmap.org)", mode="dir", wordlist="/usr/share/seclists/Discovery/Web-Content/common.txt", additional_args="-t 5 --no-error -q")

```

Expect: gobuster banner and a small result set.

### 2.3 `nikto_scan`

```text
nikto_scan(target="scanme.nmap.org", additional_args="-maxtime 30s -Tuning 1")

```

Expect: nikto header lines.

### 2.4 `sqlmap_scan`

```text
sqlmap_scan(url="[http://scanme.nmap.org/?id=1](http://scanme.nmap.org/?id=1)", data="", additional_args="--batch --flush-session --crawl=0 --threads=1 --timeout=10 --retries=0")

```

Expect: sqlmap banner and a "no injection found" outcome.

### 2.5 `metasploit_run`

```text
metasploit_run(module="auxiliary/scanner/portscan/tcp", options={"RHOSTS": "127.0.0.1", "PORTS": "22", "THREADS": "1"})

```

Expect: msfconsole runs the module and exits.

### 2.6 `hydra_attack`

```text
hydra_attack(target="127.0.0.1", service="ssh", username="root", password="this_is_not_a_real_password_diagnostic_only", additional_args="-t 1 -W 1 -f")

```

Expect: hydra runs and reports a failed attempt.

### 2.7 `john_crack`

First create a known-format hash:

```text
execute_command(command="echo 'test:$1$abc$ZHbZWzKjz9q5fH/r.YxiI/' > /tmp/diag-hash.txt")

```

Then:

```text
john_crack(hash_file="/tmp/diag-hash.txt", wordlist="/usr/share/wordlists/rockyou.txt", format_type="md5crypt", additional_args="--max-run-time=10")

```

Expect: john banner and either a crack result or timeout.

### 2.8 `wpscan_analyze`

```text
wpscan_analyze(url="[https://wordpress.org/](https://wordpress.org/)", additional_args="--no-update --random-user-agent --disable-tls-checks --max-scan-duration 30")

```

Expect: wpscan banner.

### 2.9 `enum4linux_scan`

```text
enum4linux_scan(target="127.0.0.1", additional_args="-U")

```

Expect: enum4linux banner.

### 2.10 `server_health` (re-check)

```text
server_health()

```

Confirm the server didn't crash during diagnostics.

### 2.11 `execute_command` (basic sanity)

```text
execute_command(command="id && uname -a && pwd")

```

Expect: a uid/gid line, a uname line, and a working directory.

## 3. Binaries reachable via `execute_command`

Verify that the entire suite of platform tools is accessible on the PATH.

```text
execute_command(command="for b in nmap naabu masscan nikto whatweb wafw00f sslscan sslyze nuclei httpx-toolkit subfinder dnsx amass sqlmap commix gobuster ffuf feroxbuster wfuzz dirb hydra john hashcat medusa patator ncrack wpscan joomscan enum4linux msfconsole cewl crunch theharvester recon-ng dnsrecon dnsenum fierce trufflehog gitleaks dalfox katana waybackurls gau hakrawler gospider subjack subzy arjun qsreplace gf anew sstimap nosqlmap ssrfmap fuxploider jwt_tool linkfinder secretfinder xnLinkFinder graphw00f graphql-cop kr burpsuite zaproxy mitmproxy; do if command -v $b >/dev/null 2>&1; then echo \"OK  $b -> $(command -v $b)\"; else echo \"MISSING $b\"; fi; done")

```

Expect: one line per binary. Any line starting with `MISSING` is a tool that failed to install or is missing from the PATH. Record these in the report.

## 4. Common path sanity

Verify the standard wordlist and tool data paths exist.

```text
execute_command(command="for p in /usr/share/wordlists/rockyou.txt /usr/share/seclists/Discovery/Web-Content /usr/share/seclists/Fuzzing /usr/share/wordlists/assetnote/httparchive_directories_1m_2024_05_28.txt; do if [ -e $p ]; then echo \"OK  $p\"; else echo \"MISSING $p\"; fi; done")

```

Expect: each path either present or flagged missing.

## 5. PATH and user context

Confirm what user the server runs as and what its PATH actually is.

```text
execute_command(command="echo USER=$(whoami); echo PATH=$PATH; echo HOME=$HOME; echo PWD=$(pwd)")

```

Expect: `mcpuser` (per the Dockerfile) and a PATH that includes `/usr/local/bin`, `/usr/bin`, and `/opt/go/bin`.

## 6. Report template

After running all steps, produce a single markdown file `mcp-diagnostic-<UTC_TIMESTAMP>.md` with three sections:

### 6.1 MCP function status

A table with one row per dedicated function:

```text
| Function           | Status | Notes                                |
|--------------------|--------|--------------------------------------|
| server_health      |        |                                      |
| execute_command    |        |                                      |
| nmap_scan          |        |                                      |
| gobuster_scan      |        |                                      |
| nikto_scan         |        |                                      |
| sqlmap_scan        |        |                                      |
| metasploit_run     |        |                                      |
| hydra_attack       |        |                                      |
| john_crack         |        |                                      |
| wpscan_analyze     |        |                                      |
| enum4linux_scan    |        |                                      |

```

Status is one of `PASS`, `FAIL`, or `ERROR`. `Notes` captures the relevant error line.

### 6.2 Binary availability

The raw output of step 3, unmodified, fenced in a code block. Then a one-line summary: `<n> of <total> binaries present`.

### 6.3 Path and environment

The raw output of steps 4 and 5 in code blocks, plus a brief verdict.

## 7. Interpreting the report

* **All step 2 entries PASS, step 3 mostly OK** → The container platform is perfectly aligned and ready for any agent skill to utilize.
* **Step 2 mixed PASS/FAIL but step 3 mostly MISSING** → The Kali host is installed but the MCP server's PATH is stripped.
* **Most of step 2 FAILs with "not found"** → Wrong container or failed build. Rebuild from the latest Dockerfile.
* **Step 1 FAILs** → The MCP server isn't running or port 5000 is blocked.

## 8. Out of scope

This skill does not:

* Exploit, scan, or attack any third-party target beyond the safe diagnostic invocations against `scanme.nmap.org` and `wordpress.org`.
* Verify tool *correctness* — only *presence and reachability*.
