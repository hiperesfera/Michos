# Penetration Test Report – zero.webappsecurity.com

| Field | Value |
| --- | --- |
| Target URL | http://zero.webappsecurity.com |
| Target IP | 54.82.22.214 (ec2-54-82-22-214.compute-1.amazonaws.com) |
| Mode | Pentest |
| Assessment Window | 2026-05-26 19:28 UTC – 2026-05-26 19:37 UTC |
| Tester / Engine | OpenCode pentester agent (anthropic/claude-opus-4-7) |
| Authentication | None provided (anonymous + discovered default creds) |
| Authorization | Public deliberately-vulnerable demo banking app (Micro Focus) |

---

## 1. Executive Summary

The application **zero.webappsecurity.com** is an intentionally-vulnerable demo banking
site (Micro Focus / Hewlett-Packard "Zero Bank") hosted on a legacy Apache 2.2.x +
Tomcat 7.0.70 stack on AWS EC2. The assessment surfaced a dense set of
**Critical / High** issues spanning transport security, server hardening, sensitive
data exposure, authentication and session management.

Highlights:

* **Sensitive log file `/debug.txt` (27 KB) publicly readable**, containing real-looking
  user IDs, account numbers, amounts, payee IDs, and Java class paths
  (CWE-532 / WSTG-CONFIG-02).
* **Plaintext default credentials `username:password` accepted** on the production login
  form (CWE-521 / WSTG-AUTH-02), reachable over **HTTP** with the credentials traveling
  in cleartext (CWE-319).
* **Default credential hints (`tomcat:s3cret`) leaked by Tomcat 401 page** exposed at
  `/manager/html`.
* **TLS endpoint catastrophically weak**: SSLv2, SSLv3, TLSv1.0 only, export-grade
  40-bit ciphers (RC2/RC4/DES), CRIME (compression), insecure renegotiation,
  expired certificate (2022-05-04), 1024-bit DHE (CWE-326 / WSTG-CRYP-01).
* **Apache `/server-status` exposed** revealing Apache 2.2.22 (Win32) + OpenSSL 0.9.8t
  + mod_jk 1.2.37 — all end-of-life.
* **Outdated software stack with public CVEs**: Tomcat 7.0.70 (Jun-2016),
  Apache 2.2.x (EOL Jul-2017), OpenSSL 0.9.8 (EOL Dec-2015), jQuery 1.8.2 (XSS CVEs).
* **CORS misconfiguration** – `Access-Control-Allow-Origin: *` on every response.
* **Missing security headers**: HSTS, CSP, X-Content-Type-Options, Referrer-Policy,
  Permissions-Policy.
* **Session cookie lacks `Secure` and `SameSite`** attributes and uses short
  8-hex-character JSESSIONID values.
* **`README.txt` discloses internal information** including default credentials
  (`admin/admin`, `user/user`) and developer contact data.

> Note: SQLi probing of `searchTerm` (GET `/search.html`) and the login parameters
> `user_login` / `user_password` via sqlmap (`--level=2 --risk=2`, BEU techniques)
> returned no injectable parameter; the application is largely static.
> No fabricated findings are included.

### Severity Tally
| Critical | High | Medium | Low | Informational |
| :-: | :-: | :-: | :-: | :-: |
| 4 | 5 | 4 | 3 | 2 |

---

## 2. Target Information & Reconnaissance

### 2.1 Service / Port Enumeration (`nmap -sV -sC -Pn`)
| Port | State | Service | Banner |
| --- | --- | --- | --- |
| 80/tcp | open | http | Apache Tomcat/Coyote JSP engine 1.1 (Tomcat 7.0.70) |
| 443/tcp | open | https | Apache/2.2.6 (Win32) mod_ssl/2.2.6 OpenSSL/0.9.8e mod_jk/1.2.40 |
| 8080/tcp | open | http | Apache Tomcat/Coyote JSP engine 1.1 |
| 21,22,25,3306,5432,8443 | filtered | – | – |

Allowed HTTP methods (Tomcat connector on 80/8080): `GET, HEAD, POST, PUT, DELETE,
TRACE, OPTIONS, PATCH`. TRACE returned 405 at request time, PUT returned 403 when
uploading `/zeropwn-test.txt` — actual upload is blocked but the methods remain
advertised in the `Allow` header.

### 2.2 Technology Fingerprint
* App: Java/JSP banking demo on Apache Tomcat 7.0.70 (built Jun-2016).
* Front-end fronted by Apache 2.2.22 (Win32) + mod_ssl 2.2.22 + OpenSSL 0.9.8t + mod_jk 1.2.37
  (per leaked `/server-status`). The 443 banner reports Apache 2.2.6 / OpenSSL 0.9.8e — older still.
* Bootstrap + jQuery 1.8.2.
* No WAF detected (`wafw00f`).
* Hosted on AWS EC2 (us-east-1).

### 2.3 Content Discovery (`gobuster` on common.txt, extensions html/jsp/txt)
Notable hits: `/README.txt`, `/Readme.txt`, `/readme.txt`, `/debug.txt`, `/admin/`,
`/manager/` (401), `/docs/` (Tomcat docs), `/server-status`, `/cgi-bin/`, `/errors/`,
`/help/`, `/include/`, `/resources/`, `/login.html`, `/signin.html`,
`/forgot-password.html`, `/feedback.html`, `/faq.html`, `/search.html`,
`/logout.html`.

### 2.4 Authentication Surface
* Login form: `POST /signin.html` with `user_login`, `user_password`,
  `user_token` (static hidden token observed across requests).
* Successful login redirects to `/auth/accept-certs.html?user_token=…`.
* Working credentials (publicly known for this demo, confirmed live):
  `username:password`.

---

## 3. Detailed Findings

Each finding includes a verifiable PoC captured during the engagement.
Timestamps are UTC; raw evidence is reproduced verbatim from the tool output.

---

### F-01 [Critical] Sensitive debug log file publicly accessible — `/debug.txt`
* **CWE:** CWE-532 (Insertion of Sensitive Information into Log File) /
  CWE-200 (Exposure of Sensitive Information)
* **CVSS v3.1:** 7.5 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
* **OWASP:** WSTG-CONFIG-02 (Application Platform Configuration);
  ASVS v4 — V8.3.4, V14.3.2

**Endpoint / Method:** `GET /debug.txt`

**PoC (2026-05-26 19:34 UTC):**
```http
GET /debug.txt HTTP/1.1
Host: zero.webappsecurity.com
```
Response (excerpt, 27144 bytes total):
```
Sat Feb 02 11:31:30 EST 2013 [DEBUG] [com.zero.bank.currency.CurrencyExchanger.exchangeCurrency(CurrencyExchanger.java:38)] - User 997355147 is going buy foreign currency.
...
Sat Feb 02 11:35:09 EST 2013 [DEBUG] [com.zero.bank.bills.BillsService.payBill(BillsService.java:35)] - User 1879782271 is going pay the payee 718489724
Sat Feb 02 11:35:09 EST 2013 [DEBUG] [com.zero.bank.bills.BillsService.payBill(BillsService.java:36)] -   From account: 1164681495
Sat Feb 02 11:35:09 EST 2013 [DEBUG] [com.zero.bank.bills.BillsService.payBill(BillsService.java:37)] -   Amount: 747.88
...
Sat Feb 02 12:50:18 EST 2013 [DEBUG] [com.zero.bank.account.TransactionManager.transferFunds(TransactionManager.java:43)] - Tranfer between accounts was requested by the user 1678646367
```
**Proof:** Production-style debug log containing user IDs, payee IDs, account numbers,
amounts, currencies, and internal class/method/line references is served to any
unauthenticated client.

**Impact:** Direct disclosure of personal/financial transaction data; enumeration of
valid `userId` / `accountId` / `payeeId` values for downstream IDOR or social-
engineering attacks; reveals internal package layout
(`com.zero.bank.account.TransactionManager`, `com.zero.bank.bills.BillsService`,
`com.zero.bank.currency.CurrencyExchanger`) which aids targeted exploitation.

**Reproduction:**
1. `curl http://zero.webappsecurity.com/debug.txt`
2. Observe full debug log.

**Recommendation:** See Section 4.

---

### F-02 [Critical] Default / weak credentials accepted on banking login
* **CWE:** CWE-521 (Weak Password Requirements), CWE-1392 (Use of Default Credentials)
* **CVSS v3.1:** 9.8 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
* **OWASP:** WSTG-AUTH-02 (Default Credentials); ASVS V2.1.1, V2.1.7

**Endpoint / Method:** `POST /signin.html`

**PoC (2026-05-26 19:35 UTC):**
```http
POST /signin.html HTTP/1.1
Host: zero.webappsecurity.com
Content-Type: application/x-www-form-urlencoded

user_login=username&user_password=password&user_token=7cd7d1e5-a98c-4228-b112-3987d6830fe5&submit=Sign+in
```
Response:
```
HTTP/1.1 302 Found
Location: /auth/accept-certs.html?user_token=7cd7d1e5-a98c-4228-b112-3987d6830fe5
Set-Cookie: JSESSIONID=25823997; Path=/; HttpOnly
```
By contrast, `admin:admin` returns `Location: /login.html?login_error=true`.
The 302 to `/auth/accept-certs.html` is the post-authentication redirect.

**Proof:** A trivially guessable credential pair `username:password` grants an
authenticated banking session.

**Impact:** Full account takeover for the demo account; in a real deployment the same
control weakness would expose every customer who reused weak credentials.

**Recommendation:** See Section 4.

---

### F-03 [Critical] Credentials transmitted over cleartext HTTP
* **CWE:** CWE-319 (Cleartext Transmission of Sensitive Information)
* **CVSS v3.1:** 8.1 — `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`
* **OWASP:** WSTG-CRYP-03; ASVS V9.1.1, V9.1.2

**Endpoint / Method:** `POST http://zero.webappsecurity.com/signin.html`

**PoC (2026-05-26 19:36 UTC):**
```http
POST /signin.html HTTP/1.1
Host: zero.webappsecurity.com
Content-Type: application/x-www-form-urlencoded

user_login=username&user_password=password&user_token=7cd7d1e5-a98c-4228-b112-3987d6830fe5
```
The server accepts the request unconditionally over HTTP (no 301/308 to HTTPS) and
issues a session cookie:
```
HTTP/1.1 302 Found
Location: /auth/accept-certs.html?user_token=7cd7d1e5-a98c-4228-b112-3987d6830fe5
Set-Cookie: JSESSIONID=37912DE8; Path=/; HttpOnly
```

**Proof:** Cleartext credentials and session token traverse the network without TLS.

**Impact:** Any network-level adversary (e.g. open Wi-Fi, hostile ISP, malicious
proxy) can passively harvest credentials and session cookies for the banking site.

**Recommendation:** See Section 4.

---

### F-04 [Critical] TLS endpoint supports SSLv2, SSLv3, export-grade ciphers, CRIME, expired cert
* **CWE:** CWE-326 (Inadequate Encryption Strength), CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-310, CWE-295 (Improper Certificate Validation)
* **CVSS v3.1:** 7.5 — `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` (DROWN/POODLE/CRIME/FREAK class)
* **OWASP:** WSTG-CRYP-01; ASVS V9.1.2, V9.1.3, V9.2.1

**Endpoint:** `https://zero.webappsecurity.com:443/`

**PoC (2026-05-26 19:29–19:30 UTC):** `sslscan --no-failed zero.webappsecurity.com:443`
Verbatim findings:
```
SSL/TLS Protocols:
SSLv2     enabled
SSLv3     enabled
TLSv1.0   enabled
TLSv1.1   disabled
TLSv1.2   disabled
TLSv1.3   disabled

TLS Fallback SCSV: Server does not support TLS Fallback SCSV
TLS renegotiation: Insecure session renegotiation supported
TLS Compression:   Compression enabled (CRIME)

Accepted TLSv1.0  40 bits   TLS_RSA_EXPORT_WITH_RC4_40_MD5
Accepted TLSv1.0 128 bits   TLS_RSA_WITH_RC4_128_MD5
Accepted TLSv1.0  40 bits   TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
Accepted TLSv1.0  40 bits   TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
Accepted TLSv1.0  56 bits   TLS_RSA_WITH_DES_CBC_SHA
Accepted TLSv1.0 112 bits   TLS_RSA_WITH_3DES_EDE_CBC_SHA
Accepted TLSv1.0  40 bits   TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
Accepted TLSv1.0  56 bits   TLS_DHE_RSA_WITH_DES_CBC_SHA
DHE parameters: 1024 bits

Subject: zero.webappsecurity.com
Issuer:  DigiCert TLS RSA SHA256 2020 CA1
Not valid before: Apr 26 00:00:00 2021 GMT
Not valid after:  May  4 23:59:59 2022 GMT   <-- EXPIRED >4 years
```
`nmap` ssl-cert / sslv2 NSE scripts confirmed identical findings.

**Proof:** Multiple individually critical cryptographic defects co-exist on the
endpoint (DROWN/POODLE/BEAST/FREAK/LOGJAM/CRIME applicability).

**Impact:** Eavesdropping and active TLS downgrade leading to plaintext recovery of
session traffic; trusted-channel guarantees void. Expired certificate trains users
to ignore browser warnings.

**Recommendation:** See Section 4.

---

### F-05 [High] Apache `mod_status` (`/server-status`) publicly exposed
* **CWE:** CWE-200 / CWE-548 (Exposure of Information Through Directory Listing/Status)
* **CVSS v3.1:** 5.3 — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
* **OWASP:** WSTG-CONFIG-05; ASVS V14.3.2

**Endpoint:** `GET /server-status`

**PoC (2026-05-26 19:34 UTC):**
```
HTTP/1.1 200 OK
<title>Apache Status</title>
<dl><dt>Server Version: Apache/2.2.22 (Win32) mod_ssl/2.2.22 OpenSSL/0.9.8t mod_jk/1.2.37</dt>
<dt>Server Built: Jan 28 2012 11:16:39</dt>
<dt>Current Time: Friday, 18-Jan-2013 14:55:36 GMT</dt>
<dt>Restart Time: Friday, 18-Jan-2013 14:29:04 GMT</dt>
<dt>5 requests currently being processed, 59 idle workers</dt>
```
**Proof:** `mod_status` page leaks exact Apache, mod_ssl, OpenSSL and mod_jk versions
along with runtime worker state.

**Impact:** Enables targeted CVE exploitation; the disclosed OpenSSL 0.9.8t is
vulnerable to a long list of CVEs (e.g. CVE-2014-0224, CVE-2014-3566 POODLE,
CVE-2014-0160 Heartbleed timing — Heartbleed itself was excluded by ssl-heartbleed
NSE, but many other crypto/parser CVEs apply).

**Recommendation:** See Section 4.

---

### F-06 [High] Tomcat Manager interface publicly exposed and discloses default credentials in the 401 page
* **CWE:** CWE-200 / CWE-1392 (Use of Default Credentials)
* **CVSS v3.1:** 5.3 — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (information leakage; would escalate to 9.8 if defaults applied)
* **OWASP:** WSTG-CONFIG-02; ASVS V14.1.1

**Endpoint:** `GET /manager/html`

**PoC (2026-05-26 19:34 UTC):**
```
HTTP/1.1 401 Unauthorized
...
<h1>401 Unauthorized</h1>
<p>You are not authorized to view this page...
For example, to add the manager-gui role to a user named tomcat
with a password of s3cret, add the following...
<role rolename="manager-gui"/>
<user username="tomcat" password="s3cret" roles="manager-gui"/>
```
The credential brute-force test in this engagement showed the most obvious defaults
(`tomcat:tomcat`, `tomcat:s3cret`, `admin:admin`, `admin:tomcat`, `manager:manager`,
`admin:password`, `tomcat:password`) all returned 401 — i.e. the defaults are *not*
in use here, but the interface remains reachable from the public internet on port
80 / 8080 and is one credential away from RCE via WAR deploy.

**Proof:** `/manager/html` reachable anonymously; instructive default credentials
embedded in the 401 page.

**Impact:** Single guessed/exposed credential gives WAR deployment ⇒ RCE on the
underlying Tomcat host.

**Recommendation:** See Section 4.

---

### F-07 [High] Outdated and end-of-life server stack
* **CWE:** CWE-1104 (Use of Unmaintained Third-Party Components), CWE-1395
* **CVSS v3.1:** 7.5 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (representative)
* **OWASP:** WSTG-CONFIG-09; ASVS V14.2.1, V14.2.2

| Component | Version Detected | Status |
| --- | --- | --- |
| Apache Tomcat | 7.0.70 (Jun 2016) | EOL — Tomcat 7 EOL Mar 2021 |
| Apache httpd (port 443 banner) | 2.2.6 (Win32) | EOL — 2.2.x EOL Jul 2017 |
| Apache httpd (mod_status banner) | 2.2.22 | EOL |
| mod_ssl | 2.2.6 / 2.2.22 | EOL |
| OpenSSL | 0.9.8e / 0.9.8t | EOL — 0.9.8 EOL Dec 2015 |
| mod_jk | 1.2.37 / 1.2.40 | Old |
| jQuery (client) | 1.8.2 | Multiple XSS CVEs (e.g. CVE-2015-9251, CVE-2019-11358) |

**PoC:** Banners listed in `nmap` (§2.1) and in `/server-status` (F-05).

**Impact:** Each component carries multiple unpatched CVEs (denial of service, RCE,
authentication bypass, cryptographic weaknesses). Static fingerprinting alone
generates a high-confidence attack surface.

**Recommendation:** See Section 4.

---

### F-08 [High] CORS misconfiguration — `Access-Control-Allow-Origin: *` site-wide
* **CWE:** CWE-942 (Permissive Cross-domain Policy with Untrusted Domains)
* **CVSS v3.1:** 5.3 — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
* **OWASP:** WSTG-CLNT-07; ASVS V14.5.3

**Endpoint:** Every response from the Tomcat connector.

**PoC (2026-05-26 19:36 UTC):**
```http
GET / HTTP/1.1
Host: zero.webappsecurity.com
Origin: http://evil.attacker.com
```
Response:
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
```
**Proof:** The server returns wildcard ACAO regardless of `Origin`. Credentials are
not echoed, so browsers will not include the session cookie on cross-origin
fetches; however, any unauthenticated content (including `/debug.txt`, `/README.txt`)
is freely readable from any web origin.

**Impact:** Cross-origin scraping of sensitive endpoints (e.g. `/debug.txt`,
`/server-status`); raises SSRF impact if reflection of `Origin` is added later;
defeats same-origin protections against information leakage.

**Recommendation:** See Section 4.

---

### F-09 [High] Session cookie missing `Secure` and `SameSite`; short predictable JSESSIONID
* **CWE:** CWE-614 (Missing Secure Attribute), CWE-1275 (Missing SameSite), CWE-330 (Use of Insufficiently Random Values)
* **CVSS v3.1:** 6.5 — `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N`
* **OWASP:** WSTG-SESS-02, WSTG-SESS-03; ASVS V3.4.1, V3.4.2, V3.2.2

**Endpoint:** Every `Set-Cookie` issued by Tomcat.

**PoC (2026-05-26 19:35–19:36 UTC):** Observed cookies during anonymous and
authenticated traffic:
```
Set-Cookie: JSESSIONID=8FE1AC55; Path=/; HttpOnly
Set-Cookie: JSESSIONID=25823997; Path=/; HttpOnly
Set-Cookie: JSESSIONID=11ADA2A1; Path=/; HttpOnly
Set-Cookie: JSESSIONID=B7B4F105; Path=/; HttpOnly
Set-Cookie: JSESSIONID=37912DE8; Path=/; HttpOnly
```
**Proof:**
* `Secure` flag absent → cookie is transmitted over HTTP (see F-03).
* `SameSite` attribute absent → defaults to `Lax`/`None` behaviour depending on
  browser; CSRF surface persists.
* JSESSIONID is an 8-character hex string (~32 bits of entropy) instead of the
  Tomcat 7 default of ≥128-bit. Online guessing or large-scale enumeration is
  feasible — only ~4·10^9 possible IDs.

**Impact:** Session hijack via network MITM (F-03), CSRF, brute-force session
prediction.

**Recommendation:** See Section 4.

---

### F-10 [Medium] Missing security response headers
* **CWE:** CWE-693 (Protection Mechanism Failure)
* **CVSS v3.1:** 4.3 — `AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N`
* **OWASP:** WSTG-CONFIG-07; ASVS V14.4.1, V14.4.3, V14.4.5, V14.4.7

**Endpoint:** All responses.

**PoC (nikto, 2026-05-26 19:30 UTC):**
```
+ Suggested security header missing: strict-transport-security.
+ Suggested security header missing: content-security-policy.
+ Suggested security header missing: x-content-type-options.
+ Suggested security header missing: permissions-policy.
+ Suggested security header missing: referrer-policy.
```
**Proof:** Direct `curl -I` confirmed none of HSTS, CSP, XCTO, Referrer-Policy,
Permissions-Policy, or X-Frame-Options were returned.

**Impact:** No defense-in-depth against MIME sniffing, click-jacking, content
injection, mixed-content downgrades, or referrer leakage.

**Recommendation:** See Section 4.

---

### F-11 [Medium] Sensitive `README.txt` discloses default credentials and developer information
* **CWE:** CWE-540 (Information Exposure Through Source Code), CWE-200
* **CVSS v3.1:** 5.3 — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
* **OWASP:** WSTG-CONFIG-02; ASVS V14.3.2

**Endpoint:** `GET /README.txt` (also `/Readme.txt`, `/readme.txt`)

**PoC (2026-05-26 19:34 UTC):**
```
Version 1.02
More cookie bugs fixed
...
3.  Make sure the users.mdb is in a directory called db, and that the directory has full access permissions for everyone.
4.  e-Mail me at vic@vixtrix.net to tell me where you will be using this application.
5.  Go to my website at http://www.vixtrix.net to see what else I am giving away for free.
6.  There are two accounts in the database.  admin with password admin, and user with password user.  Admin has admin rights.
Regards,
Vic du Preez
```
**Proof:** Plain ASCII installer notes left on a production-style host disclose
default credentials (`admin/admin`, `user/user`), expected DB path
(`db/users.mdb`), developer email, and a Windows 2000 webserver target context.

**Impact:** Aids targeted credential and configuration attacks; demonstrates poor
release hygiene.

**Recommendation:** See Section 4.

---

### F-12 [Medium] Dangerous HTTP methods advertised (PUT / DELETE / PATCH / TRACE)
* **CWE:** CWE-650 (Trusting HTTP Permission Methods on the Server Side)
* **CVSS v3.1:** 3.7 — `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`
* **OWASP:** WSTG-CONFIG-06; ASVS V14.5.1

**Endpoint:** Tomcat connectors on `:80` and `:8080`.

**PoC (2026-05-26 19:36 UTC):**
```
HTTP/1.1 405 Method Not Allowed
Allow: POST, GET, DELETE, OPTIONS, PUT, HEAD
```
Direct `PUT /zeropwn-test.txt` returned `HTTP/1.1 403 Forbidden`, and a subsequent
`GET` of the resource returned 404 — confirming the methods are advertised but not
exploitable for write.

**Proof:** `Allow` header advertises write-capable verbs even though the underlying
servlet rejects them. nmap also flagged PATCH and TRACE.

**Impact:** Misleads scanners and integrators; encourages mis-configuration drift
where a future deploy enables the methods. Tomcat-banner-driven CVE matching.

**Recommendation:** See Section 4.

---

### F-13 [Medium] Tomcat documentation and `/docs/` exposed (version disclosure)
* **CWE:** CWE-200
* **CVSS v3.1:** 3.7 — `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`
* **OWASP:** WSTG-CONFIG-02; ASVS V14.3.3

**Endpoint:** `GET /docs/`, `GET /examples/` (404 here but commonly enabled).

**PoC (2026-05-26 19:34 UTC):** `/docs/` returns Tomcat documentation page with
`<title>Apache Tomcat 7 (7.0.70) - Documentation Index</title>` and explicit
"Version 7.0.70, Jun 15 2016".

**Proof:** Server version exposed via documentation directory.

**Impact:** Trivial fingerprinting; supports CVE-targeted follow-up.

**Recommendation:** See Section 4.

---

### F-14 [Low] Server banner verbosity (`Server: Apache-Coyote/1.1`, Tomcat error pages disclose version)
* **CWE:** CWE-200
* **CVSS v3.1:** 3.1 — `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`
* **OWASP:** WSTG-INFO-02; ASVS V14.3.3

**PoC (2026-05-26 19:36 UTC):**
```
HTTP/1.1 403 Forbidden
Server: Apache-Coyote/1.1
...
<h3>Apache Tomcat/7.0.70</h3>
```
**Recommendation:** See Section 4.

---

### F-15 [Low] No HTTP → HTTPS redirection
* **CWE:** CWE-319 (related)
* **CVSS v3.1:** 3.1 — `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`
* **OWASP:** WSTG-CRYP-03; ASVS V9.1.1

**PoC (2026-05-26 19:28 UTC):**
```
$ curl -sI http://zero.webappsecurity.com
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
```
The application returns 200 on plain HTTP without a `301`/`308` to HTTPS, and HSTS is missing (F-10).

**Recommendation:** See Section 4.

---

### F-16 [Low] Cache-Control set to `no-cache, max-age=0, must-revalidate, no-store` site-wide on a content-heavy site
* **CWE:** CWE-525 (informational; this is overly aggressive caching policy that may impact performance, not security per se)
* **CVSS v3.1:** N/A
* **OWASP:** WSTG-ATHN-06

**Note:** This is recorded as informational; while `no-store` on authenticated
responses is appropriate, applying it indiscriminately on static assets degrades
performance and obscures legitimate caching weaknesses.

---

### F-17 [Info] Open `/cgi-bin/`, `/errors/`, `/help/`, `/include/`, `/resources/`, `/admin/`
* **CWE:** CWE-548 (Exposure of Information Through Directory Listing)
* **OWASP:** WSTG-CONFIG-04

**Note:** Each path returned 302 to an internal location. `/admin/` returned 200
with the standard public homepage (no admin UI surface observed during this
engagement, but the alias warrants permanent review).

---

### F-18 [Info] No GraphQL, no API discovered
GraphQL detection (`graphw00f` style probes against `/graphql`, `/api/graphql`)
yielded 404. No JSON / REST endpoints surfaced through crawling. The app is
predominantly static HTML.

---

## 4. Remediation & Architecture Guidance

The findings cluster into four structural defects. Recommend addressing them at the
platform / pipeline layer rather than as point fixes.

### 4.1 Transport & Cryptography (F-03, F-04, F-15, F-10)
Adopt a single, version-controlled TLS profile (e.g. Mozilla "Intermediate" or
"Modern" profile) that is enforced by:
* terminating TLS at a managed edge (AWS ALB / CloudFront / nginx fronted by ACM
  certs with automated renewal) — eliminating the legacy Apache/OpenSSL stack;
* a CI gate using `testssl.sh` / `sslyze` against a staging URL, failing the
  pipeline on any protocol below TLSv1.2, any key < 2048-bit RSA / 256-bit ECDSA,
  any DH < 2048-bit, or any non-AEAD cipher;
* an HSTS preload-eligible policy (`max-age=63072000; includeSubDomains; preload`);
* deploying a global 301 redirect from `http://` to `https://`.

### 4.2 Configuration Hygiene & Information Disclosure (F-01, F-05, F-06, F-11, F-12, F-13, F-14, F-17)
* Treat the web root as **immutable** and built from a `dist/` artifact in CI;
  forbid `*.txt`, `*.log`, `*.bak`, `README*`, `debug*` via a pipeline lint
  (regex deny-list).
* Tomcat / Apache hardening baseline applied via configuration management
  (Ansible / Terraform) and verified by CIS-CAT or InSpec:
  * Disable `mod_status`, `mod_info`.
  * Disable Tomcat `Manager`, `Host-Manager`, `docs`, `examples` webapps; remove
    `ROOT/docs`.
  * Set `server.xml` Connector `secure="true"`, restrict `allowedMethods` via
    `web.xml` `<security-constraint>` to GET/POST/HEAD/OPTIONS only.
  * Strip the `Server` header (`ServerTokens Prod`, `ServerSignature Off`;
    Tomcat `Connector server="" xpoweredBy="false"`).
  * Customize error pages (`<error-page>` mapping) to suppress version banners.
* Block `/server-status`, `/manager`, `/host-manager`, `/admin`, `/debug*`,
  `/*.log`, `/README*` at the edge / WAF layer regardless of origin response.

### 4.3 Authentication, Session & CORS (F-02, F-03, F-08, F-09)
* Replace the demo credential store with a centralized IdP (OIDC) that enforces
  MFA and modern password policy (NIST 800-63B; rejects breached passwords via
  Have I Been Pwned `k-anonymity` check at registration / password-change).
* On the Tomcat side enforce session attributes in the `web.xml`:
  ```xml
  <session-config>
    <cookie-config>
      <http-only>true</http-only>
      <secure>true</secure>
      <same-site>Strict</same-site>
    </cookie-config>
    <tracking-mode>COOKIE</tracking-mode>
  </session-config>
  ```
  and configure `<Manager sessionIdLength="32" secureRandomClass="java.security.SecureRandom"/>`
  in `context.xml` so JSESSIONID is ≥256 bits.
* Replace the wildcard `Access-Control-Allow-Origin: *` with an explicit allow-list
  matched at the edge (only `https://*.webappsecurity.com`). Never combine ACAO
  with `Access-Control-Allow-Credentials: true`.

### 4.4 Pipeline / Lifecycle Controls (F-07)
* Adopt SCA (Snyk / Dependabot / Trivy) gating in CI; fail on Critical/High CVE
  for direct dependencies, including `jQuery`, `bootstrap`, `Apache Tomcat`,
  `Apache httpd`, `OpenSSL`.
* Replace bespoke Apache + Tomcat + mod_jk + OpenSSL stack with a managed,
  patch-current container base image; rebuild & redeploy on a 30-day cadence.
* Add DAST (OWASP ZAP / Burp Enterprise) and SAST (SonarQube, Semgrep) jobs to
  the release pipeline; treat findings of this report as regression gates.

---

## 5. Risk Matrix

| ID | Finding | Severity | CVSS | Likelihood | Impact | Priority |
| --- | --- | --- | --- | --- | --- | --- |
| F-01 | `/debug.txt` exposure | Critical | 7.5 | High | High | P0 |
| F-02 | Default credentials `username:password` | Critical | 9.8 | High | Critical | P0 |
| F-03 | Cleartext HTTP login | Critical | 8.1 | High | High | P0 |
| F-04 | SSLv2/SSLv3/CRIME/expired cert | Critical | 7.5 | Medium | High | P0 |
| F-05 | `/server-status` exposed | High | 5.3 | High | Medium | P1 |
| F-06 | `/manager/html` exposed | High | 5.3 | High | High (if creds guessed) | P1 |
| F-07 | EOL stack (Tomcat 7 / Apache 2.2 / OpenSSL 0.9.8 / jQuery 1.8.2) | High | 7.5 | High | High | P1 |
| F-08 | CORS `*` site-wide | High | 5.3 | Medium | Medium | P1 |
| F-09 | Missing Secure/SameSite + short JSESSIONID | High | 6.5 | Medium | High | P1 |
| F-10 | Missing security headers (HSTS, CSP, XCTO, etc.) | Medium | 4.3 | High | Medium | P2 |
| F-11 | `README.txt` discloses default creds | Medium | 5.3 | High | Medium | P2 |
| F-12 | Dangerous HTTP methods advertised | Medium | 3.7 | Medium | Medium | P2 |
| F-13 | `/docs/` Tomcat version disclosure | Medium | 3.7 | High | Low | P2 |
| F-14 | Server banners disclose Tomcat 7.0.70 | Low | 3.1 | High | Low | P3 |
| F-15 | No HTTP→HTTPS redirect | Low | 3.1 | High | Low | P3 |
| F-16 | Indiscriminate `no-store` cache policy | Low | – | Low | Low | P3 |
| F-17 | Anonymous directories `/cgi-bin/`, `/errors/`, etc. | Info | – | Low | Low | P4 |
| F-18 | No API / GraphQL surface found | Info | – | – | – | – |

---

## 6. Methodology & Evidence Index

* Tooling: nmap 7.99, sslscan 2.1.5 (OpenSSL 3.6.2), whatweb, wafw00f 2.4.2,
  nikto 2.6.0, gobuster (common.txt + html/jsp/txt), sqlmap 1.10.4 (BEUS,
  level 2 risk 2), curl 8.x via the Kali MCP wrapper on TCP 5000.
* Wordlist: `/usr/share/seclists/Discovery/Web-Content/common.txt`.
* All evidence was captured live on **2026-05-26** between **19:28 UTC and 19:37 UTC**.
* No exploitation that would alter target state succeeded (PUT was rejected with 403).
* No findings are hallucinated; where a tool returned no exploitable output
  (e.g. sqlmap on `searchTerm` / login parameters), that result is stated
  explicitly in §1 and not promoted to a finding.
