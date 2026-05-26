# zero.webappsecurity.com - Penetration Test Report

**Report Generated:** 2026-05-26  
**Target:** http://zero.webappsecurity.com  
**Assessment Type:** Full Penetration Test  
**Assessor:** AI Security Agent  

---

## Executive Summary

A comprehensive penetration test was conducted against http://zero.webappsecurity.com, a demonstration banking application by Micro Focus Fortify. The assessment revealed **multiple critical and high-severity vulnerabilities** that would allow an attacker to gain unauthorized access to sensitive data and administrative functionality.

### Key Findings Summary

| Severity | Count |
|----------|-------|
| Critical | 3 |
| High | 4 |
| Medium | 3 |
| Low | 2 |
| Info | 3 |

### Risk Rating: **CRITICAL**

Immediate remediation is required. The combination of unrestricted admin panel access, exposed sensitive endpoints, and outdated cryptographic protocols creates severe security risks.

---

## Target Information

- **URL:** http://zero.webappsecurity.com
- **IP Address:** 54.82.22.214 (AWS EC2)
- **Technology Stack:**
  - Web Server: Apache Tomcat/Coyote JSP engine 1.1
  - Secondary Server: Apache httpd 2.2.6 (Windows)
  - Framework: Bootstrap
  - JavaScript: jQuery 1.8.2 (outdated)
  - SSL/TLS: mod_ssl/2.2.6 OpenSSL/0.9.8e

---

## Reconnaissance Results

### Open Ports

| Port | Service | Version |
|------|---------|---------|
| 80/tcp | HTTP | Apache Tomcat/Coyote JSP engine 1.1 |
| 443/tcp | HTTPS | Apache httpd 2.2.6 (Win32) mod_ssl/2.2.6 OpenSSL/0.9.8e |

### Discovered Endpoints

| Endpoint | Status | Description |
|----------|--------|-------------|
| `/admin/` | 200 OK | Administrative panel (UNPROTECTED) |
| `/admin/users.html` | 200 OK | User management with credentials exposed |
| `/admin/currencies.html` | 200 OK | Currency management |
| `/admin/currencies-add.html` | 200 OK | Add currency form |
| `/server-status` | 200 OK | Apache mod_status exposed |
| `/readme.txt` | 200 OK | Documentation file |
| `/login.html` | 200 OK | Authentication page |
| `/feedback.html` | 200 OK | Contact form |
| `/forgot-password.html` | 200 OK | Password reset |
| `/online-banking.html` | 200 OK | Banking portal |

---

## Detailed Findings

### CRITICAL - 1: Unauthenticated Admin Panel Access

**CWE:** CWE-306 (Missing Authentication for Critical Function)  
**CVSS v3.1:** 9.8 (Critical) - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`  
**OWASP WSTG:** WSTG-ATHN-01 (Testing for Credentials Transported over an Encrypted Channel)  
**OWASP ASVS:** ASVS V2.1.1

**Endpoint:** `GET /admin/`

**Proof of Concept:**
```
Timestamp: 2026-05-26 18:28:42 UTC
Request: GET http://zero.webappsecurity.com/admin/ HTTP/1.1
Host: zero.webappsecurity.com

Response: HTTP/1.1 200 OK
Content-Type: text/html;charset=UTF-8

<!DOCTYPE html>
<html lang="en">
<head>
    <title>Zero - Admin - Home</title>
...
```

**Evidence:** The admin panel at `/admin/` is accessible without any authentication. All administrative functionality including user management and currency configuration is exposed to unauthenticated attackers.

**Impact:** Complete compromise of administrative functionality. Attackers can view, modify, or delete sensitive data including user credentials.

**Recommendation:**
- Implement robust authentication and authorization controls for all administrative endpoints
- Deploy role-based access control (RBAC)
- Consider implementing multi-factor authentication for admin access
- Add IP-based access restrictions for admin panels

---

### CRITICAL - 2: Sensitive User Data Exposure

**CWE:** CWE-200 (Information Exposure)  
**CVSS v3.1:** 9.1 (Critical) - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H`  
**OWASP WSTG:** WSTG-INFO-03 (Testing for Information Leakage Through Error Messages)  
**OWASP ASVS:** ASVS V6.1.1

**Endpoint:** `GET /admin/users.html`

**Proof of Concept:**
```
Timestamp: 2026-05-26 18:29:15 UTC
Request: GET http://zero.webappsecurity.com/admin/users.html HTTP/1.1

Response contains user table:
<table class="table">
    <thead>
        <tr>
            <th>Name</th>
            <th>Password</th>
            <th>SSN</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>Leeroy Jenkins</td>
            <td>VIZ10AWT8VL</td>
            <td>536-48-3769</td>
        </tr>
        <tr>
            <td>Stephen Bowen</td>
            <td>OTZ07BXM0BE</td>
            <td>607-58-7435</td>
        </tr>
        ... (6 more users)
    </tbody>
</table>
```

**Evidence:** The user management page displays plaintext passwords and Social Security Numbers for all users in an unprotected HTML table.

**Exposed Credentials:**
| Username | Password | SSN |
|----------|----------|-----|
| Leeroy Jenkins | VIZ10AWT8VL | 536-48-3769 |
| Stephen Bowen | OTZ07BXM0BE | 607-58-7435 |
| Linus Moran | FKO04SXA7TI | 247-54-1719 |
| Nero Chan | TXJ77CQO5EI | 578-13-3713 |
| Kadeem Higgins | MFC50OQE7VO | 449-20-3206 |
| Quinn Burks | HWZ97ZUM3NK | 008-70-6738 |
| Davis Thompson | RGD78SHB0TG | 574-56-1932 |
| Lester Keller | EIJ79NLT0TP | 330-58-4012 |

**Impact:** Complete identity theft potential. Attackers can use these credentials to access user accounts and commit fraud using exposed SSNs.

**Recommendation:**
- Never display passwords in plaintext, even hashed passwords should not be visible
- Implement proper access controls requiring authentication
- Mask or redact sensitive PII (SSN) in all interfaces
- Encrypt sensitive data at rest and in transit

---

### CRITICAL - 3: SSLv2 Support with Weak Ciphers

**CWE:** CWE-326 (Inadequate Encryption Strength)  
**CVSS v3.1:** 9.1 (Critical) - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H`  
**OWASP WSTG:** WSTG-CRYP-01 (Testing for Weak Transport Layer Security)  
**OWASP ASVS:** ASVS V8.3.1

**Endpoint:** `tcp/443`

**Proof of Concept:**
```
Timestamp: 2026-05-26 18:27:30 UTC
Nmap Output:
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
```

**Evidence:** The server supports the deprecated SSLv2 protocol with multiple weak cipher suites including export-grade encryption (40-bit) and RC4.

**Impact:** Man-in-the-middle attacks possible. SSLv2 has known cryptographic weaknesses allowing decryption of encrypted traffic.

**Recommendation:**
- Disable SSLv2 and SSLv3 completely
- Disable TLS 1.0 and 1.1; use only TLS 1.2 and 1.3
- Remove all weak cipher suites
- Implement perfect forward secrecy (PFS)

---

### HIGH - 4: Apache mod_status Information Disclosure

**CWE:** CWE-200 (Information Exposure)  
**CVSS v3.1:** 7.5 (High) - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`  
**OWASP WSTG:** WSTG-INFO-01 (Testing for Information Leakage Through Server Responses)  
**OWASP ASVS:** ASVS V6.1.3

**Endpoint:** `GET /server-status`

**Proof of Concept:**
```
Timestamp: 2026-05-26 18:28:55 UTC
Request: GET http://zero.webappsecurity.com/server-status HTTP/1.1

Response:
<h1>Apache Server Status for localhost</h1>
<dl>
    <dt>Server Version: Apache/2.2.22 (Win32) mod_ssl/2.2.22 OpenSSL/0.9.8t mod_jk/1.2.37</dt>
    <dt>Server uptime:  26 minutes 31 seconds</dt>
    <dt>5 requests currently being processed, 59 idle workers</dt>
</dl>
```

**Evidence:** The Apache mod_status module is publicly accessible, revealing server configuration, active connections, and worker process details.

**Impact:** Information disclosure aids attackers in planning targeted attacks. Can reveal internal IP addresses and application paths.

**Recommendation:**
- Disable mod_status in production or restrict access to localhost only
- Use `<Location /server-status>` directives with IP restrictions
- Enable ExtendedStatus only when required for debugging

---

### HIGH - 5: Dangerous HTTP Methods Enabled

**CWE:** CWE-749 (Exposed Dangerous Method or Function)  
**CVSS v3.1:** 7.3 (High) - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L`  
**OWASP WSTG:** WSTG-CONF-04 (Testing for Old or Backup Files)  
**OWASP ASVS:** ASVS V5.1.1

**Endpoint:** `OPTIONS /`

**Proof of Concept:**
```
Timestamp: 2026-05-26 18:27:15 UTC
Nikto Output:
[999990] OPTIONS: Allowed HTTP Methods: GET, HEAD, POST, PUT, DELETE, TRACE, OPTIONS, PATCH

[400001] HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
[400000] HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
[400004] HTTP method: 'PATCH' may allow client to issue patch commands to server.
```

**Evidence:** The server allows dangerous HTTP methods including PUT, DELETE, TRACE, and PATCH without apparent restrictions.

**Impact:** 
- PUT/DELETE: Potential for unauthorized file upload/deletion
- TRACE: Cross-site tracing (XST) attacks possible

**Recommendation:**
- Disable unnecessary HTTP methods in web server configuration
- Restrict to GET, HEAD, POST only where possible
- Implement proper authentication for any state-changing methods

---

### HIGH - 6: Outdated jQuery Library (XSS Risk)

**CWE:** CWE-1104 (Use of Unmaintained Third Party Components)  
**CVSS v3.1:** 6.5 (Medium-High) - `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N`  
**OWASP WSTG:** WSTG-ATHZ-01 (Testing for Directory Listing)  
**OWASP ASVS:** ASVS V6.4.1

**Endpoint:** `/resources/js/jquery-1.8.2.min.js`

**Proof of Concept:**
```
Timestamp: 2026-05-26 18:25:45 UTC
WhatWeb Output:
JQuery[1.8.2]

Nmap Output:
|_http-title: Zero - Personal Banking - Loans - Credit Cards
```

**Evidence:** The application uses jQuery 1.8.2, released in 2012. This version has multiple known XSS vulnerabilities (CVE-2015-9251, CVE-2019-11358, CVE-2020-11966).

**Impact:** Known XSS vulnerabilities in this jQuery version could allow attackers to execute arbitrary JavaScript in user browsers.

**Recommendation:**
- Update jQuery to the latest stable version (3.7.x or later)
- Implement Content Security Policy (CSP) headers
- Use Subresource Integrity (SRI) for CDN-hosted libraries

---

### HIGH - 7: Password Reset without Email Verification

**CWE:** CWE-640 (Weak Password Recovery Mechanism for Forgotten Password)  
**CVSS v3.1:** 6.5 (High) - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`  
**OWASP WSTG:** WSTG-ATHN-04 (Testing for Bypassing Authentication Schema)  
**OWASP ASVS:** ASVS V2.6.1

**Endpoint:** `POST /forgotten-password-send.html`

**Proof of Concept:**
```
Timestamp: 2026-05-26 18:36:22 UTC
Request: POST /forgotten-password-send.html HTTP/1.1
Content-Type: application/x-www-form-urlencoded

email=test@example.com

Response: Your password will be sent to the following email: test@example.com
```

**Evidence:** The password reset functionality accepts any email address without verification and claims to send passwords via email.

**Impact:** Potential for account enumeration and password interception if emails are actually sent.

**Recommendation:**
- Implement email verification before password reset
- Use time-limited reset tokens instead of sending passwords
- Add rate limiting to prevent abuse

---

### MEDIUM - 8: Missing Security Headers

**CWE:** CWE-693 (Protection Mechanism Failure)  
**CVSS v3.1:** 5.3 (Medium) - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`  
**OWASP WSTG:** WSTG-INFO-05 (Testing for Information Leakage Through HTTP Headers)  
**OWASP ASVS:** ASVS V5.1.2

**Endpoint:** All endpoints

**Proof of Concept:**
```
Timestamp: 2026-05-26 18:26:59 UTC
Nikto Output:
[013587] /: Suggested security header missing: content-security-policy
[013587] /: Suggested security header missing: permissions-policy
[013587] /: Suggested security header missing: x-content-type-options
[013587] /: Suggested security header missing: strict-transport-security
[013587] /: Suggested security header missing: referrer-policy
```

**Evidence:** The application is missing critical security headers that protect against common web vulnerabilities.

**Impact:** Increased susceptibility to XSS, clickjacking, MIME-type sniffing, and other client-side attacks.

**Recommendation:**
Add the following headers:
```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

---

### MEDIUM - 9: Expired SSL Certificate

**CWE:** CWE-324 (Use of a Key Past its Expiration Date)  
**CVSS v3.1:** 4.3 (Medium) - `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N`  
**OWASP WSTG:** WSTG-CRYP-01 (Testing for Weak Transport Layer Security)  
**OWASP ASVS:** ASVS V8.3.2

**Endpoint:** `tcp/443`

**Proof of Concept:**
```
Timestamp: 2026-05-26 18:27:30 UTC
Nmap Output:
| ssl-cert: Subject: commonName=zero.webappsecurity.com
| Not valid before: 2021-04-26T00:00:00
|_Not valid after:  2022-05-04T23:59:59
```

**Evidence:** The SSL certificate expired on May 4, 2022. Current date is May 26, 2026.

**Impact:** Users may see security warnings, and MITM attacks are easier against expired certificates.

**Recommendation:**
- Renew SSL certificate immediately
- Implement automated certificate renewal (e.g., Let's Encrypt with auto-renewal)
- Monitor certificate expiration dates

---

### MEDIUM - 10: CORS Misconfiguration

**CWE:** CWE-942 (Permissive Cross-domain Policy with Untrusted Domains)  
**CVSS v3.1:** 4.3 (Medium) - `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N`  
**OWASP WSTG:** WSTG-INFO-05 (Testing for Information Leakage Through HTTP Headers)  
**OWASP ASVS:** ASVS V5.1.3

**Endpoint:** All endpoints

**Proof of Concept:**
```
Timestamp: 2026-05-26 18:26:59 UTC
Nikto Output:
[999986] /: Retrieved access-control-allow-origin header: *.
```

**Evidence:** The `Access-Control-Allow-Origin: *` header allows any domain to make cross-origin requests.

**Impact:** Potential for data exfiltration via malicious websites if authentication is used.

**Recommendation:**
- Restrict CORS to specific trusted domains
- Remove wildcard (*) Access-Control-Allow-Origin
- Implement proper origin validation

---

### LOW - 11: readme.txt Information Disclosure

**CWE:** CWE-200 (Information Exposure)  
**CVSS v3.1:** 3.7 (Low) - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`  
**OWASP WSTG:** WSTG-INFO-03 (Testing for Information Leakage)  
**OWASP ASVS:** ASVS V6.1.2

**Endpoint:** `GET /readme.txt`

**Evidence:** Documentation file reveals application structure and default credentials (admin/admin, user/user).

**Recommendation:** Remove documentation files from production servers.

---

### LOW - 12: Server Version Disclosure

**CWE:** CWE-200 (Information Exposure)  
**CVSS v3.1:** 3.7 (Low) - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`  
**OWASP WSTG:** WSTG-INFO-01 (Testing for Information Leakage)  
**OWASP ASVS:** ASVS V6.1.1

**Evidence:** Server banners reveal exact versions of Apache, Tomcat, and OpenSSL.

**Recommendation:** Configure servers to suppress version information in headers and error pages.

---

### INFO - 13: XSS Test Results

**Endpoint:** `GET /search.html?searchTerm=<script>alert('XSS')</script>`

**Result:** Input appears to be properly HTML-encoded (`&lt;script&gt;`), indicating XSS protection is in place for this endpoint.

---

### INFO - 14: SQL Injection Test Results

**Endpoint:** `POST /search.html` and `POST /admin/currencies-add.html`

**Result:** SQLmap testing found no injectable parameters after comprehensive testing of boolean-based, error-based, time-based, and UNION-based injection techniques.

---

### INFO - 15: Application Architecture

The target is a demonstration banking application created by Micro Focus Fortify for WebInspect product demonstration purposes. This is confirmed by the disclaimer present on all pages stating the site is not a real banking site.

---

## Risk Matrix

| Finding ID | Severity | CVSS Score | Remediation Priority |
|------------|----------|------------|---------------------|
| 1 | Critical | 9.8 | Immediate |
| 2 | Critical | 9.1 | Immediate |
| 3 | Critical | 9.1 | Immediate |
| 4 | High | 7.5 | High |
| 5 | High | 7.3 | High |
| 6 | High | 6.5 | High |
| 7 | High | 6.5 | High |
| 8 | Medium | 5.3 | Medium |
| 9 | Medium | 4.3 | Medium |
| 10 | Medium | 4.3 | Medium |
| 11 | Low | 3.7 | Low |
| 12 | Low | 3.7 | Low |

---

## Remediation Roadmap

### Immediate (0-7 days)
1. Implement authentication for all `/admin/*` endpoints
2. Remove or protect sensitive data exposure in user management
3. Disable SSLv2 and weak ciphers
4. Restrict access to `/server-status`

### Short-term (1-4 weeks)
5. Update jQuery to latest version
6. Implement security headers
7. Renew SSL certificate
8. Configure CORS properly
9. Disable dangerous HTTP methods

### Medium-term (1-3 months)
10. Implement comprehensive input validation
11. Deploy Web Application Firewall (WAF)
12. Establish security monitoring and logging
13. Conduct code review for additional vulnerabilities

---

## Testing Methodology

This assessment followed industry-standard penetration testing methodologies including:
- OWASP Testing Guide v4 (WSTG)
- OWASP Application Security Verification Standard v4 (ASVS)
- NIST SP 800-115 Technical Guide to Information Security Testing

### Tools Used
- Nmap (port scanning)
- Nikto (web vulnerability scanner)
- WhatWeb (technology fingerprinting)
- WAFW00F (WAF detection)
- SQLmap (SQL injection testing)
- Curl (manual HTTP requests)

---

## Conclusion

The penetration test revealed significant security vulnerabilities in the target application. The most critical issues relate to **complete lack of authentication for administrative functions** and **exposure of sensitive user data including plaintext passwords and SSNs**. These vulnerabilities, combined with weak cryptographic configurations, create a severe risk profile.

**Overall Risk Assessment: CRITICAL**

Immediate action is required to address the critical and high-severity findings before this application handles any real user data or is exposed to production traffic.

---

*Report generated by AI Security Agent*  
*For questions regarding this report, contact the security assessment team.*
