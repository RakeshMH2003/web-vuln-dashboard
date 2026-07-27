import requests
import ssl
import socket
import datetime
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

TIMEOUT = 10

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "High",
        "description": "Content-Security-Policy (CSP) header is missing. This allows attackers to inject malicious scripts into your pages (XSS attacks).",
        "fix": "Add 'Content-Security-Policy: default-src self;' to your server's HTTP response headers."
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "description": "X-Frame-Options header is missing. Your site can be embedded in iframes, enabling Clickjacking attacks.",
        "fix": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to your HTTP response headers."
    },
    "Strict-Transport-Security": {
        "severity": "High",
        "description": "HSTS (HTTP Strict Transport Security) header is missing. Browsers may connect over insecure HTTP.",
        "fix": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to your HTTPS response headers."
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "description": "X-Content-Type-Options header is missing. Browsers may MIME-sniff responses, leading to security issues.",
        "fix": "Add 'X-Content-Type-Options: nosniff' to your HTTP response headers."
    },
    "Referrer-Policy": {
        "severity": "Low",
        "description": "Referrer-Policy header is missing. Sensitive URL information may leak to third-party sites.",
        "fix": "Add 'Referrer-Policy: strict-origin-when-cross-origin' to your HTTP response headers."
    },
    "Permissions-Policy": {
        "severity": "Low",
        "description": "Permissions-Policy header is missing. Browser features like camera/microphone are not restricted.",
        "fix": "Add 'Permissions-Policy: geolocation=(), microphone=(), camera=()' to restrict browser feature access."
    }
}

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "javascript:alert(1)",
    "<img src=x onerror=alert(1)>",
]

SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "1; DROP TABLE users--",
    "' OR 1=1--",
]

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-01756", "unclosed quotation",
    "sqlite_error", "pg_query", "syntax error", "sql error",
    "database error", "odbc error", "microsoft ole db",
]

SENSITIVE_PATHS = [
    "/admin", "/admin/", "/backup", "/config",
    "/.env", "/wp-admin", "/phpmyadmin", "/.git",
    "/api/users", "/uploads", "/logs", "/debug"
]


def check_security_headers(url):
    findings = []
    try:
        response = requests.get(url, timeout=TIMEOUT, verify=False)
        headers = {k.lower(): v for k, v in response.headers.items()}

        for header, info in SECURITY_HEADERS.items():
            if header.lower() not in headers:
                findings.append({
                    "vuln_type": f"Missing Header: {header}",
                    "severity": info["severity"],
                    "description": info["description"],
                    "fix": info["fix"]
                })
    except Exception:
        pass
    return findings


def check_ssl(url):
    findings = []
    parsed = urlparse(url)
    hostname = parsed.hostname

    if parsed.scheme != "https":
        findings.append({
            "vuln_type": "No HTTPS",
            "severity": "Critical",
            "description": f"The site is served over HTTP, not HTTPS. All data transferred (including passwords and form data) is sent in plain text and can be intercepted.",
            "fix": "Configure your web server with a valid SSL/TLS certificate and redirect all HTTP traffic to HTTPS."
        })
        return findings

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(TIMEOUT)
            s.connect((hostname, 443))
            cert = s.getpeercert()

        expire_str = cert.get("notAfter", "")
        if expire_str:
            expire_date = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (expire_date - datetime.datetime.now(datetime.UTC).replace(tzinfo=None)).days
            if days_left < 0:
                findings.append({
                    "vuln_type": "SSL Certificate Expired",
                    "severity": "Critical",
                    "description": f"The SSL certificate expired {abs(days_left)} day(s) ago. Browsers will show a security warning to all visitors.",
                    "fix": "Renew your SSL certificate immediately. Services like Let's Encrypt offer free, auto-renewing certificates."
                })
            elif days_left < 30:
                findings.append({
                    "vuln_type": "SSL Certificate Expiring Soon",
                    "severity": "Medium",
                    "description": f"The SSL certificate expires in {days_left} day(s). If not renewed, visitors will see security warnings.",
                    "fix": "Renew your SSL certificate before it expires. Consider setting up auto-renewal."
                })
    except ssl.SSLError as e:
        findings.append({
            "vuln_type": "SSL Error",
            "severity": "Critical",
            "description": f"SSL/TLS error detected: {str(e)[:120]}. The connection is not secure.",
            "fix": "Check your server's SSL configuration. Ensure you're using TLS 1.2 or 1.3 and a valid certificate."
        })
    except Exception:
        pass

    return findings


def check_xss(url):
    findings = []
    try:
        response = requests.get(url, timeout=TIMEOUT, verify=False)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        for form in forms[:3]:
            action = form.get("action", url)
            method = form.get("method", "get").lower()
            full_action = urljoin(url, action)
            inputs = form.find_all("input")

            for payload in XSS_PAYLOADS[:2]:
                data = {}
                for inp in inputs:
                    name = inp.get("name")
                    if name:
                        data[name] = payload

                try:
                    if method == "post":
                        r = requests.post(full_action, data=data, timeout=TIMEOUT, verify=False)
                    else:
                        r = requests.get(full_action, params=data, timeout=TIMEOUT, verify=False)

                    if payload in r.text:
                        findings.append({
                            "vuln_type": "Reflected XSS",
                            "severity": "High",
                            "description": f"A form at '{full_action}' reflects user input without sanitization. An attacker could inject malicious JavaScript that executes in victims' browsers.",
                            "fix": "Sanitize and escape all user input before displaying it. Use a library like DOMPurify on the frontend and html.escape() in Python on the backend. Enable Content-Security-Policy headers."
                        })
                        return findings
                except Exception:
                    continue
    except Exception:
        pass
    return findings


def check_sqli(url):
    findings = []
    try:
        response = requests.get(url, timeout=TIMEOUT, verify=False)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        for form in forms[:3]:
            action = form.get("action", url)
            method = form.get("method", "get").lower()
            full_action = urljoin(url, action)
            inputs = form.find_all("input")

            for payload in SQLI_PAYLOADS[:2]:
                data = {}
                for inp in inputs:
                    name = inp.get("name")
                    if name:
                        data[name] = payload

                try:
                    if method == "post":
                        r = requests.post(full_action, data=data, timeout=TIMEOUT, verify=False)
                    else:
                        r = requests.get(full_action, params=data, timeout=TIMEOUT, verify=False)

                    response_lower = r.text.lower()
                    for err in SQLI_ERRORS:
                        if err in response_lower:
                            findings.append({
                                "vuln_type": "SQL Injection",
                                "severity": "Critical",
                                "description": f"A form at '{full_action}' appears vulnerable to SQL injection. Database error messages were returned in response to malformed input, exposing backend structure.",
                                "fix": "Use parameterized queries or prepared statements instead of string concatenation. Never expose raw database errors to users. Use an ORM like SQLAlchemy."
                            })
                            return findings
                except Exception:
                    continue
    except Exception:
        pass
    return findings


def check_sensitive_paths(url):
    findings = []
    exposed = []

    for path in SENSITIVE_PATHS:
        try:
            target = url.rstrip("/") + path
            r = requests.get(target, timeout=5, verify=False, allow_redirects=False)
            if r.status_code == 200:
                exposed.append(path)
        except Exception:
            continue

    if exposed:
        findings.append({
            "vuln_type": "Sensitive Paths Exposed",
            "severity": "High",
            "description": f"The following sensitive paths are publicly accessible: {', '.join(exposed)}. These may expose admin panels, configuration files, or source code.",
            "fix": "Restrict access to sensitive paths using server configuration (e.g., .htaccess or nginx rules). Require authentication for admin areas. Remove unused endpoints."
        })
    return findings


def check_cookies(url):
    findings = []
    try:
        response = requests.get(url, timeout=TIMEOUT, verify=False)
        for cookie in response.cookies:
            issues = []
            if not cookie.secure:
                issues.append("missing Secure flag")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("missing HttpOnly flag")
            if not cookie.has_nonstandard_attr("SameSite"):
                issues.append("missing SameSite attribute")

            if issues:
                findings.append({
                    "vuln_type": f"Insecure Cookie: {cookie.name}",
                    "severity": "Medium",
                    "description": f"Cookie '{cookie.name}' has security issues: {', '.join(issues)}. This can expose session tokens to theft via XSS or network interception.",
                    "fix": "Set cookies with Secure, HttpOnly, and SameSite=Strict flags. Example: Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Strict"
                })
    except Exception:
        pass
    return findings


def check_info_disclosure(url):
    findings = []
    try:
        response = requests.get(url, timeout=TIMEOUT, verify=False)
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        leaked = []
        if "server" in headers:
            leaked.append(f"Server: {headers['server']}")
        if "x-powered-by" in headers:
            leaked.append(f"X-Powered-By: {headers['x-powered-by']}")
        if "x-aspnet-version" in headers:
            leaked.append(f"X-AspNet-Version: {headers['x-aspnet-version']}")
            
        if leaked:
            findings.append({
                "vuln_type": "Information Disclosure",
                "severity": "Low",
                "description": f"The server leaks detailed version information in HTTP headers: {', '.join(leaked)}. Attackers can use this to find known vulnerabilities for these specific versions.",
                "fix": "Configure your web server and application frameworks to suppress version headers. For example, set 'server_tokens off' in Nginx or 'expose_php = Off' in php.ini."
            })
    except Exception:
        pass
    return findings


def check_sri(url):
    findings = []
    try:
        response = requests.get(url, timeout=TIMEOUT, verify=False)
        soup = BeautifulSoup(response.text, "html.parser")
        
        missing_sri = []
        for tag in soup.find_all(["script", "link"]):
            src = tag.get("src") or tag.get("href")
            # Only flag external resources loaded without integrity attribute
            if src and src.startswith("http") and not src.startswith(url):
                if not tag.has_attr("integrity"):
                    missing_sri.append(src)
                    
        if missing_sri:
            sample = missing_sri[0]
            count_msg = f" and {len(missing_sri)-1} other resources" if len(missing_sri) > 1 else ""
            findings.append({
                "vuln_type": "Missing Subresource Integrity (SRI)",
                "severity": "Medium",
                "description": f"External resources (e.g., '{sample}'{count_msg}) are loaded without an 'integrity' attribute. If the third-party CDN is compromised, attackers can execute malicious scripts on your site.",
                "fix": "Add the 'integrity' attribute with a cryptographic hash to all external <script> and <link> tags. Example: <script src='...' integrity='sha384-...' crossorigin='anonymous'></script>"
            })
    except Exception:
        pass
    return findings


def check_directory_listing(url):
    findings = []
    test_dirs = ["/images/", "/assets/", "/uploads/", "/css/", "/js/"]
    exposed = []
    
    for directory in test_dirs:
        try:
            target = url.rstrip("/") + directory
            r = requests.get(target, timeout=5, verify=False, allow_redirects=False)
            if r.status_code == 200 and ("Index of" in r.text or "Directory Listing" in r.text or "<title>Index of" in r.text):
                exposed.append(directory)
        except Exception:
            continue
            
    if exposed:
        findings.append({
            "vuln_type": "Directory Listing Enabled",
            "severity": "Medium",
            "description": f"Directory listing is enabled on the following paths: {', '.join(exposed)}. This exposes all files in the directory to the public, which may include sensitive backups or internal documents.",
            "fix": "Disable directory indexing in your web server configuration. For Apache, use 'Options -Indexes'. For Nginx, ensure 'autoindex off;' is set."
        })
    return findings


def check_cors(url):
    findings = []
    try:
        test_origin = "https://evil-attacker.com"
        headers = {"Origin": test_origin}
        r = requests.get(url, headers=headers, timeout=TIMEOUT, verify=False)
        
        allow_origin = r.headers.get("Access-Control-Allow-Origin")
        if allow_origin == "*" or allow_origin == test_origin:
            findings.append({
                "vuln_type": "CORS Misconfiguration",
                "severity": "High",
                "description": f"The server has an overly permissive Cross-Origin Resource Sharing (CORS) policy (Access-Control-Allow-Origin: {allow_origin}). This allows any malicious website to read sensitive data from authenticated users.",
                "fix": "Configure CORS to only allow trusted origins. Never use the wildcard '*' or dynamically reflect the requested Origin if the endpoint handles sensitive authenticated data."
            })
    except Exception:
        pass
    return findings


DANGEROUS_PORTS = {
    21:   ("FTP",        "High",     "FTP is unencrypted and allows file access. Use SFTP or FTPS instead."),
    22:   ("SSH",        "Medium",   "SSH is exposed. Restrict access via firewall to trusted IPs only."),
    23:   ("Telnet",     "Critical", "Telnet transmits data in plain text. Disable it immediately and use SSH."),
    25:   ("SMTP",       "Medium",   "SMTP is exposed. Restrict outbound mail relay to prevent abuse."),
    3306: ("MySQL",     "Critical", "MySQL database port is publicly accessible. Bind it to 127.0.0.1 and use a firewall."),
    5432: ("PostgreSQL","Critical", "PostgreSQL port is publicly accessible. Restrict access via pg_hba.conf and firewall."),
    6379: ("Redis",     "Critical", "Redis has no authentication by default. Bind to localhost and enable requirepass."),
    27017:("MongoDB",   "Critical", "MongoDB is publicly accessible. Enable authentication and bind to 127.0.0.1."),
    3389: ("RDP",       "Critical", "Remote Desktop is exposed to the internet. Restrict to VPN-only access."),
    8080: ("HTTP-Alt",  "Low",      "Alternative HTTP port is open. Ensure it does not expose dev/debug servers."),
    8443: ("HTTPS-Alt", "Low",      "Alternative HTTPS port is open. Verify this is intentional."),
    9200: ("Elasticsearch", "Critical", "Elasticsearch is publicly accessible with no auth by default. Restrict immediately."),
}


def check_open_ports(url):
    findings = []
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return findings

    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        return findings

    open_ports = []
    for port, (service, severity, fix) in DANGEROUS_PORTS.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            result = s.connect_ex((ip, port))
            s.close()
            if result == 0:
                open_ports.append((port, service, severity, fix))
        except Exception:
            continue

    for port, service, severity, fix in open_ports:
        findings.append({
            "vuln_type": f"Open Port: {port}/{service}",
            "severity": severity,
            "description": f"Port {port} ({service}) is open and publicly accessible on {hostname} ({ip}). Exposing administrative/database services to the internet significantly increases the attack surface.",
            "fix": fix
        })
    return findings


def check_robots_txt(url):
    findings = []
    try:
        robots_url = url.rstrip("/") + "/robots.txt"
        r = requests.get(robots_url, timeout=TIMEOUT, verify=False)
        if r.status_code != 200 or "Disallow" not in r.text:
            return findings

        disallowed = []
        for line in r.text.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    disallowed.append(path)

        accessible = []
        for path in disallowed[:10]:  # limit checks
            try:
                target = url.rstrip("/") + path
                resp = requests.get(target, timeout=5, verify=False, allow_redirects=False)
                if resp.status_code == 200:
                    accessible.append(path)
            except Exception:
                continue

        if accessible:
            findings.append({
                "vuln_type": "Hidden Paths Exposed via robots.txt",
                "severity": "High",
                "description": f"The robots.txt file reveals hidden paths that are publicly accessible: {', '.join(accessible)}. Attackers always read robots.txt to find admin panels, APIs, and staging servers that developers tried to hide from search engines.",
                "fix": "robots.txt is not a security control — it is public. Move sensitive endpoints behind authentication. Do not rely on 'Disallow' to hide admin areas."
            })
    except Exception:
        pass
    return findings


def check_hidden_inputs(url):
    findings = []
    try:
        response = requests.get(url, timeout=TIMEOUT, verify=False)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        suspicious_keywords = [
            "price", "amount", "cost", "total", "discount", "role",
            "admin", "user_id", "uid", "account", "level", "access",
            "token", "auth", "secret", "key", "hash"
        ]

        flagged = []
        for form in forms:
            hidden_inputs = form.find_all("input", {"type": "hidden"})
            for inp in hidden_inputs:
                name = inp.get("name", "").lower()
                value = inp.get("value", "")
                if any(kw in name for kw in suspicious_keywords) and value:
                    flagged.append(f"{inp.get('name')}={value[:30]}")

        if flagged:
            findings.append({
                "vuln_type": "Sensitive Hidden Form Fields",
                "severity": "High",
                "description": f"Hidden form fields with sensitive names were found: {', '.join(flagged[:5])}. Attackers can modify these values using browser DevTools before submitting, potentially manipulating prices, user roles, or access levels.",
                "fix": "Never store sensitive business logic (prices, roles, user IDs) in hidden form fields. Validate and recalculate all critical values server-side. Use signed tokens (HMAC) if state must be passed through forms."
            })
    except Exception:
        pass
    return findings


def run_scan(url):
    import warnings
    warnings.filterwarnings("ignore")

    all_findings = []
    all_findings += check_ssl(url)
    all_findings += check_security_headers(url)
    all_findings += check_xss(url)
    all_findings += check_sqli(url)
    all_findings += check_sensitive_paths(url)
    all_findings += check_cookies(url)
    all_findings += check_info_disclosure(url)
    all_findings += check_sri(url)
    all_findings += check_directory_listing(url)
    all_findings += check_cors(url)
    all_findings += check_open_ports(url)
    all_findings += check_robots_txt(url)
    all_findings += check_hidden_inputs(url)

    return all_findings
