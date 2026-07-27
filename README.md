# Web Vulnerability Dashboard

A full-stack web security scanner dashboard built as a 3rd year student project. It scans websites for common vulnerabilities and displays results in an interactive dashboard.

## Features

- **13 Vulnerability Checks:** SSL/TLS, Security Headers, XSS, SQL Injection, Sensitive Paths, Cookie Security, Info Disclosure, Missing SRI, Directory Listing, CORS, Open Ports, robots.txt Paths, Hidden Form Fields
- **Risk Scoring:** Automated 0–100 risk score per scan
- **Interactive Dashboard:** Charts, stats, severity filters
- **Scan History:** View, filter, and delete past scans
- **Fix Suggestions:** Every finding includes a step-by-step fix

## Tech Stack

| Layer    | Technology                              |
|----------|-----------------------------------------|
| Frontend | React 18, React Router, Recharts, Axios |
| Backend  | Python 3, Flask, Flask-CORS             |
| Database | SQLite (file-based, no setup needed)    |
| Scanner  | requests, BeautifulSoup4, ssl           |

## Project Structure

```
web-vuln-dashboard/
├── backend/
│   ├── app.py          # Flask REST API
│   ├── scanner.py      # All vulnerability checks
│   └── requirements.txt
├── frontend/
│   ├── public/
│   │   └── index.html
│   ├── src/
│   │   ├── App.js
│   │   ├── index.js
│   │   ├── components/
│   │   │   └── Components.js   # SeverityBadge, StatCard, FindingCard, RiskScore
│   │   └── pages/
│   │       ├── Dashboard.js    # Overview with charts
│   │       ├── ScanPage.js     # URL input + scan trigger
│   │       ├── ResultsPage.js  # Detailed findings view
│   │       └── HistoryPage.js  # All past scans
│   └── package.json
└── README.md
```

## Setup & Run

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/web-vuln-dashboard.git
cd web-vuln-dashboard
```

### 2. Start the Backend

```bash
cd backend
pip install -r requirements.txt
python app.py
```

Backend runs at: `http://localhost:5000`

### 3. Start the Frontend

```bash
cd frontend
npm install
npm start
```

Frontend runs at: `http://localhost:3000`

> The frontend proxies API calls to the backend via the `"proxy"` field in `package.json`.

## API Endpoints

| Method | Endpoint              | Description                    |
|--------|-----------------------|--------------------------------|
| POST   | `/api/scan`           | Submit URL for scanning        |
| GET    | `/api/scans`          | Get all scan history           |
| GET    | `/api/scans/:id`      | Get single scan with findings  |
| DELETE | `/api/scans/:id`      | Delete a scan                  |
| GET    | `/api/stats`          | Dashboard summary stats        |

### POST /api/scan — Request Body

```json
{ "url": "https://example.com" }
```

### POST /api/scan — Response

```json
{
  "scan_id": 1,
  "url": "https://example.com",
  "scanned_at": "2024-01-15 14:30:00",
  "risk_score": 65,
  "total_findings": 5,
  "findings": [
    {
      "vuln_type": "Missing Header: Content-Security-Policy",
      "severity": "High",
      "description": "...",
      "fix": "..."
    }
  ]
}
```

## Vulnerability Checks Explained

### 1. SSL/TLS Certificate
Checks whether the site uses HTTPS and whether the SSL certificate is valid and not expiring soon. Uses Python's built-in `ssl` module.

### 2. Security Headers
Checks for the presence of these HTTP response headers:
- `Content-Security-Policy` (prevents XSS)
- `Strict-Transport-Security` (enforces HTTPS)
- `X-Frame-Options` (prevents Clickjacking)
- `X-Content-Type-Options` (prevents MIME sniffing)
- `Referrer-Policy`
- `Permissions-Policy`

### 3. Reflected XSS
Finds HTML forms, injects test payloads like `<script>alert(1)</script>`, and checks if the payload is reflected in the response unescaped.

### 4. SQL Injection
Submits SQL-breaking characters (`'`, `1=1`) into form fields and URL parameters, then checks if the response contains database error messages.

### 5. Sensitive Paths
Requests common sensitive paths like `/admin`, `/.env`, `/.git`, `/backup` and flags any that return HTTP 200.

### 6. Cookie Security
Checks all cookies set by the server for missing `Secure`, `HttpOnly`, and `SameSite` flags.

### 7. Information Disclosure
Inspects HTTP headers (like `Server`, `X-Powered-By`) to see if the server leaks its exact software version, making it easier for attackers to find known vulnerabilities.

### 8. Missing Subresource Integrity (SRI)
Scans the HTML for external `<script>` and `<link>` tags (like CDNs) that are loaded without the `integrity` attribute. SRI prevents malicious code execution if the external CDN is compromised.

### 9. Directory Listing
Attempts to access common asset directories (`/images/`, `/uploads/`) to check if the server exposes all files within them as a public index.

### 10. CORS Misconfiguration
Checks if the server has an overly permissive Cross-Origin Resource Sharing (CORS) policy (e.g., `Access-Control-Allow-Origin: *`) that could allow malicious websites to make unauthorized requests.

### 11. Open Ports Scanner
Uses Python's `socket` library to probe the target host for dangerous open ports: FTP (21), SSH (22), Telnet (23), MySQL (3306), PostgreSQL (5432), Redis (6379), MongoDB (27017), RDP (3389), and Elasticsearch (9200). Exposed database and admin services dramatically increase the attack surface.

### 12. Hidden Paths via robots.txt
Fetches `/robots.txt`, extracts all `Disallow` entries, and actively probes those paths to see if they are publicly accessible (HTTP 200). Attackers always check this file to discover admin panels, APIs, and staging servers that developers tried to hide from search engines.

### 13. Hidden Form Field Tampering
Parses HTML forms and identifies `<input type="hidden">` fields whose names suggest sensitive data (e.g., `price`, `role`, `user_id`, `token`). These fields can be trivially modified in browser DevTools before form submission, potentially enabling price manipulation or privilege escalation.

## Risk Score Calculation

```
score = (Critical × 10) + (High × 7) + (Medium × 4) + (Low × 1)
score = min(score, 100)
```

| Score | Risk Level |
|-------|------------|
| 70–100 | Critical  |
| 40–69  | High      |
| 20–39  | Medium    |
| 0–19   | Low       |

## Screenshots

### Dashboard
- Summary KPI cards (total scans, findings, by severity)
- Pie chart: findings by severity
- Bar chart: risk scores across recent scans
- Recent scans table

### Scan Page
- URL input with one-click scanning
- Live progress messages during scan
- Preset vulnerable test URLs

### Results Page
- Circular risk score gauge
- Severity breakdown cards
- Expandable findings with fix suggestions
- Filter by severity level

### History Page
- All past scans in a table
- Risk level badges
- View or delete any scan

## Test Websites (Legal to Scan)

These are intentionally vulnerable sites for learning:

- `http://testphp.vulnweb.com` — PHP-based, many vulns
- `http://demo.testfire.net` — IBM demo banking site
- `http://zero.webappsecurity.com` — OWASP Zero Bank

> **Important:** Only scan websites you own or have explicit permission to scan. Never use this tool on live production websites without authorization.

## Future Improvements

- [ ] PDF report export
- [ ] User authentication with Flask-Login
- [ ] Integration with OWASP ZAP API
- [ ] Email alerts for critical findings
- [ ] Scheduled/recurring scans
- [ ] CVSS score per finding

## Key Concepts (for Viva)

**XSS (Cross-Site Scripting):** Attacker injects JavaScript into a page that runs in other users' browsers. Detected by checking if user input reflects back unsanitized.

**SQL Injection:** Attacker manipulates SQL queries by injecting SQL syntax into input fields. Detected by triggering database errors.

**CVSS:** Common Vulnerability Scoring System — industry standard 0–10 scale for severity (Critical 9–10, High 7–8.9, Medium 4–6.9, Low 0–3.9).

**OWASP Top 10:** The ten most critical web application security risks published by OWASP. This project covers: Injection (A03), Security Misconfiguration (A05), and Vulnerable/Outdated Components (A06).

## License

MIT License — free to use and modify for educational purposes.
