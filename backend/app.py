from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import datetime
from scanner import run_scan

app = Flask(__name__)
CORS(app)

DB_PATH = "vuln_dashboard.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            scanned_at TEXT NOT NULL,
            risk_score INTEGER DEFAULT 0,
            total_findings INTEGER DEFAULT 0,
            status TEXT DEFAULT 'completed'
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            vuln_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            fix TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );
    """)
    conn.commit()
    conn.close()


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "URL is required"}), 400

    if not url.startswith("http"):
        url = "https://" + url

    findings = run_scan(url)

    severity_scores = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1}
    risk_score = 0
    for f in findings:
        risk_score += severity_scores.get(f["severity"], 0)
    risk_score = min(risk_score, 100)

    scanned_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    cursor = conn.execute(
        "INSERT INTO scans (url, scanned_at, risk_score, total_findings) VALUES (?, ?, ?, ?)",
        (url, scanned_at, risk_score, len(findings))
    )
    scan_id = cursor.lastrowid

    for f in findings:
        conn.execute(
            "INSERT INTO findings (scan_id, vuln_type, severity, description, fix) VALUES (?, ?, ?, ?, ?)",
            (scan_id, f["vuln_type"], f["severity"], f["description"], f["fix"])
        )

    conn.commit()
    conn.close()

    return jsonify({
        "scan_id": scan_id,
        "url": url,
        "scanned_at": scanned_at,
        "risk_score": risk_score,
        "total_findings": len(findings),
        "findings": findings
    })


@app.route("/api/scans", methods=["GET"])
def get_scans():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM scans ORDER BY scanned_at DESC LIMIT 20"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/scans/<int:scan_id>", methods=["GET"])
def get_scan(scan_id):
    conn = get_db()
    scan = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    findings = conn.execute(
        "SELECT * FROM findings WHERE scan_id=?", (scan_id,)
    ).fetchall()
    conn.close()
    return jsonify({
        "scan": dict(scan),
        "findings": [dict(f) for f in findings]
    })


@app.route("/api/stats", methods=["GET"])
def get_stats():
    conn = get_db()
    total_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    total_findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    critical = conn.execute("SELECT COUNT(*) FROM findings WHERE severity='Critical'").fetchone()[0]
    high = conn.execute("SELECT COUNT(*) FROM findings WHERE severity='High'").fetchone()[0]
    medium = conn.execute("SELECT COUNT(*) FROM findings WHERE severity='Medium'").fetchone()[0]
    low = conn.execute("SELECT COUNT(*) FROM findings WHERE severity='Low'").fetchone()[0]
    conn.close()
    return jsonify({
        "total_scans": total_scans,
        "total_findings": total_findings,
        "by_severity": {
            "Critical": critical,
            "High": high,
            "Medium": medium,
            "Low": low
        }
    })


@app.route("/api/scans/<int:scan_id>", methods=["DELETE"])
def delete_scan(scan_id):
    conn = get_db()
    conn.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
    conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Scan deleted"})


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)
