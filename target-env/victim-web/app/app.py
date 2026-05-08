"""
target-env/victim-web/app/app.py
Intentionally vulnerable Flask web application — OWASP Top 10 lab target.
WARNING: This application is deliberately insecure. Do NOT expose to the internet.
"""

import os
import sqlite3
from flask import Flask, request, render_template_string, redirect, session, make_response

app = Flask(__name__)
app.secret_key = "super-insecure-secret-123"  # Intentionally weak

# In-memory SQLite for portability
DB_PATH = "/tmp/lab.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY, user_id INTEGER, content TEXT)""")
    conn.executemany("INSERT OR IGNORE INTO users VALUES (?,?,?,?)", [
        (1, "admin", "password123", "admin"),
        (2, "victim", "letmein", "user"),
        (3, "test", "test", "user"),
    ])
    conn.executemany("INSERT OR IGNORE INTO notes VALUES (?,?,?)", [
        (1, 1, "Admin secret: FLAG{sql_injection_success}"),
        (2, 2, "My note here"),
    ])
    conn.commit()
    conn.close()

INDEX_HTML = """<!DOCTYPE html>
<html><head><title>LabCorp Internal Portal</title>
<style>body{font-family:Arial;max-width:800px;margin:50px auto;padding:20px;background:#f5f5f5;}
.vuln-label{background:#ff4444;color:white;padding:2px 8px;border-radius:4px;font-size:11px;}
form{background:white;padding:20px;border-radius:8px;margin:10px 0;}
input{display:block;width:100%;margin:8px 0;padding:8px;border:1px solid #ddd;border-radius:4px;}
button{background:#0066cc;color:white;border:none;padding:10px 20px;border-radius:4px;cursor:pointer;}
nav a{margin-right:15px;color:#0066cc;}
</style></head><body>
<h1>LabCorp Internal Portal <span class="vuln-label">LAB TARGET</span></h1>
<nav><a href="/">Home</a><a href="/login">Login</a><a href="/search">Search</a><a href="/file">File Viewer</a></nav>
<p>Welcome to the intentionally vulnerable lab environment. This application contains OWASP Top 10 vulnerabilities for educational purposes.</p>
<ul>
<li><a href="/login">Login Page</a> — SQLi (A03:2021)</li>
<li><a href="/search?q=test">Search</a> — XSS (A03:2021)</li>
<li><a href="/file?name=notes.txt">File Viewer</a> — Path Traversal (A01:2021)</li>
</ul>
</body></html>"""

LOGIN_HTML = """<!DOCTYPE html>
<html><head><title>Login — LabCorp</title>
<style>body{font-family:Arial;max-width:400px;margin:100px auto;padding:20px;}
input,button{display:block;width:100%;margin:10px 0;padding:10px;border:1px solid #ddd;border-radius:4px;}
button{background:#0066cc;color:white;border:none;cursor:pointer;}
.error{color:red;} .success{color:green;}</style></head><body>
<h2>Login</h2>
{% if error %}<p class="error">{{ error }}</p>{% endif %}
{% if success %}<p class="success">{{ success }}</p>{% endif %}
<form method="POST">
<input name="username" placeholder="Username" value="{{ username or '' }}">
<input name="password" type="password" placeholder="Password">
<button type="submit">Login</button>
</form>
<p><small>Hint: Try ' OR '1'='1 as username</small></p>
</body></html>"""

SEARCH_HTML = """<!DOCTYPE html>
<html><head><title>Search — LabCorp</title>
<style>body{font-family:Arial;max-width:600px;margin:50px auto;padding:20px;}
input,button{padding:8px;} </style></head><body>
<h2>Search</h2>
<form method="GET"><input name="q" value="{{ query }}"><button>Search</button></form>
<p>Results for: {{ query|safe }}</p>
</body></html>"""

@app.route("/")
def index():
    return INDEX_HTML

@app.route("/login", methods=["GET", "POST"])
def login():
    error = success = username = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # VULNERABILITY: SQL Injection (A03:2021)
        conn = sqlite3.connect(DB_PATH)
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        try:
            row = conn.execute(query).fetchone()
            if row:
                session["user"] = row[1]
                success = f"Welcome, {row[1]}! (role: {row[3]})"
            else:
                error = "Invalid credentials"
        except sqlite3.OperationalError as e:
            error = f"DB Error: {e}"
        conn.close()
    return render_template_string(LOGIN_HTML, error=error, success=success, username=username)

@app.route("/search")
def search():
    # VULNERABILITY: Reflected XSS (A03:2021) — query not sanitized
    query = request.args.get("q", "")
    return render_template_string(SEARCH_HTML, query=query)

@app.route("/file")
def file_viewer():
    # VULNERABILITY: Path Traversal (A01:2021)
    filename = request.args.get("name", "notes.txt")
    base_dir = "/var/www/files/"
    # Missing path sanitization — allows traversal
    full_path = base_dir + filename
    try:
        with open(full_path) as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except FileNotFoundError:
        # Try the traversal path directly for demo
        try:
            with open(filename.replace("../", "/").replace("..%2F", "/")) as f:
                return f"<pre>{f.read()}</pre>"
        except Exception:
            return f"File not found: {filename}", 404
    except PermissionError:
        return f"Access denied: {filename}", 403

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=80, debug=False)
