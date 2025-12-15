import os
import re
import uuid
import sqlite3
from datetime import datetime
from email import policy
from email.parser import BytesParser
from typing import Tuple

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import joblib
import pandas as pd

# -------- CONFIG --------
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"eml"}
DB_PATH = "database.db"
MODEL_PATH = "model.joblib"

app = Flask(__name__)
app.secret_key = "super-secret-key"  # change for production
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# -------- DB helpers --------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            stored_filename TEXT NOT NULL,
            original_filename TEXT,
            label TEXT,
            confidence REAL,
            subject TEXT,
            sender TEXT,
            snippet TEXT,
            urls_flag INTEGER DEFAULT 0,
            created_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """)
init_db()

# -------- Model loading --------
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError("model.joblib not found. Place model.joblib in project root.")
model = joblib.load(MODEL_PATH)

# -------- Utilities --------
def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

URL_RE = re.compile(r"https?://[^\s'\"<>]+", flags=re.IGNORECASE)

def extract_text_from_email(msg) -> Tuple[str, str, str]:
    """
    Extract subject, body, sender
    """
    subject = msg.get("subject", "") or ""
    sender = msg.get("from", "") or ""
    body = ""

    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            ctype = part.get_content_type()
            cdisp = str(part.get("Content-Disposition", "")).lower()
            if ctype == "text/plain" and "attachment" not in cdisp:
                try:
                    parts.append(part.get_content())
                except Exception:
                    try:
                        raw = part.get_payload(decode=True)
                        if raw:
                            parts.append(raw.decode(errors="ignore"))
                    except Exception:
                        pass
        body = "\n".join(parts)
        if not body:
            # fallback to text/html if no plain text
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    try:
                        body = part.get_content()
                        break
                    except:
                        pass
    else:
        try:
            body = msg.get_content()
        except Exception:
            try:
                raw = msg.get_payload(decode=True)
                body = raw.decode(errors="ignore") if raw else ""
            except:
                body = ""

    return subject, body, sender

def has_url(text: str) -> int:
    if not text:
        return 0
    return 1 if URL_RE.search(text) else 0

def classify_email_bytes(raw_bytes: bytes):
    """
    Returns (label, confidence_percent, info_dict)
    info_dict contains from/subject/snippet/urls_flag
    """
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    subject, body, sender = extract_text_from_email(msg)
    text = (subject or "") + " " + (body or "")
    urls_flag = has_url(text)

    # Build dataframe to match training features: 'text' and 'urls'
    df = pd.DataFrame([{"text": text, "urls": int(urls_flag)}])

    try:
        proba = model.predict_proba(df)[0]
        pred = int(proba.argmax())
        phishing_prob = float(proba[1]) if len(proba) > 1 else 0.0
    except Exception as e:
        # fallback heuristic if model fails
        # (this ensures app remains usable even if model interface differs)
        suspicion = 0
        if urls_flag:
            suspicion += 2
        if re.search(r"(urgent|verify|password|account|click here|update|bank)", text, flags=re.IGNORECASE):
            suspicion += 2
        pred = 1 if suspicion >= 2 else 0
        phishing_prob = min(0.95, 0.5 + 0.15 * suspicion)

    label = "Phishing / Spam" if pred == 1 else "Legitimate"
    confidence = round((phishing_prob if pred == 1 else (1 - phishing_prob)) * 100, 2)

    info = {
        "from": sender,
        "subject": subject,
        "snippet": (body[:800] + "...") if len(body) > 800 else body,
        "urls_flag": bool(urls_flag)
    }
    return label, confidence, info
         # Parse email
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    subject, body, sender = extract_text_from_email(msg)
    text = (subject or "") + " " + (body or "")

    # ------------------- Modern phishing features -------------------
    urls = URL_RE.findall(body)
    urls_count = len(urls)
    urls_flag = int(urls_count > 0)
    punycode_flag = int(any("xn--" in url for url in urls))
    script_flag = int(bool(SCRIPT_RE.search(body)))
    base64_flag = int(bool(BASE64_RE.search(body)))

    attachments = [p.get_filename() for p in msg.iter_attachments() if p.get_filename()]
    attachments_count = len(attachments)
    suspicious_attachment = int(any(SUSPICIOUS_EXT.search(f) for f in attachments))

    headers = str(msg)
    spf_fail = int("Received-SPF: fail" in headers)
    dkim_fail = int("DKIM: fail" in headers)

    # ------------------- Build dataframe for logistic regression -------------------
    df = pd.DataFrame([{
        "text": text,
        "urls_count": urls_count,
        "punycode_flag": punycode_flag,
        "script_flag": script_flag,
        "base64_flag": base64_flag,
        "attachments_count": attachments_count,
        "suspicious_attachment": suspicious_attachment,
        "spf_fail": spf_fail,
        "dkim_fail": dkim_fail
    }])

    # ------------------- Classification -------------------
    try:
        proba = model.predict_proba(df)[0]
        pred = int(proba.argmax())
        phishing_prob = float(proba[1]) if len(proba) > 1 else 0.0
    except Exception as e:
        # Fallback heuristic (original app logic)
        suspicion = 0
        if urls_flag:
            suspicion += 2
        if re.search(r"(urgent|verify|password|account|click here|update|bank)", text, flags=re.IGNORECASE):
            suspicion += 2
        if script_flag or base64_flag:
            suspicion += 1
        if suspicious_attachment:
            suspicion += 1
        pred = 1 if suspicion >= 2 else 0
        phishing_prob = min(0.95, 0.5 + 0.15 * suspicion)

    label = "Phishing / Spam" if pred == 1 else "Legitimate"
    confidence = round((phishing_prob if pred == 1 else (1 - phishing_prob)) * 100, 2)

    # ------------------- Info dict for display -------------------
    info = {
        "from": sender,
        "subject": subject,
        "snippet": (body[:800] + "...") if len(body) > 800 else body,
        "urls_flag": bool(urls_flag)
    }

    return label, confidence, info
# -------- Auth helpers --------
def current_user_id():
    return session.get("user_id")

# -------- Routes --------
@app.route("/")
def index():
    # If user is logged in, go to upload
    if current_user_id():
        return redirect(url_for("upload"))

    # Check if there are any users in DB
    with get_db() as db:
        row = db.execute("SELECT COUNT(*) as count FROM users").fetchone()
        user_count = row["count"] if row else 0

    # If no users exist, force registration first
    if user_count == 0:
        return redirect(url_for("register"))

    # Otherwise go to login
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        if not email or not password:
            flash("Provide email and password", "danger")
            return redirect(url_for("register"))

        hashed = generate_password_hash(password)
        created_at = datetime.utcnow().isoformat()
        try:
            with get_db() as db:
                cur = db.execute(
                    "INSERT INTO users (email, password, created_at) VALUES (?, ?, ?)",
                    (email, hashed, created_at)
                )
                user_id = cur.lastrowid
            # Do NOT log the user in immediately
            flash("Account created — please sign in", "success")
            return redirect(url_for("login"))  # redirect to login instead of upload
        except sqlite3.IntegrityError:
            flash("Email already registered", "danger")
            return redirect(url_for("register"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        with get_db() as db:
            row = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if not row:
            flash("Invalid credentials", "danger")
            return redirect(url_for("login"))
        if not check_password_hash(row["password"], password):
            flash("Invalid credentials", "danger")
            return redirect(url_for("login"))
        # success
        session["user_id"] = row["id"]
        flash("Signed in — redirected to upload", "success")
        return redirect(url_for("upload"))  # go to upload after login
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Signed out", "info")
    return redirect(url_for("login"))

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if not current_user_id():
        return redirect(url_for("login"))

    if request.method == "POST":
        if "file" not in request.files:
            flash("No file provided", "danger")
            return redirect(request.url)
        f = request.files["file"]
        if f.filename == "":
            flash("No file selected", "warning")
            return redirect(request.url)
        if not allowed_file(f.filename):
            flash("Invalid file type. Use .eml", "danger")
            return redirect(request.url)

        raw = f.read()
        try:
            label, confidence, info = classify_email_bytes(raw)
        except Exception as e:
            flash(f"Error classifying email: {e}", "danger")
            return redirect(request.url)

        # Save file with unique name
        safe = secure_filename(f.filename)
        uid = uuid.uuid4().hex
        stored_name = f"{current_user_id()}_{uid}_{safe}"
        stored_path = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)
        # write raw bytes to disk
        with open(stored_path, "wb") as fh:
            fh.write(raw)

        created_at = datetime.utcnow().isoformat()
        with get_db() as db:
            cur = db.execute(
                """INSERT INTO emails
                   (user_id, stored_filename, original_filename, label, confidence, subject, sender, snippet, urls_flag, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    current_user_id(),
                    stored_name,
                    f.filename,
                    label,
                    confidence,
                    info.get("subject"),
                    info.get("from"),
                    info.get("snippet"),
                    1 if info.get("urls_flag") else 0,
                    created_at
                )
            )
            email_id = cur.lastrowid

        flash("Email analyzed and saved", "success")
        return redirect(url_for("result", email_id=email_id))

    return render_template("upload.html")

@app.route("/history")
def history():
    if not current_user_id():
        return redirect(url_for("login"))
    with get_db() as db:
        rows = db.execute(
            "SELECT id, original_filename AS filename, subject, label, confidence, created_at FROM emails WHERE user_id = ? ORDER BY created_at DESC",
            (current_user_id(),)
        ).fetchall()
    # convert sqlite Row -> dict for templates
    emails = [dict(r) for r in rows]
    return render_template("history.html", emails=emails)

@app.route("/result/<int:email_id>")
def result(email_id):
    if not current_user_id():
        return redirect(url_for("login"))
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM emails WHERE id = ? AND user_id = ?",
            (email_id, current_user_id())
        ).fetchone()
    if not row:
        flash("Record not found", "warning")
        return redirect(url_for("history"))
    email = dict(row)
    # convert urls_flag to boolean for templates if needed
    email["urls_flag"] = bool(email.get("urls_flag"))
    return render_template("result.html", email=email)

@app.route("/dashboard")
def dashboard():
    if not current_user_id():
        return redirect(url_for("login"))
    with get_db() as db:
        rows = db.execute(
            "SELECT label, COUNT(*) AS count FROM emails WHERE user_id = ? GROUP BY label",
            (current_user_id(),)
        ).fetchall()
    # convert rows to plain dicts so tojson works in template
    stats = [dict(r) for r in rows]  # <-- important: sqlite Row -> dict
    return render_template("dashboard.html", stats=stats)

# optional: serve uploaded file (only owner)
@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    if not current_user_id():
        return redirect(url_for("login"))
    with get_db() as db:
        row = db.execute("SELECT * FROM emails WHERE stored_filename = ? AND user_id = ?", (filename, current_user_id())).fetchone()
    if not row:
        abort(404)
    return app.send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)

# -------- Run --------
if __name__ == "__main__":
    # preload model (already loaded above)
    app.run(debug=True)
