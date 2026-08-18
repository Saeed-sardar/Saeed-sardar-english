import os
import sqlite3
import secrets
import hashlib
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, g

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
DB = os.path.join(os.path.dirname(__file__), "english_academy.db")

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception=None):
    conn = g.pop("db", None)
    if conn:
        conn.close()

def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return salt.hex() + "$" + digest.hex()

def verify_password(password, stored):
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1)
        return secrets.compare_digest(digest.hex(), digest_hex)
    except Exception:
        return False

def init_db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row  # Enables string key access like row["name"]
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        phone TEXT NOT NULL,
        age INTEGER NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        event TEXT NOT NULL,
        ip TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS progress (
        user_id INTEGER PRIMARY KEY,
        vocabulary INTEGER DEFAULT 0,
        grammar INTEGER DEFAULT 0,
        reading INTEGER DEFAULT 0,
        listening INTEGER DEFAULT 0,
        speaking INTEGER DEFAULT 0,
        writing INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)
    con.close()

def log_event(event, user_id=None):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ip and "," in ip:
        ip = ip.split(",")[0].strip()
    db().execute(
        "INSERT INTO audit_logs(user_id,event,ip,created_at) VALUES(?,?,?,?)",
        (user_id, event, ip, datetime.utcnow().isoformat(timespec="seconds"))
    )
    db().commit()

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to access your lessons.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name","").strip()
        email = request.form.get("email","").strip().lower()
        phone = request.form.get("phone","").strip()
        age_raw = request.form.get("age","").strip()
        password = request.form.get("password","")
        confirm = request.form.get("confirm","")

        errors = []
        if len(name) < 2: errors.append("Enter your full name.")
        if "@" not in email or "." not in email: errors.append("Enter a valid email address.")
        if len(phone) < 7: errors.append("Enter a valid phone number.")
        try:
            age = int(age_raw)
            if age < 13 or age > 120: errors.append("Age must be between 13 and 120.")
        except ValueError:
            errors.append("Enter a valid age.")
        if len(password) < 8: errors.append("Password must be at least 8 characters.")
        if password != confirm: errors.append("Passwords do not match.")

        if errors:
            for e in errors: flash(e, "error")
            return render_template("signup.html")

        try:
            cur = db().execute(
                "INSERT INTO users(name,email,phone,age,password_hash,created_at) VALUES(?,?,?,?,?,?)",
                (name, email, phone, age, hash_password(password), datetime.utcnow().isoformat(timespec="seconds"))
            )
            user_id = cur.lastrowid
            db().execute("INSERT INTO progress(user_id) VALUES(?)", (user_id,))
            db().commit()
            log_event("account_created", user_id)
            flash("Account created. You can now log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("That email is already registered.", "error")
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        user = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user and verify_password(password, user["password_hash"]):
            session.clear()
            session["user_id"] = user["id"]
            log_event("login_success", user["id"])
            return redirect(url_for("dashboard"))
        log_event("login_failed")
        flash("Invalid email or password.", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    uid = session.get("user_id")
    if uid: log_event("logout", uid)
    session.clear()
    return redirect(url_for("home"))

@app.route("/dashboard")
@login_required
def dashboard():
    user = db().execute("SELECT id,name,email FROM users WHERE id=?", (session["user_id"],)).fetchone()
    progress = db().execute("SELECT * FROM progress WHERE user_id=?", (session["user_id"],)).fetchone()
    return render_template("dashboard.html", user=user, progress=progress)

@app.route("/lessons")
@login_required
def lessons():
    return render_template("lessons.html")

@app.route("/practice")
@login_required
def practice():
    return render_template("practice.html")

@app.route("/admin")
@login_required
def admin():
    logs = db().execute("""
        SELECT audit_logs.*, users.email FROM audit_logs
        LEFT JOIN users ON users.id = audit_logs.user_id
        ORDER BY audit_logs.id DESC LIMIT 100
    """).fetchall()
    return render_template("admin.html", logs=logs)

@app.context_processor
def inject_user():
    user = None
    if session.get("user_id"):
        user = db().execute("SELECT name FROM users WHERE id=?", (session["user_id"],)).fetchone()
    return {"current_user": user}

# Initialize database on app startup
init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
                                            
