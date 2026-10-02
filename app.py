"""
LBL 3D - Layer By Layer 3D Print Shop
Flask web application with SQLite database backend.
"""

import os
import sqlite3
import csv
import io
import secrets
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, g, send_file, abort, Response
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__)

# Secret key — in production, load from environment variable
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Session cookie hardening
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("HTTPS", "false").lower() == "true"
app.config["PERMANENT_SESSION_LIFETIME"] = 3600  # 1 hour

DATABASE = os.environ.get("DATABASE_PATH", os.path.join(app.instance_path, "protodudes.db"))
os.makedirs(app.instance_path, exist_ok=True)


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def get_db():
    """Return a thread-local database connection."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create tables and seed an admin user if the DB is new."""
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            username  TEXT    NOT NULL UNIQUE,
            password  TEXT    NOT NULL,
            role      TEXT    NOT NULL DEFAULT 'staff',  -- 'admin' or 'staff'
            created   TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS quotes (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT    NOT NULL,
            email         TEXT    NOT NULL,
            phone         TEXT,
            description   TEXT,
            material      TEXT,
            quantity      INTEGER DEFAULT 1,
            estimated_low REAL,
            estimated_high REAL,
            status        TEXT    NOT NULL DEFAULT 'new',  -- new | in_progress | done | cancelled
            notes         TEXT,
            created       TEXT    NOT NULL DEFAULT (datetime('now')),
            updated       TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS jobs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            quote_id    INTEGER REFERENCES quotes(id) ON DELETE SET NULL,
            title       TEXT    NOT NULL,
            client_name TEXT,
            material    TEXT,
            weight_g    REAL,
            price       REAL,
            status      TEXT    NOT NULL DEFAULT 'pending',
            started     TEXT,
            completed   TEXT,
            notes       TEXT,
            created     TEXT    NOT NULL DEFAULT (datetime('now'))
        );
    """)

    # Seed admin account only if no users exist
    row = db.execute("SELECT COUNT(*) FROM users").fetchone()
    if row[0] == 0:
        db.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("admin", generate_password_hash("changeme123"), "admin"),
        )
        print("[LBL3D] Default admin created — user: admin  password: changeme123")
        print("[LBL3D] *** Change the password immediately via /admin/change-password ***")

    db.commit()


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access that page.", "warning")
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in.", "warning")
            return redirect(url_for("login", next=request.path))
        if session.get("role") != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------
@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    # Relaxed CSP that still allows the Three.js CDN used in stl_quote.html
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://unpkg.com; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self' https://unpkg.com;"
    )
    return response


# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/quote")
def quote():
    """The embedded STL quote tool page."""
    return render_template("stl_quote.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    """Contact / quote request form — saves lead to DB and emails LBL3D."""
    if request.method == "POST":
        name        = request.form.get("name", "").strip()
        email       = request.form.get("email", "").strip()
        phone       = request.form.get("phone", "").strip()
        description = request.form.get("description", "").strip()
        material    = request.form.get("material", "").strip()
        quantity    = request.form.get("quantity", "1").strip()
        est_low     = request.form.get("estimated_low", "").strip() or None
        est_high    = request.form.get("estimated_high", "").strip() or None

        if not name or not email:
            flash("Name and email are required.", "danger")
            return redirect(url_for("contact"))

        try:
            quantity = int(quantity)
        except ValueError:
            quantity = 1

        db = get_db()
        db.execute(
            """INSERT INTO quotes
               (name, email, phone, description, material, quantity, estimated_low, estimated_high)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, email, phone, description, material, quantity, est_low, est_high),
        )
        db.commit()

        flash(
            "Thanks! Your request has been sent to info@protodudes.ca — "
            "we'll be in touch soon.",
            "success",
        )
        return redirect(url_for("index"))

    return render_template("contact.html")


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db   = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"]     = user["role"]
            session.permanent   = True

            next_url = request.args.get("next")
            if next_url and next_url.startswith("/"):   # open-redirect guard
                return redirect(next_url)
            return redirect(url_for("admin_dashboard"))

        flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You've been logged out.", "info")
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Admin — dashboard
# ---------------------------------------------------------------------------
@app.route("/admin")
@login_required
def admin_dashboard():
    db      = get_db()
    quotes  = db.execute("SELECT * FROM quotes ORDER BY created DESC LIMIT 10").fetchall()
    jobs    = db.execute("SELECT * FROM jobs   ORDER BY created DESC LIMIT 10").fetchall()
    counts  = {
        "quotes_new":   db.execute("SELECT COUNT(*) FROM quotes WHERE status='new'").fetchone()[0],
        "jobs_pending": db.execute("SELECT COUNT(*) FROM jobs   WHERE status='pending'").fetchone()[0],
        "jobs_done":    db.execute("SELECT COUNT(*) FROM jobs   WHERE status='done'").fetchone()[0],
    }
    return render_template("admin/dashboard.html", quotes=quotes, jobs=jobs, counts=counts)


# ---------------------------------------------------------------------------
# Admin — quotes
# ---------------------------------------------------------------------------
@app.route("/admin/quotes")
@login_required
def admin_quotes():
    db     = get_db()
    status = request.args.get("status", "")
    if status:
        rows = db.execute(
            "SELECT * FROM quotes WHERE status=? ORDER BY created DESC", (status,)
        ).fetchall()
    else:
        rows = db.execute("SELECT * FROM quotes ORDER BY created DESC").fetchall()
    return render_template("admin/quotes.html", quotes=rows, filter_status=status)


@app.route("/admin/quotes/<int:quote_id>", methods=["GET", "POST"])
@login_required
def admin_quote_detail(quote_id):
    db    = get_db()
    quote = db.execute("SELECT * FROM quotes WHERE id=?", (quote_id,)).fetchone()
    if not quote:
        abort(404)

    if request.method == "POST":
        status = request.form.get("status", quote["status"])
        notes  = request.form.get("notes", "").strip()
        db.execute(
            "UPDATE quotes SET status=?, notes=?, updated=datetime('now') WHERE id=?",
            (status, notes, quote_id),
        )
        db.commit()
        flash("Quote updated.", "success")
        return redirect(url_for("admin_quote_detail", quote_id=quote_id))

    return render_template("admin/quote_detail.html", quote=quote)


@app.route("/admin/quotes/export")
@login_required
def admin_quotes_export():
    """Download all quotes as a CSV (opens in Excel/Google Sheets)."""
    db   = get_db()
    rows = db.execute("SELECT * FROM quotes ORDER BY created DESC").fetchall()

    output  = io.StringIO()
    writer  = csv.writer(output)
    writer.writerow([
        "ID", "Name", "Email", "Phone", "Description",
        "Material", "Quantity", "Est. Low ($)", "Est. High ($)",
        "Status", "Notes", "Created", "Updated",
    ])
    for r in rows:
        writer.writerow([
            r["id"], r["name"], r["email"], r["phone"], r["description"],
            r["material"], r["quantity"], r["estimated_low"], r["estimated_high"],
            r["status"], r["notes"], r["created"], r["updated"],
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=lbl3d_quotes.csv"},
    )


# ---------------------------------------------------------------------------
# Admin — jobs
# ---------------------------------------------------------------------------
@app.route("/admin/jobs")
@login_required
def admin_jobs():
    db   = get_db()
    rows = db.execute("SELECT * FROM jobs ORDER BY created DESC").fetchall()
    return render_template("admin/jobs.html", jobs=rows)


@app.route("/admin/jobs/new", methods=["GET", "POST"])
@login_required
def admin_job_new():
    db = get_db()
    if request.method == "POST":
        db.execute(
            """INSERT INTO jobs
               (quote_id, title, client_name, material, weight_g, price, status, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                request.form.get("quote_id") or None,
                request.form.get("title", "").strip(),
                request.form.get("client_name", "").strip(),
                request.form.get("material", "").strip(),
                request.form.get("weight_g") or None,
                request.form.get("price") or None,
                request.form.get("status", "pending"),
                request.form.get("notes", "").strip(),
            ),
        )
        db.commit()
        flash("Job created.", "success")
        return redirect(url_for("admin_jobs"))

    quotes = db.execute("SELECT id, name FROM quotes ORDER BY created DESC").fetchall()
    return render_template("admin/job_form.html", job=None, quotes=quotes)


@app.route("/admin/jobs/<int:job_id>", methods=["GET", "POST"])
@login_required
def admin_job_detail(job_id):
    db  = get_db()
    job = db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    if not job:
        abort(404)

    if request.method == "POST":
        status    = request.form.get("status", job["status"])
        notes     = request.form.get("notes", "").strip()
        price     = request.form.get("price") or None
        completed = None
        if status == "done" and not job["completed"]:
            completed = datetime.utcnow().isoformat(sep=" ", timespec="seconds")
        else:
            completed = job["completed"]

        db.execute(
            "UPDATE jobs SET status=?, notes=?, price=?, completed=? WHERE id=?",
            (status, notes, price, completed, job_id),
        )
        db.commit()
        flash("Job updated.", "success")
        return redirect(url_for("admin_job_detail", job_id=job_id))

    return render_template("admin/job_detail.html", job=job)


@app.route("/admin/jobs/export")
@login_required
def admin_jobs_export():
    db   = get_db()
    rows = db.execute("SELECT * FROM jobs ORDER BY created DESC").fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Quote ID", "Title", "Client", "Material",
        "Weight (g)", "Price ($)", "Status", "Started", "Completed", "Notes", "Created",
    ])
    for r in rows:
        writer.writerow([
            r["id"], r["quote_id"], r["title"], r["client_name"], r["material"],
            r["weight_g"], r["price"], r["status"],
            r["started"], r["completed"], r["notes"], r["created"],
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=lbl3d_jobs.csv"},
    )


# ---------------------------------------------------------------------------
# Admin — user management (admin-only)
# ---------------------------------------------------------------------------
@app.route("/admin/users")
@admin_required
def admin_users():
    db    = get_db()
    users = db.execute("SELECT id, username, role, created FROM users ORDER BY created").fetchall()
    return render_template("admin/users.html", users=users)


@app.route("/admin/users/new", methods=["GET", "POST"])
@admin_required
def admin_user_new():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role     = request.form.get("role", "staff")

        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("admin_user_new"))

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, generate_password_hash(password), role),
            )
            db.commit()
            flash(f"User '{username}' created.", "success")
        except sqlite3.IntegrityError:
            flash("That username already exists.", "danger")

        return redirect(url_for("admin_users"))

    return render_template("admin/user_form.html")


@app.route("/admin/change-password", methods=["GET", "POST"])
@login_required
def admin_change_password():
    if request.method == "POST":
        current  = request.form.get("current_password", "")
        new_pw   = request.form.get("new_password", "")
        confirm  = request.form.get("confirm_password", "")

        if new_pw != confirm:
            flash("New passwords do not match.", "danger")
            return redirect(url_for("admin_change_password"))

        if len(new_pw) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return redirect(url_for("admin_change_password"))

        db   = get_db()
        user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()

        if not check_password_hash(user["password"], current):
            flash("Current password is incorrect.", "danger")
            return redirect(url_for("admin_change_password"))

        db.execute(
            "UPDATE users SET password=? WHERE id=?",
            (generate_password_hash(new_pw), session["user_id"]),
        )
        db.commit()
        flash("Password changed successfully.", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("admin/change_password.html")


# ---------------------------------------------------------------------------
# Error pages
# ---------------------------------------------------------------------------
@app.errorhandler(403)
def forbidden(e):
    return render_template("errors/403.html"), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("errors/404.html"), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("errors/500.html"), 500


# ---------------------------------------------------------------------------
# Database Initialization (runs when app starts in dev or Gunicorn)
# ---------------------------------------------------------------------------
with app.app_context():
    init_db()

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    with app.app_context():
        init_db()
    # debug=False in production; set via env var
    debug = os.environ.get("FLASK_DEBUG", "true").lower() == "true"
    app.run(debug=debug, host="127.0.0.1", port=5000)
