# PROTODUDES — Layer By Layer 3D Print Shop Website

Flask web app with SQLite database, admin dashboard, quote management, and the embedded STL quote tool.

---

## PyCharm Setup (one-time)

1. **Open the project folder** in PyCharm (`File → Open → lbl3d/`).

2. **Create a virtual environment**
   - Go to `Settings → Python Interpreter → Add Interpreter → Add Local Interpreter → Virtualenv`.
   - PyCharm will create `.venv` inside the project.

3. **Install dependencies**
   Open the built-in Terminal and run:
   ```
   pip install -r requirements.txt
   ```

4. **Run the app**
   - Right-click `app.py` → `Run 'app'`, **or**
   - In the Terminal: `python app.py`
   - Visit `http://127.0.0.1:5000`

---

## Folder Structure

```
lbl3d/
├── app.py                  ← Main Flask application
├── requirements.txt
├── instance/
│   └── lbl3d.db            ← SQLite database (auto-created on first run)
├── static/
│   ├── css/style.css
│   └── images/3d_printer_image.jpeg
└── templates/
    ├── base.html
    ├── index.html
    ├── contact.html
    ├── login.html
    ├── stl_quote.html      ← The STL estimator tool
    ├── admin/
    │   ├── base_admin.html
    │   ├── dashboard.html
    │   ├── quotes.html / quote_detail.html
    │   ├── jobs.html / job_detail.html / job_form.html
    │   ├── users.html / user_form.html
    │   └── change_password.html
    └── errors/
        ├── 403.html / 404.html / 500.html
```

---

## Database / Spreadsheet Export

The app uses **SQLite** (zero config, single file `instance/lbl3d.db`).

To export data as a spreadsheet at any time:
- **Quotes CSV:** `http://127.0.0.1:5000/admin/quotes/export`
- **Jobs CSV:**   `http://127.0.0.1:5000/admin/jobs/export`

Both open directly in Excel or Google Sheets.

You can also open `lbl3d.db` directly with **DB Browser for SQLite** (free download at https://sqlitebrowser.org/) to view and edit rows in a GUI identical to a spreadsheet.

---

## Security Features

- Passwords hashed with **Werkzeug PBKDF2-SHA256** (never stored in plaintext)
- **Session cookie** hardening: `HttpOnly`, `SameSite=Lax`, configurable `Secure`
- **All admin routes** protected by `@login_required` / `@admin_required`
- **Role separation**: `admin` vs `staff` (only admins can manage users)
- **Open-redirect guard** on login `next` parameter
- **Security headers** on every response: `X-Frame-Options`, `X-Content-Type-Options`, `CSP`, `Referrer-Policy`
- **Parameterised SQL** queries throughout (no string formatting into queries)

---

## Production Checklist

Before going live:

1. Set `SECRET_KEY` as a real environment variable (don't use the auto-generated one).
2. Set `HTTPS=true` to enable `Secure` on session cookies.
3. Set `FLASK_DEBUG=false`.
4. Run behind a reverse proxy (nginx + gunicorn) — never expose Flask's dev server to the internet.
5. Back up `instance/lbl3d.db` regularly.
