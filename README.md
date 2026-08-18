# Saeed Sardar English Learning

A professional English-learning website starter built with Flask and SQLite.

## Features
- Public landing page
- Required account login for lessons
- Signup: name, email, phone, age, password
- Secure password hashing with scrypt
- Login/logout
- Student dashboard
- Lessons and practice pages
- Progress database
- Security/audit event logging
- Responsive modern UI

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

On Windows:
```powershell
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

## Production checklist
- Set a strong random SECRET_KEY in the environment.
- Use HTTPS.
- Use PostgreSQL/MySQL instead of SQLite for a larger deployment.
- Add email verification and password-reset tokens.
- Add a real admin role/permission system before exposing `/admin`.
- Add CSRF protection (for example Flask-WTF) to production forms.
- Apply rate limiting to login/signup.
- Minimize and protect audit-log retention; provide an appropriate privacy notice.
- Never store plaintext passwords.
- Do not log passwords or authentication tokens.
