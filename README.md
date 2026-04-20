# HC Box — CS 419 Project

Secure document sharing system with encryption, RBAC, and audit logging.

## Setup

### 1. Clone and install

```bash
git clone <your-repo-url>
cd secure-app

python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env and set a strong SECRET_KEY
python -c "import secrets; print(secrets.token_hex(32))"
```

### 3. (Optional) Generate a self-signed TLS certificate

```bash
openssl req -x509 -newkey rsa:4096 -nodes \
  -out cert.pem -keyout key.pem -days 365 \
  -subj "/CN=localhost"
```

### 4. Run

```bash
python app.py
# Open http://127.0.0.1:5000
```

### 5. Create an admin account

Register normally, then manually edit `data/users.json` and change your user's `"role"` from `"user"` to `"admin"`.

## Run tests

```bash
python -m pytest tests/ -v
```

## Project structure

```
secure-app/
├── app.py              # Flask app, routes, middleware
├── config.py           # Environment-based config
├── security.py         # Security headers + HTTPS redirect
├── session_manager.py  # Secure session handling
├── security_logger.py  # Structured security event logging
├── user_store.py       # User CRUD, bcrypt, lockout logic
├── document_store.py   # Encrypted file storage
├── rbac.py             # Role-based access control decorators
├── rate_limiter.py     # IP-based login rate limiting
├── filters.py          # Jinja2 template filters
├── auth.py             # /register /login /logout blueprint
├── documents.py        # Upload/download/share/delete blueprint
├── admin.py            # Admin user management + audit log
├── data/               # JSON storage (git-ignored)
├── logs/               # Security logs (git-ignored)
├── static/             # CSS + JS
├── templates/          # Jinja2 HTML templates
├── tests/              # Security test suite
└── docs/               # Security design doc + pentest report
```

## Security controls implemented

| Requirement             | Implementation                                      |
|-------------------------|-----------------------------------------------------|
| Password hashing        | bcrypt, cost factor 12                              |
| Account lockout         | 5 failures → 15-minute lockout                      |
| Rate limiting           | 10 login attempts per IP per minute                 |
| Session tokens          | `secrets.token_urlsafe(32)`, 30-min timeout         |
| Session cookie flags    | HttpOnly, Secure, SameSite=Strict                   |
| RBAC                    | Admin / User / Guest with permission decorators     |
| Input validation        | Whitelist regex, length limits, HTML escaping       |
| XSS prevention          | Jinja2 auto-escape + `html.escape()` on all inputs  |
| Path traversal          | `secure_filename` + `os.path.abspath` boundary check|
| File encryption         | Fernet (AES-128-CBC + HMAC-SHA256)                  |
| Security headers        | CSP, X-Frame-Options, HSTS, nosniff, etc.           |
| Audit logging           | JSON-structured events in `logs/security.log`       |
| HTTPS redirect          | Force HTTP → HTTPS in non-development mode          |


