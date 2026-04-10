"""
File-based user storage.
All passwords stored as bcrypt hashes — never plaintext.
"""

import json
import os
import re
import time
import bcrypt
from config import Config

USERS_FILE = os.path.join(Config.DATA_DIR, 'users.json')


# ── File I/O ─────────────────────────────────────────────────────────────────

def _load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def _save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)


# ── Validators ───────────────────────────────────────────────────────────────

def validate_username(username):
    """3–20 chars, alphanumeric + underscore only."""
    return bool(re.match(r'^[a-zA-Z0-9_]{3,20}$', username))

def validate_email(email):
    """Basic RFC-compliant email check."""
    return bool(re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email))

def validate_password(password):
    """
    Min 12 chars, requires: uppercase, lowercase, digit, special char.
    Returns (bool, reason_string).
    """
    if len(password) < 12:
        return False, 'Password must be at least 12 characters'
    if not re.search(r'[A-Z]', password):
        return False, 'Password must contain an uppercase letter'
    if not re.search(r'[a-z]', password):
        return False, 'Password must contain a lowercase letter'
    if not re.search(r'[0-9]', password):
        return False, 'Password must contain a number'
    if not re.search(r'[!@#$%^&*]', password):
        return False, 'Password must contain a special character (!@#$%^&*)'
    return True, ''


# ── CRUD ─────────────────────────────────────────────────────────────────────

def create_user(username, email, password, role='user'):
    """
    Register a new user. Returns (user_dict, None) on success,
    or (None, error_string) on failure.
    """
    if not validate_username(username):
        return None, 'Invalid username (3–20 alphanumeric chars)'
    if not validate_email(email):
        return None, 'Invalid email address'

    ok, msg = validate_password(password)
    if not ok:
        return None, msg

    users = _load_users()

    # Duplicate check
    for u in users.values():
        if u['username'].lower() == username.lower():
            return None, 'Username already taken'
        if u['email'].lower() == email.lower():
            return None, 'Email already registered'

    # Hash password
    pw_hash = bcrypt.hashpw(password.encode('utf-8'),
                             bcrypt.gensalt(rounds=Config.BCRYPT_ROUNDS))

    user_id = f"u_{int(time.time() * 1000)}"
    user = {
        'id': user_id,
        'username': username,
        'email': email,
        'password_hash': pw_hash.decode('utf-8'),
        'role': role,
        'created_at': time.time(),
        'failed_attempts': 0,
        'locked_until': None,
    }
    users[user_id] = user
    _save_users(users)
    return user, None


def get_user_by_username(username):
    users = _load_users()
    for u in users.values():
        if u['username'].lower() == username.lower():
            return u
    return None

def get_user_by_id(user_id):
    users = _load_users()
    return users.get(user_id)


def verify_password(user, password):
    """Check password against bcrypt hash. Returns bool."""
    return bcrypt.checkpw(password.encode('utf-8'),
                          user['password_hash'].encode('utf-8'))


def is_account_locked(user):
    if user.get('locked_until') and time.time() < user['locked_until']:
        remaining = int(user['locked_until'] - time.time())
        return True, remaining
    return False, 0


def record_failed_attempt(user_id):
    """Increment failed attempts; lock account after MAX_LOGIN_ATTEMPTS."""
    users = _load_users()
    user = users.get(user_id)
    if not user:
        return

    user['failed_attempts'] = user.get('failed_attempts', 0) + 1
    if user['failed_attempts'] >= Config.MAX_LOGIN_ATTEMPTS:
        user['locked_until'] = time.time() + Config.LOCKOUT_MINUTES * 60

    users[user_id] = user
    _save_users(users)


def reset_failed_attempts(user_id):
    """Clear lockout on successful login."""
    users = _load_users()
    if user_id in users:
        users[user_id]['failed_attempts'] = 0
        users[user_id]['locked_until'] = None
        _save_users(users)


def safe_user_dict(user):
    """Return a user dict with sensitive fields removed."""
    return {k: v for k, v in user.items()
            if k not in ('password_hash',)}
