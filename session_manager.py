"""
Secure session management using file-based storage.
Tokens are generated with secrets.token_urlsafe(32) — cryptographically random.
"""

import secrets
import time
import json
import os
from flask import request
from config import Config


class SessionManager:
    def __init__(self):
        self.timeout = Config.SESSION_TIMEOUT
        self.sessions_file = os.path.join(Config.DATA_DIR, 'sessions.json')
        self._ensure_file()

    def _ensure_file(self):
        if not os.path.exists(self.sessions_file):
            with open(self.sessions_file, 'w') as f:
                json.dump({}, f)

    def _load(self):
        try:
            with open(self.sessions_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}

    def _save(self, sessions):
        with open(self.sessions_file, 'w') as f:
            json.dump(sessions, f, indent=2)

    def create_session(self, user_id, user_data=None):
        """Create a new session token. Returns the token string."""
        token = secrets.token_urlsafe(32)
        session = {
            'token': token,
            'user_id': user_id,
            'user': user_data or {},
            'created_at': time.time(),
            'last_activity': time.time(),
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', '')[:200],
        }
        sessions = self._load()
        sessions[token] = session
        self._save(sessions)
        return token

    def validate_session(self, token):
        """Return session dict if valid, else None."""
        sessions = self._load()
        if token not in sessions:
            return None

        session = sessions[token]

        # Timeout check
        if time.time() - session['last_activity'] > self.timeout:
            self.destroy_session(token)
            return None

        # Only save if last_activity is meaningfully stale (e.g. 60 seconds)
        now = time.time()
        if now - session['last_activity'] > 60:
            session['last_activity'] = now
            sessions[token] = session
            self._save(sessions)

        return session

    def destroy_session(self, token):
        """Delete a session (logout)."""
        sessions = self._load()
        sessions.pop(token, None)
        self._save(sessions)

    def destroy_all_user_sessions(self, user_id):
        """Force-logout a user from all devices."""
        sessions = self._load()
        to_delete = [t for t, s in sessions.items() if s['user_id'] == user_id]
        for t in to_delete:
            del sessions[t]
        self._save(sessions)

    def purge_expired(self):
        """Remove all timed-out sessions (call periodically)."""
        sessions = self._load()
        now = time.time()
        active = {t: s for t, s in sessions.items()
                  if now - s['last_activity'] <= self.timeout}
        self._save(active)
