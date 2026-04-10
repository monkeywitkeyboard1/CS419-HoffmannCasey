"""
Configuration - loaded from environment variables.
Never hardcode secrets here. Use a .env file locally (git-ignored).
"""

import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask secret (used for flash messages, CSRF tokens)
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-only-change-me-in-prod'

    # Session
    SESSION_TIMEOUT = int(os.environ.get('SESSION_TIMEOUT', 1800))  # 30 min

    # Auth
    BCRYPT_ROUNDS = 12
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_MINUTES = 15
    RATE_LIMIT_PER_MINUTE = 10

    # Paths
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    DATA_DIR = os.path.join(BASE_DIR, 'data')
    LOGS_DIR = os.path.join(BASE_DIR, 'logs')
    UPLOAD_DIR = os.path.join(DATA_DIR, 'uploads')

    # Upload limits
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB
    ALLOWED_EXTENSIONS = {'pdf', 'txt', 'docx', 'png', 'jpg', 'jpeg'}

    # Environment
    ENV = os.environ.get('FLASK_ENV', 'development')

    # Ensure dirs exist
    for d in (DATA_DIR, LOGS_DIR, UPLOAD_DIR):
        os.makedirs(d, exist_ok=True)
