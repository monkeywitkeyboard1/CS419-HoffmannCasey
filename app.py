"""
CS 419 - Secure Document Sharing System
Main application entry point
"""

from flask import Flask, render_template, request, redirect, url_for, g, make_response, abort, jsonify
from config import Config
from auth import auth_bp
from documents import docs_bp
from admin import admin_bp
from security import set_security_headers, require_https
from session_manager import SessionManager
from security_logger import SecurityLogger
from filters import timestamp_to_date
import os

app = Flask(__name__)
app.config.from_object(Config)

# Initialize core services
session_manager = SessionManager()
security_log = SecurityLogger()

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(docs_bp)
app.register_blueprint(admin_bp)

# Jinja2 filters
app.jinja_env.filters['timestamp_to_date'] = timestamp_to_date

# ── Security middleware ──────────────────────────────────────────────────────

@app.after_request
def apply_security_headers(response):
    return set_security_headers(response)

@app.before_request
def enforce_https():
    return require_https(app)

@app.before_request
def load_session():
    """Attach current user to g on every request."""
    token = request.cookies.get('session_token')
    g.user = None
    g.user_id = None
    if token:
        session_data = session_manager.validate_session(token)
        if session_data:
            g.user_id = session_data['user_id']
            g.user = session_data.get('user')

# ── Error handlers ───────────────────────────────────────────────────────────

@app.errorhandler(403)
def forbidden(e):
    security_log.log_event('ACCESS_DENIED', g.user_id,
                           {'path': request.path}, severity='WARNING')
    return render_template('errors/403.html'), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def server_error(e):
    # Never expose internal errors to users
    security_log.log_event('SERVER_ERROR', g.user_id,
                           {'path': request.path, 'error': str(e)}, severity='ERROR')
    return render_template('errors/500.html'), 500

# ── Root route ───────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if g.user_id:
        return redirect(url_for('documents.dashboard'))
    return render_template('index.html')

if __name__ == '__main__':
    # Development only - use gunicorn + TLS in production
    ssl_context = None
    if os.path.exists('cert.pem') and os.path.exists('key.pem'):
        ssl_context = ('cert.pem', 'key.pem')

    app.run(
        debug=False,          # NEVER True in production
        ssl_context=ssl_context,
        host='127.0.0.1',
        port=5000
    )
