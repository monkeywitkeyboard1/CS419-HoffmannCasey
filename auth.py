"""
Authentication blueprint: /register, /login, /logout
"""

from flask import Blueprint, request, render_template, redirect, url_for, make_response, flash, g
from user_store import (create_user, get_user_by_username, verify_password,
                        is_account_locked, record_failed_attempt,
                        reset_failed_attempts, safe_user_dict)
from session_manager import SessionManager
from security_logger import (SecurityLogger, log_login_success, log_login_fail,
                             log_account_locked, log_validation_failure)
from rate_limiter import RateLimiter
import html

auth_bp = Blueprint('auth', __name__)
session_manager = SessionManager()
security_log = SecurityLogger()
rate_limiter = RateLimiter()


def sanitize(value):
    """Escape HTML to prevent XSS."""
    return html.escape(str(value).strip())


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if g.user_id:
        return redirect(url_for('documents.dashboard'))

    if request.method == 'POST':
        username = sanitize(request.form.get('username', ''))
        email = sanitize(request.form.get('email', ''))
        password = request.form.get('password', '')  # Don't escape — goes to bcrypt
        confirm = request.form.get('confirm_password', '')

        if password != confirm:
            flash('Passwords do not match', 'error')
            return render_template('auth/register.html')

        user, error = create_user(username, email, password)
        if error:
            log_validation_failure(security_log, None, 'registration', error)
            flash(error, 'error')
            return render_template('auth/register.html')

        flash('Account created! Please log in.', 'success')
        security_log.log_event('USER_REGISTERED', user['id'], {'username': username})
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if g.user_id:
        return redirect(url_for('documents.dashboard'))

    if request.method == 'POST':
        ip = request.remote_addr

        # IP-level rate limiting
        if not rate_limiter.allow(ip):
            security_log.log_event('RATE_LIMIT_HIT', None,
                                   {'ip': ip}, severity='WARNING')
            flash('Too many login attempts. Please wait a minute.', 'error')
            return render_template('auth/login.html'), 429

        username = sanitize(request.form.get('username', ''))
        password = request.form.get('password', '')

        user = get_user_by_username(username)

        if not user:
            log_login_fail(security_log, username, 'User not found')
            flash('Invalid credentials', 'error')
            return render_template('auth/login.html')

        # Lockout check
        locked, remaining = is_account_locked(user)
        if locked:
            flash(f'Account locked. Try again in {remaining // 60 + 1} minute(s).', 'error')
            return render_template('auth/login.html')

        if not verify_password(user, password):
            record_failed_attempt(user['id'])
            log_login_fail(security_log, username, 'Wrong password')

            # Check if this attempt triggered a lockout
            locked, _ = is_account_locked(user)
            if locked:
                log_account_locked(security_log, user['id'], username)
                flash('Account locked after too many failed attempts.', 'error')
            else:
                flash('Invalid credentials', 'error')

            return render_template('auth/login.html')

        # ── Success ──────────────────────────────────────────────────────────
        reset_failed_attempts(user['id'])
        token = session_manager.create_session(user['id'], safe_user_dict(user))
        log_login_success(security_log, user['id'], username)

        response = make_response(redirect(url_for('documents.dashboard')))
        response.set_cookie(
            'session_token',
            token,
            httponly=True,
            secure=True,
            samesite='Strict',
            max_age=1800,
        )
        return response

    return render_template('auth/login.html')


@auth_bp.route('/logout', methods=['POST'])
def logout():
    token = request.cookies.get('session_token')
    if token:
        session_manager.destroy_session(token)
        security_log.log_event('LOGOUT', g.user_id, {})

    response = make_response(redirect(url_for('auth.login')))
    response.delete_cookie('session_token')
    return response
