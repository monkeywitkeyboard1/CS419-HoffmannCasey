"""
Admin blueprint: user management, audit logs
"""

import json
from flask import Blueprint, render_template, request, redirect, url_for, flash, g, abort
from rbac import require_role
from user_store import _load_users, _save_users, safe_user_dict
from session_manager import SessionManager
from security_logger import SecurityLogger

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')
session_manager = SessionManager()
security_log = SecurityLogger()


@admin_bp.route('/dashboard')
@require_role('admin')
def dashboard():
    users = {uid: safe_user_dict(u) for uid, u in _load_users().items()}
    return render_template('admin/dashboard.html', users=users, user=g.user)


@admin_bp.route('/users/<user_id>/lock', methods=['POST'])
@require_role('admin')
def lock_user(user_id):
    import time
    users = _load_users()
    if user_id not in users:
        abort(404)
    users[user_id]['locked_until'] = time.time() + 365 * 24 * 3600  # 1 year
    _save_users(users)
    security_log.log_event('ADMIN_LOCK_USER', g.user_id,
                           {'target': user_id}, severity='WARNING')
    flash('User locked', 'success')
    return redirect(url_for('admin.dashboard'))


@admin_bp.route('/users/<user_id>/unlock', methods=['POST'])
@require_role('admin')
def unlock_user(user_id):
    users = _load_users()
    if user_id not in users:
        abort(404)
    users[user_id]['locked_until'] = None
    users[user_id]['failed_attempts'] = 0
    _save_users(users)
    security_log.log_event('ADMIN_UNLOCK_USER', g.user_id, {'target': user_id})
    flash('User unlocked', 'success')
    return redirect(url_for('admin.dashboard'))


@admin_bp.route('/users/<user_id>/delete', methods=['POST'])
@require_role('admin')
def delete_user(user_id):
    if user_id == g.user_id:
        flash('Cannot delete your own account', 'error')
        return redirect(url_for('admin.dashboard'))
    users = _load_users()
    if user_id in users:
        session_manager.destroy_all_user_sessions(user_id)
        del users[user_id]
        _save_users(users)
        security_log.log_event('ADMIN_DELETE_USER', g.user_id,
                               {'target': user_id}, severity='WARNING')
    flash('User deleted', 'success')
    return redirect(url_for('admin.dashboard'))


@admin_bp.route('/logs')
@require_role('admin')
def audit_logs():
    """Show last 200 security log entries."""
    try:
        with open('logs/security.log', 'r') as f:
            lines = f.readlines()[-200:]
        entries = []
        for line in reversed(lines):
            try:
                entries.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                pass
    except FileNotFoundError:
        entries = []
    return render_template('admin/logs.html', entries=entries, user=g.user)
