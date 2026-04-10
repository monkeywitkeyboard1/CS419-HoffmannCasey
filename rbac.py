"""
Role-Based Access Control (RBAC)
Roles: admin > user > guest
"""

from functools import wraps
from flask import g, redirect, url_for, abort
from security_logger import SecurityLogger, log_access_denied

security_log = SecurityLogger()

ROLES = ['guest', 'user', 'admin']

PERMISSIONS = {
    'create_document':  ['user', 'admin'],
    'edit_own':         ['user', 'admin'],
    'delete_own':       ['user', 'admin'],
    'view_all':         ['admin'],
    'manage_users':     ['admin'],
    'view_shared':      ['guest', 'user', 'admin'],
    'admin_dashboard':  ['admin'],
}


def has_permission(user, permission):
    """Check if a user dict has the given permission."""
    if not user:
        return False
    role = user.get('role', 'guest')
    return role in PERMISSIONS.get(permission, [])


def role_rank(role):
    return ROLES.index(role) if role in ROLES else -1


def require_auth(f):
    """Redirect unauthenticated users to login."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.user_id:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated


def require_role(role):
    """Require at least the given role level."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not g.user_id:
                return redirect(url_for('auth.login'))
            user = g.user or {}
            if role_rank(user.get('role', 'guest')) < role_rank(role):
                log_access_denied(security_log, g.user_id, f.__name__)
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator


def require_permission(permission):
    """Require a named permission."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not g.user_id:
                return redirect(url_for('auth.login'))
            if not has_permission(g.user, permission):
                log_access_denied(security_log, g.user_id, permission)
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator
