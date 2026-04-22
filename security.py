"""
Security middleware: headers + HTTPS enforcement
"""

from flask import request, redirect


def set_security_headers(response):
    """Apply all required security headers to every response."""

    # Content Security Policy
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "script-src-attr 'none'; "         
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )

    # Clickjacking
    response.headers['X-Frame-Options'] = 'DENY'

    # MIME-sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # Legacy XSS filter
    response.headers['X-XSS-Protection'] = '1; mode=block'

    # Referrer
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Permissions
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'

    # HSTS (only effective over HTTPS)
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    return response


def require_https(app):
    """Redirect HTTP → HTTPS in non-development environments."""
    if not request.is_secure and app.config.get('ENV') != 'development':
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)