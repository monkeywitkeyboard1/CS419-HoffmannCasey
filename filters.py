"""
Jinja2 custom filters.
Register these in app.py via app.template_filter().
"""

from datetime import datetime, timezone


def timestamp_to_date(ts):
    """Convert a Unix timestamp float to a human-readable date string."""
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime('%Y-%m-%d %H:%M')
    except (ValueError, TypeError):
        return '—'
