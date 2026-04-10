"""
Structured security event logger.
Writes JSON-formatted log entries to logs/security.log.
"""

import logging
import json
import os
from datetime import datetime, timezone
from flask import request
from config import Config


class SecurityLogger:
    def __init__(self):
        log_path = os.path.join(Config.LOGS_DIR, 'security.log')
        self.logger = logging.getLogger('security')
        self.logger.setLevel(logging.DEBUG)

        if not self.logger.handlers:
            handler = logging.FileHandler(log_path)
            handler.setFormatter(logging.Formatter('%(message)s'))
            self.logger.addHandler(handler)

    def log_event(self, event_type, user_id, details, severity='INFO'):
        """Log a structured security event."""
        try:
            ip = request.remote_addr
            ua = request.headers.get('User-Agent', '')[:200]
        except RuntimeError:
            ip = 'N/A'
            ua = 'N/A'

        entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event_type': event_type,
            'user_id': user_id,
            'ip_address': ip,
            'user_agent': ua,
            'details': details,
            'severity': severity,
        }

        line = json.dumps(entry)
        getattr(self.logger, severity.lower(), self.logger.info)(line)


# Common event helpers (keeps call sites clean)
def log_login_success(logger, user_id, username):
    logger.log_event('LOGIN_SUCCESS', user_id, {'username': username})

def log_login_fail(logger, username, reason):
    logger.log_event('LOGIN_FAILED', None, {'username': username, 'reason': reason},
                     severity='WARNING')

def log_account_locked(logger, user_id, username):
    logger.log_event('ACCOUNT_LOCKED', user_id,
                     {'username': username, 'reason': '5 failed attempts'},
                     severity='ERROR')

def log_access_denied(logger, user_id, resource):
    logger.log_event('ACCESS_DENIED', user_id, {'resource': resource},
                     severity='WARNING')

def log_data_access(logger, user_id, resource, action):
    logger.log_event('DATA_ACCESS', user_id, {'resource': resource, 'action': action})

def log_validation_failure(logger, user_id, field, reason):
    logger.log_event('VALIDATION_FAILURE', user_id,
                     {'field': field, 'reason': reason}, severity='WARNING')
