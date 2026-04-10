"""
Encrypted document storage using Fernet symmetric encryption.
Encryption key is stored in data/secret.key (NOT committed to git).
"""

import json
import os
import time
import re
import mimetypes
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename
from config import Config

KEY_FILE = os.path.join(Config.DATA_DIR, 'secret.key')
DOCS_META_FILE = os.path.join(Config.DATA_DIR, 'documents.json')


def _get_cipher():
    """Load or generate the Fernet encryption key."""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
    return Fernet(key)


def _load_meta():
    if not os.path.exists(DOCS_META_FILE):
        return {}
    with open(DOCS_META_FILE, 'r') as f:
        return json.load(f)

def _save_meta(docs):
    with open(DOCS_META_FILE, 'w') as f:
        json.dump(docs, f, indent=2)


# ── Input validation ──────────────────────────────────────────────────────────

def safe_filename_check(filename):
    """
    Validate and sanitise filename.
    Returns clean name or raises ValueError.
    """
    name = secure_filename(filename)
    if not name:
        raise ValueError('Invalid filename')

    ext = name.rsplit('.', 1)[-1].lower() if '.' in name else ''
    if ext not in Config.ALLOWED_EXTENSIONS:
        raise ValueError(f'File type .{ext} not allowed')

    # Extra: no path separators survive secure_filename, but double-check
    if not re.match(r'^[\w\-\.]+$', name):
        raise ValueError('Filename contains invalid characters')

    return name


def safe_path(filename, base_dir=Config.UPLOAD_DIR):
    """
    Build an absolute path and verify it stays within base_dir.
    Prevents path traversal attacks.
    """
    full = os.path.abspath(os.path.join(base_dir, filename))
    if not full.startswith(os.path.abspath(base_dir) + os.sep):
        raise ValueError('Path traversal detected')
    return full


# ── Document operations ───────────────────────────────────────────────────────

def upload_document(file_storage, owner_id, title, description=''):
    """
    Encrypt and save an uploaded file. Returns (doc_dict, None) or (None, error).
    file_storage: Flask FileStorage object.
    """
    try:
        original_name = safe_filename_check(file_storage.filename)
    except ValueError as e:
        return None, str(e)

    doc_id = f"doc_{int(time.time() * 1000)}"
    stored_name = f"{doc_id}_{original_name}.enc"
    dest_path = safe_path(stored_name)

    cipher = _get_cipher()
    data = file_storage.read()

    # Validate MIME type matches extension (basic check)
    mime, _ = mimetypes.guess_type(original_name)
    if mime and mime.startswith('text/x-script'):
        return None, 'Script files are not allowed'

    encrypted = cipher.encrypt(data)
    with open(dest_path, 'wb') as f:
        f.write(encrypted)

    doc = {
        'id': doc_id,
        'title': title[:200],           # length limit
        'description': description[:500],
        'original_name': original_name,
        'stored_name': stored_name,
        'owner_id': owner_id,
        'shared_with': {},              # {user_id: role}
        'created_at': time.time(),
        'versions': [],
        'size': len(data),
    }

    docs = _load_meta()
    docs[doc_id] = doc
    _save_meta(docs)

    return doc, None


def download_document(doc_id, user_id, user_role='user'):
    """
    Decrypt and return file bytes if the user has access.
    Returns (bytes, original_filename) or raises PermissionError / FileNotFoundError.
    """
    docs = _load_meta()
    doc = docs.get(doc_id)
    if not doc:
        raise FileNotFoundError('Document not found')

    # Access check: owner, shared user, or admin
    if (doc['owner_id'] != user_id
            and user_id not in doc.get('shared_with', {})
            and user_role != 'admin'):
        raise PermissionError('Access denied')

    path = safe_path(doc['stored_name'])
    cipher = _get_cipher()
    with open(path, 'rb') as f:
        encrypted = f.read()

    return cipher.decrypt(encrypted), doc['original_name']


def get_user_documents(user_id, user_role='user'):
    """Return all documents visible to this user."""
    docs = _load_meta()
    if user_role == 'admin':
        return list(docs.values())
    return [d for d in docs.values()
            if d['owner_id'] == user_id or user_id in d.get('shared_with', {})]


def share_document(doc_id, owner_id, target_user_id, role='viewer'):
    """Share a document with another user (owner only)."""
    docs = _load_meta()
    doc = docs.get(doc_id)
    if not doc or doc['owner_id'] != owner_id:
        raise PermissionError('Only the owner can share this document')
    doc['shared_with'][target_user_id] = role
    _save_meta(docs)


def delete_document(doc_id, user_id, user_role='user'):
    """Securely delete a document (owner or admin only)."""
    docs = _load_meta()
    doc = docs.get(doc_id)
    if not doc:
        raise FileNotFoundError('Document not found')
    if doc['owner_id'] != user_id and user_role != 'admin':
        raise PermissionError('Access denied')

    # Overwrite file before deleting (basic secure deletion)
    try:
        path = safe_path(doc['stored_name'])
        size = os.path.getsize(path)
        with open(path, 'wb') as f:
            f.write(os.urandom(size))
        os.remove(path)
    except FileNotFoundError:
        pass

    del docs[doc_id]
    _save_meta(docs)
