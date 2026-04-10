"""
Documents blueprint: upload, download, share, delete
"""

import html
from flask import (Blueprint, render_template, request, redirect,
                   url_for, g, flash, send_file, abort)
from rbac import require_auth, require_permission
from document_store import (upload_document, download_document,
                             get_user_documents, share_document, delete_document)
from security_logger import SecurityLogger, log_data_access, log_validation_failure
from user_store import get_user_by_username
import io

docs_bp = Blueprint('documents', __name__, url_prefix='/documents')
security_log = SecurityLogger()


def sanitize(v):
    return html.escape(str(v).strip())


@docs_bp.route('/')
@require_auth
def dashboard():
    user = g.user or {}
    docs = get_user_documents(g.user_id, user.get('role', 'user'))
    return render_template('documents/dashboard.html', documents=docs, user=user)


@docs_bp.route('/upload', methods=['GET', 'POST'])
@require_auth
@require_permission('create_document')
def upload():
    if request.method == 'POST':
        if 'file' not in request.files or request.files['file'].filename == '':
            flash('No file selected', 'error')
            return render_template('documents/upload.html')

        title = sanitize(request.form.get('title', ''))[:200]
        description = sanitize(request.form.get('description', ''))[:500]

        if not title:
            flash('Title is required', 'error')
            return render_template('documents/upload.html')

        doc, error = upload_document(request.files['file'], g.user_id,
                                     title, description)
        if error:
            log_validation_failure(security_log, g.user_id, 'file_upload', error)
            flash(error, 'error')
            return render_template('documents/upload.html')

        log_data_access(security_log, g.user_id, doc['id'], 'upload')
        flash('Document uploaded and encrypted successfully!', 'success')
        return redirect(url_for('documents.dashboard'))

    return render_template('documents/upload.html')


@docs_bp.route('/download/<doc_id>')
@require_auth
def download(doc_id):
    # Validate doc_id format to prevent injection
    if not doc_id.startswith('doc_') or not doc_id[4:].isdigit():
        abort(400)

    user = g.user or {}
    try:
        data, filename = download_document(doc_id, g.user_id, user.get('role', 'user'))
        log_data_access(security_log, g.user_id, doc_id, 'download')
        return send_file(
            io.BytesIO(data),
            download_name=filename,
            as_attachment=True
        )
    except PermissionError:
        abort(403)
    except FileNotFoundError:
        abort(404)


@docs_bp.route('/share/<doc_id>', methods=['POST'])
@require_auth
@require_permission('edit_own')
def share(doc_id):
    target_username = sanitize(request.form.get('username', ''))
    role = request.form.get('role', 'viewer')

    if role not in ('viewer', 'editor'):
        flash('Invalid role', 'error')
        return redirect(url_for('documents.dashboard'))

    target = get_user_by_username(target_username)
    if not target:
        flash('User not found', 'error')
        return redirect(url_for('documents.dashboard'))

    try:
        share_document(doc_id, g.user_id, target['id'], role)
        log_data_access(security_log, g.user_id, doc_id,
                        f'share_with_{target["id"]}')
        flash(f'Shared with {target_username} as {role}', 'success')
    except PermissionError:
        abort(403)

    return redirect(url_for('documents.dashboard'))


@docs_bp.route('/delete/<doc_id>', methods=['POST'])
@require_auth
@require_permission('delete_own')
def delete(doc_id):
    user = g.user or {}
    try:
        delete_document(doc_id, g.user_id, user.get('role', 'user'))
        log_data_access(security_log, g.user_id, doc_id, 'delete')
        flash('Document deleted', 'success')
    except PermissionError:
        abort(403)
    except FileNotFoundError:
        abort(404)

    return redirect(url_for('documents.dashboard'))
