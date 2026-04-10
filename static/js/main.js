/**
 * main.js - Client-side helpers
 * Note: No inline event handlers in templates where avoidable.
 * All input sanitization is done server-side; this is UX-only.
 */

'use strict';

// ── Auto-dismiss alerts ──────────────────────────────────────────────────────
document.querySelectorAll('.alert').forEach(alert => {
  setTimeout(() => {
    alert.style.transition = 'opacity .4s';
    alert.style.opacity = '0';
    setTimeout(() => alert.remove(), 400);
  }, 5000);
});

// ── Drag-and-drop upload zone ────────────────────────────────────────────────
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');

if (dropZone && fileInput) {
  dropZone.addEventListener('click', () => fileInput.click());

  dropZone.addEventListener('dragover', e => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
  });

  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('drag-over');
  });

  dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      fileInput.files = files;
      updateDropLabel(files[0].name);
    }
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
      updateDropLabel(fileInput.files[0].name);
    }
  });

  function updateDropLabel(filename) {
    const p = dropZone.querySelector('p');
    if (p) p.textContent = filename;
  }
}

// ── Confirm-before-delete (fallback for browsers blocking inline JS) ─────────
document.querySelectorAll('[data-confirm]').forEach(el => {
  el.addEventListener('submit', e => {
    if (!confirm(el.dataset.confirm)) e.preventDefault();
  });
});

// ── Share form toggle ─────────────────────────────────────────────────────────
document.querySelectorAll('[data-share-target]').forEach(btn => {
  btn.addEventListener('click', () => {
    const target = document.getElementById(btn.dataset.shareTarget);
    if (target) target.style.display = target.style.display === 'none' ? 'block' : 'none';
  });
});

// ── Password match check ─────────────────────────────────────────────────────
const confirm_pw = document.getElementById('confirm_password');
const pw = document.getElementById('password');

if (confirm_pw && pw) {
  confirm_pw.addEventListener('input', () => {
    if (confirm_pw.value && confirm_pw.value !== pw.value) {
      confirm_pw.setCustomValidity('Passwords do not match');
    } else {
      confirm_pw.setCustomValidity('');
    }
  });
}
