"""Initialize a free demo and require the configured hybrid artifact to load.

Gunicorn imports this inside its single worker, after forking. No weights,
thresholds, preprocessing, routes, or existing application files are changed.
"""
import os
from pathlib import Path


def validate_environment():
    secret = os.environ.get('SECRET_KEY', '')
    if len(secret) < 32 or secret.lower().startswith(('replace-', 'change-me')):
        raise RuntimeError('Set a stable, random SECRET_KEY of at least 32 characters.')
    if os.environ.get('DB_BACKEND') != 'sqlite':
        raise RuntimeError('This demonstration deployment uses ephemeral SQLite.')
    if os.environ.get('SESSION_COOKIE_SECURE', '').lower() != 'true':
        raise RuntimeError('HTTPS deployment requires SESSION_COOKIE_SECURE=true.')
    if os.environ.get('SQLI_MODE') != 'hybrid':
        raise RuntimeError('The deployment requires the existing hybrid detector.')
    root = Path(__file__).resolve().parents[1]
    configured = os.environ.get('SQLI_MODEL_DIR', '')
    if not configured or (root / configured).resolve() != root / 'models/repair_v1/word':
        raise RuntimeError('SQLI_MODEL_DIR must select models/repair_v1/word.')
    if Path.cwd().resolve() != root:
        raise RuntimeError('Start the deployment from the repository root.')
    return root


root = validate_environment()

from app import app
from flask import request
from database import init_db, query, create_single_admin
from werkzeug.security import generate_password_hash

if os.environ.get('RENDER') == 'true':
    expected = Path('/opt/render/project/src/instance')
    if Path(app.instance_path) != expected:
        raise RuntimeError('The database path does not match the Render application directory.')

_initialized_pid = None


def initialize_worker():
    """Create TensorFlow's thread pools only inside the serving worker."""
    global _initialized_pid
    if _initialized_pid == os.getpid():
        return
    active = app.extensions['sqli_detector']
    active.load()
    if active.mode != 'hybrid' or active.runtime is None or active.error:
        raise RuntimeError('The configured hybrid model failed its startup compatibility check.')
    with app.app_context():
        init_db()
        # Free services have no shell and lose local data on cold starts.
        # Existing administrator credentials are never reset here.
        if not query('SELECT user_id FROM admin_access WHERE slot=1', fetch=True):
            email = os.environ.get('ADMIN_EMAIL', '').strip().casefold()
            password = os.environ.get('ADMIN_PASSWORD', '')
            if '@' not in email or len(password) < 24:
                raise RuntimeError('Provide ADMIN_EMAIL and a private ADMIN_PASSWORD of at least 24 characters.')
            create_single_admin(email, generate_password_hash(password))
    _initialized_pid = os.getpid()
    app.logger.warning('Hosted worker ready: pid=%s hybrid model loaded; database initialized.', _initialized_pid)


@app.before_request
def require_initialized_worker():
    if _initialized_pid != os.getpid():
        raise RuntimeError('The hosting worker initialization hook has not run.')
