import hmac
import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from flask import Flask, render_template, request, redirect, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from ai_detector.detector import detector
from database import query, init_db, close_db, create_single_admin, is_single_admin
from soc_dashboard import soc_pages, admin_required, overview

load_dotenv()

def create_app(config=None):
    app = Flask(__name__)
    app.config.update(SECRET_KEY=os.getenv('SECRET_KEY') or secrets.token_hex(32),
        DB_BACKEND=os.getenv('DB_BACKEND', 'mysql'),
        SQLITE_PATH=str(Path(app.instance_path) / 'development.sqlite'),
        MAX_CONTENT_LENGTH=65536, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax')
    app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
    if config:
        app.config.update(config)
    app.extensions['sqli_detector'] = app.config.get('SQLI_DETECTOR', detector)
    Path(app.instance_path).mkdir(exist_ok=True)
    app.teardown_appcontext(close_db)
    app.jinja_env.globals['csrf_token'] = lambda: session.setdefault('csrf_token', secrets.token_urlsafe(32))
    app.register_blueprint(soc_pages)

    @app.before_request
    def protect_forms():
        if request.content_length and request.content_length > app.config['MAX_CONTENT_LENGTH']:
            abort(413)
        if request.method == 'POST':
            if request.content_length and request.mimetype not in ('application/x-www-form-urlencoded', 'multipart/form-data'):
                abort(415, 'This endpoint accepts HTML forms only')
            if request.files or any(len(request.form.getlist(k)) != 1 for k in request.form):
                abort(400, 'Duplicate fields and files are not accepted')
            expected = session.get('csrf_token', '')
            if not expected or not hmac.compare_digest(expected, request.form.get('csrf_token', '')):
                abort(400, 'Invalid CSRF token')

    def inspect_form():
        limits = {'name':255, 'full_name':255, 'email':255, 'message':8192,
                  'password':1024, 'confirm_password':1024}
        fields = {'/contact':('name','email','message'), '/login':('email','password'),
                  '/register':('full_name','email','password','confirm_password')}[request.path]
        if set(request.form) - set(fields) - {'csrf_token'}:
            abort(400, 'Unsupported form field')
        if any(not request.form.get(k, '').strip() for k in fields):
            abort(400, 'All fields are required')
        if any(len(request.form[k]) > limits[k] for k in fields):
            abort(413, 'Form field is too long')
        # Field boundaries matter. Passwords are inspected but never persisted.
        active = app.extensions['sqli_detector']
        results = [active.analyze(v, 'password' if 'password' in k else k)
                   for k in request.form for v in request.form.getlist(k) if k != 'csrf_token']
        result = max(results, key=lambda r: ({'ALLOW':0,'REVIEW':1,'BLOCK':2}[r['decision']], r['score']))
        actor = session.setdefault('security_actor', secrets.token_hex(16))
        query('''INSERT INTO security_events(timestamp,endpoint,score,risk,decision,category,indicators,model_probability,model_status,actor,
            mode,decision_source,rule_score,model_error) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
            (datetime.now(timezone.utc).isoformat(), request.path, result['score'], result['risk'], result['decision'],
             result['category'], json.dumps(result['indicators']), result['model_probability'], result['model_status'], actor,
             result['mode'],result['decision_source'],result['rule_score'],result['model_error']))
        if result['decision'] == 'BLOCK':
            flash('SQL Injection Detected!', 'danger')
            return True
        return False

    @app.route('/')
    def home():
        return render_template('home.html')

    @app.route('/about')
    def about():
        return render_template('about.html')

    @app.route('/contact', methods=['GET', 'POST'])
    def contact():
        if request.method == 'POST':
            if inspect_form():
                return redirect('/contact')
            values = [request.form.get(k, '').strip() for k in ('name','email','message')]
            if not all(values):
                abort(400, 'All fields are required')
            query('INSERT INTO contacts(name,email,message) VALUES(%s,%s,%s)', values)
            flash('Message Sent Successfully!', 'success')
        return render_template('contact.html')

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            if inspect_form():
                return redirect('/register')
            name, email, password = (request.form.get(k, '') for k in ('full_name','email','password'))
            email = email.strip().casefold()
            if not name.strip() or not email.strip() or len(password)<8 or password != request.form.get('confirm_password'):
                flash('Complete all fields and provide matching passwords of at least 8 characters.', 'danger')
                return redirect('/register')
            if query('SELECT id FROM users WHERE LOWER(email)=%s', (email,), True):
                flash('Unable to register this account.', 'danger')
                return redirect('/register')
            query('INSERT INTO users(full_name,email,password,role) VALUES(%s,%s,%s,%s)', (name,email,generate_password_hash(password),'user'))
            flash('Registration Successful!', 'success')
            return redirect('/login')
        return render_template('register.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            if inspect_form():
                return redirect('/login')
            rows = query('SELECT id,full_name,email,password,role FROM users WHERE LOWER(email)=%s', (request.form.get('email','').strip().casefold(),), True)
            password = request.form.get('password','')
            user = rows[0] if rows else None
            if user and user[3].startswith(('scrypt:', 'pbkdf2:')) and check_password_hash(user[3], password):
                actor = session.get('security_actor', secrets.token_hex(16))
                session.clear()
                session['security_actor'] = actor
                session.update(user_id=user[0], full_name=user[1], email=user[2], role=user[4])
                flash('Login Successful!', 'success')
                return redirect('/admin' if user[4]=='admin' else '/dashboard')
            flash('Invalid credentials. Legacy plaintext accounts require a password reset.', 'danger')
        return render_template('login.html')

    @app.route('/dashboard')
    def dashboard():
        return render_template('dashboard.html') if 'user_id' in session else redirect('/login')

    @app.route('/admin')
    @admin_required
    def admin():
        return overview()

    def database_unavailable(error):
        app.logger.error('Database operation failed (%s)', type(error).__name__)
        return 'Database temporarily unavailable. Please try again later.', 503
    app.register_error_handler(sqlite3.Error, database_unavailable)
    try:
        from mysql.connector import Error as MySQLError
        app.register_error_handler(MySQLError, database_unavailable)
    except ImportError:
        pass

    @app.route('/logout', methods=['POST'])
    def logout():
        session.clear()
        flash('Logged Out Successfully', 'info')
        return redirect('/')

    @app.cli.command('init-db')
    def initialize():
        init_db()
        print('Missing development tables created; existing tables and records preserved.')

    @app.cli.command('check-db')
    def check_database():
        import click
        expected={
            'users':{'id','full_name','email','password','role'},
            'contacts':{'id','name','email','message'},
            'admin_access':{'slot','user_id'},
            'security_events':{'id','timestamp','endpoint','score','risk','decision','category','indicators','model_probability','model_status','actor',
                               'mode','decision_source','rule_score','model_error'}}
        problems=[]
        for table,required in expected.items():
            if app.config['DB_BACKEND']=='sqlite':
                columns={row[1] for row in query('PRAGMA table_info('+table+')',fetch=True)}
            else:
                columns={row[0] for row in query('SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s',
                    (os.getenv('DB_NAME','sqli_project'),table),True)}
            missing=required-columns
            if missing: problems.append(table+': missing '+', '.join(sorted(missing)))
        if problems:
            raise click.ClickException('; '.join(problems)+'; no existing schema was modified')
        print('Database reachable; required columns present ('+app.config['DB_BACKEND']+').')

    @app.cli.command('create-admin')
    def create_admin():
        import click
        if query('SELECT user_id FROM admin_access WHERE slot=1', fetch=True):
            raise click.ClickException('The administrator already exists. Only one admin account is permitted.')
        email = click.prompt('Admin email')
        password = click.prompt('Admin password (8+ characters)', hide_input=True, confirmation_prompt=True)
        if len(password)<8:
            raise click.ClickException('Password must contain at least 8 characters')
        try:
            create_single_admin(email, generate_password_hash(password))
        except Exception as exc:
            raise click.ClickException('Administrator not created; an account may already exist or database setup is incomplete.') from exc
        print('Single administrator created. Sign in at /login to access /admin.')

    @app.cli.command('reset-password')
    def reset_password():
        import click
        email = click.prompt('Existing account email')
        if not query('SELECT id FROM users WHERE email=%s', (email,), True):
            raise click.ClickException('Account does not exist')
        password = click.prompt('New password', hide_input=True, confirmation_prompt=True)
        if len(password)<8:
            raise click.ClickException('Password must contain at least eight characters')
        query('UPDATE users SET password=%s WHERE email=%s', (generate_password_hash(password),email))
        print('Password hash updated; account and role preserved.')

    return app

app = create_app()
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
