"""Per-request connections; explicit schema initialization never drops data."""
import os
import sqlite3
from flask import g, current_app

def connection():
    if 'db' not in g:
        if current_app.config['DB_BACKEND'] == 'sqlite':
            g.db = sqlite3.connect(current_app.config['SQLITE_PATH'])
        else:
            import mysql.connector
            g.db = mysql.connector.connect(host=os.getenv('DB_HOST', '127.0.0.1'),
                port=int(os.getenv('DB_PORT', '3306')), user=os.environ['DB_USER'],
                password=os.environ['DB_PASSWORD'], database=os.getenv('DB_NAME', 'sqli_project'))
    return g.db

def query(sql, args=(), fetch=False):
    db = connection()
    cursor = db.cursor()
    try:
        cursor.execute(sql.replace('%s', '?') if current_app.config['DB_BACKEND'] == 'sqlite' else sql, args)
        if fetch:
            return cursor.fetchall()
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        cursor.close()

def init_db():
    mysql = current_app.config['DB_BACKEND'] == 'mysql'
    pk = 'INTEGER PRIMARY KEY AUTO_INCREMENT' if mysql else 'INTEGER PRIMARY KEY AUTOINCREMENT'
    for sql in [
        f'''CREATE TABLE IF NOT EXISTS users (id {pk}, full_name VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL, password VARCHAR(255) NOT NULL, role VARCHAR(20) DEFAULT 'user')''',
        f'''CREATE TABLE IF NOT EXISTS contacts (id {pk}, name VARCHAR(255), email VARCHAR(255), message TEXT)''',
        f'''CREATE TABLE IF NOT EXISTS security_events (id {pk}, timestamp VARCHAR(32), endpoint VARCHAR(255),
            score DOUBLE, risk VARCHAR(10), decision VARCHAR(10), category VARCHAR(50), indicators TEXT,
            model_probability DOUBLE, model_status VARCHAR(255), actor VARCHAR(64))''']:
        query(sql)
    configure_single_admin()
    # Explicit init-db adds metadata columns without dropping or rewriting rows.
    columns = ({r[1] for r in query('PRAGMA table_info(security_events)', fetch=True)} if not mysql
               else {r[0] for r in query('SHOW COLUMNS FROM security_events', fetch=True)})
    for name, kind in [('mode','VARCHAR(20)'),('decision_source','VARCHAR(20)'),
                       ('rule_score','DOUBLE'),('model_error','VARCHAR(255)')]:
        if name not in columns:
            query(f'ALTER TABLE security_events ADD COLUMN {name} {kind}')

def configure_single_admin():
    """Reserve slot 1 for the sole administrator; never demote existing accounts."""
    query('CREATE TABLE IF NOT EXISTS admin_access (slot INTEGER PRIMARY KEY, user_id INTEGER UNIQUE NOT NULL)')
    admins = query("SELECT id FROM users WHERE role=%s", ('admin',), True)
    if len(admins) > 1:
        raise ValueError('Multiple existing admin accounts found. Resolve their roles locally before enabling admin access.')
    assigned = query('SELECT user_id FROM admin_access WHERE slot=1', fetch=True)
    if admins and not assigned:
        query('INSERT INTO admin_access(slot,user_id) VALUES(1,%s)', (admins[0][0],))
    elif admins and assigned[0][0] != admins[0][0]:
        raise ValueError('Admin account does not match the reserved administrator slot')

def create_single_admin(email, password_hash):
    db = connection()
    cursor = db.cursor()
    sqlite = current_app.config['DB_BACKEND'] == 'sqlite'
    def execute(sql, values=()):
        cursor.execute(sql.replace('%s','?') if sqlite else sql, values)
    try:
        if sqlite:
            cursor.execute('BEGIN IMMEDIATE')
        execute('SELECT user_id FROM admin_access WHERE slot=1')
        if cursor.fetchone():
            raise ValueError('The administrator already exists. Only one admin account is permitted.')
        execute('SELECT id FROM users WHERE email=%s OR role=%s', (email,'admin'))
        if cursor.fetchall():
            raise ValueError('Account or administrator already exists; no roles changed.')
        execute('INSERT INTO users(full_name,email,password,role) VALUES(%s,%s,%s,%s)',
                ('Administrator',email,password_hash,'admin'))
        user_id = cursor.lastrowid
        # Concurrent attempts contend for this primary key; the loser rolls back its user too.
        execute('INSERT INTO admin_access(slot,user_id) VALUES(1,%s)', (user_id,))
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        cursor.close()

def is_single_admin(user_id):
    return bool(query("SELECT u.id FROM users u JOIN admin_access a ON a.user_id=u.id WHERE a.slot=1 AND u.id=%s AND u.role=%s", (user_id,'admin'), True))

def close_db(error=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()
