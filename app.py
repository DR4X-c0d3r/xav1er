# backend/app.py
from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import sqlite3
import datetime
import ipaddress
import re
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import os

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['DATABASE'] = os.path.join(os.path.dirname(__file__), 'waf.db')
app.config['ALLOWED_DOMAINS'] = ['yourdomain.com']  # Admin can add more

# Rate limiting
limiter = Limiter(
    app=app,  # Use named parameter
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Database setup
def get_db():
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with app.app_context():
        db = get_db()
        try:
            # Check if tables exist
            db.execute("SELECT 1 FROM admins LIMIT 1")
            db.execute("SELECT 1 FROM requests LIMIT 1")
            db.execute("SELECT 1 FROM blocked_ips LIMIT 1")
        except sqlite3.OperationalError:
            # Tables don't exist, create them
            db.execute('''
            CREATE TABLE admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
            ''')
            
            db.execute('''
            CREATE TABLE requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                user_agent TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_attack BOOLEAN DEFAULT 0,
                attack_type TEXT,
                blocked BOOLEAN DEFAULT 0
            )
            ''')
            
            db.execute('''
            CREATE TABLE blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL UNIQUE,
                reason TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            # Add default admin
            try:
                db.execute(
                    "INSERT INTO admins (username, password_hash) VALUES (?, ?)",
                    ('admin', generate_password_hash('admin'))
                )
                db.commit()
                print("Database initialized successfully")
            except sqlite3.IntegrityError:
                db.rollback()
                print("Default admin already exists")
        finally:
            db.close()

# Authentication decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            return redirect(url_for('login'))
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# WAF Core Functions
def is_malicious_request(req):
    """Analyze request for potential attacks"""
    # SQL Injection check
    sql_injection_patterns = [
        r'(\%27)|(\')|(\-\-)',
        r'((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))',
        r'\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))'
    ]
    
    # XSS check
    xss_patterns = [
        r'(\%3C)|<[^\n]*((\%3E)|>)',
        r'((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)',
        r'((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))[^\n]+((\%3E)|>)'
    ]
    
    # Path traversal
    traversal_patterns = [
        r'\.\.\/',
        r'\.\.\\',
        r'\/etc\/passwd'
    ]
    
    # Combine all checks
    all_checks = {
        'SQL Injection': sql_injection_patterns,
        'XSS': xss_patterns,
        'Path Traversal': traversal_patterns
    }
    
    # Check request path and query parameters
    for attack_type, patterns in all_checks.items():
        for pattern in patterns:
            if re.search(pattern, req.path, re.IGNORECASE):
                return True, attack_type
            if re.search(pattern, req.query_string.decode(), re.IGNORECASE):
                return True, attack_type
    
    return False, None

# API Endpoints
@app.route('/api/log_request', methods=['POST'])
def log_request():
    """Endpoint for applications to send request data"""
    data = request.json
    ip = data.get('ip', request.remote_addr)
    method = data.get('method')
    path = data.get('path')
    user_agent = data.get('user_agent')
    
    if not all([ip, method, path]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Check if IP is blocked
    db = get_db()
    blocked = db.execute('SELECT 1 FROM blocked_ips WHERE ip = ?', (ip,)).fetchone()
    if blocked:
        return jsonify({'error': 'IP blocked'}), 403
    
    # Analyze request
    is_attack, attack_type = is_malicious_request(request)
    
    # Log request
    db.execute(
        'INSERT INTO requests (ip, method, path, user_agent, is_attack, attack_type) VALUES (?, ?, ?, ?, ?, ?)',
        (ip, method, path, user_agent, is_attack, attack_type)
    )
    db.commit()
    db.close()
    
    if is_attack:
        return jsonify({'warning': 'Potential attack detected'}), 200
    return jsonify({'message': 'Request logged'}), 200

@app.route('/api/requests')
@admin_required
def get_requests():
    """Get all requests with filters"""
    is_attack = request.args.get('is_attack')
    limit = request.args.get('limit', 100)
    
    query = 'SELECT * FROM requests ORDER BY timestamp DESC LIMIT ?'
    params = [limit]
    
    if is_attack == 'true':
        query = 'SELECT * FROM requests WHERE is_attack = 1 ORDER BY timestamp DESC LIMIT ?'
    elif is_attack == 'false':
        query = 'SELECT * FROM requests WHERE is_attack = 0 ORDER BY timestamp DESC LIMIT ?'
    
    db = get_db()
    requests = db.execute(query, params).fetchall()
    db.close()
    
    return jsonify([dict(row) for row in requests])

@app.route('/api/block_ip', methods=['POST'])
@admin_required
def block_ip():
    """Block an IP address"""
    data = request.json
    ip = data.get('ip')
    reason = data.get('reason', 'Manual block by admin')
    
    if not ip:
        return jsonify({'error': 'IP required'}), 400
    
    try:
        # Validate IP
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({'error': 'Invalid IP address'}), 400
    
    db = get_db()
    try:
        db.execute(
            'INSERT INTO blocked_ips (ip, reason) VALUES (?, ?)',
            (ip, reason)
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.close()
        return jsonify({'error': 'IP already blocked'}), 400
    
    db.close()
    return jsonify({'message': 'IP blocked successfully'})

# Admin routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        db = get_db()
        admin = db.execute(
            'SELECT * FROM admins WHERE username = ?', 
            (username,)
        ).fetchone()
        db.close()
        
        if not admin or not check_password_hash(admin['password_hash'], password):
            return render_template('login.html', error='Invalid credentials')
        
        # Create JWT token
        token = jwt.encode({
            'username': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=8)
        }, app.config['SECRET_KEY'])
        
        response = redirect(url_for('dashboard'))
        response.set_cookie('token', token)
        return response
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    response = redirect(url_for('login'))
    response.set_cookie('token', '', expires=0)
    return response

@app.route('/settings')
@admin_required
def settings():
    return render_template('settings.html')

@app.route('/')
@admin_required
def dashboard():
    return render_template('dashboard.html')

# Add these new routes to your existing app.py

# Settings API Endpoints
@app.route('/api/settings/domains', methods=['GET', 'POST', 'DELETE'])
@admin_required
def manage_domains():
    if request.method == 'GET':
        return jsonify({'domains': app.config['ALLOWED_DOMAINS']})
    
    data = request.json
    if request.method == 'POST':
        domain = data.get('domain')
        if domain and domain not in app.config['ALLOWED_DOMAINS']:
            app.config['ALLOWED_DOMAINS'].append(domain)
            return jsonify({'message': 'Domain added'})
        
    elif request.method == 'DELETE':
        domain = data.get('domain')
        if domain and domain in app.config['ALLOWED_DOMAINS']:
            app.config['ALLOWED_DOMAINS'].remove(domain)
            return jsonify({'message': 'Domain removed'})
    
    return jsonify({'error': 'Invalid request'}), 400

@app.route('/api/settings/security_rules', methods=['GET', 'POST'])
@admin_required
def security_rules():
    if request.method == 'GET':
        # Return current security rules
        return jsonify({
            'sql_injection_protection': True,
            'xss_protection': True,
            'rate_limiting': True
        })
    
    # Update rules
    data = request.json
    # In a real implementation, you would save these to database
    return jsonify({'message': 'Security rules updated'})

@app.route('/api/settings/change_password', methods=['POST'])
@admin_required
def change_password():
    data = request.json
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    token = request.cookies.get('token')
    token_data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    username = token_data['username']
    
    db = get_db()
    admin = db.execute(
        'SELECT * FROM admins WHERE username = ?', 
        (username,)
    ).fetchone()
    
    if not admin or not check_password_hash(admin['password_hash'], current_password):
        return jsonify({'error': 'Current password is incorrect'}), 400
    
    db.execute(
        'UPDATE admins SET password_hash = ? WHERE username = ?',
        (generate_password_hash(new_password), username)
    )
    db.commit()
    db.close()
    
    return jsonify({'message': 'Password updated successfully'})

if __name__ == '__main__':
    init_db()
    app.run(debug=True)