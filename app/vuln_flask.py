#!/usr/bin/env python3
"""
Vulnerable Flask Application - FOR EDUCATIONAL PURPOSES ONLY

This application contains intentional security vulnerabilities for learning.
DO NOT deploy this to production or expose it to the internet.

Vulnerabilities included:
- SQL Injection in login form
- Missing security headers
- Weak session management
- Information disclosure
"""

import sqlite3
import os
from flask import Flask, request, render_template_string, session, redirect, url_for

app = Flask(__name__)
app.secret_key = 'insecure_secret_key_for_demo'  # VULNERABILITY: Weak secret

# Database setup
DB_PATH = 'vulnerable_app.db'


def init_db():
    """Initialize SQLite database with sample data"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user'
        )
    ''')
    
    # Insert sample users
    cursor.execute("DELETE FROM users")  # Clear existing data
    sample_users = [
        ('admin', 'admin123', 'admin@example.com', 'admin'),
        ('user', 'password', 'user@example.com', 'user'),
        ('test', 'test123', 'test@example.com', 'user'),
    ]
    
    cursor.executemany(
        'INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)',
        sample_users
    )
    
    conn.commit()
    conn.close()
    print("[+] Database initialized with sample users")


# HTML Templates (inline for simplicity)
LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Login - Security Testing Lab</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 400px;
            margin: 100px auto;
            padding: 20px;
            background: #f0f0f0;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h2 { color: #333; text-align: center; }
        input {
            width: 100%;
            padding: 10px;
            margin: 10px 0;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 12px;
            background: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
        }
        button:hover { background: #0056b3; }
        .warning {
            background: #fff3cd;
            border: 1px solid #ffc107;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 4px;
            color: #856404;
        }
        .error {
            color: #dc3545;
            margin: 10px 0;
        }
        .hint {
            font-size: 12px;
            color: #666;
            margin-top: 15px;
            padding: 10px;
            background: #e7f3ff;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="warning">
            ⚠️ <strong>WARNING:</strong> This is a vulnerable application for security testing.
            For educational purposes only!
        </div>
        <h2>🔒 Login</h2>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <div class="hint">
            <strong>Testing Hint:</strong> Try SQL injection payloads like:<br>
            <code>admin' OR '1'='1</code><br>
            <code>' OR 1=1--</code>
        </div>
    </div>
</body>
</html>
'''

DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard - Logged In</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
            background: #f0f0f0;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h2 { color: #28a745; }
        .user-info {
            background: #e7f3ff;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
        }
        a {
            display: inline-block;
            margin-top: 20px;
            color: #007bff;
            text-decoration: none;
        }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h2>✅ Login Successful!</h2>
        <div class="user-info">
            <strong>Username:</strong> {{ username }}<br>
            <strong>Role:</strong> {{ role }}<br>
            <strong>Email:</strong> {{ email }}
        </div>
        <p>You have successfully exploited the SQL injection vulnerability!</p>
        <a href="/logout">Logout</a>
    </div>
</body>
</html>
'''

HOME_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Security Testing Lab</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background: #f0f0f0;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 { color: #333; }
        .endpoints {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 4px;
            margin: 20px 0;
        }
        .endpoint {
            margin: 10px 0;
            padding: 10px;
            background: white;
            border-left: 4px solid #007bff;
        }
        code {
            background: #e9ecef;
            padding: 2px 6px;
            border-radius: 3px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Security Testing Lab</h1>
        <p>Welcome to the vulnerable web application for security testing practice.</p>
        
        <div class="endpoints">
            <h3>Available Endpoints:</h3>
            <div class="endpoint">
                <strong>GET /</strong> - This page
            </div>
            <div class="endpoint">
                <strong>GET /login</strong> - Vulnerable login form
            </div>
            <div class="endpoint">
                <strong>POST /login</strong> - Login submission (SQL injection vulnerable)
            </div>
            <div class="endpoint">
                <strong>GET /dashboard</strong> - Protected dashboard
            </div>
            <div class="endpoint">
                <strong>GET /admin</strong> - Admin panel (hidden)
            </div>
            <div class="endpoint">
                <strong>GET /api/users</strong> - User data API (information disclosure)
            </div>
        </div>
        
        <p><a href="/login">Go to Login Page</a></p>
    </div>
</body>
</html>
'''


@app.route('/')
def home():
    """Home page with endpoint information"""
    return render_template_string(HOME_TEMPLATE)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Vulnerable login endpoint
    VULNERABILITY: SQL Injection
    """
    if request.method == 'GET':
        return render_template_string(LOGIN_TEMPLATE)
    
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    # VULNERABILITY: SQL Injection - Direct string concatenation
    # This allows attackers to manipulate the SQL query
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    
    print(f"[DEBUG] Executing query: {query}")  # Information disclosure
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(query)  # UNSAFE: Vulnerable to SQL injection
        user = cursor.fetchone()
        conn.close()
        
        if user:
            # Successful login
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[4]
            return redirect(url_for('dashboard'))
        else:
            return render_template_string(LOGIN_TEMPLATE, error="Invalid credentials")
    
    except sqlite3.Error as e:
        # VULNERABILITY: Information disclosure through error messages
        return render_template_string(LOGIN_TEMPLATE, error=f"Database error: {str(e)}")


@app.route('/dashboard')
def dashboard():
    """Protected dashboard - requires login"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    return render_template_string(
        DASHBOARD_TEMPLATE,
        username=session.get('username'),
        role=session.get('role'),
        email='user@example.com'
    )


@app.route('/logout')
def logout():
    """Logout endpoint"""
    session.clear()
    return redirect(url_for('login'))


@app.route('/admin')
def admin():
    """Hidden admin panel - discoverable through directory enumeration"""
    if session.get('role') != 'admin':
        return "Access Denied", 403
    return "<h1>Admin Panel</h1><p>Welcome, administrator!</p>"


@app.route('/api/users')
def api_users():
    """
    API endpoint exposing user data
    VULNERABILITY: Information disclosure, no authentication
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT username, email, role FROM users")
    users = cursor.fetchall()
    conn.close()
    
    # Return user data without authentication
    return {
        'users': [
            {'username': u[0], 'email': u[1], 'role': u[2]}
            for u in users
        ]
    }


@app.route('/robots.txt')
def robots():
    """Robots.txt with information disclosure"""
    return '''User-agent: *
Disallow: /admin
Disallow: /api/
Disallow: /backup/
# Hidden endpoints for testing
'''


@app.after_request
def add_insecure_headers(response):
    """
    VULNERABILITY: Missing security headers
    This demonstrates what NOT to do in production
    """
    # Intentionally NOT setting security headers:
    # - No Content-Security-Policy
    # - No X-Frame-Options
    # - No X-Content-Type-Options
    # - No Strict-Transport-Security
    
    # Information disclosure
    response.headers['X-Powered-By'] = 'Flask/3.0.0 (Vulnerable)'
    response.headers['Server'] = 'Werkzeug/3.0.1 Python/3.11'
    
    return response


if __name__ == '__main__':
    print("=" * 60)
    print("🔒 VULNERABLE FLASK APPLICATION")
    print("=" * 60)
    print("⚠️  WARNING: This application is intentionally vulnerable!")
    print("⚠️  FOR EDUCATIONAL PURPOSES ONLY")
    print("⚠️  DO NOT expose to the internet!")
    print("=" * 60)
    
    # Initialize database
    if not os.path.exists(DB_PATH):
        init_db()
    
    print("\n[+] Starting server on http://127.0.0.1:5000")
    print("[+] Press CTRL+C to stop\n")
    
    # Run on localhost only for safety
    app.run(host='127.0.0.1', port=5000, debug=True)
