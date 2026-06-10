from flask import Flask, render_template_string, request, redirect, url_for, flash, session, Response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import os
import requests

app = Flask(__name__)

# Secure static fallback key for handling production session cookies safely
app.secret_key = os.environ.get("SECRET_KEY", "prod-security-fallback-string-123789")

# 1. Database Infrastructure Setup
db_url = os.environ.get("DATABASE_URL", "sqlite:///fallback.db")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# 2. Access Control Credentials & Zrok Target Configuration
VALID_USERNAME = "Pup"
VALID_PASSWORD = "123"

# TARGET TUNNEL ENDPOINT:
ZROK_STREAM_URL = "https://3x0uxjl3s7p0.shares.zrok.io/?skip-zrok-office=true"

# 3. Persistent Storage Schemas
class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50))
    action = db.Column(db.String(255))

class IpTracker(db.Model):
    __tablename__ = 'ip_tracker'
    ip_address = db.Column(db.String(50), primary_key=True)
    failed_attempts = db.Column(db.Integer, default=0)
    banned_until = db.Column(db.DateTime, nullable=True)

def log_event(ip, action_text):
    try:
        new_log = AuditLog(ip_address=ip, action=action_text)
        db.session.add(new_log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Logging telemetry write error: {e}")

# 4. User Interface Matrix Template
LOGIN_HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>System Authentication</title>
    <style>
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: #0f172a;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            color: #fff;
        }
        .login-card {
            background: #1e293b;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 10px 25px -5px rgba(0,0,0,0.3);
            width: 100%;
            max-width: 400px;
        }
        h2 { margin-bottom: 24px; font-weight: 600; text-align: center; color: #38bdf8; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; font-size: 14px; color: #94a3b8; }
        input {
            width: 100%;
            padding: 12px;
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 6px;
            color: #fff;
            font-size: 15px;
            box-sizing: border-box;
        }
        input:focus { border-color: #38bdf8; outline: none; }
        button {
            width: 100%;
            padding: 12px;
            background: #0284c7;
            border: none;
            border-radius: 6px;
            color: #fff;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            margin-top: 10px;
            transition: background 0.2s;
        }
        button:hover { background: #0369a1; }
        .flash-messages {
            background: #fee2e2;
            color: #991b1b;
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 14px;
            font-weight: 500;
            border-left: 4px solid #ef4444;
        }
        .footer-text { text-align: center; margin-top: 24px; font-size: 14px; color: #64748b; }
    </style>
</head>
<body>
    <div class="login-card">
        <h2>📷 Security Access</h2>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="flash-messages">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <form action="{{ url_for('login') }}" method="POST">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autocomplete="off">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Authenticate Session</button>
        </form>
        <div class="footer-text">System Administration Portal</div>
    </div>
</body>
</html>
'''

# 5. Route Core Logic Block
@app.route('/', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        return redirect(url_for('stream'))
        
    ip = request.remote_addr or "127.0.0.1"
    now = datetime.utcnow()
    
    tracker = IpTracker.query.filter_by(ip_address=ip).first()

    if tracker and tracker.banned_until and tracker.banned_until > now:
        remaining = tracker.banned_until - now
        minutes_left = int(remaining.total_seconds() / 60)
        return f"<h1>Access Denied</h1><p>Your IP ({ip}) is banned due to excessive failed attempts. Try again in {minutes_left} minutes.</p>", 403
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == VALID_USERNAME and password == VALID_PASSWORD:
            if tracker:
                tracker.failed_attempts = 0
                tracker.banned_until = None
                db.session.commit()
            session['logged_in'] = True
            session['username'] = username
            log_event(ip, "Internal System Event: Session Established Successfully.")
            return redirect(url_for('stream'))
        else:
            if not tracker:
                tracker = IpTracker(ip_address=ip, failed_attempts=1)
                db.session.add(tracker)
            else:
                tracker.failed_attempts += 1
            if tracker.failed_attempts >= 3:
                tracker.banned_until = now + timedelta(hours=1)
                log_event(ip, f"IP banned for 1 hour after 3 failed attempts.")
                db.session.commit()
                return f"<h1>Access Denied</h1><p>Too many failed attempts. Your
