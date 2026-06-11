from flask import Flask, render_template_string, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "super-secret-key-change-in-production")

# 1. PostgreSQL Database Configuration
db_url = os.environ.get("DATABASE_URL", "sqlite:///fallback.db")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# 2. Hardcoded Credentials & Stream Config
VALID_USERNAME = "Pup"
VALID_PASSWORD = "123"
ZROK_STREAM_URL = "https://2f9pbe6dxjos.shares.zrok.io/video_feed"

# 3. Database Models
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
        print(f"Logging error: {e}")

# 4. Preexisting Custom HTML Template Integrated
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
        .footer-text {
            text-align: center;
            margin-top: 24px;
            font-size: 14px;
            color: #64748b;
        }
        .footer-text a { color: #38bdf8; text-decoration: none; }
        .footer-text a:hover { text-decoration: underline; }
    </style>
</head>
<body>

    <div class="login-card">
        <h2>📷 Security Access</h2>

        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="flash-messages">
                        {{ message }}
                    </div>
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

        <div class="footer-text">
            System Administration Portal
        </div>
    </div>

</body>
</html>
'''

# 5. Routes and Security Logic
@app.route('/', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        return redirect(url_for('stream'))

    ip = request.remote_addr
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
            log_event(ip, f"User '{username}' successfully logged in.")
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
                return f"<h1>Access Denied</h1><p>Too many failed attempts. Your IP has been banned for 1 hour.</p>", 403
            else:
                log_event(ip, f"Failed login attempt ({tracker.failed_attempts}/3 attempts).")
                db.session.commit()
                flash(f"Invalid credentials. Attempt {tracker.failed_attempts} of 3.")

    return render_template_string(LOGIN_HTML_TEMPLATE)

@app.route('/logout')
def logout():
    ip = request.remote_addr
    username = session.get('username', 'Unknown')
    session.clear()
    log_event(ip, f"User '{username}' logged out.")
    return redirect(url_for('login'))

@app.route('/stream')
def stream():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Live CCTV Stream</title>
        <style>
            body {{ background: #0f172a; color: white; text-align: center; font-family: sans-serif; padding: 20px; }}
            .nav {{ margin-bottom: 20px; }}
            .nav a {{ color: #38bdf8; margin: 0 15px; text-decoration: none; font-weight: bold; }}
            img {{ width: 100%; max-width: 854px; border: 3px solid #38bdf8; border-radius: 12px; background: #000; }}
        </style>
    </head>
    <body>
        <div class="nav">
            <a href="/dashboard">📊 View Security Dashboard</a> | 
            <a href="/logout">🚪 Logout</a>
        </div>
        <h1>🎥 Live CCTV Stream</h1>
        <img src="{ZROK_STREAM_URL}" alt="Live Feed Target">
    </body>
    </html>
    '''

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
    
    log_rows = ""
    for log in recent_logs:
        log_rows += f"""
        <tr>
            <td style="padding: 10px; border-bottom: 1px solid #334155;">{log.timestamp.strftime('%Y-%m-%d %H:%M:%S')} UTC</td>
            <td style="padding: 10px; border-bottom: 1px solid #334155;">{log.ip_address}</td>
            <td style="padding: 10px; border-bottom: 1px solid #334155;">{log.action}</td>
        </tr>
        """

    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Dashboard</title>
        <style>
            body {{ background: #0f172a; color: white; font-family: sans-serif; padding: 30px; }}
            .container {{ max-width: 900px; margin: 0 auto; }}
            table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }}
            th {{ background: #0284c7; text-align: left; padding: 12px; }}
            .back-btn {{ display: inline-block; margin-bottom: 20px; color: #38bdf8; text-decoration: none; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="container">
            <a class="back-btn" href="/stream">← Back to Stream</a>
            <h2>📊 System Access & Security Logs</h2>
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>IP Address</th>
                        <th>Event Logged</th>
                    </tr>
                </thead>
                <tbody>
                    {log_rows if log_rows else "<tr><td colspan='3' style='padding:15px; text-align:center;'>No events logged yet.</td></tr>"}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    '''

# 6. DB Initialization Block
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
