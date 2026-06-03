import os
import requests
from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, url_for, request, flash, session, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.url_map.strict_slashes = False
app.secret_key = os.environ.get('SECRET_KEY', 'supersecretkey')

# PROXY CONFIGURATION
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

app.config.update(
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_DURATION=3600
)

raw_db_url = os.environ.get('DATABASE_URL')
if raw_db_url and raw_db_url.startswith("postgresql://"):
    raw_db_url = raw_db_url.replace("postgresql://", "postgresql+psycopg2://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = raw_db_url or 'sqlite:///local_system.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Get tunnel URL from environment variable
LOCALXPOSE_TUNNEL_URL = os.environ.get('PINGGY_TUNNEL_URL', 'https://wqto6cwuow.loclx.io')

# Relational Tables
class User(UserMixin, db.Model):
    __tablename__ = 'account_user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False)

class LoginAudit(db.Model):
    __tablename__ = 'login_audit'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), nullable=False)
    ip_address = db.Column(db.String(50))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==========================================
# APPLICATION CONTEXT INITIALIZATION
# ==========================================
with app.app_context():
    db.create_all()
    
    try:
        db.session.query(LoginAudit).delete()
        db.session.commit()
        print("\n" + "="*60)
        print("DATABASE MAINTENANCE: Active login ban lists have been cleared!")
        print("="*60 + "\n")
    except Exception as e:
        db.session.rollback()
        print(f"Failed to clear audit table logs on boot: {e}")

MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_DURATION_HOURS = 1

# ==========================================
# CAMERA STREAM PROXY - FIXED VERSION
# ==========================================
@app.route('/video_feed')
def video_feed():
    if 'user_id' not in session:
        return "Unauthorized", 401
        
    def stream_proxy():
        try:
            # Build the target URL to your local tunnel
            target_url = f"{PINGGY_TUNNEL_URL.rstrip('/')}/video_feed"
            
            if not PINGGY_TUNNEL_URL:
                print("[ERROR] PINGGY_TUNNEL_URL environment variable not set")
                yield b''
                return
            
            print(f"[INFO] Proxying video feed from: {target_url}")
            
            # Make request to the tunnel with streaming
            response = requests.get(target_url, stream=True, timeout=5)
            
            # Forward the exact same content type (multipart/x-mixed-replace)
            # This is critical for MJPEG streaming
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    yield chunk
                    
        except requests.exceptions.Timeout:
            print("[ERROR] Timeout connecting to tunnel")
            yield b''
        except requests.exceptions.ConnectionError as e:
            print(f"[ERROR] Connection error to tunnel: {e}")
            yield b''
        except Exception as e:
            print(f"[ERROR] Stream proxy error: {e}")
            yield b''
    
    # Return with the correct MJPEG mimetype
    return Response(stream_proxy(), mimetype='multipart/x-mixed-replace; boundary=frame')

# ==========================================
# SECURE INTERFACE ROUTING LOGIC
# ==========================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        user_ip = request.remote_addr
        
        current_time = datetime.utcnow()
        time_window = current_time - timedelta(hours=LOCKOUT_DURATION_HOURS)

        # 1. EVALUATE IP-BASED LOCKOUT STATUS
        recent_ip_failures = LoginAudit.query.filter(
            LoginAudit.ip_address == user_ip,
            LoginAudit.status == 'FAILED',
            LoginAudit.timestamp >= time_window
        ).order_by(LoginAudit.timestamp.desc()).all()

        if len(recent_ip_failures) >= MAX_LOGIN_ATTEMPTS:
            last_failure_time = recent_ip_failures[0].timestamp
            lockout_expiration = last_failure_time + timedelta(hours=LOCKOUT_DURATION_HOURS)

            if current_time < lockout_expiration:
                time_remaining = lockout_expiration - current_time
                minutes_left = int(time_remaining.total_seconds() // 60) + 1
                
                audit_entry = LoginAudit(username=username, status='LOCKED', ip_address=user_ip)
                db.session.add(audit_entry)
                db.session.commit()
                
                flash(f'Your IP address is temporarily blocked due to multiple failed attempts. Try again in {minutes_left} minutes.', 'error')
                return render_template('login.html')

        # 2. EVALUATE AUTHENTICATION
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            audit_entry = LoginAudit(username=username, status='SUCCESS', ip_address=user_ip)
            db.session.add(audit_entry)
            db.session.commit()

            session['user_id'] = user.id
            session['username'] = user.username
            session.permanent = True
            login_user(user, remember=True)
            session.modified = True
            return redirect(url_for('dashboard'))
        
        else:
            audit_entry = LoginAudit(username=username, status='FAILED', ip_address=user_ip)
            db.session.add(audit_entry)
            db.session.commit()

            fail_count = LoginAudit.query.filter(
                LoginAudit.ip_address == user_ip,
                LoginAudit.status == 'FAILED',
                LoginAudit.timestamp >= time_window
            ).count()

            remaining_attempts = MAX_LOGIN_ATTEMPTS - fail_count
            
            if remaining_attempts <= 0:
                flash(f'Too many failed attempts. Access from this IP is locked for {LOCKOUT_DURATION_HOURS} hour.', 'error')
            else:
                flash(f'Invalid credentials. {remaining_attempts} attempts remaining for this IP.', 'error')
                
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        username = session.get('username', 'Unknown')
        user_ip = request.remote_addr
        
        audit_entry = LoginAudit(username=username, status='LOGOUT', ip_address=user_ip)
        db.session.add(audit_entry)
        db.session.commit()

    try:
        logout_user()
    except Exception:
        pass
    
    session.clear()
    session.modified = True
    response = redirect(url_for('login'))
    response.delete_cookie('session')
    return response

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access the dashboard.', 'error')
        return redirect(url_for('login'))
        
    total_logins = LoginAudit.query.count()
    success_count = LoginAudit.query.filter_by(status='SUCCESS').count()
    failed_count = LoginAudit.query.filter_by(status='FAILED').count()
    logout_count = LoginAudit.query.filter_by(status='LOGOUT').count()
    
    time_window = datetime.utcnow() - timedelta(hours=LOCKOUT_DURATION_HOURS)
    all_recent_fails = LoginAudit.query.filter(
        LoginAudit.status == 'FAILED',
        LoginAudit.timestamp >= time_window
    ).all()
    
    ip_fail_map = {}
    for f in all_recent_fails:
        if f.ip_address:
            ip_fail_map[f.ip_address] = ip_fail_map.get(f.ip_address, 0) + 1
    
    blocked_count = sum(1 for ip, count in ip_fail_map.items() if count >= MAX_LOGIN_ATTEMPTS)
    
    time_threshold = datetime.utcnow() - timedelta(hours=24)
    raw_logs = LoginAudit.query.filter(LoginAudit.timestamp >= time_threshold)\
                               .order_by(LoginAudit.timestamp.desc()).all()
    
    processed_logs = []
    for log in raw_logs:
        processed_logs.append({
            'timestamp': log.timestamp,
            'username': log.username,
            'ip_address': log.ip_address,
            'status': log.status
        })

    return render_template(
        'dashboard.html', 
        total_logins=total_logins,
        success_count=success_count,
        failed_count=failed_count,
        logout_count=logout_count,
        blocked_count=blocked_count,
        recent_logs=processed_logs
    )

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
