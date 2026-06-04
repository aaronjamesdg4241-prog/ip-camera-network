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

# Trust Railway/Cloudflare proxy headers to capture accurate client IP addresses
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

# ============================================================================
# TUNNEL PIPELINE CONFIGURATION
# Reads from Railway's panel environment tokens first. Falls back natively to 
# your verified active zrok share address so the cloud server remains online.
# ============================================================================
ACTIVE_TUNNEL_URL = os.environ.get('ZROK_TUNNEL_URL') or os.environ.get('PINGGY_TUNNEL_URL', 'https://fx4og87yqkex.shares.zrok.io')

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

with app.app_context():
    db.create_all()
    try:
        db.session.query(LoginAudit).delete()
        db.session.commit()
        print("DATABASE MAINTENANCE: Active login ban lists cleared on boot.")
    except Exception as e:
        db.session.rollback()

MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_DURATION_HOURS = 1

# ==========================================
# ZROK REVERSE PROXY CAMERA ENGINE
# ==========================================
@app.route('/video_feed')
def video_feed():
    if 'user_id' not in session:
        return "Unauthorized", 401
        
    def stream_proxy():
        target_url = f"{ACTIVE_TUNNEL_URL.rstrip('/')}/video_feed"
        try:
            headers = {"User-Agent": "Railway-Cloud-Backend"}
            response = requests.get(target_url, stream=True, timeout=(5, 15), headers=headers)
            
            # Verify zrok actually returned the stream instead of a 502 Offline text card
            if response.status_code == 200 and 'multipart/x-mixed-replace' in response.headers.get('Content-Type', ''):
                for chunk in response.iter_content(chunk_size=4096):
                    if chunk:
                        yield chunk
            else:
                print(f"[WARNING] Tunnel endpoint connected, but stream is down. Status: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Live network pipeline broken: {e}")

    return Response(
        stream_proxy(), 
        mimetype='multipart/x-mixed-replace; boundary=frame'
    )

# ==========================================
# SECURE ROUTING & AUTHENTICATION
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

        # Secure matching across unique IP + Username pairing to prevent global NAT locks
        recent_failures = LoginAudit.query.filter(
            LoginAudit.ip_address == user_ip,
            LoginAudit.username == username,
            LoginAudit.status == 'FAILED',
            LoginAudit.timestamp >= time_window
        ).order_by(LoginAudit.timestamp.desc()).all()

        if len(recent_failures) >= MAX_LOGIN_ATTEMPTS:
            last_failure_time = recent_failures[0].timestamp
            lockout_expiration = last_failure_time + timedelta(hours=LOCKOUT_DURATION_HOURS)

            if current_time < lockout_expiration:
                time_remaining = lockout_expiration - current_time
                minutes_left = int(time_remaining.total_seconds() // 60) + 1
                
                db.session.add(LoginAudit(username=username, status='LOCKED', ip_address=user_ip))
                db.session.commit()
                
                flash(f'Account temporarily locked. Try again in {minutes_left} minutes.', 'error')
                return render_template('login.html')

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            db.session.add(LoginAudit(username=username, status='SUCCESS', ip_address=user_ip))
            db.session.commit()

            session['user_id'] = user.id
            session['username'] = user.username
            session.permanent = True
            login_user(user, remember=True)
            return redirect(url_for('dashboard'))
        
        else:
            db.session.add(LoginAudit(username=username, status='FAILED', ip_address=user_ip))
            db.session.commit()

            fail_count = LoginAudit.query.filter(
                LoginAudit.ip_address == user_ip,
                LoginAudit.username == username,
                LoginAudit.status == 'FAILED',
                LoginAudit.timestamp >= time_window
            ).count()

            remaining_attempts = MAX_LOGIN_ATTEMPTS - fail_count
            
            if remaining_attempts <= 0:
                flash(f'Account locked for {LOCKOUT_DURATION_HOURS} hour.', 'error')
            else:
                flash(f'Invalid credentials. {remaining_attempts} attempts remaining.', 'error')
                
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        db.session.add(LoginAudit(
            username=session.get('username', 'Unknown'), 
            status='LOGOUT', 
            ip_address=request.remote_addr
        ))
        db.session.commit()

    try:
        logout_user()
    except Exception:
        pass  
    
    session.clear()
    response = redirect(url_for('login'))
    response.delete_cookie('session')  
    return response

# ==========================================
# FIXED DASHBOARD ROUTE (Syntax Restored)
# ==========================================
@app.route('/dashboard', methods=['GET'])
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
            key = f"{f.ip_address}_{f.username}"
            ip_fail_map[key] = ip_fail_map.get(key, 0) + 1
    
    blocked_count = sum(1 for count in ip_fail_map.values() if count >= MAX_LOGIN_ATTEMPTS)
    
    time_threshold = datetime.utcnow() - timedelta(hours=24)
    raw_logs = LoginAudit.query.filter(LoginAudit.timestamp >= time_threshold)\
                               .order_by(LoginAudit.timestamp.desc()).all()
    
    processed_logs = []
    for log in raw_logs:
        processed_logs.append({
            'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
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
