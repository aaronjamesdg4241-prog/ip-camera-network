import os
from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'supersecretkey') 

# Multi-worker session cookie tracking configurations
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
    status = db.Column(db.String(50), nullable=False) # 'SUCCESS', 'FAILED', or 'LOCKED'
    ip_address = db.Column(db.String(50))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_DURATION_HOURS = 1

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        current_time = datetime.utcnow()
        time_window = current_time - timedelta(hours=LOCKOUT_DURATION_HOURS)

        # 1. EVALUATE IP-BASED LOCKOUT STATUS
        # Track failures matching the incoming IP address, regardless of username
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

            # Verify IP failure totals to calculate the exact feedback warnings
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
                
    return
