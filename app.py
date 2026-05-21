import os
from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text

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
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    lockout_until = db.Column(db.DateTime, nullable=True)

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

# Automated Schema Patching Routine Engine
with app.app_context():
    db.create_all()
    
    # Safely migrate existing tables if columns are missing
    try:
        bind_engine = db.session.get_bind()
        with bind_engine.connect() as conn:
            # Check for the missing lockout column structure
            check_query = text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='account_user' AND column_name='failed_login_attempts';
            """)
            result = conn.execute(check_query).fetchone()
            
            # If columns are completely missing, patch the live production table schemas
            if not result:
                conn.execute(text("ALTER TABLE account_user ADD COLUMN failed_login_attempts INTEGER DEFAULT 0 NOT NULL;"))
                conn.execute(text("ALTER TABLE account_user ADD COLUMN lockout_until TIMESTAMP WITHOUT TIME ZONE;"))
                conn.commit()
    except Exception as e:
        print(f"Schema engine non-critical pass or sqlite environment active: {e}")

MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_DURATION_HOURS = 1

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        current_time = datetime.utcnow()

        if user:
            if user.lockout_until and current_time < user.lockout_until:
                time_remaining = user.lockout_until - current_time
                minutes_left = int(time_remaining.total_seconds() // 60) + 1
                
                audit_entry = LoginAudit(username=username, status='LOCKED', ip_address=user_ip)
                db.session.add(audit_entry)
                db.session.commit()
                
                flash(f'Account is locked due to multiple failures. Try again in {minutes_left} minutes.', 'error')
                return render_template('login.html')

        if user and check_password_hash(user.password, password):
            user.failed_login_attempts = 0
            user.lockout_until = None
            
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
            
            if user:
                user.failed_login_attempts += 1
                remaining_attempts = MAX_LOGIN_ATTEMPTS - user.failed_login_attempts
                
                if user.failed_login_attempts >= MAX_LOGIN_ATTEMPTS:
                    user.lockout_until = current_time + timedelta(hours=LOCKOUT_DURATION_HOURS)
                    db.session.commit()
                    flash(f'Too many failed attempts. Your account is locked for {LOCKOUT_DURATION_HOURS} hour.', 'error')
                else:
                    db.session.commit()
                    flash(f'Invalid credentials. {remaining_attempts} attempts remaining.', 'error')
            else:
                db.session.commit()
                flash('Invalid credentials.', 'error')
                
    return render_template('login.html')

@app.route('/logout')
def logout():
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
    
    blocked_count = User.query.filter(User.lockout_until > datetime.utcnow()).count()
    
    time_threshold = datetime.utcnow() - timedelta(hours=24)
    raw_logs = LoginAudit.query.filter(LoginAudit.timestamp >= time_threshold)\
                               .order_by(LoginAudit.timestamp.desc()).all()
    
    processed_logs = []
    for log in raw_logs:
        if log.status == 'SUCCESS':
            processed_logs.append({
                'timestamp': log.timestamp,
                'username': 'Successful',
                'ip_address': 'X.X.X.X',
                'status': log.status
            })
        else:
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
        username = request.form['username']
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
