import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'supersecretkey') 

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

# Models
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
    status = db.Column(db.String(50), nullable=False) # 'SUCCESS' or 'FAILED'
    ip_address = db.Column(db.String(50))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

MAX_LOGIN_ATTEMPTS = 3

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if 'failed_attempts' not in session:
        session['failed_attempts'] = 0

    if request.method == 'POST':
        if session['failed_attempts'] >= MAX_LOGIN_ATTEMPTS:
            flash('Too many failed attempts. You are locked out.', 'error')
            return render_template('login.html')
        
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        # Gather IP data for auditing logs
        user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

        if user and check_password_hash(user.password, password):
            session['failed_attempts'] = 0  
            session['user_id'] = user.id
            session['username'] = user.username
            session.permanent = True
            
            # Write a Successful tracking marker to DB
            audit_entry = LoginAudit(username=username, status='SUCCESS', ip_address=user_ip)
            db.session.add(audit_entry)
            db.session.commit()

            login_user(user, remember=True)
            session.modified = True
            return redirect(url_for('dashboard'))
        else:
            session['failed_attempts'] += 1
            remaining_attempts = MAX_LOGIN_ATTEMPTS - session['failed_attempts']
            
            # Write a Failed tracking marker to DB
            audit_entry = LoginAudit(username=username, status='FAILED', ip_address=user_ip)
            db.session.add(audit_entry)
            db.session.commit()

            if remaining_attempts > 0:
                flash(f'Invalid credentials. {remaining_attempts} attempts remaining.', 'error')
            else:
                flash('Too many failed attempts. You are locked out.', 'error')
                
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access the dashboard.', 'error')
        return redirect(url_for('login'))
        
    # Generate system metrics from our tracking logs
    total_logins = LoginAudit.query.count()
    success_count = LoginAudit.query.filter_by(status='SUCCESS').count()
    failed_count = LoginAudit.query.filter_by(status='FAILED').count()
    recent_logs = LoginAudit.query.order_by(LoginAudit.timestamp.desc()).limit(5).all()

    return render_template(
        'dashboard.html', 
        total_logins=total_logins,
        success_count=success_count,
        failed_count=failed_count,
        recent_logs=recent_logs
    )

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/camera')
def camera():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('camera.html')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
