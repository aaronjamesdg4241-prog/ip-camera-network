import os
from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'supersecretkey') 

# Fixes session dropped during redirect across various environments
app.config.update(
    SESSION_COOKIE_SECURE=False,     # Set to True if you are explicitly using https://
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'    # Permits cookie delivery on top-level redirects
)

raw_db_url = os.environ.get('DATABASE_URL')

# Driver Patch for SQLAlchemy 2.0+
if raw_db_url and raw_db_url.startswith("postgresql://"):
    raw_db_url = raw_db_url.replace("postgresql://", "postgresql+psycopg2://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = raw_db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin, db.Model):
    __tablename__ = 'account_user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

# Max login configurations
MAX_LOGIN_ATTEMPTS = 3

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If already authenticated, bypass login completely
    if current_user.is_authenticated or 'user_id' in session:
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

        if user and check_password_hash(user.password, password):
            session['failed_attempts'] = 0  # Reset counter
            
            # Force cookie assignment prior to launching redirect
            login_user(user, remember=True)
            session['user_id'] = user.id 
            session.permanent = True
            
            return redirect(url_for('dashboard'))
        else:
            session['failed_attempts'] += 1
            remaining_attempts = MAX_LOGIN_ATTEMPTS - session['failed_attempts']
            
            if remaining_attempts > 0:
                flash(f'Invalid credentials. {remaining_attempts} attempts remaining.', 'error')
            else:
                flash('Too many failed attempts. You are locked out.', 'error')
                
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Secondary redundancy pass: checks traditional session dictionary if Flask-Login dropped tracking
    if not current_user.is_authenticated and 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

# FIXED: Added methods to handle initial landing and potential raw submissions
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # If a POST hits root, seamlessly forward it to the login processing block
        return redirect(url_for('login'), code=307) 
        
    if current_user.is_authenticated or 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/camera')
@login_required
def camera():
    if not current_user.is_authenticated and 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('camera.html')

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
