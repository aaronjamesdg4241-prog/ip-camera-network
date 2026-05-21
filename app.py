import os
from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Production-grade secret tracking keys
app.secret_key = os.environ.get('SECRET_KEY', 'supersecretkey') 

# Force strict cookie synchronization across multi-worker environments
app.config.update(
    SESSION_COOKIE_SECURE=False,     # Flip to True if using custom domain SSL (https://)
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_DURATION=3600    # Keeps state alive for 1 hour across instances
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
    # If standard browser cookies state they are authorized, skip login wall entirely
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

        if user and check_password_hash(user.password, password):
            # 1. Reset security limit variables
            session['failed_attempts'] = 0  
            
            # 2. Bind structural session state to Flask's global cookie dictionary
            session['user_id'] = user.id
            session['username'] = user.username
            session.permanent = True
            
            # 3. Inform Flask-Login layer to authenticate instance
            login_user(user, remember=True)
            
            # 4. Explicitly force an update flush onto the user's browser client
            session.modified = True
            
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
def logout():
    logout_user()
    session.clear() # Completely wipes out session tracking tokens
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    # Bulletproof Multi-worker State Pass:
    # If the user has a valid tracking token in their session cookie array, let them through!
    if 'user_id' in session:
        return render_template('dashboard.html')
        
    # If cookie tracking dropped off entirely, route back to login
    flash('Please log in to access the dashboard.', 'error')
    return redirect(url_for('login'))

@app.route('/', methods=['GET'])
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/camera')
def camera():
    if 'user_id' not in session:
        flash('Please log in to access the camera.', 'error')
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
