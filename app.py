from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from camera import Camera
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-prod')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    ip = db.Column(db.String(45))
    user_agent = db.Column(db.String(200))
    success = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/health')
def health():
    return "OK", 200  # Railway healthcheck[web:5]

@app.route('/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip = request.remote_addr
        ua = request.headers.get('User-Agent')
        
        # Log ALL attempts
        log = LoginLog(username=username, ip=ip, user_agent=ua)
        db.session.add(log)
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            log.success = True
            db.session.commit()
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
            db.session.commit()
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('User exists')
        else:
            hashed = generate_password_hash(password)
            user = User(username=username, password_hash=hashed)
            db.session.add(user)
            db.session.commit()
            flash('Registered! Login now.')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/video_feed')
@login_required
def video_feed():
    return Response(gen(Camera()), mimetype='multipart/x-mixed-replace; boundary=frame')

def gen(camera):
    while True:
        frame = camera.get_frame()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n\r\n')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

