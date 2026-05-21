import os
import cv2
from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, url_for, request, flash, session, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, UserMixin

app = Flask(__name__)
# Fixes 404 errors by allowing paths with or without trailing slashes
app.url_map.strict_slashes = False
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

# ==========================================
# APPLICATION CONTEXT INITIALIZATION & RESET
# ==========================================
with app.app_context():
    db.create_all()
    
    # TEMPORARY OPERATIONS RESET BLOCK: Wipes out the ledger tracking 
    # records to lift active IP bans every time the container boots.
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
# IP CAMERA GENERATOR STREAM ENGINE
# ==========================================
def generate_camera_frames():
    """
    Connects to an external network endpoint hosted by a phone or tablet IP camera application,
    captures frames, encodes them to JPEG data payloads, and yields them sequentially.
    """
    mobile_stream_url = os.environ.get('MOBILE_CAMERA_URL', 'http://192.168.1.50:8080/video')
    camera = cv2.VideoCapture(mobile_stream_url)
    
    while True:
        success, frame = camera.read()
        if not success:
            break
        else:
            ret, buffer = cv2.imencode('.jpg', frame)
            if not ret:
                continue
            frame_bytes = buffer.tobytes()
            
            yield (b'--frame\
