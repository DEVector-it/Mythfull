# --- Imports ---
import os
import json
import logging
import time
import uuid
import secrets
import requests
from flask import Flask, Response, request, session, jsonify, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from datetime import datetime, date, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
import stripe
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from flask_mail import Mail, Message
from flask_talisman import Talisman
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event, or_, func
from sqlalchemy.engine import Engine
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS

# ==============================================================================
# --- 1. INITIAL CONFIGURATION & SETUP ---
# ==============================================================================
load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

# Correctly configure CORS for your frontend origins
allowed_origins = [
    "https://reallymythai.netlify.app",
    "https://mythproal.netlify.app",
    "https://myth-ai.onrender.com",
    "http://127.0.0.1:5000",
    "http://localhost:5000",
    "http://127.0.0.1:5500",
    "http://localhost:5500",
    "null"
]
CORS(app, supports_credentials=True, origins=allowed_origins)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-fallback-secret-key-for-development')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get('SECURITY_PASSWORD_SALT', 'a-fallback-salt')

SITE_CONFIG = {
    "STRIPE_SECRET_KEY": os.environ.get('STRIPE_SECRET_KEY'),
    "STRIPE_PUBLIC_KEY": os.environ.get('STRIPE_PUBLIC_KEY'),
    "STRIPE_STUDENT_PRICE_ID": os.environ.get('STRIPE_STUDENT_PRICE_ID'),
    "STRIPE_STUDENT_PRO_PRICE_ID": os.environ.get('STRIPE_STUDENT_PRO_PRICE_ID'),
    "YOUR_DOMAIN": os.environ.get('YOUR_DOMAIN', 'http://localhost:5000'),
    "SECRET_TEACHER_KEY": os.environ.get('SECRET_TEACHER_KEY'),
    "ADMIN_SECRET_KEY": os.environ.get('ADMIN_SECRET_KEY'),
    "STRIPE_WEBHOOK_SECRET": os.environ.get('STRIPE_WEBHOOK_SECRET'),
    "GEMINI_API_KEY": os.environ.get('GEMINI_API_KEY'),
    "SUPPORT_EMAIL": os.environ.get('SUPPORT_EMAIL')
}

stripe.api_key = SITE_CONFIG.get("STRIPE_SECRET_KEY")
password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_SENDER')
mail = Mail(app)

# ==============================================================================
# --- DATABASE MODELS ---
# ==============================================================================
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite'):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

student_class_association = db.Table('student_class_association',
    db.Column('user_id', db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True),
    db.Column('class_id', db.String(36), db.ForeignKey('class.id', ondelete='CASCADE'), primary_key=True)
)

team_member_association = db.Table('team_member_association',
    db.Column('user_id', db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True),
    db.Column('team_id', db.String(36), db.ForeignKey('team.id', ondelete='CASCADE'), primary_key=True)
)

class User(UserMixin, db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True)
    role = db.Column(db.String(20), nullable=False, default='student')
    taught_classes = db.relationship('Class', back_populates='teacher', lazy=True, foreign_keys='Class.teacher_id', cascade="all, delete-orphan")
    enrolled_classes = db.relationship('Class', secondary=student_class_association, back_populates='students', lazy='dynamic')
    teams = db.relationship('Team', secondary=team_member_association, back_populates='members', lazy='dynamic')

    # --- ADDED METHOD ---
    # This method serializes the user object into a dictionary.
    # It ensures the frontend receives all necessary user data.
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            # NOTE: You'll need to implement the logic for these fields based on your app's features
            'has_subscription': False, # Placeholder
            'profile': {
                'bio': '', # Placeholder
                'avatar': '' # Placeholder
            }
        }

class Team(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(8), unique=True, nullable=False)
    owner_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    owner = db.relationship('User', foreign_keys=[owner_id])
    members = db.relationship('User', secondary=team_member_association, back_populates='teams', lazy='dynamic')

class Class(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(8), unique=True, nullable=False)
    teacher_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    teacher = db.relationship('User', back_populates='taught_classes', foreign_keys=[teacher_id])
    students = db.relationship('User', secondary=student_class_association, back_populates='enrolled_classes', lazy='dynamic')

class SiteSettings(db.Model):
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.String(500))

# ==============================================================================
# --- USER & SESSION MANAGEMENT ---
# ==============================================================================
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.unauthorized_handler
def unauthorized():
    return jsonify({"error": "Login required.", "logged_in": False}), 401

@login_manager.user_loader
def load_user(user_id): return User.query.get(user_id)

def role_required(role_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated: return jsonify({"error": "Login required."}), 401
            if current_user.role != role_name and current_user.role != 'admin': return jsonify({"error": f"{role_name.capitalize()} access required."}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

admin_required = role_required('admin')

# ==============================================================================
# --- FRONTEND CONTENT ---
# ==============================================================================
# The HTML_CONTENT variable is omitted for brevity but remains unchanged.
HTML_CONTENT = """
...
"""
# ==============================================================================
# --- API ROUTES ---
# ==============================================================================
@app.route('/')
def serve_frontend():
    return Response(HTML_CONTENT, mimetype='text/html')

# --- MODIFIED ROUTE ---
@app.route('/api/status')
def status():
    settings = {s.key: s.value for s in SiteSettings.query.all()}
    if current_user.is_authenticated:
        # Now returns the complete user object using the to_dict() method.
        return jsonify({
            "logged_in": True,
            "user": current_user.to_dict(),
            "settings": settings
        })
    return jsonify({"logged_in": False, "settings": settings})

# --- MODIFIED ROUTE ---
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    # The frontend sends the selected role in the 'account_type' field.
    role_attempt = data.get('account_type', 'student')
    admin_secret_key = data.get('admin_secret_key', '')

    user = User.query.filter(User.username.ilike(username)).first()

    if not user or not user.password_hash or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid username or password."}), 401

    # ADDED: Validate that the user's actual role matches the portal they are trying to log into.
    if user.role != role_attempt:
        # Admins are a special case and can log in via any portal if they have the key.
        # Normal users cannot log into the wrong portal.
        if user.role != 'admin':
            return jsonify({"error": f"Authentication failed. This is not a {role_attempt} account."}), 403

    if user.role == 'admin':
        if username.lower() != 'big ballz' or admin_secret_key != SITE_CONFIG.get('ADMIN_SECRET_KEY'):
            return jsonify({"error": "Invalid admin credentials."}), 401

    login_user(user, remember=True)
    # Now returns the complete user object on successful login.
    return jsonify({"success": True, "user": user.to_dict()})

# --- MODIFIED ROUTE ---
@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username','').strip()
    password = data.get('password','')
    email = data.get('email','').strip().lower()
    account_type = data.get('account_type', 'student')
    secret_key = data.get('secret_key', '')

    if not all([username, password, email]):
        return jsonify({"error": "Missing required fields."}), 400
    if User.query.filter(or_(User.username.ilike(username), User.email.ilike(email))).first():
        return jsonify({"error": "Username or email already exists."}), 409

    role = 'student'
    if account_type == 'teacher':
        if secret_key != SITE_CONFIG.get('SECRET_TEACHER_KEY'):
            return jsonify({"error": "Invalid teacher registration key."}), 403
        role = 'teacher'

    new_user = User(username=username, email=email, password_hash=generate_password_hash(password), role=role)
    db.session.add(new_user)
    db.session.commit()
    login_user(new_user, remember=True)
    # Now returns the complete user object on successful signup.
    return jsonify({"success": True, "user": new_user.to_dict()})

@app.route('/api/logout')
@login_required
def logout():
    logout_user()
    return jsonify({"success": True})

@app.route('/api/contact', methods=['POST'])
def contact():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    message = data.get('message')
    if not all([name, email, message]):
        return jsonify({"error": "All fields are required."}), 400

    support_email = SITE_CONFIG.get('SUPPORT_EMAIL')
    if not support_email:
        logging.error("SUPPORT_EMAIL environment variable is not set.")
        return jsonify({"error": "Contact feature is not configured."}), 500

    try:
        msg = Message(
            subject=f"New Contact Form Message from {name}",
            recipients=[support_email],
            body=f"From: {name} <{email}>\n\n{message}"
        )
        mail.send(msg)
        return jsonify({"success": True, "message": "Your message has been sent!"})
    except Exception as e:
        logging.error(f"Failed to send contact email: {e}")
        return jsonify({"error": "Could not send message at this time."}), 500

@app.route('/api/admin/update_settings', methods=['POST'])
@admin_required
def admin_update_settings():
    data = request.get_json()
    for key, value in data.items():
        setting = SiteSettings.query.filter_by(key=key).first()
        if setting:
            setting.value = value
        else:
            db.session.add(SiteSettings(key=key, value=value))
    db.session.commit()
    return jsonify({"success": True, "message": "Settings updated."})

@app.route('/api/admin/toggle_maintenance', methods=['POST'])
@admin_required
def toggle_maintenance():
    setting = SiteSettings.query.filter_by(key='maintenance_mode').first()
    if setting:
        setting.value = 'false' if setting.value == 'true' else 'true'
        message = f"Maintenance mode {'disabled' if setting.value == 'false' else 'enabled'}."
    else:
        db.session.add(SiteSettings(key='maintenance_mode', value='true'))
        message = "Maintenance mode enabled."
    db.session.commit()
    return jsonify({"success": True, "message": message})

# ==============================================================================
# --- APP INITIALIZATION & EXECUTION ---
# ==============================================================================
def initialize_app_database():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='big ballz').first():
            admin_pass = os.environ.get('ADMIN_PASSWORD', 'supersecret')
            admin_email = os.environ.get('ADMIN_EMAIL', 'admin@myth.ai')
            admin = User(username='big ballz', email=admin_email, password_hash=generate_password_hash(admin_pass), role='admin')
            db.session.add(admin)
        if not SiteSettings.query.filter_by(key='maintenance_mode').first():
            db.session.add(SiteSettings(key='maintenance_mode', value='false'))
        db.session.commit()

if __name__ == '__main__':
    initialize_app_database()
    port = int(os.environ.get('PORT', 10000))
    socketio.run(app, host='0.0.0.0', port=port)







