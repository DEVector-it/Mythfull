# --- Imports ---
import os
import json
import logging
import time
import uuid
import secrets
import requests
import bleach
import re
from flask import Flask, request, jsonify, redirect, url_for, render_template_string, abort, g
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
from sqlalchemy import event, or_
from sqlalchemy.orm import joinedload
from sqlalchemy.engine import Engine
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
from sqlalchemy.exc import IntegrityError
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from markupsafe import escape
from flask_bcrypt import Bcrypt

# ==============================================================================
# --- 1. INITIAL CONFIGURATION & SETUP ---
# ==============================================================================
load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Flask App Initialization ---
app = Flask(__name__)

# --- App Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///database.db'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(16)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get('SECURITY_PASSWORD_SALT') or secrets.token_hex(16)

# --- Production Security Checks ---
is_production = os.environ.get('FLASK_ENV') == 'production'
if is_production:
    required_secrets = ['SECRET_KEY', 'DATABASE_URL', 'SECURITY_PASSWORD_SALT', 'STRIPE_SECRET_KEY', 'YOUR_DOMAIN', 'SECRET_TEACHER_KEY', 'ADMIN_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET', 'MAIL_SENDER', 'MAIL_USERNAME', 'MAIL_PASSWORD']
    for key in required_secrets:
        if not os.environ.get(key):
            logging.critical(f"Missing a required production secret: {key}. Exiting.")
            exit(1)
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['REMEMBER_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['REMEMBER_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
else:
    app.config['SESSION_COOKIE_SECURE'] = False
    app.config['REMEMBER_COOKIE_SECURE'] = False

# --- Site-wide Configuration Dictionary ---
SITE_CONFIG = {
    "STRIPE_SECRET_KEY": os.environ.get('STRIPE_SECRET_KEY'),
    "STRIPE_PUBLIC_KEY": os.environ.get('STRIPE_PUBLIC_KEY'),
    "STRIPE_STUDENT_PRO_PRICE_ID": os.environ.get('STRIPE_STUDENT_PRO_PRICE_ID'),
    "YOUR_DOMAIN": os.environ.get('YOUR_DOMAIN', 'http://localhost:5000'),
    "SECRET_TEACHER_KEY": os.environ.get('SECRET_TEACHER_KEY'),
    "ADMIN_SECRET_KEY": os.environ.get('ADMIN_SECRET_KEY'),
    "STRIPE_WEBHOOK_SECRET": os.environ.get('STRIPE_WEBHOOK_SECRET'),
    "GEMINI_API_KEY": os.environ.get('GEMINI_API_KEY'),
    "SUPPORT_EMAIL": os.environ.get('MAIL_SENDER')
}

# --- SECURITY: Restrict CORS in production ---
prod_origin = SITE_CONFIG.get("YOUR_DOMAIN")
CORS(app, supports_credentials=True, origins=[prod_origin] if is_production else "*")

# --- SECURITY: Content Security Policy (CSP) ---
csp = {
    'default-src': '\'self\'',
    'script-src': [
        '\'self\'',
        'https://cdn.tailwindcss.com',
        'https://cdnjs.cloudflare.com',
        'https://js.stripe.com',
        '\'nonce-{nonce}\''
    ],
    'style-src': [
        '\'self\'',
        'https://cdn.tailwindcss.com',
        'https://fonts.googleapis.com',
        '\'nonce-{nonce}\''
    ],
    'font-src': ['\'self\'', 'https://fonts.gstatic.com'],
    'img-src': ['*', 'data:'],
    'connect-src': [
        '\'self\'',
        f'wss://{SITE_CONFIG["YOUR_DOMAIN"].split("//")[-1]}' if is_production and 'localhost' not in SITE_CONFIG["YOUR_DOMAIN"] else 'ws://localhost:5000',
        'https://api.stripe.com'
    ],
    'object-src': '\'none\'',
    'base-uri': '\'self\'',
    'form-action': '\'self\''
}

talisman = Talisman(app, content_security_policy=csp, force_https=is_production, strict_transport_security=is_production, frame_options='DENY', referrer_policy='strict-origin-when-cross-origin')
csrf = CSRFProtect(app)
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
bcrypt = Bcrypt(app)

# --- Initialize Other Extensions ---
stripe.api_key = SITE_CONFIG.get("STRIPE_SECRET_KEY")
password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins=prod_origin if is_production else "*")
mail = Mail(app)

if SITE_CONFIG.get("GEMINI_API_KEY"):
    try:
        import google.generativeai as genai
        genai.configure(api_key=SITE_CONFIG.get("GEMINI_API_KEY"))
    except ImportError:
        logging.warning("google-generativeai library not found. AI features will be disabled.")
        genai = None

# --- Flask-Mail Configuration ---
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_SENDER')

# ==============================================================================
# --- 2. DATABASE MODELS ---
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

class User(UserMixin, db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='student')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    points = db.Column(db.Integer, default=0)
    last_login = db.Column(db.DateTime, default=datetime.utcnow)
    streak = db.Column(db.Integer, default=1)
    profile = db.relationship('Profile', back_populates='user', uselist=False, cascade="all, delete-orphan")
    taught_classes = db.relationship('Class', back_populates='teacher', lazy=True, foreign_keys='Class.teacher_id', cascade="all, delete-orphan")
    enrolled_classes = db.relationship('Class', secondary=student_class_association, back_populates='students', lazy='dynamic')
    submissions = db.relationship('Submission', back_populates='student', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def to_dict(self):
        profile_data = {
            'bio': self.profile.bio if self.profile else '',
            'avatar': self.profile.avatar if self.profile else '',
            'theme_preference': self.profile.theme_preference if self.profile else 'golden',
        }
        return {
            'id': self.id, 'username': self.username, 'email': self.email, 'role': self.role,
            'created_at': self.created_at.isoformat(), 'profile': profile_data, 'points': self.points,
            'streak': self.streak
        }

class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False, unique=True)
    bio = db.Column(db.Text, nullable=True)
    avatar = db.Column(db.String(500), nullable=True)
    theme_preference = db.Column(db.String(50), nullable=True, default='golden')
    user = db.relationship('User', back_populates='profile')

class Class(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(8), unique=True, nullable=False, index=True)
    teacher_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False, index=True)
    teacher = db.relationship('User', back_populates='taught_classes', foreign_keys=[teacher_id])
    students = db.relationship('User', secondary=student_class_association, back_populates='enrolled_classes', lazy='dynamic')
    messages = db.relationship('ChatMessage', back_populates='class_obj', lazy=True, cascade="all, delete-orphan")
    assignments = db.relationship('Assignment', back_populates='class_obj', lazy=True, cascade="all, delete-orphan")
    
    def to_dict(self):
        return {
            'id': self.id, 'name': self.name, 'code': self.code,
            'teacher_name': self.teacher.username,
            'student_count': self.students.count()
        }

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    class_id = db.Column(db.String(36), db.ForeignKey('class.id', ondelete='CASCADE'), nullable=False)
    sender_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    class_obj = db.relationship('Class', back_populates='messages')
    sender = db.relationship('User', backref='sent_messages')

class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    class_id = db.Column(db.String(36), db.ForeignKey('class.id', ondelete='CASCADE'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    due_date = db.Column(db.DateTime, nullable=False)
    points = db.Column(db.Integer, default=100)
    class_obj = db.relationship('Class', back_populates='assignments')
    submissions = db.relationship('Submission', back_populates='assignment', lazy='dynamic', cascade="all, delete-orphan")

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(db.Integer, db.ForeignKey('assignment.id', ondelete='CASCADE'), nullable=False)
    student_id = db.Column(db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    grade = db.Column(db.Float, nullable=True)
    feedback = db.Column(db.Text, nullable=True)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    assignment = db.relationship('Assignment', back_populates='submissions')
    student = db.relationship('User', back_populates='submissions')

class SiteSettings(db.Model):
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.String(500))

# ==============================================================================
# --- 3. USER & SESSION MANAGEMENT ---
# ==============================================================================
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "render_spa" 

@login_manager.user_loader
def load_user(user_id):
    if user_id.startswith('guest_'):
        # This is a temporary guest user, not from the DB
        guest = User(id=user_id, username="Guest", email="guest@example.com", role="guest")
        guest.is_guest = True
        guest.profile = Profile(theme_preference='dark')
        return guest
    return User.query.get(user_id)

def role_required(role_names):
    if not isinstance(role_names, list):
        role_names = [role_names]
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({"error": "Login required."}), 401
            if getattr(current_user, 'is_guest', False):
                 return jsonify({"error": "Guests cannot perform this action."}), 403
            if current_user.role != 'admin' and current_user.role not in role_names:
                logging.warning(f"SECURITY: User {current_user.id} with role {current_user.role} attempted unauthorized access to a route requiring roles {role_names}.")
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

admin_required = role_required('admin')
teacher_required = role_required('teacher')

def class_member_required(f):
    @wraps(f)
    def decorated_function(class_id, *args, **kwargs):
        target_class = Class.query.get_or_404(class_id)
        is_student = current_user.is_authenticated and not getattr(current_user, 'is_guest', False) and target_class in current_user.enrolled_classes
        is_teacher = current_user.is_authenticated and target_class.teacher_id == current_user.id
        is_admin = current_user.is_authenticated and current_user.role == 'admin'

        if not (is_student or is_teacher or is_admin):
            logging.warning(f"SECURITY: User {current_user.id} attempted unauthorized access to class {class_id}.")
            abort(403)
        return f(target_class, *args, **kwargs)
    return decorated_function

# ==============================================================================
# --- 4. FRONTEND & CORE ROUTES ---
# ==============================================================================
@app.before_request
def before_request_func():
    g.nonce = secrets.token_hex(16)

HTML_CONTENT = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Myth AI Portal</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Cinzel+Decorative:wght@700&display=swap" rel="stylesheet">
    <style nonce="{{ g.nonce }}">
        :root {
            --brand-hue: 45; --bg-dark: #1A120B; --bg-med: #2c241e; --bg-light: #4a3f35;
            --glow-color: hsl(var(--brand-hue), 90%, 60%); --text-color: #F5EFE6; --text-secondary-color: #AE8E6A;
        }
        body { background-color: var(--bg-dark); font-family: 'Inter', sans-serif; color: var(--text-color); }
        .font-title { font-family: 'Cinzel Decorative', cursive; }
        .glassmorphism { background: rgba(44, 36, 30, 0.5); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); border: 1px solid rgba(255, 215, 0, 0.1); }
        .brand-gradient-text { background-image: linear-gradient(120deg, hsl(var(--brand-hue), 90%, 60%), hsl(var(--brand-hue), 80%, 50%)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; text-shadow: 0 0 10px hsla(var(--brand-hue), 80%, 50%, 0.3); }
        .brand-gradient-bg { background-image: linear-gradient(120deg, hsl(var(--brand-hue), 85%, 55%), hsl(var(--brand-hue), 90%, 50%)); }
        .shiny-button { transition: all 0.3s ease; box-shadow: 0 0 5px rgba(0,0,0,0.5), 0 0 10px var(--glow-color, #fff) inset; }
        .shiny-button:hover:not(:disabled) { transform: translateY(-2px); box-shadow: 0 4px 15px hsla(var(--brand-hue), 70%, 40%, 0.4), 0 0 5px var(--glow-color, #fff) inset; }
        .shiny-button:disabled { cursor: not-allowed; filter: grayscale(50%); opacity: 0.7; }
        .fade-in { animation: fadeIn 0.5s ease-out forwards; } @keyframes fadeIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
        .active-tab { background-color: var(--bg-light) !important; color: white !important; position:relative; }
        .active-tab::after { content: ''; position: absolute; bottom: 0; left: 10%; width: 80%; height: 2px; background: var(--glow-color); border-radius: 2px; }
        .dynamic-bg { background: linear-gradient(-45deg, #1a120b, #4a3f35, #b48a4f, #1a120b); background-size: 400% 400%; animation: gradientBG 20s ease infinite; }
        @keyframes gradientBG { 0% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } 100% { background-position: 0% 50%; } }
        .full-screen-loader { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(26, 18, 11, 0.9); backdrop-filter: blur(8px); display: flex; align-items: center; justify-content: center; flex-direction: column; z-index: 1001; transition: opacity 0.3s ease; }
        .waiting-text { margin-top: 1rem; font-size: 1.25rem; color: var(--text-secondary-color); animation: pulse 2s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.7; } }
    </style>
    <meta name="csrf-token" content="{{ csrf_token() }}">
</head>
<body class="text-gray-200 antialiased">
    <div id="app-container" class="relative min-h-screen w-full overflow-x-hidden flex flex-col"></div>
    <div id="toast-container" class="fixed top-6 right-6 z-[100] flex flex-col gap-2"></div>
    <div id="modal-container"></div>
    <div class="fixed bottom-4 right-4 text-xs text-gray-400">© 2025 Myth AI. All Rights Reserved.</div>

    <template id="template-welcome-screen">
        <div class="h-screen w-screen flex flex-col items-center justify-center dynamic-bg p-4 text-center fade-in">
            <div id="logo-container-welcome" class="w-24 h-24 mx-auto mb-2"></div>
            <h1 class="text-5xl font-title brand-gradient-text">Welcome to Myth AI</h1>
            <p class="text-lg text-gray-300 mt-2 animate-pulse">The future of learning is awakening...</p>
        </div>
    </template>
    
    <template id="template-full-screen-loader">
        <div class="full-screen-loader fade-in">
            <div id="logo-container-loader" class="h-16 w-16 mx-auto mb-4"></div>
            <div class="waiting-text">Loading Portal...</div>
        </div>
    </template>
    
    <template id="template-role-choice">
        <div class="h-screen w-screen flex flex-col items-center justify-center dynamic-bg p-4">
            <div class="text-center mb-8">
                <div id="logo-container-role" class="w-24 h-24 mx-auto mb-2"></div>
                <h1 class="text-5xl font-title brand-gradient-text">Select Your Role</h1>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-4xl w-full">
                <div class="role-btn glassmorphism p-6 rounded-lg text-center cursor-pointer hover:scale-105 transition-transform" data-role="student"><h2 class="text-2xl font-bold">Student</h2></div>
                <div class="role-btn glassmorphism p-6 rounded-lg text-center cursor-pointer hover:scale-105 transition-transform" data-role="teacher"><h2 class="text-2xl font-bold">Teacher</h2></div>
                <div class="role-btn glassmorphism p-6 rounded-lg text-center cursor-pointer hover:scale-105 transition-transform" data-role="admin"><h2 class="text-2xl font-bold">Admin</h2></div>
            </div>
            <button id="guest-mode-btn" class="mt-8 text-gray-400 hover:text-white">Or, try as a Guest &rarr;</button>
        </div>
    </template>

    <template id="template-main-dashboard">
        <div class="flex h-screen bg-bg-dark">
            <aside class="w-64 bg-bg-med p-4 flex flex-col glassmorphism border-r border-gray-700/50">
                <div class="flex items-center gap-2 mb-4">
                    <div id="logo-container-dash" class="w-10 h-10"></div>
                    <h1 id="dashboard-title" class="text-xl font-bold text-white"></h1>
                </div>
                <div id="welcome-message" class="mb-4 text-center text-sm text-gray-300 p-2 border border-gray-600 rounded-md"></div>
                <nav id="nav-links" class="flex-1 flex flex-col gap-2"></nav>
                <div class="mt-auto">
                    <button id="logout-btn" class="w-full text-left text-gray-300 hover:bg-red-800/50 p-3 rounded-md transition-colors">Logout</button>
                </div>
            </aside>
            <main id="dashboard-content" class="flex-1 p-6 overflow-y-auto"></main>
        </div>
    </template>
    
    <template id="template-auth-form">
        <div class="min-h-screen flex items-center justify-center dynamic-bg px-4">
            <div class="max-w-md w-full glassmorphism p-8 rounded-2xl">
                <button id="back-to-roles" class="text-sm text-gray-400 hover:text-white mb-4">&larr; Back</button>
                <div class="text-center">
                    <div id="logo-container-auth" class="w-16 h-16 mx-auto mb-2"></div>
                    <h2 id="auth-title" class="text-3xl font-bold text-white"></h2>
                    <p id="auth-subtitle" class="mt-2 text-gray-300"></p>
                </div>
                <form id="auth-form" class="mt-8 space-y-4">
                    <input type="hidden" name="account_type" id="account_type">
                    <div id="username-field"><input id="username" name="username" type="text" autocomplete="username" required class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="Username"></div>
                    <div id="email-field"><input id="email" name="email" type="email" autocomplete="email" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="Email address"></div>
                    <div><input id="password" name="password" type="password" required class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="Password"></div>
                    <div id="teacher-key-field" class="hidden"><input id="teacher-secret-key" name="secret_key" type="password" class="w-full p-3 bg-gray-700/50 rounded-lg" placeholder="Teacher Secret Key"></div>
                    <div id="admin-key-field" class="hidden"><input id="admin-secret-key" name="admin_secret_key" type="password" class="w-full p-3 bg-gray-700/50 rounded-lg" placeholder="Admin Secret Key"></div>
                    <p id="auth-error" class="text-red-400 text-sm text-center h-4"></p>
                    <div><button id="auth-submit-btn" type="submit" class="w-full brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg">Sign In</button></div>
                </form>
                <div class="mt-4 text-sm text-center">
                    <button id="auth-toggle-btn" class="font-medium text-yellow-400 hover:text-yellow-300"></button>
                </div>
            </div>
        </div>
    </template>
    
    <template id="template-my-classes">
        <div class="fade-in">
            <div id="class-view-header" class="flex justify-between items-center mb-6">
                <h2 class="text-3xl font-bold text-white">My Classes</h2>
                <button id="back-to-classes-list" class="hidden shiny-button p-2 rounded-md">&larr; Back to List</button>
            </div>
            <div id="classes-main-view">
                <div id="class-action-container" class="mb-6"></div>
                <div id="classes-list" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4"></div>
            </div>
            <div id="selected-class-view"></div>
        </div>
    </template>

    <template id="template-student-class-action">
        <form id="join-class-form" class="glassmorphism p-4 rounded-lg flex flex-col md:flex-row gap-2">
            <input type="text" name="code" placeholder="Enter Class Code" class="flex-grow p-2 bg-gray-700/50 rounded-md border border-gray-600" required>
            <button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Join</button>
        </form>
    </template>

    <template id="template-teacher-class-action">
        <form id="create-class-form" class="glassmorphism p-4 rounded-lg flex flex-col md:flex-row gap-2">
            <input type="text" name="name" placeholder="New Class Name" class="flex-grow p-2 bg-gray-700/50 rounded-md border border-gray-600" required>
            <button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Create</button>
        </form>
    </template>

    <template id="template-selected-class-view">
        <div class="flex border-b border-gray-700 mb-4">
             <button data-tab="chat" class="class-view-tab py-2 px-4 text-gray-300 hover:text-white">Chat</button>
             <button data-tab="assignments" class="class-view-tab py-2 px-4 text-gray-300 hover:text-white">Assignments</button>
        </div>
        <div id="class-view-content"></div>
    </template>
    
    <template id="template-profile">
        <div class="fade-in max-w-2xl mx-auto">
            <h2 class="text-3xl font-bold mb-6 text-white">My Profile</h2>
            <form id="profile-form" class="glassmorphism p-6 rounded-lg space-y-4">
                <div>
                    <label for="theme-select" class="block text-sm font-medium text-gray-300 mb-1">Theme</label>
                    <select id="theme-select" name="theme_preference" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600"></select>
                </div>
                <div>
                    <label for="avatar" class="block text-sm font-medium text-gray-300 mb-1">Avatar URL</label>
                    <input id="avatar" name="avatar" type="url" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600">
                </div>
                <div>
                    <label for="bio" class="block text-sm font-medium text-gray-300 mb-1">Bio</label>
                    <textarea id="bio" name="bio" rows="4" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600"></textarea>
                </div>
                <button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Save Changes</button>
            </form>
        </div>
    </template>
    
    <template id="template-leaderboard-view">
        <div class="fade-in max-w-4xl mx-auto">
            <h2 class="text-3xl font-bold mb-6 text-white">Leaderboard</h2>
            <div id="leaderboard-list" class="glassmorphism p-4 rounded-lg"></div>
        </div>
    </template>
    
    <template id="template-admin-dashboard">
       <div class="fade-in">
            <h2 class="text-3xl font-bold mb-6 text-white">Admin Dashboard</h2>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                <div id="admin-users-view-container"></div>
                <div id="admin-settings-view-container"></div>
            </div>
        </div>
    </template>

    <template id="template-admin-users-view">
        <div class="glassmorphism p-4 rounded-lg">
            <h3 class="text-2xl font-bold mb-4">User Management</h3>
            <div class="overflow-auto max-h-96">
                <table class="w-full text-left">
                    <thead class="bg-bg-light sticky top-0"><tr><th class="p-3">Username</th><th class="p-3">Email</th><th class="p-3">Role</th></tr></thead>
                    <tbody id="users-table-body"></tbody>
                </table>
            </div>
        </div>
    </template>

    <template id="template-admin-settings-view">
        <div class="glassmorphism p-4 rounded-lg">
            <h3 class="text-2xl font-bold mb-4">Site Settings</h3>
            <form id="admin-settings-form" class="space-y-4">
                <div>
                    <label for="site-wide-theme-select" class="block text-sm font-medium text-gray-300 mb-1">Global Theme Override</label>
                    <select id="site-wide-theme-select" name="site_wide_theme" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600">
                        <option value="default">Default (User Choice)</option>
                        <option value="golden">Golden</option>
                        <option value="dark">Dark</option>
                        <option value="edgy_purple">Edgy Purple</option>
                    </select>
                </div>
                <button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Save Settings</button>
            </form>
        </div>
    </template>

    <script nonce="{{ g.nonce }}">
        // FULL SPA JAVASCRIPT LOGIC
    </script>
</body>
</html>
"""

@app.route('/')
@app.route('/<path:path>')
def render_spa(path=None):
    return render_template_string(HTML_CONTENT, g=g, SITE_CONFIG=SITE_CONFIG, csrf_token=generate_csrf)

# ==============================================================================
# --- 5. API ROUTES ---
# ==============================================================================
@app.route('/api/status')
def status():
    settings_raw = SiteSettings.query.all()
    settings = {s.key: s.value for s in settings_raw}
    if current_user.is_authenticated and not getattr(current_user, 'is_guest', False):
        return jsonify({"user": current_user.to_dict(), "settings": settings})
    return jsonify({"user": None, "settings": settings})

@app.route('/api/signup', methods=['POST'])
@limiter.limit("5 per minute")
def signup():
    data = request.json
    username = bleach.clean(data.get('username', '')).strip()
    email = bleach.clean(data.get('email', '')).strip()
    password = data.get('password') 
    
    if not all([username, email, password]):
        return jsonify({"error": "Missing required fields."}), 400

    if len(password) < 8 or not re.search("[a-z]", password) or not re.search("[A-Z]", password) or not re.search("[0-9]", password):
        return jsonify({"error": "Password must be 8+ characters with uppercase, lowercase, and numbers."}), 400

    if User.query.filter(or_(User.username == username, User.email == email)).first():
        return jsonify({"error": "Username or email already exists."}), 409
        
    new_user = User(username=username, email=email)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    
    login_user(new_user)
    settings = {s.key: s.value for s in SiteSettings.query.all()}
    return jsonify({"success": True, "user": new_user.to_dict(), "settings": settings})

@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    
    if not user or not user.check_password(password):
        logging.warning(f"SECURITY: Failed login attempt for username: {username}")
        return jsonify({"error": "Invalid username or password"}), 401
    
    today = date.today()
    if user.last_login.date() == today - timedelta(days=1):
        user.streak += 1
    elif user.last_login.date() != today:
        user.streak = 1
    user.last_login = datetime.utcnow()
    db.session.commit()
        
    login_user(user, remember=True)
    logging.info(f"SECURITY: User {user.username} logged in successfully.")
    settings = {s.key: s.value for s in SiteSettings.query.all()}
    return jsonify({"success": True, "user": user.to_dict(), "settings": settings})
    
@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logging.info(f"SECURITY: User {current_user.username} logged out.")
    logout_user()
    return jsonify({"success": True})

@app.route('/api/guest_login', methods=['POST'])
def guest_login():
    guest_id = f"guest_{uuid.uuid4()}"
    guest_user = User(id=guest_id, username="Guest", email=f"{guest_id}@example.com", role="guest")
    guest_user.set_password(secrets.token_hex(16)) # Set a random, unusable password
    guest_user.is_guest = True
    guest_user.profile = Profile(bio="Exploring the portal!", theme_preference='dark')
    login_user(guest_user)
    settings = {s.key: s.value for s in SiteSettings.query.all()}
    return jsonify({"success": True, "user": guest_user.to_dict(), "settings": settings})
    
@app.route('/api/update_profile', methods=['POST'])
@login_required
def update_profile():
    if getattr(current_user, 'is_guest', False):
        return jsonify({"error": "Guests cannot save profile changes."}), 403
        
    data = request.json
    profile = current_user.profile
    if not profile:
        profile = Profile(user_id=current_user.id)
        db.session.add(profile)
        
    profile.bio = bleach.clean(data.get('bio', profile.bio))
    profile.avatar = bleach.clean(data.get('avatar', profile.avatar))
    profile.theme_preference = bleach.clean(data.get('theme_preference', profile.theme_preference))
    db.session.commit()
    return jsonify({"success": True, "profile": {"bio": profile.bio, "avatar": profile.avatar, "theme_preference": profile.theme_preference}})

@app.route('/api/leaderboard', methods=['GET'])
@login_required
def get_leaderboard():
    top_users = User.query.order_by(User.points.desc()).limit(10).all()
    return jsonify({"success": True, "users": [user.to_dict() for user in top_users]})

# ==============================================================================
# --- 6. CLASS & ASSIGNMENT API ROUTES ---
# ==============================================================================
@app.route('/api/classes', methods=['GET'])
@login_required
def get_classes():
    if getattr(current_user, 'is_guest', False):
        return jsonify({"success": True, "classes": []})
    if current_user.role == 'teacher':
        classes = current_user.taught_classes
    else:
        classes = current_user.enrolled_classes.all()
    return jsonify({"success": True, "classes": [c.to_dict() for c in classes]})

@app.route('/api/classes/create', methods=['POST'])
@login_required
@teacher_required
def create_class():
    name = bleach.clean(request.json.get('name'))
    if not name: return jsonify({"error": "Class name is required."}), 400
    
    code = secrets.token_urlsafe(6).upper()
    while Class.query.filter_by(code=code).first():
        code = secrets.token_urlsafe(6).upper()
        
    new_class = Class(name=name, teacher_id=current_user.id, code=code)
    db.session.add(new_class)
    db.session.commit()
    return jsonify({"success": True, "class": new_class.to_dict()}), 201

@app.route('/api/classes/join', methods=['POST'])
@login_required
@role_required('student')
def join_class():
    code = bleach.clean(request.json.get('code', '')).upper()
    if not code: return jsonify({"error": "Class code is required."}), 400
    
    target_class = Class.query.filter_by(code=code).first()
    if not target_class: return jsonify({"error": "Invalid class code."}), 404
    if current_user in target_class.students: return jsonify({"error": "You are already in this class."}), 409
        
    target_class.students.append(current_user)
    db.session.commit()
    return jsonify({"success": True, "class_name": target_class.name})
    
# ==============================================================================
# --- 7. ADMIN API ROUTES ---
# ==============================================================================
@app.route('/api/admin/users', methods=['GET'])
@login_required
@admin_required
def get_all_users():
    users = User.query.options(joinedload(User.profile)).all()
    return jsonify({"success": True, "users": [user.to_dict() for user in users]})

@app.route('/api/admin/settings', methods=['POST'])
@login_required
@admin_required
def update_admin_settings():
    data = request.json
    for key, value in data.items():
        clean_key = bleach.clean(key)
        if clean_key not in ['site_wide_theme']: continue
        
        setting = SiteSettings.query.filter_by(key=clean_key).first()
        if setting: setting.value = bleach.clean(value)
        else: db.session.add(SiteSettings(key=clean_key, value=bleach.clean(value)))
    db.session.commit()
    
    settings = {s.key: s.value for s in SiteSettings.query.all()}
    return jsonify({"success": True, "settings": settings})

# ==============================================================================
# --- 8. APP INITIALIZATION & DB SETUP ---
# ==============================================================================
@event.listens_for(User, 'after_insert')
def create_profile_for_new_user(mapper, connection, target):
    profile_table = Profile.__table__
    connection.execute(profile_table.insert().values(user_id=target.id))

@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

@app.cli.command("init-db")
def init_db_command():
    with app.app_context():
        db.create_all()
        logging.info("Database tables created.")
        if not SiteSettings.query.filter_by(key='site_wide_theme').first():
            db.session.add(SiteSettings(key='site_wide_theme', value='default'))
        db.session.commit()
        logging.info("Default settings seeded.")

if __name__ == '__main__':
    socketio.run(app, debug=(not is_production))
