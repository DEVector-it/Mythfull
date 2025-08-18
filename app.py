# --- Imports ---
import os
import json
import logging
import time
import uuid
import secrets
import bleach
import re
from flask import Flask, request, jsonify, redirect, url_for, render_template_string, abort, g
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from datetime import datetime, date, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
import stripe
from itsdangerous import TimestampSigner, SignatureExpired, BadTimeSignature
from flask_mail import Mail, Message
from flask_talisman import Talisman
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event, or_
from sqlalchemy.orm import joinedload, selectinload
from sqlalchemy.engine import Engine
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
from sqlalchemy.exc import IntegrityError
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from markupsafe import escape
from flask_bcrypt import Bcrypt
from flask import session
from password_strength import PasswordPolicy

# ==============================================================================
# --- 1. INITIAL CONFIGURATION & SETUP ---
# ==============================================================================

# Ensure critical dependencies are installed
try:
    import eventlet
except ImportError:
    logging.critical("FATAL ERROR: The 'eventlet' package is required. Run: pip install eventlet")
    exit(1)

load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [SECURITY] - %(message)s')

# --- Flask App Initialization ---
app = Flask(__name__)

# --- App Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///database.db'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get('SECURITY_PASSWORD_SALT') or secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

# --- Production Security Configuration ---
is_production = os.environ.get('FLASK_ENV') == 'production'
if is_production:
    required_secrets = ['SECRET_KEY', 'DATABASE_URL', 'SECURITY_PASSWORD_SALT', 'STRIPE_SECRET_KEY', 'YOUR_DOMAIN', 'SECRET_TEACHER_KEY', 'ADMIN_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET', 'MAIL_SENDER', 'MAIL_USERNAME', 'MAIL_PASSWORD']
    for key in required_secrets:
        if not os.environ.get(key):
            logging.critical(f"Missing a required production secret: {key}. Exiting.")
            exit(1)
    app.config.update(
        SESSION_COOKIE_SECURE=True, REMEMBER_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True, REMEMBER_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax'
    )

# --- Site-wide Configuration ---
SITE_CONFIG = {
    "STRIPE_SECRET_KEY": os.environ.get('STRIPE_SECRET_KEY'),
    "STRIPE_PUBLIC_KEY": os.environ.get('STRIPE_PUBLIC_KEY'),
    "STRIPE_STUDENT_PRO_PRICE_ID": os.environ.get('STRIPE_STUDENT_PRO_PRICE_ID'),
    "YOUR_DOMAIN": os.environ.get('YOUR_DOMAIN', 'https://myth-ai-io.onrender.com'),
    "SECRET_TEACHER_KEY": os.environ.get('SECRET_TEACHER_KEY'),
    "ADMIN_SECRET_KEY": os.environ.get('ADMIN_SECRET_KEY'),
    "STRIPE_WEBHOOK_SECRET": os.environ.get('STRIPE_WEBHOOK_SECRET'),
    "GEMINI_API_KEY": os.environ.get('GEMINI_API_KEY'),
    "SUPPORT_EMAIL": os.environ.get('MAIL_SENDER')
}

# --- Security & Extensions Initialization ---
prod_origin = SITE_CONFIG["YOUR_DOMAIN"]
CORS(app, supports_credentials=True, origins=[prod_origin] if is_production else "*")

csp = {
    'default-src': '\'self\'',
    'script-src': ['\'self\'', 'https://cdn.tailwindcss.com', 'https://cdnjs.cloudflare.com', 'https://js.stripe.com', '\'nonce-{nonce}\''],
    'style-src': ['\'self\'', '\'unsafe-inline\'', 'https://cdn.tailwindcss.com', 'https://fonts.googleapis.com', '\'nonce-{nonce}\''],
    'font-src': ['\'self\'', 'https://fonts.gstatic.com'],
    'img-src': ['*', 'data:'],
    'media-src': ['*'],
    'connect-src': [
        '\'self\'',
        f'wss://{prod_origin.split("//")[-1]}' if is_production else 'ws://localhost:5000',
        'https://api.stripe.com', 'https://generativelanguage.googleapis.com'
    ],
    'object-src': '\'none\'', 'base-uri': '\'self\'', 'form-action': '\'self\''
}
talisman = Talisman(app, content_security_policy=csp, force_https=is_production, strict_transport_security=is_production, frame_options='DENY', referrer_policy='strict-origin-when-cross-origin')
csrf = CSRFProtect(app)
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins=prod_origin if is_production else "*", async_mode='eventlet')
mail = Mail(app)
stripe.api_key = SITE_CONFIG.get("STRIPE_SECRET_KEY")

# --- Password Policy ---
password_policy = PasswordPolicy.from_names(length=12, uppercase=1, numbers=1, special=1)

# --- AI Model Initialization ---
if SITE_CONFIG.get("GEMINI_API_KEY"):
    try:
        import google.generativeai as genai
        genai.configure(api_key=SITE_CONFIG.get("GEMINI_API_KEY"))
    except ImportError:
        logging.error("The 'google-generativeai' library is not found, AI features are disabled.")
        genai = None

# --- Flask-Mail Configuration ---
app.config.update(
    MAIL_SERVER=os.environ.get('MAIL_SERVER'),
    MAIL_PORT=int(os.environ.get('MAIL_PORT', 587)),
    MAIL_USE_TLS=os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true',
    MAIL_USERNAME=os.environ.get('MAIL_USERNAME'),
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD'),
    MAIL_DEFAULT_SENDER=os.environ.get('MAIL_SENDER')
)

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
    role = db.Column(db.String(20), nullable=False, default='student', index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    points = db.Column(db.Integer, default=0, index=True)
    last_login = db.Column(db.DateTime, default=datetime.utcnow)
    streak = db.Column(db.Integer, default=1)
    profile = db.relationship('Profile', back_populates='user', uselist=False, cascade="all, delete-orphan")
    taught_classes = db.relationship('Class', back_populates='teacher', lazy='dynamic', foreign_keys='Class.teacher_id', cascade="all, delete-orphan")
    enrolled_classes = db.relationship('Class', secondary=student_class_association, back_populates='students', lazy='dynamic')
    subscription = db.relationship('Subscription', back_populates='user', uselist=False, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def to_dict(self, include_email=False):
        profile_data = {
            'bio': self.profile.bio if self.profile else '',
            'avatar': self.profile.avatar if self.profile else '',
            'theme_preference': self.profile.theme_preference if self.profile else 'edgy_purple',
        }
        data = {
            'id': self.id, 'username': self.username, 'role': self.role,
            'created_at': self.created_at.isoformat(), 'profile': profile_data, 'points': self.points,
            'streak': self.streak,
            'subscription_status': self.subscription.status if self.subscription else 'free'
        }
        if include_email: data['email'] = self.email
        return data

class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False, unique=True)
    bio = db.Column(db.Text, nullable=True)
    avatar = db.Column(db.String(500), nullable=True)
    theme_preference = db.Column(db.String(50), nullable=True, default='edgy_purple')
    user = db.relationship('User', back_populates='profile')

class Class(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(8), unique=True, nullable=False, index=True)
    teacher_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False, index=True)
    teacher = db.relationship('User', back_populates='taught_classes', foreign_keys=[teacher_id])
    students = db.relationship('User', secondary=student_class_association, back_populates='enrolled_classes', lazy='dynamic')
    messages = db.relationship('ChatMessage', back_populates='class_obj', lazy='dynamic', cascade="all, delete-orphan")

    def to_dict(self):
        return {
            'id': self.id, 'name': self.name, 'code': self.code,
            'teacher_name': self.teacher.username,
            'student_count': self.students.count()
        }

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    class_id = db.Column(db.String(36), db.ForeignKey('class.id', ondelete='CASCADE'), nullable=False, index=True)
    sender_id = db.Column(db.String(36), db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    is_edited = db.Column(db.Boolean, default=False)
    reactions = db.Column(db.JSON, default=lambda: {})
    class_obj = db.relationship('Class', back_populates='messages')
    sender = db.relationship('User', backref='sent_messages')

    def to_dict(self):
        return {
            'id': self.id, 'class_id': self.class_id,
            'sender': self.sender.to_dict() if self.sender else {'username': 'Unknown User', 'id': None, 'profile': {}},
            'content': self.content, 'timestamp': self.timestamp.isoformat(),
            'is_edited': self.is_edited, 'reactions': self.reactions or {}
        }

class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False, unique=True)
    stripe_customer_id = db.Column(db.String(255), unique=True)
    stripe_subscription_id = db.Column(db.String(255), unique=True)
    status = db.Column(db.String(50), default='free', index=True)
    user = db.relationship('User', back_populates='subscription')

class SiteSettings(db.Model):
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.Text)

class IssueReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    page_url = db.Column(db.String(500), nullable=True)
    user_agent = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text, nullable=False)
    user = db.relationship('User', backref='issue_reports')

# ==============================================================================
# --- 3. USER & SESSION MANAGEMENT ---
# ==============================================================================
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "render_spa"

@login_manager.user_loader
def load_user(user_id):
    if user_id.startswith('guest_'):
        guest = User(id=user_id, username="Guest", email=f"{user_id}@example.com", role="guest")
        guest.is_guest = True
        guest.profile = Profile(theme_preference='dark')
        guest.subscription = Subscription(status='free')
        return guest
    return User.query.options(selectinload(User.profile), selectinload(User.subscription)).get(user_id)

def role_required(role_names):
    if not isinstance(role_names, list): role_names = [role_names]
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated: return jsonify({"error": "Login required."}), 401
            if getattr(current_user, 'is_guest', False): return jsonify({"error": "Guests cannot perform this action."}), 403
            if current_user.role != 'admin' and current_user.role not in role_names:
                logging.warning(f"SECURITY: User {current_user.id} with role {current_user.role} attempted unauthorized access to a route requiring roles {role_names}.")
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

admin_required = role_required(['admin'])
teacher_required = role_required(['teacher'])

def class_member_required(f):
    @wraps(f)
    def decorated_function(class_id, *args, **kwargs):
        target_class = Class.query.options(selectinload(Class.teacher)).get_or_404(class_id)
        is_student = False
        if current_user.is_authenticated and not getattr(current_user, 'is_guest', False):
            is_student = db.session.query(student_class_association.c.user_id).filter_by(user_id=current_user.id, class_id=class_id).first() is not None
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
    g.request_start_time = time.time()

@app.after_request
def after_request_func(response):
    if hasattr(g, 'request_start_time'):
        duration = time.time() - g.request_start_time
        if duration > 0.5:
            logging.warning(f"PERFORMANCE: Slow request: {request.path} took {duration:.2f}s")
    return response

@app.errorhandler(Exception)
def handle_exception(e):
    logging.error(f"An unhandled exception occurred: {e}", exc_info=True)
    response = jsonify(error="An internal server error occurred. The developers have been notified.")
    response.status_code = 500
    return response

HTML_CONTENT = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Myth AI Portal</title>
    <script src="https://js.stripe.com/v3/"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Cinzel+Decorative:wght@700&display=swap" rel="stylesheet">
    <style nonce="{{ g.nonce }}">
        :root {
            --brand-hue: 260; --bg-dark: #110D19; --bg-med: #211A2E; --bg-light: #3B2D4F;
            --glow-color: hsl(var(--brand-hue), 90%, 60%); --text-color: #EADFFF; --text-secondary-color: #A17DFF;
        }
        body {
            background-color: var(--bg-dark); font-family: 'Inter', sans-serif; color: var(--text-color);
            background-size: cover; background-position: center; background-attachment: fixed; transition: background-image 0.5s ease-in-out;
        }
        .font-title { font-family: 'Cinzel Decorative', cursive; }
        .glassmorphism { background: rgba(33, 26, 46, 0.5); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); border: 1px solid rgba(161, 125, 255, 0.1); }
        .brand-gradient-text { background-image: linear-gradient(120deg, hsl(var(--brand-hue), 90%, 60%), hsl(var(--brand-hue), 80%, 50%)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; text-shadow: 0 0 10px hsla(var(--brand-hue), 80%, 50%, 0.3); }
        .brand-gradient-bg { background-image: linear-gradient(120deg, hsl(var(--brand-hue), 85%, 55%), hsl(var(--brand-hue), 90%, 50%)); }
        .shiny-button { transition: all 0.2s ease-in-out; box-shadow: 0 0 5px rgba(0,0,0,0.5), 0 0 10px var(--glow-color, #fff) inset; }
        .shiny-button:hover:not(:disabled) { transform: translateY(-2px); box-shadow: 0 4px 15px hsla(var(--brand-hue), 70%, 40%, 0.4), 0 0 5px var(--glow-color, #fff) inset; }
        .shiny-button:disabled { cursor: not-allowed; filter: grayscale(50%); opacity: 0.7; }
        .fade-in { animation: fadeIn 0.5s ease-out forwards; } @keyframes fadeIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
        .active-tab { background-color: var(--bg-light) !important; color: white !important; position:relative; }
        .active-tab::after { content: ''; position: absolute; bottom: 0; left: 10%; width: 80%; height: 2px; background: var(--glow-color); border-radius: 2px; }
        .dynamic-bg { background: linear-gradient(-45deg, var(--bg-dark), var(--bg-light), var(--bg-med), var(--bg-dark)); background-size: 400% 400%; animation: gradientBG 20s ease infinite; }
        @keyframes gradientBG { 0% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } 100% { background-position: 0% 50%; } }
        .full-screen-loader { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(17, 13, 25, 0.9); backdrop-filter: blur(8px); display: flex; align-items: center; justify-content: center; flex-direction: column; z-index: 1001; transition: opacity 0.3s ease; }
        .waiting-text { margin-top: 1rem; font-size: 1.25rem; color: var(--text-secondary-color); animation: pulse 2s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.7; } }
    </style>
    <meta name="csrf-token" content="{{ csrf_token() }}">
</head>
<body class="text-gray-200 antialiased">
    <div id="app-container" class="relative min-h-screen w-full overflow-x-hidden flex flex-col"></div>
    <div id="toast-container" class="fixed top-6 right-6 z-[100] flex flex-col gap-2"></div>
    <div id="modal-container"></div>
    <div id="music-player-container" class="fixed bottom-4 left-4 z-50"></div>
    <div class="fixed bottom-4 right-4 text-xs text-gray-400 z-0">© 2025 Myth AI</div>

    <template id="template-welcome-screen">
        <div class="relative h-screen w-screen flex flex-col items-center justify-center overflow-hidden bg-bg-dark">
            <div class="absolute inset-0 overflow-hidden">
                <div class="particles"></div>
                <div class="gradient-overlay"></div>
            </div>
            <div class="relative z-10 flex flex-col items-center text-center px-4">
                <div id="logo-container-welcome" class="w-32 h-32 mb-6 transform hover:scale-110 transition-transform duration-500"></div>
                <h1 class="text-6xl md:text-7xl font-title brand-gradient-text animate-pulse-slow">Myth AI</h1>
                <p class="text-xl md:text-2xl text-text-secondary-color mt-4 max-w-lg animate-fade-in-up">
                    Embark on a journey of knowledge with an AI-powered learning experience.
                </p>
                <button id="enter-portal-btn" class="mt-8 brand-gradient-bg shiny-button text-white font-bold py-3 px-6 rounded-lg text-lg transform hover:scale-105 transition-all duration-300">
                    Enter the Portal
                </button>
                <p class="mt-6 text-sm text-gray-400 animate-fade-in-up delay-200">
                    Powered by xAI &bull; Unleashing Limitless Learning
                </p>
            </div>
            <style nonce="{{ g.nonce }}">
                .gradient-overlay { position: absolute; inset: 0; background: radial-gradient(circle at center, hsla(var(--brand-hue), 90%, 60%, 0.15) 0%, transparent 70%); }
                .particles { position: absolute; inset: 0; background: transparent; animation: particles 20s linear infinite; }
                .particles::before {
                    content: ''; position: absolute; width: 2px; height: 2px; background: hsla(var(--brand-hue), 90%, 60%, 0.3);
                    box-shadow: 10vw 20vh 2px hsla(var(--brand-hue), 90%, 60%, 0.2), 30vw 40vh 2px hsla(var(--brand-hue), 90%, 60%, 0.3), 50vw 10vh 2px hsla(var(--brand-hue), 90%, 60%, 0.25), 70vw 70vh 2px hsla(var(--brand-hue), 90%, 60%, 0.2), 90vw 30vh 2px hsla(var(--brand-hue), 90%, 60%, 0.3);
                    animation: float 15s ease-in-out infinite;
                }
                @keyframes float { 0%, 100% { transform: translateY(0); opacity: 0.5; } 50% { transform: translateY(-20px); opacity: 0.8; } }
                @keyframes particles { 0% { transform: translateY(0); } 100% { transform: translateY(-1000px); } }
                .animate-pulse-slow { animation: pulse-slow 3s ease-in-out infinite; }
                @keyframes pulse-slow { 0%, 100% { transform: scale(1); opacity: 1; } 50% { transform: scale(1.02); opacity: 0.95; } }
                .animate-fade-in-up { animation: fade-in-up 0.8s ease-out forwards; }
                @keyframes fade-in-up { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
                .delay-200 { animation-delay: 0.2s; }
                #enter-portal-btn { box-shadow: 0 0 15px hsla(var(--brand-hue), 70%, 40%, 0.4); }
                #enter-portal-btn:hover { box-shadow: 0 0 20px hsla(var(--brand-hue), 70%, 40%, 0.6); }
            </style>
        </div>
    </template>
    <template id="template-full-screen-loader">
        <div class="full-screen-loader fade-in">
            <div id="logo-container-loader" class="h-16 w-16 mx-auto mb-4 animate-spin"></div>
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
            <aside class="w-64 bg-bg-med p-4 flex-col glassmorphism border-r border-gray-700/50 hidden md:flex">
                <div class="flex items-center gap-2 mb-4">
                    <div id="logo-container-dash" class="w-10 h-10"></div>
                    <h1 id="dashboard-title" class="text-xl font-bold text-white"></h1>
                </div>
                <div id="welcome-message" class="mb-4 text-center text-sm text-gray-300 p-2 border border-gray-600 rounded-md"></div>
                <nav id="nav-links" class="flex-1 flex flex-col gap-2"></nav>
                <div class="mt-auto">
                    <button id="report-issue-btn" class="w-full text-left text-gray-300 hover:bg-purple-800/50 p-3 rounded-md transition-colors mb-2">Report Issue</button>
                    <button id="logout-btn" class="w-full text-left text-gray-300 hover:bg-red-800/50 p-3 rounded-md transition-colors">Logout</button>
                </div>
            </aside>
            <main id="dashboard-content" class="flex-1 p-4 md:p-6 overflow-y-auto"></main>
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
                    <button id="auth-toggle-btn" class="font-medium text-purple-400 hover:text-purple-300"></button>
                    <span class="text-gray-400 mx-1">|</span>
                    <button id="forgot-password-btn" class="font-medium text-purple-400 hover:text-purple-300">Forgot Password?</button>
                </div>
            </div>
        </div>
    </template>
    <template id="template-my-classes">
        <div class="fade-in">
            <div id="class-view-header" class="flex justify-between items-center mb-6">
                <h2 id="my-classes-title" class="text-3xl font-bold text-white">My Classes</h2>
                <button id="back-to-classes-list" class="hidden shiny-button p-2 rounded-md">&larr; Back to List</button>
            </div>
            <div id="classes-main-view">
                <div id="class-action-container" class="mb-6"></div>
                <div id="classes-list" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4"></div>
            </div>
            <div id="selected-class-view" class="hidden"></div>
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
        </div>
        <div id="class-view-content"></div>
    </template>
    <template id="template-class-chat-view">
        <div class="flex flex-col h-[calc(100vh-15rem)]">
            <div id="chat-messages" class="flex-1 overflow-y-auto p-4 space-y-4"></div>
            <div id="typing-indicator" class="h-6 px-4 text-sm text-gray-400 italic"></div>
            <form id="chat-form" class="p-4 bg-bg-med glassmorphism mt-2 rounded-lg">
                <div class="flex items-center gap-2">
                    <input id="chat-input" type="text" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="Type a message..." autocomplete="off">
                    <button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-3 px-5 rounded-lg">Send</button>
                </div>
            </form>
        </div>
    </template>
    <template id="template-profile">
        <div class="fade-in max-w-2xl mx-auto">
            <h2 class="text-3xl font-bold mb-6 text-white">My Profile</h2>
            <div class="flex border-b border-gray-700 mb-4">
                <button data-tab="settings" class="profile-view-tab py-2 px-4 text-gray-300 hover:text-white">Settings</button>
                <button data-tab="billing" class="profile-view-tab py-2 px-4 text-gray-300 hover:text-white">Billing</button>
            </div>
            <div id="profile-view-content"></div>
        </div>
    </template>
    <template id="template-profile-settings">
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
    </template>
    <template id="template-profile-billing">
        <div class="glassmorphism p-6 rounded-lg space-y-4">
            <h3 class="text-2xl font-bold">Subscription</h3>
            <div id="subscription-status"></div>
            <div id="billing-actions"></div>
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
            <div class="flex border-b border-gray-700 mb-4">
                <button data-tab="users" class="admin-view-tab py-2 px-4 text-gray-300 hover:text-white">Users</button>
                <button data-tab="settings" class="admin-view-tab py-2 px-4 text-gray-300 hover:text-white">Settings</button>
                <button data-tab="appearance" class="admin-view-tab py-2 px-4 text-gray-300 hover:text-white">Appearance</button>
            </div>
            <div id="admin-view-content"></div>
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
                        <option value="light_green">Light Green</option>
                    </select>
                </div>
                <button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Save Settings</button>
            </form>
        </div>
    </template>
    <template id="template-admin-appearance-view">
        <div class="glassmorphism p-4 rounded-lg">
            <h3 class="text-2xl font-bold mb-4">Site Appearance</h3>
            <form id="admin-appearance-form" class="space-y-4">
                <div>
                    <label for="background-image-url" class="block text-sm font-medium text-gray-300 mb-1">Background Image URL</label>
                    <input id="background-image-url" name="background_image_url" type="url" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="https://example.com/image.gif">
                </div>
                <div>
                    <label for="music-url" class="block text-sm font-medium text-gray-300 mb-1">Background Music URL</label>
                    <input id="music-url" name="music_url" type="url" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="https://example.com/music.mp3">
                </div>
                <button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Save Appearance</button>
            </form>
        </div>
    </template>
    <template id="template-report-issue-modal">
        <div id="report-issue-overlay" class="fixed inset-0 bg-black bg-opacity-70 flex items-center justify-center z-[1000] fade-in">
            <div class="glassmorphism p-6 rounded-lg max-w-lg w-full m-4">
                <h3 class="text-2xl font-bold mb-4">Report an Issue</h3>
                <form id="report-issue-form">
                    <textarea id="issue-description" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" rows="5" placeholder="Please describe the issue in detail..." required></textarea>
                    <div class="mt-4 flex justify-between items-center">
                        <button type="button" id="copy-debug-info-btn" class="text-sm text-purple-400 hover:text-purple-300">Copy Debug Info</button>
                        <div>
                            <button type="button" id="cancel-report-btn" class="py-2 px-4 rounded-lg">Cancel</button>
                            <button type="submit" id="submit-report-btn" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg ml-2">Submit Report</button>
                        </div>
                    </div>
                </form>
            </div>
        </div>
    </template>
    
    <script nonce="{{ g.nonce }}">
        document.addEventListener('DOMContentLoaded', () => {
            try {
                const DOMElements = {
                    appContainer: document.getElementById('app-container'),
                    toastContainer: document.getElementById('toast-container'),
                    modalContainer: document.getElementById('modal-container'),
                    musicPlayerContainer: document.getElementById('music-player-container'),
                };
                let appState = { currentUser: null, isLoginView: true, selectedRole: 'student', siteSettings: {}, currentClass: null, socket: null, classCache: new Map() };

                const themes = {
                    golden: { '--brand-hue': 45, '--bg-dark': '#1A120B', '--bg-med': '#2c241e', '--bg-light': '#4a3f35', '--text-color': '#F5EFE6', '--text-secondary-color': '#AE8E6A' },
                    dark: { '--brand-hue': 220, '--bg-dark': '#0F172A', '--bg-med': '#1E293B', '--bg-light': '#334155', '--text-color': '#E2E8F0', '--text-secondary-color': '#94A3B8' },
                    edgy_purple: { '--brand-hue': 260, '--bg-dark': '#110D19', '--bg-med': '#211A2E', '--bg-light': '#3B2D4F', '--text-color': '#EADFFF', '--text-secondary-color': '#A17DFF' },
                    light_green: { '--brand-hue': 140, '--bg-dark': '#131f17', '--bg-med': '#1a2e23', '--bg-light': '#274a34', '--text-color': '#e1f2e9', '--text-secondary-color': '#6fdc9d' }
                };
                const svgLogo = `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="logoGradient" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" style="stop-color:hsl(var(--brand-hue), 90%, 60%);" /><stop offset="100%" style="stop-color:hsl(var(--brand-hue), 80%, 50%);" /></linearGradient></defs><path fill="url(#logoGradient)" d="M50,14.7C30.5,14.7,14.7,30.5,14.7,50S30.5,85.3,50,85.3S85.3,69.5,85.3,50S69.5,14.7,50,14.7z M50,77.6 C34.8,77.6,22.4,65.2,22.4,50S34.8,22.4,50,22.4s27.6,12.4,27.6,27.6S65.2,77.6,50,77.6z"/><circle cx="50" cy="50" r="10" fill="white"/></svg>`;

                // --- UTILITY FUNCTIONS ---
                function escapeHtml(unsafe) { if (typeof unsafe !== 'string') return ''; return unsafe.replace(/[&<>"']/g, m => ({'&': '&amp;','<': '&lt;','>': '&gt;','"': '&quot;',"'": '&#039;'})[m]); }
                function injectLogo() { document.querySelectorAll('[id^="logo-container-"]').forEach(c => c.innerHTML = svgLogo); }

                function applyTheme(userPreference) {
                    const siteTheme = appState.siteSettings.site_wide_theme;
                    const themeToApply = (siteTheme && siteTheme !== 'default') ? siteTheme : userPreference;
                    const t = themes[themeToApply] || themes.edgy_purple;
                    Object.entries(t).forEach(([k, v]) => document.documentElement.style.setProperty(k, v));
                }

                function applyCustomizations(settings) {
                    if (settings.background_image_url) {
                        document.body.style.backgroundImage = `url(${settings.background_image_url})`;
                        document.querySelectorAll('.dynamic-bg').forEach(el => el.classList.remove('dynamic-bg'));
                    } else {
                        document.body.style.backgroundImage = 'none';
                    }
                    DOMElements.musicPlayerContainer.innerHTML = '';
                    if (settings.music_url) {
                        const audio = new Audio(settings.music_url);
                        audio.loop = true; audio.autoplay = true; audio.muted = true;
                        const player = document.createElement('div');
                        player.className = 'glassmorphism p-2 rounded-full flex items-center gap-2';
                        const btn = document.createElement('button');
                        btn.className = 'text-2xl'; btn.textContent = '🔇';
                        btn.onclick = () => {
                            if (audio.muted) {
                                audio.muted = false; audio.play(); btn.textContent = '🔊';
                            } else {
                                audio.muted = true; btn.textContent = '🔇';
                            }
                        };
                        player.appendChild(btn);
                        DOMElements.musicPlayerContainer.appendChild(player);
                        setTimeout(() => audio.play().catch(e => console.log("Autoplay blocked by browser.")), 500);
                    }
                }

                function showToast(message, type = 'info') { const colors = { info: 'bg-blue-600', success: 'bg-green-600', error: 'bg-red-600' }; const toast = document.createElement('div'); toast.className = `text-white text-sm py-2 px-4 rounded-lg shadow-lg fade-in ${colors[type]}`; toast.textContent = message; DOMElements.toastContainer.appendChild(toast); setTimeout(() => { toast.style.transition = 'opacity 0.5s ease'; toast.style.opacity = '0'; setTimeout(() => toast.remove(), 500); }, 3500); }
                function setButtonLoadingState(button, isLoading) { if (!button) return; if (isLoading) { button.disabled = true; button.dataset.originalText = button.innerHTML; button.innerHTML = `<svg class="animate-spin h-5 w-5 text-white inline-block" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>`; } else { button.disabled = false; if (button.dataset.originalText) { button.innerHTML = button.dataset.originalText; } } }
                async function apiCall(endpoint, options = {}) { try { const csrfToken = document.querySelector('meta[name="csrf-token"]').content; if (!options.headers) options.headers = {}; options.headers['X-CSRFToken'] = csrfToken; if (options.body && typeof options.body === 'object') { options.headers['Content-Type'] = 'application/json'; options.body = JSON.stringify(options.body); } const response = await fetch(`/api${endpoint}`, { credentials: 'include', ...options }); const contentType = response.headers.get("content-type"); if (!contentType || !contentType.includes("application/json")) { const text = await response.text(); throw new Error(`Server returned non-JSON response: ${text.substring(0, 100)}...`); } const data = await response.json(); if (!response.ok) { if (response.status === 401) handleLogout(false); throw new Error(data.error || 'Request failed'); } return { success: true, ...data }; } catch (error) { showToast(error.message, 'error'); return { success: false, error: error.message }; } }
                function renderPage(templateId, setupFunction) { const template = document.getElementById(templateId); if (!template) return; DOMElements.appContainer.innerHTML = ''; DOMElements.appContainer.appendChild(template.content.cloneNode(true)); if (setupFunction) setupFunction(); injectLogo(); }
                function renderSubTemplate(container, templateId, setupFunction) { const template = document.getElementById(templateId); if (!container || !template) return; container.innerHTML = ''; container.appendChild(template.content.cloneNode(true)); if (setupFunction) setupFunction(); }
                function showFullScreenLoader(message = 'Loading...') { renderPage('template-full-screen-loader', () => { document.querySelector('.waiting-text').textContent = message; }); }

                // --- AUTH & SESSION ---
                function connectSocket() { if (appState.socket && appState.socket.connected) return; appState.socket = io({ transports: ['websocket'] }); appState.socket.on('connect', () => console.log('Socket connected')); appState.socket.on('disconnect', () => console.log('Socket disconnected')); appState.socket.on('new_message', (msg) => renderChatMessage(msg, true)); }
                function handleLoginSuccess(user, settings) { appState.currentUser = user; appState.siteSettings = settings; applyTheme(user.profile.theme_preference); applyCustomizations(settings); if (user.role !== 'guest') connectSocket(); showFullScreenLoader(); setTimeout(() => { setupDashboard(user); }, 1000); }
                function handleLogout(doApiCall = true) { if (doApiCall) apiCall('/logout', { method: 'POST' }); if (appState.socket) appState.socket.disconnect(); appState.currentUser = null; window.location.reload(); }
                function setupRoleChoicePage() { renderPage('template-role-choice', () => { document.querySelectorAll('.role-btn').forEach(btn => btn.addEventListener('click', (e) => { appState.selectedRole = e.currentTarget.dataset.role; setupAuthPage(); })); document.getElementById('guest-mode-btn').addEventListener('click', handleGuestLogin); }); }
                function setupAuthPage() { renderPage('template-auth-form', () => { updateAuthView(); document.getElementById('auth-form').addEventListener('submit', handleAuthSubmit); document.getElementById('auth-toggle-btn').addEventListener('click', () => { appState.isLoginView = !appState.isLoginView; updateAuthView(); }); document.getElementById('back-to-roles').addEventListener('click', setupRoleChoicePage); }); }
                function updateAuthView() { const isLogin = appState.isLoginView, role = appState.selectedRole; document.getElementById('auth-title').textContent = `${role.charAt(0).toUpperCase() + role.slice(1)} Portal`; document.getElementById('auth-subtitle').textContent = isLogin ? 'Sign in to continue' : 'Create your Account'; document.getElementById('auth-submit-btn').textContent = isLogin ? 'Login' : 'Sign Up'; document.getElementById('auth-toggle-btn').innerHTML = isLogin ? "Don't have an account? <span class='font-semibold'>Sign Up</span>" : "Already have an account? <span class='font-semibold'>Login</span>"; document.getElementById('email-field').style.display = isLogin ? 'none' : 'block'; document.getElementById('email').required = !isLogin; document.getElementById('teacher-key-field').style.display = (!isLogin && role === 'teacher') ? 'block' : 'none'; document.getElementById('teacher-secret-key').required = !isLogin && role === 'teacher'; document.getElementById('admin-key-field').style.display = (isLogin && role === 'admin') ? 'block' : 'none'; document.getElementById('admin-secret-key').required = isLogin && role === 'admin'; document.getElementById('account_type').value = role; }
                async function handleAuthSubmit(e) { e.preventDefault(); const form = e.target; const btn = form.querySelector('button[type="submit"]'); setButtonLoadingState(btn, true); const body = Object.fromEntries(new FormData(form)); const endpoint = appState.isLoginView ? '/login' : '/signup'; const result = await apiCall(endpoint, { method: 'POST', body }); if (result.success) { handleLoginSuccess(result.user, result.settings); } else { document.getElementById('auth-error').textContent = result.error; } setButtonLoadingState(btn, false); }
                async function handleGuestLogin() { showFullScreenLoader('Entering Guest Mode...'); const result = await apiCall('/guest_login', { method: 'POST'}); if (result.success) { handleLoginSuccess(result.user, result.settings); } }

                // --- DASHBOARD & TABS ---
                function setupDashboard(user) {
                    renderPage('template-main-dashboard', () => {
                        document.getElementById('welcome-message').innerHTML = `Welcome, ${escapeHtml(user.username)}! <br> Streak: 🔥 ${user.streak}`;
                        let tabs = [ { id: 'profile', label: 'Profile' } ];
                        if (['student', 'teacher'].includes(user.role)) {
                            document.getElementById('dashboard-title').textContent = user.role === 'student' ? "Student Hub" : "Teacher Hub";
                            tabs.unshift({ id: 'my-classes', label: 'My Classes' }, { id: 'leaderboard', label: 'Leaderboard' });
                            appState.currentTab = 'my-classes';
                        } else if (user.role === 'admin') {
                            document.getElementById('dashboard-title').textContent = "Admin Panel";
                            tabs.unshift({ id: 'admin-dashboard', label: 'Dashboard' });
                            appState.currentTab = 'admin-dashboard';
                        }
                        const navLinks = document.getElementById('nav-links');
                        navLinks.innerHTML = tabs.map(tab => `<button data-tab="${escapeHtml(tab.id)}" class="dashboard-tab text-left text-gray-300 hover:bg-gray-700/50 p-3 rounded-md transition-colors">${escapeHtml(tab.label)}</button>`).join('');
                        navLinks.querySelectorAll('.dashboard-tab').forEach(tab => tab.addEventListener('click', (e) => switchTab(e.currentTarget.dataset.tab)));
                        document.getElementById('logout-btn').addEventListener('click', () => handleLogout(true));
                        document.getElementById('report-issue-btn').addEventListener('click', setupReportIssueModal);
                        switchTab(appState.currentTab);
                    });
                }

                function switchTab(tab) {
                    const setups = { 'my-classes': setupMyClassesTab, 'profile': setupProfileTab, 'admin-dashboard': setupAdminDashboardTab, 'leaderboard': setupLeaderboardTab };
                    if (setups[tab]) {
                        appState.currentTab = tab;
                        document.querySelectorAll('.dashboard-tab').forEach(t => t.classList.toggle('active-tab', t.dataset.tab === tab));
                        setups[tab](document.getElementById('dashboard-content'));
                    }
                }

                // --- FULL TAB IMPLEMENTATIONS ---
                async function setupMyClassesTab(container) { renderSubTemplate(container, 'template-my-classes', () => { document.getElementById('back-to-classes-list').addEventListener('click', () => showClassList(true)); showClassList(false); }); }
                async function showClassList(isRefresh) {
                    document.getElementById('classes-main-view').classList.remove('hidden');
                    const selectedView = document.getElementById('selected-class-view');
                    selectedView.classList.add('hidden');
                    selectedView.innerHTML = '';
                    document.getElementById('back-to-classes-list').classList.add('hidden');
                    document.getElementById('my-classes-title').textContent = "My Classes";
                    const actionContainer = document.getElementById('class-action-container');
                    const role = appState.currentUser.role;
                    if (role !== 'guest') {
                        const actionTemplateId = `template-${role}-class-action`;
                        renderSubTemplate(actionContainer, actionTemplateId, () => {
                            if (role === 'student') document.getElementById('join-class-form').addEventListener('submit', handleJoinClass);
                            else if (role === 'teacher') document.getElementById('create-class-form').addEventListener('submit', handleCreateClass);
                        });
                    } else {
                        actionContainer.innerHTML = '<p class="text-center text-gray-400">Guest mode is read-only. Please sign up to create or join classes.</p>';
                    }
                    const classesList = document.getElementById('classes-list');
                    classesList.innerHTML = '<p class="text-gray-400">Loading classes...</p>';
                    if (!isRefresh && appState.classCache.has('list')) {
                        renderClasses(appState.classCache.get('list'));
                    } else {
                        const result = await apiCall('/classes');
                        if (result.success) { appState.classCache.set('list', result.classes); renderClasses(result.classes); }
                    }
                }
                function renderClasses(classes) {
                    const classesList = document.getElementById('classes-list');
                    if (classes.length === 0) {
                        classesList.innerHTML = `<p class="text-gray-400 col-span-full">You are not in any classes yet.</p>`;
                    } else {
                        classesList.innerHTML = classes.map(c => `
                            <div class="class-card glassmorphism p-4 rounded-lg cursor-pointer hover:scale-105 transition-transform" data-class-id="${escapeHtml(c.id)}" data-class-name="${escapeHtml(c.name)}">
                                <h3 class="text-xl font-bold">${escapeHtml(c.name)}</h3>
                                <p class="text-sm text-gray-400">Teacher: ${escapeHtml(c.teacher_name)}</p>
                                <p class="text-sm text-gray-400 mt-2">Code: <span class="font-mono bg-bg-dark p-1 rounded">${escapeHtml(c.code)}</span></p>
                            </div>`).join('');
                        classesList.querySelectorAll('.class-card').forEach(card => card.addEventListener('click', (e) => showClassDetail(e.currentTarget.dataset.classId, e.currentTarget.dataset.className)));
                    }
                }
                function showClassDetail(classId, className) {
                    appState.currentClass = { id: classId, name: className };
                    document.getElementById('classes-main-view').classList.add('hidden');
                    document.getElementById('selected-class-view').classList.remove('hidden');
                    document.getElementById('back-to-classes-list').classList.remove('hidden');
                    document.getElementById('my-classes-title').textContent = className;
                    const container = document.getElementById('selected-class-view');
                    renderSubTemplate(container, 'template-selected-class-view', () => {
                        container.querySelector('.class-view-tab').addEventListener('click', (e) => switchClassTab(e.currentTarget.dataset.tab));
                        switchClassTab('chat');
                    });
                }
                function switchClassTab(tab) {
                    document.querySelectorAll('.class-view-tab').forEach(t => t.classList.toggle('active-tab', t.dataset.tab === tab));
                    const contentContainer = document.getElementById('class-view-content');
                    if (tab === 'chat') { setupClassChatTab(contentContainer); }
                }
                async function setupClassChatTab(container) {
                    renderSubTemplate(container, 'template-class-chat-view', async () => {
                        if (appState.socket) appState.socket.emit('join', { room: appState.currentClass.id });
                        const chatMessages = document.getElementById('chat-messages');
                        chatMessages.innerHTML = '<p class="text-gray-400">Loading messages...</p>';
                        const result = await apiCall(`/classes/${appState.currentClass.id}/messages`);
                        if (result.success) {
                            chatMessages.innerHTML = '';
                            result.messages.forEach(msg => renderChatMessage(msg, false));
                            chatMessages.scrollTop = chatMessages.scrollHeight;
                        }
                        document.getElementById('chat-form').addEventListener('submit', (e) => {
                            e.preventDefault();
                            const input = document.getElementById('chat-input');
                            const content = input.value.trim();
                            if (content && appState.socket) {
                                appState.socket.emit('send_message', { room: appState.currentClass.id, content: content });
                                input.value = '';
                            }
                        });
                    });
                }
                function renderChatMessage(msg, shouldScroll) {
                    const messagesContainer = document.getElementById('chat-messages');
                    if (!messagesContainer) return;
                    const isCurrentUser = msg.sender.id === appState.currentUser.id;
                    const messageEl = document.createElement('div');
                    messageEl.id = `message-${msg.id}`;
                    messageEl.className = `chat-message-container flex items-start gap-3 ${isCurrentUser ? 'justify-end' : ''}`;
                    messageEl.innerHTML = `
                        ${!isCurrentUser ? `<img src="${escapeHtml(msg.sender.profile?.avatar || `https://i.pravatar.cc/40?u=${msg.sender.id}`)}" class="w-8 h-8 rounded-full">` : ''}
                        <div class="flex flex-col ${isCurrentUser ? 'items-end' : 'items-start'}">
                            <div class="flex items-center gap-2">
                                ${!isCurrentUser ? `<span class="font-bold text-sm">${escapeHtml(msg.sender.username)}</span>` : ''}
                                <span class="text-xs text-gray-400">${new Date(msg.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</span>
                            </div>
                            <div class="bg-bg-med p-3 rounded-lg max-w-xs md:max-w-md relative">
                                <p id="message-content-${msg.id}">${escapeHtml(msg.content)}</p>
                            </div>
                        </div>`;
                    messagesContainer.appendChild(messageEl);
                    if (shouldScroll) messagesContainer.scrollTop = messagesContainer.scrollHeight;
                }
                async function handleJoinClass(e) { e.preventDefault(); const btn = e.target.querySelector('button'); setButtonLoadingState(btn, true); const code = e.target.elements.code.value; const result = await apiCall('/classes/join', { method: 'POST', body: { code } }); if (result.success) { showToast(`Joined ${result.class_name}!`, 'success'); showClassList(true); } setButtonLoadingState(btn, false); }
                async function handleCreateClass(e) { e.preventDefault(); const btn = e.target.querySelector('button'); setButtonLoadingState(btn, true); const name = e.target.elements.name.value; const result = await apiCall('/classes/create', { method: 'POST', body: { name } }); if (result.success) { showToast(`Class "${result.class.name}" created!`, 'success'); showClassList(true); } setButtonLoadingState(btn, false); }
                async function setupProfileTab(container) { renderSubTemplate(container, 'template-profile', () => { container.querySelectorAll('.profile-view-tab').forEach(tab => tab.addEventListener('click', (e) => switchProfileTab(e.currentTarget.dataset.tab))); switchProfileTab('settings'); }); }
                function switchProfileTab(tab) { document.querySelectorAll('.profile-view-tab').forEach(t => t.classList.toggle('active-tab', t.dataset.tab === tab)); const contentContainer = document.getElementById('profile-view-content'); if (tab === 'settings') setupProfileSettingsTab(contentContainer); else if (tab === 'billing') setupProfileBillingTab(contentContainer); }
                async function setupProfileSettingsTab(container) { renderSubTemplate(container, 'template-profile-settings', () => { const profile = appState.currentUser.profile; document.getElementById('bio').value = profile.bio || ''; document.getElementById('avatar').value = profile.avatar || ''; const themeSelect = document.getElementById('theme-select'); themeSelect.innerHTML = Object.keys(themes).map(name => `<option value="${name}">${name.replace(/_/g, ' ').replace(/\\b\\w/g, l => l.toUpperCase())}</option>`).join(''); themeSelect.value = profile.theme_preference || 'edgy_purple'; document.getElementById('profile-form').addEventListener('submit', handleUpdateProfile); }); }
                async function setupProfileBillingTab(container) { renderSubTemplate(container, 'template-profile-billing', () => { const statusContainer = document.getElementById('subscription-status'); const actionsContainer = document.getElementById('billing-actions'); const status = appState.currentUser.subscription_status; statusContainer.innerHTML = `<p>Current Plan: <span class="font-bold capitalize ${status === 'active' ? 'text-green-400' : 'text-purple-400'}">${status}</span></p>`; if (status !== 'active') { actionsContainer.innerHTML = `<button id="upgrade-btn" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Upgrade to Pro</button>`; document.getElementById('upgrade-btn').addEventListener('click', handleUpgrade); } else { actionsContainer.innerHTML = `<p class="text-gray-400">You are on the Pro plan. Thank you for your support!</p>`; } }); }
                async function handleUpgrade() { const btn = document.getElementById('upgrade-btn'); setButtonLoadingState(btn, true); const result = await apiCall('/billing/create-checkout-session', { method: 'POST' }); if (result.success) { const stripe = Stripe(result.public_key); stripe.redirectToCheckout({ sessionId: result.session_id }); } setButtonLoadingState(btn, false); }
                async function handleUpdateProfile(e) { e.preventDefault(); const form = e.target; const btn = form.querySelector('button[type="submit"]'); setButtonLoadingState(btn, true); try { const body = Object.fromEntries(new FormData(form)); const result = await apiCall('/update_profile', { method: 'POST', body }); if (result.success) { appState.currentUser.profile = result.profile; applyTheme(body.theme_preference); showToast('Profile updated!', 'success'); } } finally { setButtonLoadingState(btn, false); } }
                async function setupLeaderboardTab(container) { renderSubTemplate(container, 'template-leaderboard-view', async () => { const list = document.getElementById('leaderboard-list'); list.innerHTML = `<p class="text-gray-400">Loading leaderboard...</p>`; const result = await apiCall('/leaderboard'); if (result.success) { if (result.users.length === 0) { list.innerHTML = `<p class="text-gray-400">No users on the leaderboard yet.</p>`; } else { list.innerHTML = `<ol class="list-decimal list-inside space-y-2">${result.users.map((user, index) => ` <li class="p-2 rounded-md flex items-center gap-4 ${index === 0 ? 'bg-yellow-500/20' : (index === 1 ? 'bg-gray-400/20' : (index === 2 ? 'bg-purple-700/20' : ''))}"> <span class="font-bold text-lg">${index + 1}.</span> <img src="${escapeHtml(user.profile.avatar || 'https://i.pravatar.cc/40?u=' + user.id)}" class="w-8 h-8 rounded-full"> <span class="flex-grow">${escapeHtml(user.username)}</span> <span class="font-bold">${user.points} pts</span> </li>`).join('')}</ol>`; } } }); }
                async function setupAdminDashboardTab(container) { renderSubTemplate(container, 'template-admin-dashboard', () => { container.querySelectorAll('.admin-view-tab').forEach(tab => tab.addEventListener('click', (e) => switchAdminTab(e.currentTarget.dataset.tab))); switchAdminTab('users'); }); }
                function switchAdminTab(tab) { document.querySelectorAll('.admin-view-tab').forEach(t => t.classList.toggle('active-tab', t.dataset.tab === tab)); const contentContainer = document.getElementById('admin-view-content'); if (tab === 'users') setupAdminUsersTab(contentContainer); else if (tab === 'settings') setupAdminSettingsTab(contentContainer); else if (tab === 'appearance') setupAdminAppearanceTab(contentContainer); }
                function setupAdminUsersTab(container) { renderSubTemplate(container, 'template-admin-users-view', async () => { const result = await apiCall('/admin/users'); if (result.success) { document.getElementById('users-table-body').innerHTML = result.users.map(user => ` <tr class="border-b border-gray-700/50"> <td class="p-3">${escapeHtml(user.username)}</td> <td class="p-3">${escapeHtml(user.email)}</td> <td class="p-3">${escapeHtml(user.role)}</td> </tr>`).join(''); } }); }
                function setupAdminSettingsTab(container) { renderSubTemplate(container, 'template-admin-settings-view', () => { document.getElementById('site-wide-theme-select').value = appState.siteSettings.site_wide_theme || 'default'; document.getElementById('admin-settings-form').addEventListener('submit', async e => { e.preventDefault(); const btn = e.target.querySelector('button[type="submit"]'); setButtonLoadingState(btn, true); const body = { site_wide_theme: document.getElementById('site-wide-theme-select').value }; const result = await apiCall('/admin/settings', { method: 'POST', body }); if (result.success) { showToast('Site settings updated!', 'success'); appState.siteSettings = result.settings; applyTheme(appState.currentUser.profile.theme_preference); } setButtonLoadingState(btn, false); }); }); }
                function setupAdminAppearanceTab(container) { renderSubTemplate(container, 'template-admin-appearance-view', () => { document.getElementById('background-image-url').value = appState.siteSettings.background_image_url || ''; document.getElementById('music-url').value = appState.siteSettings.music_url || ''; document.getElementById('admin-appearance-form').addEventListener('submit', async e => { e.preventDefault(); const btn = e.target.querySelector('button[type="submit"]'); setButtonLoadingState(btn, true); const body = { background_image_url: document.getElementById('background-image-url').value, music_url: document.getElementById('music-url').value }; const result = await apiCall('/admin/appearance', { method: 'POST', body }); if (result.success) { showToast('Appearance settings updated!', 'success'); appState.siteSettings = result.settings; applyCustomizations(appState.siteSettings); } setButtonLoadingState(btn, false); }); }); }
                
                function setupReportIssueModal() {
                    renderSubTemplate(DOMElements.modalContainer, 'template-report-issue-modal', () => {
                        const overlay = document.getElementById('report-issue-overlay');
                        const form = document.getElementById('report-issue-form');
                        const cancelBtn = document.getElementById('cancel-report-btn');
                        const copyBtn = document.getElementById('copy-debug-info-btn');
                        const submitBtn = document.getElementById('submit-report-btn');

                        const closeModal = () => {
                            overlay.classList.remove('fade-in');
                            overlay.style.opacity = '0';
                            setTimeout(() => DOMElements.modalContainer.innerHTML = '', 300);
                        };

                        overlay.addEventListener('click', (e) => { if (e.target === overlay) closeModal(); });
                        cancelBtn.addEventListener('click', closeModal);

                        copyBtn.addEventListener('click', () => {
                            const debugInfo = `
User ID: ${appState.currentUser.id}
Username: ${appState.currentUser.username}
Role: ${appState.currentUser.role}
Current Page: ${window.location.href}
User Agent: ${navigator.userAgent}
                            `.trim();
                            navigator.clipboard.writeText(debugInfo).then(() => {
                                showToast('Debug info copied to clipboard!', 'success');
                            }, () => {
                                showToast('Failed to copy debug info.', 'error');
                            });
                        });

                        form.addEventListener('submit', async (e) => {
                            e.preventDefault();
                            setButtonLoadingState(submitBtn, true);
                            const description = document.getElementById('issue-description').value;
                            const result = await apiCall('/report-issue', {
                                method: 'POST',
                                body: { description: description, page_url: window.location.href }
                            });
                            if (result.success) {
                                showToast('Issue report submitted successfully. Thank you!', 'success');
                                closeModal();
                            }
                            setButtonLoadingState(submitBtn, false);
                        });
                    });
                }

                // --- MAIN APP INITIALIZATION ---
                async function main() {
                    renderPage('template-welcome-screen', () => {
                        const enterButton = document.getElementById('enter-portal-btn');
                        if (enterButton) {
                            enterButton.addEventListener('click', async () => {
                                showFullScreenLoader('Initializing Portal...');
                                const result = await apiCall('/status');
                                if (result.success) {
                                    appState.siteSettings = result.settings;
                                    if (result.user) {
                                        handleLoginSuccess(result.user, result.settings);
                                    } else {
                                        applyCustomizations(result.settings);
                                        setupRoleChoicePage();
                                    }
                                } else {
                                    setupRoleChoicePage();
                                }
                            });
                        }
                    });
                }

                main();
            } catch (error) {
                console.error("A critical error occurred:", error);
                document.body.innerHTML = `<div style="background-color: #110D19; color: #EADFFF; font-family: sans-serif; padding: 2rem; height: 100vh; text-align: center;"><h1>Application Error</h1><p>A critical error occurred. Please check the console.</p><pre style="background-color:#211A2E; padding: 1rem; border-radius: 8px; text-align: left; margin-top: 1rem;">${error.stack}</pre></div>`;
            }
        });
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
        return jsonify({"user": current_user.to_dict(include_email=True), "settings": settings})
    return jsonify({"user": None, "settings": settings})

@app.route('/api/signup', methods=['POST'])
@limiter.limit("5 per 15 minutes")
def signup():
    data = request.json
    username = bleach.clean(data.get('username', '')).strip()
    email = bleach.clean(data.get('email', '')).strip().lower()
    password = data.get('password')
    role = bleach.clean(data.get('account_type', 'student'))

    if not all([username, email, password, role]):
        return jsonify({"error": "Missing required fields."}), 400

    if password_policy.test(password):
        return jsonify({"error": "Password is too weak. Must be 12+ chars with uppercase, numbers, and symbols."}), 400

    if User.query.filter(or_(User.username == username, User.email == email)).first():
        return jsonify({"error": "Username or email already exists."}), 409

    if role == 'teacher' and data.get('secret_key') != SITE_CONFIG['SECRET_TEACHER_KEY']:
        logging.warning(f"SECURITY: Failed teacher signup attempt with incorrect key from IP {get_remote_address()}.")
        return jsonify({"error": "Invalid teacher secret key."}), 403

    new_user = User(username=username, email=email, role=role)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    session.clear()
    session.regenerate()
    login_user(new_user)
    settings = {s.key: s.value for s in SiteSettings.query.all()}
    logging.info(f"SECURITY: New user signup successful for {username} from IP {get_remote_address()}.")
    return jsonify({"success": True, "user": new_user.to_dict(include_email=True), "settings": settings})

@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute; 100 per day")
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()

    if not user or not user.check_password(password):
        logging.warning(f"SECURITY: Failed login attempt for username: {username} from IP {get_remote_address()}")
        return jsonify({"error": "Invalid username or password"}), 401

    if user.role == 'admin' and data.get('admin_secret_key') != SITE_CONFIG['ADMIN_SECRET_KEY']:
        logging.warning(f"SECURITY: Failed admin login for {username} with incorrect key from IP {get_remote_address()}.")
        return jsonify({"error": "Invalid admin secret key."}), 403

    session.clear()
    session.regenerate()

    today = date.today()
    if user.last_login and user.last_login.date() == today - timedelta(days=1):
        user.streak += 1
    elif not user.last_login or user.last_login.date() != today:
        user.streak = 1
    user.last_login = datetime.utcnow()
    db.session.commit()

    login_user(user, remember=True)
    logging.info(f"SECURITY: User {user.username} logged in successfully from IP {get_remote_address()}.")
    settings = {s.key: s.value for s in SiteSettings.query.all()}
    return jsonify({"success": True, "user": user.to_dict(include_email=True), "settings": settings})

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logging.info(f"SECURITY: User {current_user.username} logged out.")
    logout_user()
    session.clear()
    return jsonify({"success": True})

@app.route('/api/guest_login', methods=['POST'])
def guest_login():
    guest_id = f"guest_{uuid.uuid4()}"
    guest_user = User(id=guest_id, username="Guest", email=f"{guest_id}@example.com", role="guest")
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
    top_users = User.query.options(selectinload(User.profile)).order_by(User.points.desc()).limit(10).all()
    return jsonify({"success": True, "users": [user.to_dict() for user in top_users]})

@app.route('/api/report-issue', methods=['POST'])
@limiter.limit("5 per hour")
@login_required
def report_issue():
    data = request.json
    description = bleach.clean(data.get('description', ''))
    page_url = bleach.clean(data.get('page_url', ''))

    if not description:
        return jsonify({"error": "Issue description cannot be empty."}), 400

    user_agent = request.headers.get('User-Agent', 'Unknown')
    user_id = current_user.id if current_user.is_authenticated and not getattr(current_user, 'is_guest', False) else None

    new_report = IssueReport(
        user_id=user_id,
        page_url=page_url,
        user_agent=user_agent,
        description=description
    )
    db.session.add(new_report)
    db.session.commit()
    logging.info(f"SECURITY: New issue reported by user '{current_user.username if user_id else 'Guest'}'. URL: {page_url}. Issue: {description[:100]}...")
    return jsonify({"success": True, "message": "Thank you for your feedback. Your report has been submitted."})

# --- Class & Content API Routes ---
@app.route('/api/classes', methods=['GET'])
@login_required
def get_classes():
    if getattr(current_user, 'is_guest', False):
        return jsonify({"success": True, "classes": []})
    query = current_user.taught_classes if current_user.role == 'teacher' else current_user.enrolled_classes
    classes = query.options(selectinload(Class.teacher)).all()
    return jsonify({"success": True, "classes": [c.to_dict() for c in classes]})

@app.route('/api/classes/create', methods=['POST'])
@login_required
@teacher_required
def create_class():
    name = bleach.clean(request.json.get('name'))
    if not name or len(name) > 100:
        return jsonify({"error": "Class name is required and must be under 100 characters."}), 400
    code = secrets.token_urlsafe(6).upper()
    while Class.query.filter_by(code=code).first():
        code = secrets.token_urlsafe(6).upper()
    new_class = Class(name=name, teacher_id=current_user.id, code=code)
    db.session.add(new_class)
    db.session.commit()
    return jsonify({"success": True, "class": new_class.to_dict()}), 201

@app.route('/api/classes/join', methods=['POST'])
@login_required
@role_required(['student'])
def join_class():
    code = bleach.clean(request.json.get('code', '')).upper()
    if not code: return jsonify({"error": "Class code is required."}), 400
    target_class = Class.query.filter_by(code=code).first()
    if not target_class: return jsonify({"error": "Invalid class code."}), 404
    if current_user in target_class.students: return jsonify({"error": "You are already in this class."}), 409
    target_class.students.append(current_user)
    db.session.commit()
    return jsonify({"success": True, "class_name": target_class.name})

@app.route('/api/classes/<string:class_id>/messages', methods=['GET'])
@login_required
@class_member_required
def get_messages(target_class):
    page = request.args.get('page', 1, type=int)
    messages = target_class.messages.options(selectinload(ChatMessage.sender).selectinload(User.profile)) \
                                     .order_by(ChatMessage.timestamp.desc()) \
                                     .paginate(page=page, per_page=50, error_out=False)
    return jsonify({
        "success": True,
        "messages": [m.to_dict() for m in reversed(messages.items)],
        "has_next": messages.has_next
    })

# --- Admin API Routes ---
@app.route('/api/admin/users', methods=['GET'])
@login_required
@admin_required
def get_all_users():
    users = User.query.options(selectinload(User.profile)).all()
    return jsonify({"success": True, "users": [user.to_dict(include_email=True) for user in users]})

@app.route('/api/admin/settings', methods=['POST'])
@login_required
@admin_required
def update_admin_settings():
    data = request.json
    allowed_keys = ['site_wide_theme']
    for key, value in data.items():
        clean_key = bleach.clean(key)
        if clean_key not in allowed_keys: continue
        setting = SiteSettings.query.filter_by(key=clean_key).first()
        if setting: setting.value = bleach.clean(value)
        else: db.session.add(SiteSettings(key=clean_key, value=bleach.clean(value)))
    db.session.commit()
    settings = {s.key: s.value for s in SiteSettings.query.all()}
    return jsonify({"success": True, "settings": settings})

@app.route('/api/admin/appearance', methods=['POST'])
@login_required
@admin_required
def update_admin_appearance():
    data = request.json
    allowed_keys = ['background_image_url', 'music_url']
    for key in allowed_keys:
        value = bleach.clean(data.get(key, ''))
        setting = SiteSettings.query.filter_by(key=key).first()
        if setting: setting.value = value
        else: db.session.add(SiteSettings(key=key, value=value))
    db.session.commit()
    settings = {s.key: s.value for s in SiteSettings.query.all()}
    return jsonify({"success": True, "settings": settings})

# ==============================================================================
# --- 8. SOCKET.IO REAL-TIME EVENTS ---
# ==============================================================================
@socketio.on('join')
def on_join(data):
    if not current_user.is_authenticated: return
    room = data['room']
    target_class = Class.query.get(room)
    if not target_class or (current_user not in target_class.students and target_class.teacher_id != current_user.id and current_user.role != 'admin'):
        logging.warning(f"SECURITY: Unauthorized socket join attempt by {current_user.id} to room {room}")
        return
    join_room(room)
    logging.info(f"User {current_user.username} joined room {room}")

@socketio.on('leave')
def on_leave(data):
    if not current_user.is_authenticated: return
    room = data['room']
    leave_room(room)
    logging.info(f"User {current_user.username} left room {room}")

@socketio.on('send_message')
def handle_send_message(data):
    if not current_user.is_authenticated or getattr(current_user, 'is_guest', False): return
    room = data['room']
    content = bleach.clean(data['content'])
    msg = ChatMessage(class_id=room, sender_id=current_user.id, content=content)
    db.session.add(msg)
    db.session.commit()
    emit('new_message', msg.to_dict(), room=room)

# ==============================================================================
# --- 9. APP INITIALIZATION & DB SETUP ---
# ==============================================================================
@event.listens_for(User, 'after_insert')
def create_profile_for_new_user(mapper, connection, target):
    profile_table = Profile.__table__
    connection.execute(profile_table.insert().values(user_id=target.id))

@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

def initialize_database():
    with app.app_context():
        db.create_all()
        default_settings = {
            'site_wide_theme': 'default',
            'background_image_url': '',
            'music_url': ''
        }
        for key, value in default_settings.items():
            if not SiteSettings.query.filter_by(key=key).first():
                db.session.add(SiteSettings(key=key, value=value))
        db.session.commit()
        logging.info("Default settings seeded.")

@app.cli.command("init-db")
def init_db_command():
    initialize_database()
    logging.info("Database tables created and settings seeded via CLI.")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Seed initial settings if they don't exist
        default_settings = {
            'site_wide_theme': 'default',
            'background_image_url': '',
            'music_url': ''
        }
        for key, value in default_settings.items():
            if not SiteSettings.query.filter_by(key=key).first():
                db.session.add(SiteSettings(key=key, value=value))
        db.session.commit()
    socketio.run(app, debug=(not is_production))
