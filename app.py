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
from datetime import datetime
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
# Nonce is used for inline scripts/styles to make them secure
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
        f'wss://{SITE_CONFIG["YOUR_DOMAIN"].split("//")[-1]}' if is_production else 'ws://localhost:5000',
        'https://api.stripe.com'
    ],
    'object-src': '\'none\'',
    'base-uri': '\'self\'',
    'form-action': '\'self\''
}

talisman = Talisman(
    app,
    content_security_policy=csp,
    force_https=is_production,
    strict_transport_security=is_production,
    frame_options='DENY',
    referrer_policy='strict-origin-when-cross-origin'
)
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
    profile = db.relationship('Profile', back_populates='user', uselist=False, cascade="all, delete-orphan")
    taught_classes = db.relationship('Class', back_populates='teacher', lazy=True, foreign_keys='Class.teacher_id', cascade="all, delete-orphan")
    enrolled_classes = db.relationship('Class', secondary=student_class_association, back_populates='students', lazy='dynamic')

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
            'created_at': self.created_at.isoformat(), 'profile': profile_data, 'points': self.points
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
    
    def to_dict(self):
        return {
            'id': self.id, 'name': self.name, 'code': self.code,
            'teacher_name': self.teacher.username
        }

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
    return User.query.get(user_id)

def role_required(role_names):
    if not isinstance(role_names, list):
        role_names = [role_names]
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({"error": "Login required."}), 401
            if current_user.role != 'admin' and current_user.role not in role_names:
                logging.warning(f"SECURITY: User {current_user.id} with role {current_user.role} attempted unauthorized access to a route requiring roles {role_names}.")
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

admin_required = role_required('admin')
teacher_required = role_required('teacher')

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
        .shiny-button:hover { transform: translateY(-2px); box-shadow: 0 4px 15px hsla(var(--brand-hue), 70%, 40%, 0.4), 0 0 5px var(--glow-color, #fff) inset; }
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
    <div class="fixed bottom-4 left-4 text-xs text-gray-400">© 2025 DeVector. All Rights Reserved.</div>

    <template id="template-welcome-screen">
        <div class="h-screen w-screen flex flex-col items-center justify-center dynamic-bg p-4 text-center fade-in">
            <div id="logo-container-welcome" class="w-24 h-24 mx-auto mb-2"></div>
            <h1 class="text-5xl font-title brand-gradient-text">Myth AI</h1>
            <p class="text-lg text-gray-300 mt-2 animate-pulse">The AI-powered learning portal.</p>
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
            <h2 class="text-3xl font-bold mb-6 text-white">My Classes</h2>
            <div id="class-action-container" class="mb-6"></div>
            <div id="classes-list" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4"></div>
        </div>
    </template>

    <template id="template-student-class-action">
        <form id="join-class-form" class="glassmorphism p-4 rounded-lg flex gap-2">
            <input type="text" name="code" placeholder="Enter Class Code" class="flex-grow p-2 bg-gray-700/50 rounded-md border border-gray-600" required>
            <button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Join</button>
        </form>
    </template>

    <template id="template-teacher-class-action">
        <form id="create-class-form" class="glassmorphism p-4 rounded-lg flex gap-2">
            <input type="text" name="name" placeholder="New Class Name" class="flex-grow p-2 bg-gray-700/50 rounded-md border border-gray-600" required>
            <button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Create</button>
        </form>
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

    <template id="template-admin-dashboard">
         <div class="fade-in">
            <h2 class="text-3xl font-bold mb-6 text-white">Admin Dashboard</h2>
            <div id="admin-users-view-container"></div>
            <div id="admin-settings-view-container" class="mt-6"></div>
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
    document.addEventListener('DOMContentLoaded', () => {
        const DOMElements = { 
            appContainer: document.getElementById('app-container'), 
            toastContainer: document.getElementById('toast-container'),
        };
        let appState = { currentUser: null, isLoginView: true, selectedRole: 'student', siteSettings: {} };

        const themes = {
            golden: { '--brand-hue': 45, '--bg-dark': '#1A120B', '--bg-med': '#2c241e', '--bg-light': '#4a3f35', '--text-color': '#F5EFE6', '--text-secondary-color': '#AE8E6A' },
            dark: { '--brand-hue': 220, '--bg-dark': '#0F172A', '--bg-med': '#1E293B', '--bg-light': '#334155', '--text-color': '#E2E8F0', '--text-secondary-color': '#94A3B8' },
            edgy_purple: { '--brand-hue': 260, '--bg-dark': '#110D19', '--bg-med': '#211A2E', '--bg-light': '#3B2D4F', '--text-color': '#EADFFF', '--text-secondary-color': '#A17DFF' }
        };
        const svgLogo = `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="logoGradient" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" style="stop-color:hsl(var(--brand-hue), 90%, 60%);" /><stop offset="100%" style="stop-color:hsl(var(--brand-hue), 80%, 50%);" /></linearGradient></defs><path fill="url(#logoGradient)" d="M85.3,50c0,19.5-15.8,35.3-35.3,35.3S14.7,69.5,14.7,50S30.5,14.7,50,14.7S85.3,30.5,85.3,50 Z M50,22.4c-15.2,0-27.6,12.4-27.6,27.6S34.8,77.6,50,77.6s27.6-12.4,27.6-27.6S65.2,22.4,50,22.4 Z" /><path fill="white" d="M50,38.9c-2.3,0-4.1,1.8-4.1,4.1v13.9c0,2.3,1.8,4.1,4.1,4.1s4.1-1.8,4.1-4.1V43 C54.1,40.7,52.3,38.9,50,38.9z" /></svg>`;
        
        function escapeHtml(unsafe) { if (typeof unsafe !== 'string') return ''; return unsafe.replace(/[&<>"']/g, m => ({'&': '&amp;','<': '&lt;','>': '&gt;','"': '&quot;',"'": '&#039;'})[m]); }
        function injectLogo() { document.querySelectorAll('[id^="logo-container-"]').forEach(c => c.innerHTML = svgLogo); }
        function applyTheme(userPreference) { const siteTheme = appState.siteSettings.site_wide_theme; const themeToApply = (siteTheme && siteTheme !== 'default') ? siteTheme : userPreference; const t = themes[themeToApply] || themes.golden; Object.entries(t).forEach(([k, v]) => document.documentElement.style.setProperty(k, v)); }
        function showToast(message, type = 'info') { const colors = { info: 'bg-blue-600', success: 'bg-green-600', error: 'bg-red-600' }; const toast = document.createElement('div'); toast.className = `text-white text-sm py-2 px-4 rounded-lg shadow-lg fade-in ${colors[type]}`; toast.textContent = message; DOMElements.toastContainer.appendChild(toast); setTimeout(() => { toast.style.transition = 'opacity 0.5s ease'; toast.style.opacity = '0'; setTimeout(() => toast.remove(), 500); }, 3500); }
        async function apiCall(endpoint, options = {}) { try { const csrfToken = document.querySelector('meta[name="csrf-token"]').content; if (!options.headers) options.headers = {}; options.headers['X-CSRFToken'] = csrfToken; if (options.body && typeof options.body === 'object') { options.headers['Content-Type'] = 'application/json'; options.body = JSON.stringify(options.body); } const response = await fetch(`/api${endpoint}`, { credentials: 'include', ...options }); const data = await response.json(); if (!response.ok) { if (response.status === 401) handleLogout(false); throw new Error(data.error || 'Request failed'); } return { success: true, ...data }; } catch (error) { showToast(error.message, 'error'); return { success: false, error: error.message }; } }
        function renderPage(templateId, setupFunction) { const template = document.getElementById(templateId); if (!template) return; DOMElements.appContainer.innerHTML = ''; DOMElements.appContainer.appendChild(template.content.cloneNode(true)); if (setupFunction) setupFunction(); injectLogo(); }
        function renderSubTemplate(container, templateId, setupFunction) { const template = document.getElementById(templateId); if (!container || !template) return; container.innerHTML = ''; container.appendChild(template.content.cloneNode(true)); if (setupFunction) setupFunction(); }
        function showFullScreenLoader(message = 'Loading...') { renderPage('template-full-screen-loader', () => { document.querySelector('.waiting-text').textContent = message; }); }

        function handleLoginSuccess(user, settings) { appState.currentUser = user; appState.siteSettings = settings; applyTheme(user.profile.theme_preference); showFullScreenLoader(); setTimeout(() => { setupDashboard(user); }, 1000); }
        function handleLogout(doApiCall = true) { if (doApiCall) apiCall('/logout', { method: 'POST' }); appState.currentUser = null; window.location.reload(); }
        
        function setupRoleChoicePage() { renderPage('template-role-choice', () => { document.querySelectorAll('.role-btn').forEach(btn => btn.addEventListener('click', (e) => { appState.selectedRole = e.currentTarget.dataset.role; setupAuthPage(); })); }); }
        function setupAuthPage() { renderPage('template-auth-form', () => { updateAuthView(); document.getElementById('auth-form').addEventListener('submit', handleAuthSubmit); document.getElementById('auth-toggle-btn').addEventListener('click', () => { appState.isLoginView = !appState.isLoginView; updateAuthView(); }); document.getElementById('back-to-roles').addEventListener('click', setupRoleChoicePage); }); }
        
        function updateAuthView() {
            const isLogin = appState.isLoginView, role = appState.selectedRole;
            document.getElementById('auth-title').textContent = `${role.charAt(0).toUpperCase() + role.slice(1)} Portal`;
            document.getElementById('auth-subtitle').textContent = isLogin ? 'Sign in to continue' : 'Create your Account';
            document.getElementById('auth-submit-btn').textContent = isLogin ? 'Login' : 'Sign Up';
            document.getElementById('auth-toggle-btn').innerHTML = isLogin ? "Don't have an account? <span class='font-semibold'>Sign Up</span>" : "Already have an account? <span class='font-semibold'>Login</span>";
            document.getElementById('email-field').style.display = isLogin ? 'none' : 'block';
            document.getElementById('email').required = !isLogin;
            document.getElementById('teacher-key-field').style.display = (!isLogin && role === 'teacher') ? 'block' : 'none';
            document.getElementById('teacher-secret-key').required = !isLogin && role === 'teacher';
            document.getElementById('admin-key-field').style.display = (isLogin && role === 'admin') ? 'block' : 'none';
            document.getElementById('admin-secret-key').required = isLogin && role === 'admin';
            document.getElementById('account_type').value = role;
        }

        async function handleAuthSubmit(e) { e.preventDefault(); const form = e.target; const body = Object.fromEntries(new FormData(form)); const endpoint = appState.isLoginView ? '/login' : '/signup'; const result = await apiCall(endpoint, { method: 'POST', body }); if (result.success) { handleLoginSuccess(result.user, result.settings); } else { document.getElementById('auth-error').textContent = result.error; } }
        
        function setupDashboard(user) {
            renderPage('template-main-dashboard', () => {
                document.getElementById('welcome-message').textContent = `Welcome, ${escapeHtml(user.username)}!`;
                let tabs = [ { id: 'profile', label: 'Profile' } ];
                if (['student', 'teacher'].includes(user.role)) {
                    document.getElementById('dashboard-title').textContent = user.role === 'student' ? "Student Hub" : "Teacher Hub";
                    tabs.unshift({ id: 'my-classes', label: 'My Classes' });
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
                switchTab(appState.currentTab);
            });
        }
        
        function switchTab(tab) {
            const setups = { 'my-classes': setupMyClassesTab, 'profile': setupProfileTab, 'admin-dashboard': setupAdminDashboardTab };
            if (setups[tab]) {
                appState.currentTab = tab;
                document.querySelectorAll('.dashboard-tab').forEach(t => t.classList.toggle('active-tab', t.dataset.tab === tab));
                setups[tab](document.getElementById('dashboard-content'));
            }
        }
        
        async function setupMyClassesTab(container) {
            renderSubTemplate(container, 'template-my-classes', async () => {
                const actionContainer = document.getElementById('class-action-container');
                const role = appState.currentUser.role;
                const actionTemplateId = `template-${role}-class-action`;
                renderSubTemplate(actionContainer, actionTemplateId, () => {
                    if (role === 'student') document.getElementById('join-class-form').addEventListener('submit', handleJoinClass);
                    else if (role === 'teacher') document.getElementById('create-class-form').addEventListener('submit', handleCreateClass);
                });
                
                const result = await apiCall('/classes');
                if (result.success) {
                    const classesList = document.getElementById('classes-list');
                    if (result.classes.length === 0) {
                        classesList.innerHTML = `<p class="text-gray-400 col-span-full">You are not in any classes yet.</p>`;
                    } else {
                        classesList.innerHTML = result.classes.map(c => `<div class="class-card glassmorphism p-4 rounded-lg cursor-pointer hover:scale-105 transition-transform" data-class-id="${escapeHtml(c.id)}"><h3 class="text-xl font-bold">${escapeHtml(c.name)}</h3><p class="text-sm text-gray-400">Teacher: ${escapeHtml(c.teacher_name)}</p><p class="text-sm text-gray-400 mt-2">Code: <span class="font-mono bg-bg-dark p-1 rounded">${escapeHtml(c.code)}</span></p></div>`).join('');
                        classesList.querySelectorAll('.class-card').forEach(card => card.addEventListener('click', () => { /* View class logic */ }));
                    }
                }
            });
        }
        
        async function handleJoinClass(e) { e.preventDefault(); const code = e.target.elements.code.value; const result = await apiCall('/classes/join', { method: 'POST', body: { code } }); if (result.success) { showToast(`Joined ${result.class_name}!`, 'success'); setupMyClassesTab(document.getElementById('dashboard-content')); } }
        async function handleCreateClass(e) { e.preventDefault(); const name = e.target.elements.name.value; const result = await apiCall('/classes/create', { method: 'POST', body: { name } }); if (result.success) { showToast(`Class "${result.class.name}" created!`, 'success'); setupMyClassesTab(document.getElementById('dashboard-content')); } }
        
        async function setupProfileTab(container) {
            renderSubTemplate(container, 'template-profile', () => {
                const profile = appState.currentUser.profile;
                document.getElementById('bio').value = profile.bio || '';
                document.getElementById('avatar').value = profile.avatar || '';
                const themeSelect = document.getElementById('theme-select');
                themeSelect.innerHTML = Object.keys(themes).map(name => `<option value="${name}">${name.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</option>`).join('');
                themeSelect.value = profile.theme_preference || 'golden';
                document.getElementById('profile-form').addEventListener('submit', async e => {
                    e.preventDefault();
                    const body = Object.fromEntries(new FormData(e.target));
                    const result = await apiCall('/update_profile', { method: 'POST', body });
                    if (result.success) {
                        appState.currentUser.profile = result.profile;
                        applyTheme(body.theme_preference);
                        showToast('Profile updated!', 'success');
                    }
                });
            });
        }

        async function setupAdminDashboardTab(container) {
            renderSubTemplate(container, 'template-admin-dashboard', async () => {
                const usersContainer = document.getElementById('admin-users-view-container');
                renderSubTemplate(usersContainer, 'template-admin-users-view', async () => {
                    const result = await apiCall('/admin/users');
                    if(result.success) {
                        document.getElementById('users-table-body').innerHTML = result.users.map(user => `
                            <tr class="border-b border-gray-700/50">
                                <td class="p-3">${escapeHtml(user.username)}</td>
                                <td class="p-3">${escapeHtml(user.email)}</td>
                                <td class="p-3">${escapeHtml(user.role)}</td>
                            </tr>`).join('');
                    }
                });

                const settingsContainer = document.getElementById('admin-settings-view-container');
                renderSubTemplate(settingsContainer, 'template-admin-settings-view', () => {
                    document.getElementById('site-wide-theme-select').value = appState.siteSettings.site_wide_theme || 'default';
                    document.getElementById('admin-settings-form').addEventListener('submit', async e => {
                        e.preventDefault();
                        const body = Object.fromEntries(new FormData(e.target));
                        const result = await apiCall('/admin/settings', { method: 'POST', body });
                        if (result.success) {
                            showToast('Site settings updated!', 'success');
                            appState.siteSettings = result.settings;
                            applyTheme(appState.currentUser.profile.theme_preference);
                        }
                    });
                });
            });
        }

        async function main() {
            renderPage('template-welcome-screen');
            setTimeout(async () => {
                const result = await apiCall('/status');
                if (result.success) {
                    appState.siteSettings = result.settings;
                    if (result.user) {
                        handleLoginSuccess(result.user, result.settings);
                    } else {
                        setupRoleChoicePage();
                    }
                } else {
                    setupRoleChoicePage(); // Fallback if status fails
                }
            }, 1500);
        }

        main();
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
    if current_user.is_authenticated:
        return jsonify({"user": current_user.to_dict(), "settings": settings})
    return jsonify({"user": None, "settings": settings})

@app.route('/api/signup', methods=['POST'])
@limiter.limit("5 per minute")
def signup():
    data = request.json
    username = bleach.clean(data.get('username', '')).strip()
    email = bleach.clean(data.get('email', '')).strip()
    password = data.get('password') # Not cleaned, will be hashed
    role = bleach.clean(data.get('account_type', 'student'))
    
    if not all([username, email, password]):
        return jsonify({"error": "Missing required fields."}), 400
    
    if len(password) < 8 or not re.search("[a-z]", password) or not re.search("[A-Z]", password) or not re.search("[0-9]", password):
        return jsonify({"error": "Password must be at least 8 characters and contain uppercase, lowercase, and numbers."}), 400

    if User.query.filter(or_(User.username == username, User.email == email)).first():
        return jsonify({"error": "Username or email already exists."}), 409
        
    new_user = User(username=username, email=email, role=role)
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

@app.route('/api/update_profile', methods=['POST'])
@login_required
def update_profile():
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

# ==============================================================================
# --- 6. CLASS MANAGEMENT API ROUTES ---
# ==============================================================================
@app.route('/api/classes', methods=['GET'])
@login_required
@role_required(['student', 'teacher'])
def get_classes():
    if current_user.role == 'teacher':
        classes = current_user.taught_classes
    else:
        classes = current_user.enrolled_classes.all()
    
    return jsonify({"success": True, "classes": [c.to_dict() for c in classes]})

@app.route('/api/classes/create', methods=['POST'])
@login_required
@teacher_required
def create_class():
    data = request.json
    name = bleach.clean(data.get('name'))
    if not name:
        return jsonify({"error": "Class name is required."}), 400
    
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
    data = request.json
    code = bleach.clean(data.get('code', '')).upper()
    if not code:
        return jsonify({"error": "Class code is required."}), 400
        
    target_class = Class.query.filter_by(code=code).first()
    if not target_class:
        return jsonify({"error": "Invalid class code."}), 404
        
    if current_user in target_class.students:
        return jsonify({"error": "You are already in this class."}), 409
        
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
        # Sanitize key to prevent unexpected settings
        clean_key = bleach.clean(key)
        if clean_key not in ['site_wide_theme', 'maintenance_mode']:
            continue
        
        setting = SiteSettings.query.filter_by(key=clean_key).first()
        if setting:
            setting.value = bleach.clean(value)
        else:
            setting = SiteSettings(key=clean_key, value=bleach.clean(value))
            db.session.add(setting)
    db.session.commit()
    
    settings_raw = SiteSettings.query.all()
    settings = {s.key: s.value for s in settings_raw}
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

def init_db_command():
    with app.app_context():
        db.create_all()
        logging.info("Database tables created.")
        
        # Seed default settings
        if not SiteSettings.query.filter_by(key='maintenance_mode').first():
            db.session.add(SiteSettings(key='maintenance_mode', value='false'))
        if not SiteSettings.query.filter_by(key='site_wide_theme').first():
            db.session.add(SiteSettings(key='site_wide_theme', value='default'))
        
        db.session.commit()
        logging.info("Default settings seeded.")

@app.cli.command("init-db")
def init_db():
    init_db_command()

if __name__ == '__main__':
    socketio.run(app, debug=(not is_production))
  #wtf
  #gemnie 
  # you gyatt to bring in
