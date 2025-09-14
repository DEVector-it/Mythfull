import os
import json
import logging
import base64
import time
import uuid
import secrets
import smtplib
from io import BytesIO
from email.mime.text import MIMEText
from flask import Flask, Response, request, stream_with_context, session, jsonify, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from datetime import datetime, timedelta, date
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import google.generativeai as genai
from dotenv import load_dotenv
import stripe
from PIL import Image
from authlib.integrations.flask_client import OAuth
from itsdangerous import URLSafeTimedSerializer

# --- 1. Initial Configuration ---
load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Security Check for Essential Keys ---
REQUIRED_KEYS = [
    'SECRET_KEY', 'GEMINI_API_KEY', 'SECRET_REGISTRATION_KEY',
    'SECRET_STUDENT_KEY', 'SECRET_TEACHER_KEY', 'STRIPE_WEBHOOK_SECRET',
    'STRIPE_STUDENT_PRICE_ID', 'STRIPE_STUDENT_PRO_PRICE_ID'
]
for key in REQUIRED_KEYS:
    if not os.environ.get(key):
        logging.critical(f"CRITICAL ERROR: Environment variable '{key}' is not set. Application cannot start.")
        exit(f"Error: Missing required environment variable '{key}'. Please set it in your .env file.")

# --- Application Setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get('SECRET_KEY')


# --- Site & API Configuration ---
SITE_CONFIG = {
    "GEMINI_API_KEY": os.environ.get("GEMINI_API_KEY"),
    "STRIPE_SECRET_KEY": os.environ.get('STRIPE_SECRET_KEY'),
    "STRIPE_PUBLIC_KEY": os.environ.get('STRIPE_PUBLIC_KEY'),
    "STRIPE_STUDENT_PRICE_ID": os.environ.get('STRIPE_STUDENT_PRICE_ID'),
    "STRIPE_STUDENT_PRO_PRICE_ID": os.environ.get('STRIPE_STUDENT_PRO_PRICE_ID'),
    "YOUR_DOMAIN": os.environ.get('YOUR_DOMAIN', 'http://localhost:5000'),
    "SECRET_REGISTRATION_KEY": os.environ.get('SECRET_REGISTRATION_KEY'),
    "SECRET_STUDENT_KEY": os.environ.get('SECRET_STUDENT_KEY'),
    "SECRET_TEACHER_KEY": os.environ.get('SECRET_TEACHER_KEY'),
    "STRIPE_WEBHOOK_SECRET": os.environ.get('STRIPE_WEBHOOK_SECRET'),
    "GOOGLE_CLIENT_ID": os.environ.get("GOOGLE_CLIENT_ID"),
    "GOOGLE_CLIENT_SECRET": os.environ.get("GOOGLE_CLIENT_SECRET"),
    "MAIL_SERVER": os.environ.get('MAIL_SERVER'),
    "MAIL_PORT": int(os.environ.get('MAIL_PORT', 587)),
    "MAIL_USE_TLS": os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', '1', 't'],
    "MAIL_USERNAME": os.environ.get('MAIL_USERNAME'),
    "MAIL_PASSWORD": os.environ.get('MAIL_PASSWORD'),
    "MAIL_SENDER": os.environ.get('MAIL_SENDER'),
}


# --- API & Services Initialization ---
GEMINI_API_CONFIGURED = False
try:
    genai.configure(api_key=SITE_CONFIG["GEMINI_API_KEY"])
    GEMINI_API_CONFIGURED = True
except Exception as e:
    logging.critical(f"Could not configure Gemini API. Details: {e}")

stripe.api_key = SITE_CONFIG["STRIPE_SECRET_KEY"]
if not stripe.api_key:
    logging.warning("Stripe Secret Key is not set. Payment flows will fail.")

GOOGLE_OAUTH_ENABLED = all([SITE_CONFIG['GOOGLE_CLIENT_ID'], SITE_CONFIG['GOOGLE_CLIENT_SECRET']])
EMAIL_ENABLED = all([SITE_CONFIG['MAIL_SERVER'], SITE_CONFIG['MAIL_USERNAME'], SITE_CONFIG['MAIL_PASSWORD']])

oauth = OAuth(app)
if GOOGLE_OAUTH_ENABLED:
    oauth.register(
        name='google',
        client_id=SITE_CONFIG['GOOGLE_CLIENT_ID'],
        client_secret=SITE_CONFIG['GOOGLE_CLIENT_SECRET'],
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'}
    )
    logging.info("Google OAuth has been configured and enabled.")
else:
    logging.warning("Google OAuth credentials not found. Google Sign-In will be disabled.")

password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
if not EMAIL_ENABLED:
    logging.warning("Email server credentials not found. Password reset functionality will be disabled.")
else:
    logging.info("Email server has been configured and enabled.")


# --- 2. Database Management ---
DATA_DIR = 'data'
DATABASE_FILE = os.path.join(DATA_DIR, 'database.json')
DB = { "users": {}, "chats": {}, "classrooms": {}, "site_settings": {"announcement": "Welcome to Myth AI for Students!"} }

def setup_database_dir():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
        logging.info(f"Created data directory at: {DATA_DIR}")
        gitignore_path = os.path.join(DATA_DIR, '.gitignore')
        if not os.path.exists(gitignore_path):
            with open(gitignore_path, 'w') as f:
                f.write('*\n')
                f.write('!.gitignore\n')
            logging.info(f"Created .gitignore in {DATA_DIR} to protect database files.")

def save_database():
    setup_database_dir()
    if os.path.exists(DATABASE_FILE):
        backup_file = os.path.join(DATA_DIR, f"database_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json.bak")
        try:
            os.rename(DATABASE_FILE, backup_file)
            backups = sorted([f for f in os.listdir(DATA_DIR) if f.endswith('.bak')], reverse=True)
            for old_backup in backups[5:]:
                os.remove(os.path.join(DATA_DIR, old_backup))
        except Exception as e:
            logging.error(f"Could not create database backup: {e}")

    temp_file = f"{DATABASE_FILE}.tmp"
    try:
        with open(temp_file, 'w') as f:
            serializable_db = {
                "users": {uid: user_to_dict(u) for uid, u in DB['users'].items()},
                "chats": DB['chats'],
                "classrooms": DB['classrooms'],
                "site_settings": DB['site_settings'],
            }
            json.dump(serializable_db, f, indent=4)
        os.replace(temp_file, DATABASE_FILE)
    except Exception as e:
        logging.error(f"FATAL: Failed to save database: {e}")
        if 'backup_file' in locals() and os.path.exists(backup_file):
            os.rename(backup_file, DATABASE_FILE)
            logging.info("Restored database from immediate backup after save failure.")
        if os.path.exists(temp_file):
            os.remove(temp_file)

def load_database():
    global DB
    setup_database_dir()
    if not os.path.exists(DATABASE_FILE):
        logging.warning(f"Database file not found at {DATABASE_FILE}. A new one will be created on first save.")
        return

    try:
        with open(DATABASE_FILE, 'r') as f:
            data = json.load(f)
        DB['chats'] = data.get('chats', {})
        DB['site_settings'] = data.get('site_settings', {"announcement": ""})
        DB['classrooms'] = data.get('classrooms', {})
        DB['users'] = {uid: User.from_dict(u_data) for uid, u_data in data.get('users', {}).items()}
        logging.info(f"Successfully loaded database from {DATABASE_FILE}")
    except (json.JSONDecodeError, FileNotFoundError, TypeError) as e:
        logging.error(f"Could not load main database file '{DATABASE_FILE}'. Error: {e}")
        backups = sorted([f for f in os.listdir(DATA_DIR) if f.endswith('.bak')], reverse=True)
        if backups:
            backup_to_load = os.path.join(DATA_DIR, backups[0])
            logging.info(f"Attempting to load most recent backup: {backup_to_load}")
            try:
                with open(backup_to_load, 'r') as f:
                    data = json.load(f)
                DB['chats'] = data.get('chats', {})
                DB['site_settings'] = data.get('site_settings', {"announcement": ""})
                DB['classrooms'] = data.get('classrooms', {})
                DB['users'] = {uid: User.from_dict(u_data) for uid, u_data in data.get('users', {}).items()}
                os.rename(backup_to_load, DATABASE_FILE)
                logging.info(f"SUCCESS: Loaded and restored from backup file {backups[0]}")
            except Exception as backup_e:
                logging.error(f"FATAL: Failed to load backup file as well. Starting with a fresh database. Error: {backup_e}")
        else:
            logging.warning("No backups found. Starting with a fresh database.")


# --- 3. User and Session Management ---
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.unauthorized_handler
def unauthorized():
    if request.path.startswith('/api/'):
        return jsonify({"error": "Login required.", "logged_in": False}), 401
    return redirect(url_for('index'))

class User(UserMixin):
    """User model for Students, Teachers, and Admins."""
    def __init__(self, id, username, email, password_hash, role='user', plan='student', account_type='student', daily_messages=0, last_message_date=None, classroom_code=None, streak=0, last_streak_date=None, message_limit_override=None):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.role = role
        self.plan = plan
        self.account_type = account_type
        self.daily_messages = daily_messages
        self.last_message_date = last_message_date or date.today().isoformat()
        self.classroom_code = classroom_code
        self.streak = streak
        self.last_streak_date = last_streak_date or date.today().isoformat()
        self.message_limit_override = message_limit_override

    @staticmethod
    def get(user_id):
        return DB['users'].get(user_id)
        
    @staticmethod
    def get_by_email(email):
        if not email: return None
        for user in DB['users'].values():
            if user.email and user.email.lower() == email.lower():
                return user
        return None

    @staticmethod
    def get_by_username(username):
        for user in DB['users'].values():
            if user.username.lower() == username.lower():
                return user
        return None

    @staticmethod
    def from_dict(data):
        data.setdefault('message_limit_override', None)
        return User(**data)

def user_to_dict(user):
    """Serializes the User object to a dictionary."""
    return {
        'id': user.id, 'username': user.username, 'email': user.email, 'password_hash': user.password_hash,
        'role': user.role, 'plan': user.plan, 'account_type': user.account_type,
        'daily_messages': user.daily_messages, 'last_message_date': user.last_message_date,
        'classroom_code': user.classroom_code, 'streak': user.streak,
        'last_streak_date': user.last_streak_date,
        'message_limit_override': user.message_limit_override
    }

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

def initialize_database_defaults():
    made_changes = False
    if not User.get_by_username('admin'):
        admin_pass = os.environ.get('ADMIN_PASSWORD', 'supersecretadminpassword123')
        admin_email = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
        admin = User(id='admin', username='admin', email=admin_email, password_hash=generate_password_hash(admin_pass), role='admin', plan='student_pro', account_type='admin')
        DB['users']['admin'] = admin
        made_changes = True
        logging.info("Created default admin user.")

    if made_changes:
        save_database()

load_database()
with app.app_context():
    initialize_database_defaults()


# --- 4. Plan & Rate Limiting Configuration (Student Focused) ---
PLAN_CONFIG = {
    "student": {"name": "Student", "price_string": "$4.99 / month", "features": ["100 Daily Messages", "Study Buddy Persona", "Streak & Leaderboard", "No Image Uploads"], "color": "text-amber-400", "message_limit": 100, "can_upload": False, "model": "gemini-1.5-flash-latest"},
    "student_pro": {"name": "Student Pro", "price_string": "$7.99 / month", "features": ["200 Daily Messages", "Image Uploads", "All AI Personas", "Streak & Leaderboard"], "color": "text-amber-300", "message_limit": 200, "can_upload": True, "model": "gemini-1.5-pro-latest"}
}

rate_limit_store = {}
RATE_LIMIT_WINDOW = 60

# --- 5. Decorators ---
def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            return jsonify({"error": "Administrator access required."}), 403
        return f(*args, **kwargs)
    return decorated_function

def teacher_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.account_type != 'teacher':
            return jsonify({"error": "Teacher access required."}), 403
        return f(*args, **kwargs)
    return decorated_function

def rate_limited(max_attempts=5):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip = request.remote_addr
            now = time.time()
            rate_limit_store[ip] = [t for t in rate_limit_store.get(ip, []) if now - t < RATE_LIMIT_WINDOW]
            if len(rate_limit_store.get(ip, [])) >= max_attempts:
                return jsonify({"error": "Too many requests. Please try again later."}), 429
            rate_limit_store.setdefault(ip, []).append(now)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- 6. HTML, CSS, and JavaScript Frontend ---
HTML_CONTENT = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Myth AI</title>
    <meta name="description" content="An advanced AI study buddy to help students learn and succeed.">
    <script src="https://js.stripe.com/v3/"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/marked/4.2.12/marked.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/2.4.1/purify.min.js"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
    <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-1136294351029434"
      crossorigin="anonymous"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: { sans: ['Inter', 'sans-serif'], mono: ['Fira Code', 'monospace'] },
                    animation: { 'fade-in': 'fadeIn 0.5s ease-out forwards', 'scale-up': 'scaleUp 0.3s ease-out forwards' },
                    keyframes: {
                        fadeIn: { '0%': { opacity: 0 }, '100%': { opacity: 1 } },
                        scaleUp: { '0%': { transform: 'scale(0.95)', opacity: 0 }, '100%': { transform: 'scale(1)', opacity: 1 } },
                    }
                }
            }
        }
    </script>
    <style>
        /* --- THEME: Yellow to Orange Gradient --- */
        :root {
            --bg-gradient-start: #FDB813; /* Bright Yellow */
            --bg-gradient-end: #F99B28;    /* Warm Orange */
            --text-dark: #333333;
            --text-light: #ffffff;
            --container-bg: rgba(255, 255, 255, 0.25);
            --glass-border: rgba(255, 255, 255, 0.4);
            --header-bg: rgba(0, 0, 0, 0.1);
            --input-bg: rgba(255, 255, 255, 0.5);
            --sent-bg: #ffffff;
            --received-bg: #dcf8c6;
            --button-bg: #F99B28;
            --button-hover-bg: #E68A1A;
            --brand-gradient-from: #FDB813;
            --brand-gradient-to: #F99B28;
        }

        body { 
            background: linear-gradient(135deg, var(--bg-gradient-start), var(--bg-gradient-end));
            color: var(--text-dark); 
        }
        .dark body {
            color: var(--text-light);
        }

        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: rgba(0,0,0,0.1); }
        ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.4); border-radius: 10px; }
        
        .glassmorphism { 
            background: var(--container-bg); 
            backdrop-filter: blur(12px); 
            -webkit-backdrop-filter: blur(12px); 
            border: 1px solid var(--glass-border); 
        }
        
        .brand-gradient { 
            background-image: linear-gradient(to right, var(--brand-gradient-from), var(--brand-gradient-to)); 
            -webkit-background-clip: text; 
            -webkit-text-fill-color: transparent; 
        }
        .prose a { color: #E68A1A; }
        .prose code { color: #fff; background-color: rgba(0,0,0,0.2); }
        .prose pre { background-color: rgba(0,0,0,0.3); border-color: rgba(255,255,255,0.1); }
        .prose h1, .prose h2, .prose h3, .prose h4, .prose strong { color: #fff; }
        .prose a:hover { color: #fff; }

        /* General UI improvements */
        .message-wrapper { animation: fadeIn 0.4s ease-out forwards; }
        pre { position: relative; }
        .copy-code-btn { position: absolute; top: 0.5rem; right: 0.5rem; background-color: rgba(0,0,0,0.3); color: white; border: none; padding: 0.25rem 0.5rem; border-radius: 0.25rem; cursor: pointer; opacity: 0; transition: opacity 0.2s; font-size: 0.75rem; }
        pre:hover .copy-code-btn { opacity: 1; }
        #sidebar.hidden { transform: translateX(-100%); }
        .typing-indicator span { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background-color: currentColor; margin: 0 2px; animation: typing-bounce 1.4s infinite ease-in-out both; }
        .typing-indicator span:nth-child(1) { animation-delay: -0.32s; }
        .typing-indicator span:nth-child(2) { animation-delay: -0.16s; }
        @keyframes typing-bounce { 0%, 80%, 100% { transform: scale(0); } 40% { transform: scale(1.0); } }
    </style>
</head>
<body class="font-sans antialiased">
    <div id="announcement-banner" class="hidden text-center p-2 bg-orange-600 text-white text-sm"></div>
    <div id="app-container" class="relative h-screen w-screen"></div>
    <div id="modal-container"></div>
    <div id="toast-container" class="fixed top-6 right-6 z-[100] flex flex-col gap-2"></div>

    <template id="template-logo">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <defs>
                <linearGradient id="logoGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:var(--brand-gradient-from);" />
                    <stop offset="100%" style="stop-color:var(--brand-gradient-to);" />
                </linearGradient>
            </defs>
            <path d="M12 2L2 7V17L12 22L22 17V7L12 2Z" stroke="url(#logoGradient)" stroke-width="1.5"/>
            <path d="M12 22V12" stroke="url(#logoGradient)" stroke-width="1.5"/>
            <path d="M22 7L12 12" stroke="url(#logoGradient)" stroke-width="1.5"/>
            <path d="M2 7L12 12" stroke="url(#logoGradient)" stroke-width="1.5"/>
            <path d="M7 4.5L17 9.5" stroke="url(#logoGradient)" stroke-width="1.5"/>
        </svg>
    </template>

    <template id="template-auth-page">
        <div class="flex flex-col items-center justify-center h-full w-full p-4">
            <div class="w-full max-w-md glassmorphism rounded-2xl p-8 shadow-2xl animate-scale-up">
                <div class="flex justify-center mb-6" id="auth-logo-container"></div>
                <h2 class="text-3xl font-bold text-center text-white mb-2" id="auth-title">Student Portal</h2>
                <p class="text-gray-200 text-center mb-8" id="auth-subtitle">Sign in to your student account.</p>
                <form id="auth-form">
                    <div class="mb-4">
                        <label for="username" class="block text-sm font-medium text-gray-100 mb-1">Username</label>
                        <input type="text" id="username" name="username" class="w-full p-3 bg-white/20 text-white rounded-lg border border-white/30 focus:outline-none focus:ring-2 focus:ring-yellow-300 transition-all" required>
                    </div>
                    <div class="mb-4">
                        <label for="password" class="block text-sm font-medium text-gray-100 mb-1">Password</label>
                        <input type="password" id="password" name="password" class="w-full p-3 bg-white/20 text-white rounded-lg border border-white/30 focus:outline-none focus:ring-2 focus:ring-yellow-300 transition-all" required>
                    </div>
                    <div class="flex justify-end mb-6">
                        <button type="button" id="forgot-password-link" class="text-xs text-yellow-200 hover:text-white">Forgot Password?</button>
                    </div>
                    <button type="submit" id="auth-submit-btn" class="w-full bg-gradient-to-r from-orange-500 to-yellow-500 hover:opacity-90 text-white font-bold py-3 px-4 rounded-lg transition-opacity">Login</button>
                    <p id="auth-error" class="text-red-300 text-sm text-center h-4 mt-3"></p>
                </form>
                <div class="text-center mt-6">
                    <button id="auth-toggle-btn" class="text-sm text-yellow-200 hover:text-white">Don't have an account? Sign Up</button>
                </div>
            </div>
             <div class="text-center mt-4 flex justify-center gap-4">
                <button id="teacher-signup-link" class="text-xs text-gray-200 hover:text-white">Teacher Portal</button>
                <button id="special-auth-link" class="text-xs text-gray-200 hover:text-white">Admin Portal</button>
             </div>
             <p class="text-xs text-gray-100/70 mt-8">Made by DeVector</p>
        </div>
    </template>
    
    <template id="template-reset-password-page">
        <div class="flex flex-col items-center justify-center h-full w-full p-4">
            <div class="w-full max-w-md glassmorphism rounded-2xl p-8 shadow-2xl animate-scale-up">
                <div class="flex justify-center mb-6" id="reset-logo-container"></div>
                <h2 class="text-3xl font-bold text-center text-white mb-2">Reset Password</h2>
                <p class="text-gray-200 text-center mb-8">Enter a new password for your account.</p>
                <form id="reset-password-form">
                    <div class="mb-4">
                        <label for="new-password" class="block text-sm font-medium text-gray-100 mb-1">New Password</label>
                        <input type="password" id="new-password" name="password" class="w-full p-3 bg-white/20 text-white rounded-lg border border-white/30 focus:outline-none focus:ring-2 focus:ring-yellow-300 transition-all" required>
                    </div>
                    <div class="mb-6">
                        <label for="confirm-password" class="block text-sm font-medium text-gray-100 mb-1">Confirm Password</label>
                        <input type="password" id="confirm-password" name="confirm-password" class="w-full p-3 bg-white/20 text-white rounded-lg border border-white/30 focus:outline-none focus:ring-2 focus:ring-yellow-300 transition-all" required>
                    </div>
                    <button type="submit" class="w-full bg-gradient-to-r from-orange-500 to-yellow-500 hover:opacity-90 text-white font-bold py-3 px-4 rounded-lg transition-opacity">Reset Password</button>
                    <p id="reset-error" class="text-red-300 text-sm text-center h-4 mt-3"></p>
                </form>
            </div>
        </div>
    </template>

    <template id="template-student-signup-page">
        <div class="flex flex-col items-center justify-center h-full w-full p-4">
            <div class="w-full max-w-md glassmorphism rounded-2xl p-8 shadow-2xl animate-scale-up">
                <div class="flex justify-center mb-6" id="student-signup-logo-container"></div>
                <h2 class="text-3xl font-bold text-center text-white mb-2">Student Account Signup</h2>
                <p class="text-gray-200 text-center mb-8">Create your student account for Myth AI.</p>
                <form id="student-signup-form">
                    <div class="mb-4">
                        <label for="student-username" class="block text-sm font-medium text-gray-100 mb-1">Username</label>
                        <input type="text" id="student-username" name="username" class="w-full p-3 bg-white/20 text-white rounded-lg border border-white/30 focus:outline-none focus:ring-2 focus:ring-yellow-300" required>
                    </div>
                    <div class="mb-4">
                        <label for="student-email" class="block text-sm font-medium text-gray-100 mb-1">Email</label>
                        <input type="email" id="student-email" name="email" class="w-full p-3 bg-white/20 text-white rounded-lg border border-white/30 focus:outline-none focus:ring-2 focus:ring-yellow-300" required>
                    </div>
                    <div class="mb-4">
                        <label for="student-password" class="block text-sm font-medium text-gray-100 mb-1">Password</label>
                        <input type="password" id="student-password" name="password" class="w-full p-3 bg-white/20 text-white rounded-lg border border-white/30 focus:outline-none focus:ring-2 focus:ring-yellow-300" required>
                    </div>
                    <div class="mb-4">
                        <label for="classroom-code" class="block text-sm font-medium text-gray-100 mb-1">Classroom Code (Optional)</label>
                        <input type="text" id="classroom-code" name="classroom_code" class="w-full p-3 bg-white/20 text-white rounded-lg border border-white/30 focus:outline-none focus:ring-2 focus:ring-yellow-300" placeholder="Enter code from your teacher">
                    </div>
                    <button type="submit" class="w-full bg-gradient-to-r from-orange-500 to-yellow-500 hover:opacity-90 text-white font-bold py-3 px-4 rounded-lg">Create Student Account</button>
                    <p id="student-signup-error" class="text-red-300 text-sm text-center h-4 mt-3"></p>
                </form>
                <div class="text-center mt-6">
                    <button id="back-to-main-login" class="text-sm text-yellow-200 hover:text-white">Already have an account? Log in</button>
                </div>
            </div>
        </div>
    </template>

    <template id="template-teacher-signup-page">
        <div class="flex flex-col items-center justify-center h-full w-full p-4">
            <div class="w-full max-w-md glassmorphism rounded-2xl p-8 shadow-2xl animate-scale-up">
                <div class="flex justify-center mb-6" id="teacher-signup-logo-container"></div>
                <h2 class="text-3xl font-bold text-center text-white mb-2">Teacher Account Signup</h2>
                <p class="text-gray-200 text-center mb-8">Create your teacher account.</p>
                <form id="teacher-signup-form">
                    <div class="mb-4">
                        <label for="teacher-username" class="block text-sm font-medium text-gray-100 mb-1">Username</label>
                        <input type="text" id="teacher-username" name="username" class="w-full p-3 bg-white/20 text-white rounded-lg border border-white/30 focus:outline-none focus:ring-2 focus:ring-yellow-300" required>
                    </div>
                    <div class="mb-4">
                        <label for="teacher-email" class="block text-sm font-medium text-gray-100 mb-1">Email</label>
                        <input type="email" id="teacher-email" name="email" class="w-full p-3 bg-white/20 text-white rounded-lg border border-white/30 focus:outline-none focus:ring-2 focus:ring-yellow-300" required>
                    </div>
                    <div class="mb-4">
                        <label for="teacher-password" class="block text-sm font-medium text-gray-100 mb-1">Password</label>
                        <input type="password" id="teacher-password" name="password" class="w-full p-3 bg-white/20 text-white rounded-lg border border-white/30 focus:outline-none focus:ring-2 focus:ring-yellow-300" required>
                    </div>
                    <div class="mb-6">
                        <label for="teacher-secret-key" class="block text-sm font-medium text-gray-100 mb-1">Teacher Access Key</label>
                        <input type="password" id="teacher-secret-key" name="secret_key" class="w-full p-3 bg-white/20 text-white rounded-lg border border-white/30 focus:outline-none focus:ring-2 focus:ring-yellow-300" required>
                    </div>
                    <button type="submit" class="w-full bg-gradient-to-r from-orange-500 to-yellow-500 hover:opacity-90 text-white font-bold py-3 px-4 rounded-lg">Create Teacher Account</button>
                    <p id="teacher-signup-error" class="text-red-300 text-sm text-center h-4 mt-3"></p>
                </form>
                <div class="text-center mt-6">
                    <button id="back-to-teacher-login" class="text-sm text-yellow-200 hover:text-white">Already have an account? Log in</button>
                </div>
            </div>
        </div>
    </template>
    
    <template id="template-special-auth-page">
        <div class="flex flex-col items-center justify-center h-full w-full p-4">
            <div class="w-full max-w-md glassmorphism rounded-2xl p-8 shadow-2xl animate-scale-up">
                <div class="flex justify-center mb-6" id="special-auth-logo-container"></div>
                <h2 class="text-3xl font-bold text-center text-white mb-2">Admin Signup</h2>
                <p class="text-gray-200 text-center mb-8">Create an admin account.</p>
                <form id="special-auth-form">
                    <div class="mb-4">
                        <label for="special-username" class="block text-sm font-medium text-gray-100 mb-1">Username</label>
                        <input type="text" id="special-username" name="username" class="w-full p-3 bg-white/20 text-white rounded-lg border border-white/30 focus:outline-none focus:ring-2 focus:ring-yellow-300" required>
                    </div>
                    <div class="mb-4">
                        <label for="special-email" class="block text-sm font-medium text-gray-100 mb-1">Email</label>
                        <input type="email" id="special-email" name="email" class="w-full p-3 bg-white/20 text-white rounded-lg border border-white/30 focus:outline-none focus:ring-2 focus:ring-yellow-300" required>
                    </div>
                    <div class="mb-4">
                        <label for="special-password" class="block text-sm font-medium text-gray-100 mb-1">Password</label>
                        <input type="password" id="special-password" name="password" class="w-full p-3 bg-white/20 text-white rounded-lg border border-white/30 focus:outline-none focus:ring-2 focus:ring-yellow-300" required>
                    </div>
                    <div class="mb-6">
                        <label for="secret-key" class="block text-sm font-medium text-gray-100 mb-1">Secret Key</label>
                        <input type="password" id="secret-key" name="secret_key" class="w-full p-3 bg-white/20 text-white rounded-lg border border-white/30 focus:outline-none focus:ring-2 focus:ring-yellow-300" required>
                    </div>
                    <button type="submit" class="w-full bg-gradient-to-r from-orange-500 to-yellow-500 hover:opacity-90 text-white font-bold py-3 px-4 rounded-lg">Create Account</button>
                    <p id="special-auth-error" class="text-red-300 text-sm text-center h-4 mt-3"></p>
                </form>
            </div>
            <div class="text-center mt-6">
                <button id="back-to-main-login" class="text-sm text-yellow-200 hover:text-white">Back to Main Login</button>
            </div>
        </div>
    </template>
    
    <template id="template-app-wrapper">
        <div id="main-app-layout" class="flex h-full w-full transition-colors duration-500 text-gray-800">
            <aside id="sidebar" class="bg-white/20 backdrop-blur-lg w-72 flex-shrink-0 flex flex-col p-2 h-full absolute md:relative z-20 transform transition-transform duration-300 ease-in-out -translate-x-full md:translate-x-0">
                <div class="flex-shrink-0 p-2 mb-2 flex items-center gap-3">
                    <div id="app-logo-container"></div>
                    <h1 class="text-2xl font-bold brand-gradient">Myth AI</h1>
                </div>
                <div id="join-classroom-container" class="flex-shrink-0 p-2"></div>
                <div class="flex-shrink-0"><button id="new-chat-btn" class="w-full text-left flex items-center gap-3 p-3 rounded-lg hover:bg-black/10 transition-colors duration-200"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14" /><path d="M5 12h14" /></svg> New Chat</button></div>
                <div id="chat-history-list" class="flex-grow overflow-y-auto my-4 space-y-1 pr-1"></div>
                <div class="flex-shrink-0 border-t border-black/10 pt-2 space-y-1">
                    <div id="user-info" class="p-3 text-sm"></div>
                    <button id="upgrade-plan-btn" class="w-full text-left flex items-center gap-3 p-3 rounded-lg hover:bg-green-500/20 text-green-600 transition-colors duration-200"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 6v12m-6-6h12"/></svg> Upgrade Plan</button>
                    <button id="logout-btn" class="w-full text-left flex items-center gap-3 p-3 rounded-lg hover:bg-red-500/20 text-red-500 transition-colors duration-200"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" /><polyline points="16 17 21 12 16 7" /><line x1="21" x2="9" y1="12" y2="12" /></svg> Logout</button>
                </div>
            </aside>
            <div id="sidebar-backdrop" class="fixed inset-0 bg-black/60 z-10 hidden md:hidden"></div>
            <main class="flex-1 flex flex-col h-full min-w-0">
                <header class="flex-shrink-0 p-4 flex items-center justify-between border-b border-black/10 text-white">
                    <div class="flex items-center gap-2 min-w-0">
                        <button id="menu-toggle-btn" class="p-2 rounded-lg hover:bg-black/20 transition-colors md:hidden">
                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>
                        </button>
                        <h2 id="chat-title" class="text-xl font-semibold truncate">New Chat</h2>
                    </div>
                    <div id="ai-mode-selector-container" class="flex items-center gap-2"></div>
                    <div class="flex items-center gap-1 sm:gap-2">
                        <button id="share-chat-btn" title="Share Chat" class="p-2 rounded-lg hover:bg-black/20 transition-colors"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8"/><polyline points="16 6 12 2 8 6"/><line x1="12" y1="2" x2="12" y2="15"/></svg></button>
                        <button id="rename-chat-btn" title="Rename Chat" class="p-2 rounded-lg hover:bg-black/20 transition-colors"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" /><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" /></svg></button>
                        <button id="delete-chat-btn" title="Delete Chat" class="p-2 rounded-lg hover:bg-red-500/20 text-red-400 transition-colors"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6" /><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" /><line x1="10" y1="11" x2="10" y2="17" /><line x1="14" y1="11" x2="14" y2="17" /></svg></button>
                        <button id="download-chat-btn" title="Download Chat" class="p-2 rounded-lg hover:bg-black/20 transition-colors"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg></button>
                    </div>
                </header>
                <div id="student-leaderboard-container" class="flex-shrink-0"></div>
                <div id="chat-window" class="flex-1 overflow-y-auto p-4 md:p-6 min-h-0 w-full">
                    <div id="message-list" class="mx-auto max-w-3xl space-y-6">
                        <!-- Messages will be rendered here by JavaScript -->
                    </div>
                </div>
                <div class="flex-shrink-0 p-2 md:p-4 md:px-6 border-t border-black/10">
                    <div class="max-w-4xl mx-auto">
                        <div id="stop-generating-container" class="text-center mb-2" style="display: none;">
                            <button id="stop-generating-btn" class="bg-red-600/50 hover:bg-red-600/80 text-white font-semibold py-2 px-4 rounded-lg transition-colors flex items-center gap-2 mx-auto"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><rect width="10" height="10" x="3" y="3" rx="1"/></svg> Stop Generating</button>
                        </div>
                        <div class="relative glassmorphism rounded-2xl shadow-lg">
                            <div id="preview-container" class="hidden p-2 border-b border-black/20"></div>
                            <textarea id="user-input" placeholder="Message Study Buddy..." class="w-full bg-transparent p-4 pl-14 pr-16 resize-none rounded-2xl focus:outline-none text-gray-800 placeholder:text-gray-600" rows="1"></textarea>
                            <div class="absolute left-3 top-1/2 -translate-y-1/2 flex items-center">
                                <button id="upload-btn" title="Upload Image" class="p-2 rounded-full hover:bg-black/10 transition-colors"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21.2 15c.7-1.2 1-2.5.7-3.9-.6-2.4-2.4-4.2-4.8-4.8-1.4-.3-2.7 0-3.9.7L12 8l-1.2-1.1c-1.2-.7-2.5-1-3.9-.7-2.4.6-4.2 2.4-4.8 4.8-.3 1.4 0 2.7.7 3.9L4 16.1M12 13l2 3h-4l2-3z"/><circle cx="12" cy="12" r="10"/></svg></button>
                                <input type="file" id="file-input" class="hidden" accept="image/png, image/jpeg, image/webp">
                            </div>
                            <div class="absolute right-3 top-1/2 -translate-y-1/2 flex items-center">
                                <button id="send-btn" class="p-2 rounded-full bg-gradient-to-r from-orange-500 to-yellow-400 hover:opacity-90 transition-opacity disabled:from-gray-500 disabled:to-gray-600 disabled:cursor-not-allowed"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="white"><path d="M2 22l20-10L2 2z"/></svg></button>
                            </div>
                        </div>
                        <div class="text-xs text-white/70 mt-2 text-center" id="message-limit-display"></div>
                    </div>
                </div>
            </main>
        </div>
    </template>
    
    <template id="template-upgrade-page">
        <div class="w-full h-full p-4 sm:p-6 md:p-8 overflow-y-auto">
            <header class="flex justify-between items-center mb-8 text-gray-800">
                <h1 class="text-3xl font-bold brand-gradient">Choose Your Plan</h1>
                <button id="back-to-chat-btn" class="bg-gray-700/50 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded-lg transition-colors">Back to Chat</button>
            </header>
            <div id="plans-container" class="grid grid-cols-1 md:grid-cols-2 gap-8 max-w-4xl mx-auto text-gray-800"></div>
        </div>
    </template>

    <template id="template-admin-dashboard">
        <div class="w-full h-full bg-white/20 backdrop-blur-lg p-4 sm:p-6 md:p-8 overflow-y-auto text-gray-800">
            <header class="flex flex-wrap justify-between items-center gap-4 mb-8">
                <div class="flex items-center gap-4">
                    <div id="admin-logo-container"></div>
                    <h1 class="text-3xl font-bold brand-gradient">Admin Dashboard</h1>
                </div>
                <div>
                    <button id="admin-impersonate-btn" class="bg-yellow-600 hover:bg-yellow-500 text-white font-bold py-2 px-4 rounded-lg transition-colors mr-2">Impersonate User</button>
                    <button id="admin-logout-btn" class="bg-red-600 hover:bg-red-500 text-white font-bold py-2 px-4 rounded-lg transition-colors">Logout</button>
                </div>
            </header>

            <div class="mb-8 p-6 glassmorphism rounded-lg text-white">
                <h2 class="text-xl font-semibold mb-4">Site Announcement</h2>
                <form id="announcement-form" class="flex flex-col sm:flex-row gap-2">
                    <input id="announcement-input" type="text" placeholder="Enter announcement text (leave empty to clear)" class="flex-grow p-2 bg-white/20 rounded-lg border border-white/30 text-white placeholder:text-gray-200">
                    <button type="submit" class="bg-indigo-600 hover:bg-indigo-500 text-white font-bold px-4 py-2 rounded-lg">Set Banner</button>
                </form>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8 text-gray-800">
                <div class="p-6 glassmorphism rounded-lg"><h2 class="text-white/70 text-lg">Total Users</h2><p id="admin-total-users" class="text-4xl font-bold text-white">0</p></div>
                <div class="p-6 glassmorphism rounded-lg"><h2 class="text-white/70 text-lg">Student Users</h2><p id="admin-student-users" class="text-4xl font-bold text-white">0</p></div>
                <div class="p-6 glassmorphism rounded-lg"><h2 class="text-white/70 text-lg">Student Pro Users</h2><p id="admin-student-pro-users" class="text-4xl font-bold text-white">0</p></div>
            </div>

            <div class="p-6 glassmorphism rounded-lg text-white">
                <h2 class="text-xl font-semibold mb-4">User Management</h2>
                <div class="overflow-x-auto">
                    <table class="w-full text-left">
                        <thead class="border-b border-white/30">
                            <tr>
                                <th class="p-2">Username</th>
                                <th class="p-2">Email</th>
                                <th class="p-2">Role</th>
                                <th class="p-2">Plan</th>
                                <th class="p-2">Actions</th>
                            </tr>
                        </thead>
                        <tbody id="admin-user-list"></tbody>
                    </table>
                </div>
            </div>
        </div>
    </template>
    
    <template id="template-teacher-dashboard">
        <div class="w-full h-full p-4 sm:p-6 md:p-8 overflow-y-auto text-gray-800">
            <header class="flex justify-between items-center mb-8">
                <div class="flex items-center gap-4">
                    <div id="teacher-logo-container"></div>
                    <h1 class="text-3xl font-bold brand-gradient">Teacher Dashboard</h1>
                </div>
                <button id="teacher-logout-btn" class="bg-red-600/70 hover:bg-red-600 text-white font-bold py-2 px-4 rounded-lg transition-colors">Logout</button>
            </header>
            
            <div class="max-w-6xl mx-auto space-y-8">
                <div id="teacher-info" class="p-6 glassmorphism rounded-lg text-white"></div>
                
                <div id="classroom-management" class="p-6 glassmorphism rounded-lg text-white">
                    <h2 class="text-2xl font-bold mb-4">Your Classroom</h2>
                    <div id="classroom-details"></div>
                    <button id="create-classroom-btn" class="mt-4 bg-yellow-600 hover:bg-yellow-500 text-white font-bold py-2 px-4 rounded-lg">Create New Classroom</button>
                </div>
                
                <div id="student-chat-viewer" class="p-6 glassmorphism rounded-lg hidden">
                    <div class="flex justify-between items-center mb-4 text-white">
                        <h2 class="text-2xl font-bold">Student Chats: <span id="viewing-student-name"></span></h2>
                        <button id="close-chat-viewer-btn" class="text-white/70 hover:text-white text-3xl leading-none">&times;</button>
                    </div>
                    <div id="student-chat-history" class="overflow-y-auto max-h-[80vh] bg-black/10 p-4 rounded-lg space-y-4 prose prose-invert max-w-none"></div>
                </div>
            </div>
        </div>
    </template>

    <script>
    /****************************************************************************
     * JAVASCRIPT FRONTEND LOGIC - FULLY REBUILT
     ****************************************************************************/
    document.addEventListener('DOMContentLoaded', () => {
        const appState = {
            chats: {}, activeChatId: null, isAITyping: false,
            abortController: null, currentUser: null,
            uploadedFile: null,
            teacherData: null,
            config: { google_oauth_enabled: false, email_enabled: false },
            activeAIMode: 'study_buddy'
        };

        const DOMElements = {
            appContainer: document.getElementById('app-container'),
            modalContainer: document.getElementById('modal-container'),
            toastContainer: document.getElementById('toast-container'),
            announcementBanner: document.getElementById('announcement-banner'),
        };

        // --- Core Functions ---
        async function apiCall(endpoint, options = {}) {
            try {
                const headers = { ...(options.headers || {}) };
                if (!headers['Content-Type'] && options.body && typeof options.body === 'string') {
                    headers['Content-Type'] = 'application/json';
                }
                const response = await fetch(endpoint, { ...options, headers, credentials: 'include' });
                const data = response.headers.get("Content-Type")?.includes("application/json") ? await response.json() : null;
                if (!response.ok) {
                    if (response.status === 401 && data?.error === "Login required.") {
                        handleLogout(false);
                    }
                    throw new Error(data?.error || `Server error: ${response.statusText}`);
                }
                return { success: true, ...(data || {}) };
            } catch (error) {
                console.error("API Call Error:", endpoint, error);
                showToast(error.message, 'error');
                return { success: false, error: error.message };
            }
        }

        function showToast(message, type = 'info') {
            const colors = { info: 'bg-blue-600', success: 'bg-green-600', error: 'bg-red-600' };
            const toast = document.createElement('div');
            toast.className = `toast text-white text-sm py-2 px-4 rounded-lg shadow-lg animate-fade-in ${colors[type]}`;
            toast.textContent = message;
            DOMElements.toastContainer.appendChild(toast);
            setTimeout(() => {
                toast.style.opacity = '0';
                toast.addEventListener('transitionend', () => toast.remove());
            }, 4000);
        }

        function renderLogo(containerId) {
            const logoTemplate = document.getElementById('template-logo');
            const container = document.getElementById(containerId);
            if (container && logoTemplate) {
                container.innerHTML = '';
                container.appendChild(logoTemplate.content.cloneNode(true));
            }
        }
        
        function escapeHTML(str) {
            if (typeof str !== 'string') return '';
            const p = document.createElement('p');
            p.appendChild(document.createTextNode(str));
            return p.innerHTML;
        }

        // --- Page Rendering & Initialization ---

        const routeHandler = async () => {
            const path = window.location.pathname;
            const urlParams = new URLSearchParams(window.location.search);

            if (path.startsWith('/reset-password/')) {
                const token = path.split('/')[2];
                renderPage('template-reset-password-page', () => setupResetPasswordPage(token));
            } else {
                if (urlParams.get('payment') === 'success') {
                    showToast('Upgrade successful!', 'success');
                    window.history.replaceState({}, document.title, "/");
                } else if (urlParams.get('payment') === 'cancel') {
                    showToast('Payment was cancelled.', 'info');
                    window.history.replaceState({}, document.title, "/");
                }
                await checkLoginStatus();
            }
        };

        async function checkLoginStatus() {
            const result = await apiCall('/api/status');
            if (result.success && result.logged_in) {
                initializeApp(result.user, result.chats, result.settings, result.config);
            } else {
                appState.config = result.config || {};
                renderPage('template-auth-page', setupAuthPage);
            }
        }

        function initializeApp(user, chats, settings, config) {
            appState.currentUser = user;
            appState.chats = chats || {};
            appState.config = config || {};
            if (settings && settings.announcement) {
                DOMElements.announcementBanner.textContent = settings.announcement;
                DOMElements.announcementBanner.classList.remove('hidden');
            } else {
                DOMElements.announcementBanner.classList.add('hidden');
            }
            // Route to the correct dashboard/UI
            if (user.role === 'admin') {
                renderPage('template-admin-dashboard', setupAdminDashboard);
            } else if (user.account_type === 'teacher') {
                renderPage('template-teacher-dashboard', setupTeacherDashboard);
            } else {
                renderPage('template-app-wrapper', setupAppUI);
            }
        }
        
        // --- Template Rendering and Event Setup ---

        function renderPage(templateId, setupFunction) {
            const template = document.getElementById(templateId);
            if (!template) {
                console.error(`Template with id ${templateId} not found.`);
                DOMElements.appContainer.innerHTML = `<div class="text-white text-center p-8">Error: UI template "${templateId}" is missing. Please check the HTML.</div>`;
                return;
            }
            DOMElements.appContainer.innerHTML = '';
            const content = template.content.cloneNode(true);
            DOMElements.appContainer.appendChild(content);

            if (setupFunction) {
                setupFunction();
            }
        }

        function setupAuthPage() {
            renderLogo('auth-logo-container');
            document.getElementById('auth-form')?.addEventListener('submit', handleLoginSubmit);
            document.getElementById('auth-toggle-btn')?.addEventListener('click', () => renderPage('template-student-signup-page', setupStudentSignupPage));
            document.getElementById('forgot-password-link')?.addEventListener('click', handleForgotPassword);
            document.getElementById('teacher-signup-link')?.addEventListener('click', () => renderPage('template-auth-page', setupTeacherLoginPage));
            document.getElementById('special-auth-link')?.addEventListener('click', () => renderPage('template-special-auth-page', setupSpecialAuthPage));
        }
        
        function setupStudentSignupPage() {
            renderLogo('student-signup-logo-container');
            document.getElementById('student-signup-form')?.addEventListener('submit', handleStudentSignupSubmit);
            document.getElementById('back-to-main-login')?.addEventListener('click', () => renderPage('template-auth-page', setupAuthPage));
        }
        
        function setupTeacherLoginPage() {
            renderPage('template-auth-page', () => {
                renderLogo('auth-logo-container');
                document.getElementById('auth-title').textContent = "Teacher Portal";
                document.getElementById('auth-subtitle').textContent = "Sign in to your teacher account.";
                document.getElementById('auth-form')?.addEventListener('submit', handleLoginSubmit);
                const toggleBtn = document.getElementById('auth-toggle-btn');
                toggleBtn.textContent = "Don't have a teacher account? Sign Up";
                toggleBtn.onclick = () => renderPage('template-teacher-signup-page', setupTeacherSignupPage);
            });
        }
        
        function setupTeacherSignupPage() {
            renderLogo('teacher-signup-logo-container');
            document.getElementById('teacher-signup-form')?.addEventListener('submit', handleTeacherSignupSubmit);
            document.getElementById('back-to-teacher-login')?.addEventListener('click', () => renderPage('template-auth-page', setupTeacherLoginPage));
        }
        
        function setupSpecialAuthPage() {
            renderLogo('special-auth-logo-container');
            document.getElementById('special-auth-form')?.addEventListener('submit', handleSpecialAuthSubmit);
            document.getElementById('back-to-main-login')?.addEventListener('click', () => renderPage('template-auth-page', setupAuthPage));
        }
        
        function setupResetPasswordPage(token) {
            renderLogo('reset-logo-container');
            document.getElementById('reset-password-form')?.addEventListener('submit', (e) => handleResetPasswordSubmit(e, token));
        }
        
        function setupAdminDashboard() {
            renderLogo('admin-logo-container');
            fetchAdminData();
            document.getElementById('admin-logout-btn')?.addEventListener('click', handleLogout);
            document.getElementById('admin-impersonate-btn')?.addEventListener('click', handleImpersonate);
            document.getElementById('announcement-form')?.addEventListener('submit', handleSetAnnouncement);
            document.getElementById('admin-user-list')?.addEventListener('click', (e) => {
                const target = e.target.closest('.delete-user-btn');
                if (target) {
                    handleAdminDeleteUser(target.dataset.userid);
                }
            });
        }
        
        async function setupTeacherDashboard() {
            renderLogo('teacher-logo-container');
            document.getElementById('teacher-logout-btn')?.addEventListener('click', handleLogout);
            const data = await apiCall('/api/teacher/dashboard_data');
            if (data.success) {
                appState.teacherData = data.classroom;
                updateTeacherDashboardUI(data.classroom, data.students);
            }
        }
        
        function setupAppUI() {
            renderLogo('app-logo-container');
            const sortedChatIds = Object.keys(appState.chats).sort((a, b) => (appState.chats[b].created_at || '').localeCompare(appState.chats[a].created_at || ''));
            appState.activeChatId = sortedChatIds.length > 0 ? sortedChatIds[0] : null;
            
            renderChatHistoryList();
            renderActiveChat();
            updateUserInfo();
            setupAppEventListeners();
            renderJoinClassroom();
            renderAIModeSelector();
            fetchStudentLeaderboard();
        }

        // --- Event Handlers ---
        async function handleLoginSubmit(e) {
            e.preventDefault();
            const form = e.target;
            const errorEl = document.getElementById('auth-error');
            errorEl.textContent = '';
            const formData = new FormData(form);
            const data = Object.fromEntries(formData.entries());
            const result = await apiCall('/api/login', { method: 'POST', body: JSON.stringify(data) });
            if (result.success) {
                initializeApp(result.user, result.chats, result.settings, result.config);
            } else {
                errorEl.textContent = result.error;
            }
        }
        
        async function handleStudentSignupSubmit(e) {
            e.preventDefault();
            const form = e.target;
            const errorEl = document.getElementById('student-signup-error');
            errorEl.textContent = '';
            const formData = new FormData(form);
            const data = Object.fromEntries(formData.entries());
            const result = await apiCall('/api/student_signup', { method: 'POST', body: JSON.stringify(data) });
            if (result.success) {
                initializeApp(result.user, result.chats, result.settings, result.config);
            } else {
                errorEl.textContent = result.error;
            }
        }

        async function handleTeacherSignupSubmit(e) {
            e.preventDefault();
            const form = e.target;
            const errorEl = document.getElementById('teacher-signup-error');
            errorEl.textContent = '';
            const formData = new FormData(form);
            const data = Object.fromEntries(formData.entries());
            const result = await apiCall('/api/teacher_signup', { method: 'POST', body: JSON.stringify(data) });
            if (result.success) {
                initializeApp(result.user, result.chats, result.settings, result.config);
            } else {
                errorEl.textContent = result.error;
            }
        }
        
        async function handleSpecialAuthSubmit(e) {
            e.preventDefault();
            const form = e.target;
            const errorEl = document.getElementById('special-auth-error');
            errorEl.textContent = '';
            const formData = new FormData(form);
            const data = Object.fromEntries(formData.entries());
            const result = await apiCall('/api/special_signup', { method: 'POST', body: JSON.stringify(data) });
            if (result.success) {
                initializeApp(result.user, {}, result.settings, result.config);
            } else {
                errorEl.textContent = result.error;
            }
        }
        
        async function handleForgotPassword() {
            const email = prompt("Please enter your email to reset your password:");
            if (email) {
                const result = await apiCall('/api/request-password-reset', { method: 'POST', body: JSON.stringify({ email }) });
                if (result.success) {
                    showToast(result.message, 'info');
                }
            }
        }
        
        async function handleResetPasswordSubmit(e, token) {
            e.preventDefault();
            const form = e.target;
            const errorEl = document.getElementById('reset-error');
            errorEl.textContent = '';
            const newPassword = form['new-password'].value;
            const confirmPassword = form['confirm-password'].value;
            if (newPassword !== confirmPassword) {
                errorEl.textContent = "Passwords do not match.";
                return;
            }
            const result = await apiCall('/api/reset-with-token', { method: 'POST', body: JSON.stringify({ token, password: newPassword }) });
            if (result.success) {
                showToast(result.message, 'success');
                setTimeout(() => window.location.href = '/', 2000);
            } else {
                errorEl.textContent = result.error;
            }
        }
        
        // --- App UI Functions ---
        function renderChatHistoryList() {
            const listEl = document.getElementById('chat-history-list');
            if (!listEl) return;
            listEl.innerHTML = '';
            Object.values(appState.chats)
                .sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''))
                .forEach(chat => {
                    const itemWrapper = document.createElement('div');
                    itemWrapper.className = `w-full flex items-center justify-between p-3 rounded-lg hover:bg-black/10 transition-colors duration-200 group ${chat.id === appState.activeChatId ? 'bg-black/20' : ''}`;
                    const chatButton = document.createElement('button');
                    chatButton.className = 'flex-grow text-left truncate text-sm font-semibold text-white';
                    chatButton.textContent = chat.title;
                    chatButton.onclick = () => {
                        appState.activeChatId = chat.id;
                        renderActiveChat();
                        renderChatHistoryList();
                        const menuToggleBtn = document.getElementById('menu-toggle-btn');
                        if (menuToggleBtn && menuToggleBtn.offsetParent !== null) {
                            document.getElementById('sidebar')?.classList.add('-translate-x-full');
                            document.getElementById('sidebar-backdrop')?.classList.add('hidden');
                        }
                    };
                    itemWrapper.appendChild(chatButton);
                    listEl.appendChild(itemWrapper);
                });
        }

        function renderActiveChat() {
            const messageList = document.getElementById('message-list');
            const chatTitle = document.getElementById('chat-title');
            if (!messageList || !chatTitle) return;
            messageList.innerHTML = '';
            appState.uploadedFile = null;
            updatePreviewContainer();
            const chat = appState.chats[appState.activeChatId];
            if (chat && chat.messages && chat.messages.length > 0) {
                chatTitle.textContent = chat.title;
                chat.messages.forEach(msg => addMessageToDOM(msg));
                renderCodeCopyButtons();
            } else {
                chatTitle.textContent = 'New Chat';
                renderWelcomeScreen();
            }
            updateUIState();
        }

        function renderWelcomeScreen() {
            const messageList = document.getElementById('message-list');
            if (!messageList) return;
            const template = document.getElementById('template-welcome-screen');
            messageList.innerHTML = '';
            messageList.appendChild(template.content.cloneNode(true));
            renderLogo('welcome-logo-container');
            document.getElementById('welcome-title').textContent = `Welcome to Myth AI`;
            document.getElementById('welcome-subtitle').textContent = `Start a new conversation or select one from the sidebar. How can I help you today?`;
        }

        function updateUserInfo() {
            const userInfoDiv = document.getElementById('user-info');
            if (!userInfoDiv || !appState.currentUser) return;
            const { username, plan, account_type, daily_messages, message_limit, streak } = appState.currentUser;
            const planDetails = PLAN_CONFIG[plan] || PLAN_CONFIG['student'];
            const planName = planDetails.name;
            const avatarChar = username[0].toUpperCase();
            const avatarColor = `hsl(${username.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0) % 360}, 70%, 50%)`;
            
            userInfoDiv.innerHTML = `
                <div class="flex items-center gap-3 text-white">
                    <div class="flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center font-bold text-white" style="background-color: ${avatarColor};">
                        ${avatarChar}
                    </div>
                    <div>
                        <div class="font-semibold">${username}</div>
                        <div class="text-xs text-white/70">${planName} (${account_type.charAt(0).toUpperCase() + account_type.slice(1)})</div>
                    </div>
                </div>`;
            const limitDisplay = document.getElementById('message-limit-display');
            if(limitDisplay) limitDisplay.textContent = `Daily Messages: ${daily_messages} / ${message_limit} | Streak: ${streak} days`;
        }
        
        async function handleJoinClassroom() {
            const code = prompt("Enter your classroom code:");
            if (code) {
                const result = await apiCall('/api/student/join_classroom', { method: 'POST', body: JSON.stringify({ classroom_code: code }) });
                if (result.success) {
                    appState.currentUser.classroom_code = result.user.classroom_code;
                    showToast("Joined classroom successfully!", "success");
                    renderJoinClassroom();
                    fetchStudentLeaderboard();
                    updateUserInfo();
                } else {
                    showToast(result.error, "error");
                }
            }
        }
        
        function updatePreviewContainer() {
            const previewContainer = document.getElementById('preview-container');
            if (!previewContainer) return;
            if (appState.uploadedFile) {
                previewContainer.classList.remove('hidden');
                const objectURL = URL.createObjectURL(appState.uploadedFile);
                previewContainer.innerHTML = `<div class="relative inline-block"><img src="${objectURL}" alt="Image preview" class="h-16 w-16 object-cover rounded-md"><button id="remove-preview-btn" class="absolute -top-2 -right-2 bg-red-600 text-white rounded-full w-5 h-5 flex items-center justify-center text-xs">&times;</button></div>`;
                document.getElementById('remove-preview-btn').onclick = () => {
                    appState.uploadedFile = null;
                    document.getElementById('file-input').value = '';
                    updatePreviewContainer();
                };
            } else {
                previewContainer.classList.add('hidden');
                previewContainer.innerHTML = '';
            }
        }
        
        function renderAIModeSelector() {
            const container = document.getElementById('ai-mode-selector-container');
            if (!container || appState.currentUser.account_type !== 'student') {
                if (container) container.innerHTML = '';
                return;
            }
            
            const planDetails = PLAN_CONFIG[appState.currentUser.plan];
            const allModes = {
                'study_buddy': 'Study Buddy',
                'quiz_master': 'Quiz Master',
                'practice_partner': 'Practice Partner',
                'test_proctor': 'Test Proctor'
            };
            const availableModes = planDetails.can_upload ? allModes : {'study_buddy': 'Study Buddy'};
            
            container.innerHTML = `
                <select id="ai-mode-selector" class="bg-black/20 border border-white/30 text-white text-sm rounded-lg focus:ring-yellow-400 focus:border-yellow-400 block p-2">
                    ${Object.entries(availableModes).map(([key, value]) => 
                        `<option value="${key}" ${key === appState.activeAIMode ? 'selected' : ''}>${value}</option>`
                    ).join('')}
                </select>
            `;
            const selector = document.getElementById('ai-mode-selector');
            selector.addEventListener('change', (e) => {
                appState.activeAIMode = e.target.value;
                document.getElementById('user-input').placeholder = `Message ${e.target.selectedOptions[0].text}...`;
            });
        }
        
        function renderJoinClassroom() {
            const container = document.getElementById('join-classroom-container');
            if (!container || appState.currentUser.account_type !== 'student' || appState.currentUser.classroom_code) {
                if(container) container.innerHTML = '';
                return;
            }
            container.innerHTML = `<button id="join-classroom-btn" class="w-full text-left flex items-center gap-3 p-3 rounded-lg bg-green-500/20 text-green-400 hover:bg-green-500/30 transition-colors duration-200"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline></svg> Join Classroom</button>`;
            document.getElementById('join-classroom-btn')?.addEventListener('click', handleJoinClassroom);
        }

        async function handleCreateClassroom() {
            const result = await apiCall('/api/teacher/generate_classroom_code', { method: 'POST' });
            if (result.success) {
                showToast(`Classroom created with code: ${result.code}`, "success");
                setupTeacherDashboard();
            } else {
                showToast(result.error, "error");
            }
        }
        
        async function updateTeacherDashboardUI(classroom, students) {
            const classroomDetailsEl = document.getElementById('classroom-details');
            if (!classroomDetailsEl) return;

            if (classroom.code) {
                classroomDetailsEl.innerHTML = `
                    <div class="space-y-4">
                        <p class="text-xl">Your Classroom Code: <span class="font-mono text-yellow-300">${classroom.code}</span></p>
                        <h3 class="text-lg font-bold">Students (${students.length}):</h3>
                        <ul id="teacher-student-list" class="space-y-2"></ul>
                    </div>
                `;
                const studentListEl = document.getElementById('teacher-student-list');
                students.forEach(student => {
                    const studentItem = document.createElement('li');
                    studentItem.className = 'flex items-center justify-between p-2 bg-black/10 rounded-lg';
                    studentItem.innerHTML = `
                        <div class="flex items-center gap-2">
                            <span>${student.username} (Streak: ${student.streak})</span>
                            <button class="bg-gray-700/50 hover:bg-gray-700 text-white text-xs px-2 py-1 rounded-full view-chats-btn" data-studentid="${student.id}">View Chats</button>
                        </div>
                        <div class="flex items-center gap-2">
                            <button class="bg-yellow-600/50 hover:bg-yellow-600 text-white text-xs px-2 py-1 rounded-full extend-limit-btn" data-studentid="${student.id}">Extend Limit</button>
                            <button class="bg-red-600/50 hover:bg-red-600 text-white text-xs px-2 py-1 rounded-full kick-student-btn" data-studentid="${student.id}">Kick</button>
                        </div>
                    `;
                    studentListEl.appendChild(studentItem);
                });

                document.getElementById('create-classroom-btn').style.display = 'none';
                classroomDetailsEl.addEventListener('click', async (e) => {
                    const target = e.target.closest('button');
                    if (!target) return;
                    if (target.classList.contains('view-chats-btn')) {
                        handleViewStudentChats(target.dataset.studentid);
                    } else if (target.classList.contains('kick-student-btn')) {
                        handleKickStudent(target.dataset.studentid);
                    } else if (target.classList.contains('extend-limit-btn')) {
                        handleExtendLimit(target.dataset.studentid);
                    }
                });

            } else {
                classroomDetailsEl.innerHTML = `<p class="text-white/70">You don't have a classroom yet. Click the button below to create one.</p>`;
                document.getElementById('create-classroom-btn').style.display = 'block';
                document.getElementById('create-classroom-btn').addEventListener('click', handleCreateClassroom);
            }
        }

        async function handleViewStudentChats(studentId) {
            const result = await apiCall(`/api/teacher/student_chats/${studentId}`);
            if (result.success) {
                const studentName = (await apiCall('/api/admin_data')).users.find(u => u.id === studentId)?.username || 'Student';
                const chatViewerEl = document.getElementById('student-chat-viewer');
                const chatHistoryEl = document.getElementById('student-chat-history');
                chatViewerEl.classList.remove('hidden');
                document.getElementById('viewing-student-name').textContent = studentName;
                chatHistoryEl.innerHTML = '';
                result.chats.forEach(chat => {
                    const chatEl = document.createElement('div');
                    chatEl.className = 'p-4 bg-black/20 rounded-lg';
                    chatEl.innerHTML = `<h5 class="font-semibold text-sm mb-2 text-yellow-300">${chat.title}</h5>`;
                    chat.messages.forEach(msg => {
                        const msgEl = document.createElement('div');
                        msgEl.className = `text-sm text-white prose-invert`;
                        const sender = msg.sender === 'user' ? 'Student' : 'Myth AI';
                        msgEl.innerHTML = `<strong>${sender}:</strong> ${escapeHTML(msg.content)}`;
                        chatEl.appendChild(msgEl);
                    });
                    chatHistoryEl.appendChild(chatEl);
                });
                document.getElementById('close-chat-viewer-btn').addEventListener('click', () => chatViewerEl.classList.add('hidden'));
            }
        }
        
        async function handleKickStudent(studentId) {
            if (confirm("Are you sure you want to kick this student? This will remove them from the classroom.")) {
                const result = await apiCall('/api/teacher/kick_student', { method: 'POST', body: JSON.stringify({ student_id: studentId }) });
                if (result.success) {
                    showToast(result.message, "success");
                    setupTeacherDashboard();
                } else {
                    showToast(result.error, "error");
                }
            }
        }

        async function handleExtendLimit(studentId) {
            const newLimit = prompt("Enter the new message limit for this student for today:");
            if (newLimit && !isNaN(parseInt(newLimit))) {
                const result = await apiCall('/api/teacher/extend_limit', { method: 'POST', body: JSON.stringify({ student_id: studentId, new_limit: parseInt(newLimit) }) });
                if (result.success) {
                    showToast(result.message, "success");
                    setupTeacherDashboard();
                } else {
                    showToast(result.error, "error");
                }
            }
        }

        async function fetchStudentLeaderboard() {
            const leaderboardContainer = document.getElementById('student-leaderboard-container');
            if (!leaderboardContainer || appState.currentUser.account_type !== 'student' || !appState.currentUser.classroom_code) {
                if (leaderboardContainer) leaderboardContainer.innerHTML = '';
                return;
            }
            const result = await apiCall('/api/student/leaderboard');
            if (result.success && result.leaderboard.length > 0) {
                leaderboardContainer.classList.remove('hidden');
                let html = `<div class="mx-auto max-w-3xl mb-4 p-4 glassmorphism rounded-lg text-white"><h3 class="text-lg font-bold mb-2 text-yellow-300">Class Leaderboard</h3>`;
                html += `<ul class="space-y-1">${result.leaderboard.map((s, i) => `<li class="flex justify-between items-center text-sm"><span class="truncate"><strong>${i + 1}.</strong> ${s.username}</span><span class="font-mono text-yellow-300">${s.streak} days</span></li>`).join('')}</ul></div>`;
                leaderboardContainer.innerHTML = html;
            } else {
                leaderboardContainer.innerHTML = '';
                leaderboardContainer.classList.add('hidden');
            }
        }
        
        async function fetchAdminData() {
            const data = await apiCall('/api/admin_data');
            if (!data.success) return;
            document.getElementById('admin-total-users').textContent = data.stats.total_users;
            document.getElementById('admin-student-users').textContent = data.stats.student_users;
            document.getElementById('admin-student-pro-users').textContent = data.stats.student_pro_users;
            document.getElementById('announcement-input').value = data.announcement;
            const userList = document.getElementById('admin-user-list');
            userList.innerHTML = '';
            data.users.forEach(user => {
                const tr = document.createElement('tr');
                tr.className = 'border-b border-white/30 text-white/80';
                tr.innerHTML = `<td class="p-2">${user.username}</td><td class="p-2">${user.email}</td><td class="p-2">${user.role}</td><td class="p-2">${user.plan}</td><td class="p-2"><button data-userid="${user.id}" class="delete-user-btn text-xs px-2 py-1 rounded bg-red-600/70 hover:bg-red-600">Delete</button></td>`;
                userList.appendChild(tr);
            });
        }
        
        async function handleSetAnnouncement(e) {
            e.preventDefault();
            const text = document.getElementById('announcement-input').value;
            const result = await apiCall('/api/admin/announcement', { method: 'POST', body: JSON.stringify({ text }) });
            if (result.success) {
                showToast(result.message, 'success');
                DOMElements.announcementBanner.textContent = text;
                DOMElements.announcementBanner.classList.toggle('hidden', !text);
            }
        }
        
        async function handleAdminDeleteUser(userId) {
            if (confirm(`Are you sure you want to delete user ${userId}? This is irreversible.`)) {
                const result = await apiCall('/api/admin/delete_user', { method: 'POST', body: JSON.stringify({ user_id: userId }) });
                if (result.success) {
                    showToast(result.message, 'success');
                    fetchAdminData();
                }
            }
        }

        async function handleImpersonate() {
            const username = prompt("Enter the username of the user to impersonate:");
            if (username) {
                const result = await apiCall('/api/admin/impersonate', { method: 'POST', body: JSON.stringify({ username }) });
                if (result.success) {
                    showToast(`Now impersonating ${username}. You will be logged in as them.`, 'success');
                    setTimeout(() => window.location.reload(), 1500);
                }
            }
        }

        async function handleLogout(doApiCall = true) {
            if (doApiCall) await apiCall('/api/logout');
            window.location.href = '/';
        }

        async function handleRenameChat() {
            if (!appState.activeChatId) return;
            const oldTitle = appState.chats[appState.activeChatId]?.title;
            const newTitle = prompt("Enter a new name for this chat:", oldTitle);
            if (newTitle && newTitle.trim() !== oldTitle) {
                const result = await apiCall('/api/chat/rename', { method: 'POST', body: JSON.stringify({ chat_id: appState.activeChatId, title: newTitle.trim() }) });
                if (result.success) {
                    appState.chats[appState.activeChatId].title = newTitle.trim();
                    renderChatHistoryList();
                    document.getElementById('chat-title').textContent = newTitle.trim();
                    showToast("Chat renamed!", "success");
                }
            }
        }

        async function handleDeleteChat() {
            if (!appState.activeChatId) return;
            if (confirm("Are you sure you want to delete this chat? This action cannot be undone.")) {
                const result = await apiCall('/api/chat/delete', { method: 'POST', body: JSON.stringify({ chat_id: appState.activeChatId }) });
                if (result.success) {
                    delete appState.chats[appState.activeChatId];
                    const sortedChatIds = Object.keys(appState.chats).sort((a, b) => (appState.chats[b].created_at || '').localeCompare(appState.chats[a].created_at || ''));
                    appState.activeChatId = sortedChatIds.length > 0 ? sortedChatIds[0] : null;
                    renderChatHistoryList();
                    renderActiveChat();
                    showToast("Chat deleted.", "success");
                }
            }
        }
        
        async function handleShareChat() {
            if (!appState.activeChatId) return;
            const result = await apiCall('/api/chat/share', { method: 'POST', body: JSON.stringify({ chat_id: appState.activeChatId }) });
            if (result.success) {
                const shareUrl = `${window.location.origin}/share/${result.share_id}`;
                const input = document.createElement('input');
                input.type = 'text';
                input.className = 'w-full p-2 bg-gray-700/50 rounded-lg border border-gray-600';
                input.value = shareUrl;
                input.readOnly = true;
                openModal('Shareable Link', input, () => {
                    navigator.clipboard.writeText(shareUrl);
                    showToast('Link copied to clipboard!', 'success');
                }, 'Copy Link');
            }
        }
        
        function handleDownloadChat() {
            if (!appState.activeChatId || !appState.chats[appState.activeChatId]) return;
            const chat = appState.chats[appState.activeChatId];
            const content = chat.messages.map(msg => `${msg.sender === 'user' ? 'You' : 'Myth AI'}: ${msg.content}`).join('\n\n');
            const blob = new Blob([content], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${chat.title.replace(/[^a-z0-9]/gi, '_').toLowerCase()}.txt`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            showToast("Chat downloaded!", "success");
        }
        
        function handleUpgradePlanClick() {
            renderPage('template-upgrade-page', setupUpgradePage);
        }
        
        async function handlePurchase(planId) {
            try {
                const sessionResult = await apiCall('/api/create-checkout-session', { method: 'POST', body: JSON.stringify({ plan_id: planId }) });
                if (!sessionResult.success) throw new Error(sessionResult.error || "Could not create payment session.");
                const stripe = Stripe(SITE_CONFIG["STRIPE_PUBLIC_KEY"]);
                const { error } = await stripe.redirectToCheckout({ sessionId: sessionResult.id });
                if (error) showToast(error.message, 'error');
            } catch (error) {
                showToast(error.message, 'error');
            }
        }

        async function setupUpgradePage() {
            const plansContainer = document.getElementById('plans-container');
            if (!plansContainer) return;
            const plansResult = await apiCall('/api/plans');
            if (!plansResult.success) { plansContainer.innerHTML = `<p class="text-red-400">Could not load plans.</p>`; return; }
            const { plans, user_plan } = plansResult;
            plansContainer.innerHTML = '';
            const planOrder = ['student', 'student_pro'];
            planOrder.forEach(planId => {
                const plan = plans[planId];
                if (!plan) return;
                const isCurrentPlan = planId === user_plan;
                const card = document.createElement('div');
                card.className = `p-8 glassmorphism rounded-lg border-2 ${isCurrentPlan ? 'border-orange-500' : 'border-white/30'}`;
                card.innerHTML = `<h2 class="text-2xl font-bold text-center ${plan.color}">${plan.name}</h2><p class="text-4xl font-bold text-center my-4 text-white">${plan.price_string}</p><ul class="space-y-2 text-white/80 mb-6">${plan.features.map(f => `<li>✓ ${f}</li>`).join('')}</ul><button ${isCurrentPlan ? 'disabled' : ''} data-planid="${planId}" class="purchase-btn w-full mt-6 font-bold py-3 px-4 rounded-lg transition-opacity ${isCurrentPlan ? 'bg-gray-600/70 cursor-not-allowed' : 'bg-gradient-to-r from-orange-500 to-yellow-500 hover:opacity-90'}">${isCurrentPlan ? 'Current Plan' : 'Upgrade'}</button>`;
                plansContainer.appendChild(card);
            });
            document.getElementById('back-to-chat-btn')?.addEventListener('click', () => renderPage('template-app-wrapper', setupAppUI));
            plansContainer.addEventListener('click', (e) => {
                const target = e.target.closest('.purchase-btn');
                if (target && !target.disabled) handlePurchase(target.dataset.planid);
            });
        }
        
        // --- FINAL SETUP ---
        document.getElementById('upgrade-plan-btn')?.addEventListener('click', handleUpgradePlanClick);
        document.getElementById('delete-chat-btn')?.addEventListener('click', handleDeleteChat);
        document.getElementById('rename-chat-btn')?.addEventListener('click', handleRenameChat);
        document.getElementById('share-chat-btn')?.addEventListener('click', handleShareChat);
        document.getElementById('download-chat-btn')?.addEventListener('click', handleDownloadChat);
        document.getElementById('upload-btn')?.addEventListener('click', () => document.getElementById('file-input')?.click());
        document.getElementById('file-input')?.addEventListener('change', (e) => {
            if (e.target.files.length > 0) { appState.uploadedFile = e.target.files[0]; updatePreviewContainer(); }
        });
        document.getElementById('stop-generating-btn')?.addEventListener('click', () => { if (appState.abortController) appState.abortController.abort(); });
        
        routeHandler();
    });
    </script>
</body>
</html>
"""

# --- 7. Backend Helper Functions ---

def send_password_reset_email(user):
    if not EMAIL_ENABLED:
        logging.error("Attempted to send email, but mail is not configured.")
        return False
    try:
        token = password_reset_serializer.dumps(user.email, salt='password-reset-salt')
        reset_url = url_for('index', _external=True) + f"reset-password/{token}"
        
        msg_body = f"Hello {user.username},\n\nPlease click the following link to reset your password:\n{reset_url}\n\nThis link will expire in one hour. If you did not request this, please ignore this email."
        msg = MIMEText(msg_body)
        msg['Subject'] = 'Password Reset Request for Myth AI'
        msg['From'] = SITE_CONFIG['MAIL_SENDER']
        msg['To'] = user.email

        with smtplib.SMTP(SITE_CONFIG['MAIL_SERVER'], SITE_CONFIG['MAIL_PORT']) as server:
            if SITE_CONFIG['MAIL_USE_TLS']:
                server.starttls()
            server.login(SITE_CONFIG['MAIL_USERNAME'], SITE_CONFIG['MAIL_PASSWORD'])
            server.send_message(msg)
        logging.info(f"Password reset email sent to {user.email}")
        return True
    except Exception as e:
        logging.error(f"Failed to send password reset email to {user.email}: {e}")
        return False

def check_and_update_streak(user):
    """
    Correctly updates a student's daily message count and streak.
    - Resets daily messages if it's a new day.
    - Increments streak if it's the next consecutive day.
    - Resets streak if a day was missed.
    """
    if user.account_type != 'student':
        return

    today = date.today()
    last_message_day = date.fromisoformat(user.last_message_date)
    last_streak_day = date.fromisoformat(user.last_streak_date)

    if last_message_day < today:
        user.daily_messages = 0
        user.last_message_date = today.isoformat()
        
        days_diff = (today - last_streak_day).days
        if days_diff == 1:
            user.streak += 1
            logging.info(f"Streak for {user.username} incremented to {user.streak}")
        elif days_diff > 1:
            user.streak = 1 # Start a new streak
            logging.info(f"Streak for {user.username} reset to 1 after missing days.")
        
        user.last_streak_date = today.isoformat()
        # No need to save here, will be saved in the calling function

def get_user_data_for_frontend(user):
    """Prepares user data for sending to the frontend."""
    if not user: return {}
    
    plan_details = PLAN_CONFIG.get(user.plan, PLAN_CONFIG['student'])
    message_limit = user.message_limit_override if user.message_limit_override is not None else plan_details["message_limit"]

    return {
        "id": user.id, "username": user.username, "email": user.email, "role": user.role, "plan": user.plan,
        "account_type": user.account_type, "daily_messages": user.daily_messages,
        "message_limit": message_limit, 
        "can_upload": plan_details["can_upload"],
        "classroom_code": user.classroom_code,
        "streak": user.streak,
    }

def get_all_user_chats(user_id):
    """Retrieves all chats belonging to a specific user."""
    return {chat_id: chat_data for chat_id, chat_data in DB['chats'].items() if chat_data.get('user_id') == user_id}

def generate_unique_classroom_code():
    while True:
        code = secrets.token_hex(4).upper()
        if code not in DB['classrooms']:
            return code


# --- 8. Core API Routes (Auth, Status, etc.) ---
@app.route('/')
@app.route('/reset-password/<token>')
def index(token=None):
    return Response(HTML_CONTENT, mimetype='text/html')

@app.route('/api/config')
@login_required
def get_config():
    return jsonify({"stripe_public_key": SITE_CONFIG["STRIPE_PUBLIC_KEY"]})

@app.route('/api/student_signup', methods=['POST'])
@rate_limited()
def student_signup():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    email = data.get('email', '').strip().lower()
    classroom_code = data.get('classroom_code', '').strip().upper()

    if not all([username, password, email]) or len(username) < 3 or len(password) < 6 or '@' not in email:
        return jsonify({"error": "Valid email, username, and password are required."}), 400
    if User.get_by_username(username): return jsonify({"error": "Username already exists."}), 409
    if User.get_by_email(email): return jsonify({"error": "Email already in use."}), 409
    
    final_code = None
    if classroom_code:
        if classroom_code not in DB['classrooms']: return jsonify({"error": "Invalid classroom code."}), 403
        final_code = classroom_code

    new_user = User(id=username, username=username, email=email, password_hash=generate_password_hash(password), account_type='student', plan='student', classroom_code=final_code)
    DB['users'][new_user.id] = new_user
    if final_code:
        DB['classrooms'][final_code]['students'].append(new_user.id)
    
    save_database()
    login_user(new_user, remember=True)
    return jsonify({
        "success": True, "user": get_user_data_for_frontend(new_user),
        "chats": {}, "settings": DB['site_settings'],
        "config": {"google_oauth_enabled": False, "email_enabled": EMAIL_ENABLED}
    })

@app.route('/api/teacher_signup', methods=['POST'])
@rate_limited()
def teacher_signup():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    email = data.get('email', '').strip().lower()
    secret_key = data.get('secret_key')

    if secret_key != SITE_CONFIG["SECRET_TEACHER_KEY"]: return jsonify({"error": "Invalid teacher access key."}), 403
    if not all([username, password, email]) or len(username) < 3 or len(password) < 6 or '@' not in email:
        return jsonify({"error": "All fields are required."}), 400
    if User.get_by_username(username): return jsonify({"error": "Username already exists."}), 409
    if User.get_by_email(email): return jsonify({"error": "Email already in use."}), 409

    new_user = User(id=username, username=username, email=email, password_hash=generate_password_hash(password), account_type='teacher', plan='student_pro', role='user')
    DB['users'][new_user.id] = new_user
    save_database()
    login_user(new_user, remember=True)
    return jsonify({
        "success": True, "user": get_user_data_for_frontend(new_user),
        "chats": {}, "settings": DB['site_settings'],
        "config": {"google_oauth_enabled": False, "email_enabled": EMAIL_ENABLED}
    })

@app.route('/api/login', methods=['POST'])
@rate_limited()
def login():
    data = request.get_json()
    username, password = data.get('username'), data.get('password')
    user = User.get_by_username(username)
    
    if user and user.password_hash and check_password_hash(user.password_hash, password):
        login_user(user, remember=True)
        return jsonify({
            "success": True, "user": get_user_data_for_frontend(user),
            "chats": get_all_user_chats(user.id),
            "settings": DB['site_settings'],
            "config": {"google_oauth_enabled": False, "email_enabled": EMAIL_ENABLED}
        })
    return jsonify({"error": "Invalid username or password."}), 401
    
@app.route('/api/request-password-reset', methods=['POST'])
@rate_limited()
def request_password_reset():
    if not EMAIL_ENABLED:
        return jsonify({"error": "Password reset is not configured on this server."}), 501
    email = request.json.get('email', '').lower()
    user = User.get_by_email(email)
    if user:
        send_password_reset_email(user)
    return jsonify({"success": True, "message": "If an account with that email exists, a reset link has been sent."})

@app.route('/api/reset-with-token', methods=['POST'])
@rate_limited()
def reset_with_token():
    if not EMAIL_ENABLED:
        return jsonify({"error": "Password reset is not configured on this server."}), 501
    token = request.json.get('token')
    password = request.json.get('password')
    try:
        email = password_reset_serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except Exception:
        return jsonify({"error": "The password reset link is invalid or has expired."}), 400

    user = User.get_by_email(email)
    if not user: return jsonify({"error": "User not found."}), 404
        
    user.password_hash = generate_password_hash(password)
    save_database()
    return jsonify({"success": True, "message": "Password has been updated."})

@app.route('/api/logout')
def logout():
    if 'impersonator_id' in session:
        impersonator = User.get(session['impersonator_id'])
        if impersonator:
            logout_user()
            login_user(impersonator)
            session.pop('impersonator_id', None)
            return redirect(url_for('index'))
    logout_user()
    return jsonify({"success": True})

@app.route('/api/status')
def status():
    config = {"google_oauth_enabled": False, "email_enabled": EMAIL_ENABLED}
    if current_user.is_authenticated:
        return jsonify({
            "logged_in": True, "user": get_user_data_for_frontend(current_user),
            "chats": get_all_user_chats(current_user.id),
            "settings": DB['site_settings'],
            "config": config
        })
    return jsonify({"logged_in": False, "config": config})

@app.route('/api/special_signup', methods=['POST'])
@rate_limited()
def special_signup():
    data = request.get_json()
    username, password, email, secret_key = data.get('username'), data.get('password'), data.get('email', '').strip().lower(), data.get('secret_key')
    if secret_key != SITE_CONFIG["SECRET_REGISTRATION_KEY"]: return jsonify({"error": "Invalid secret key."}), 403
    if not all([username, password, email]): return jsonify({"error": "Username, email and password are required."}), 400
    if User.get_by_username(username): return jsonify({"error": "Username already exists."}), 409
    
    new_user = User(id=username, username=username, email=email, password_hash=generate_password_hash(password), role='admin', plan='student_pro', account_type='admin')
    DB['users'][new_user.id] = new_user
    save_database()
    login_user(new_user, remember=True)
    return jsonify({
        "success": True, "user": get_user_data_for_frontend(new_user), 
        "settings": DB['site_settings'],
        "config": {"google_oauth_enabled": False, "email_enabled": EMAIL_ENABLED}
    })


# --- 9. Chat API Routes ---
@app.route('/api/chat', methods=['POST'])
@login_required
@rate_limited(max_attempts=20)
def chat_api():
    if not GEMINI_API_CONFIGURED: return jsonify({"error": "AI services are currently unavailable."}), 503
    
    if current_user.account_type == 'student' and not current_user.classroom_code:
        return jsonify({"error": "You must join a classroom to start chatting."}), 403

    data = request.form
    chat_id = data.get('chat_id')
    prompt = data.get('prompt', '').strip()
    ai_mode = data.get('ai_mode', 'study_buddy')
    
    if not chat_id: return jsonify({"error": "Missing chat identifier."}), 400
    chat = DB['chats'].get(chat_id)
    if not chat or chat.get('user_id') != current_user.id: return jsonify({"error": "Chat not found or access denied."}), 404

    check_and_update_streak(current_user)
    
    plan_details = PLAN_CONFIG.get(current_user.plan, PLAN_CONFIG['student'])
    message_limit = current_user.message_limit_override if current_user.message_limit_override is not None else plan_details["message_limit"]
    
    if current_user.daily_messages >= message_limit:
        return jsonify({"error": f"Daily message limit of {message_limit} reached."}), 429
    
    system_instructions = {
        "study_buddy": "You are Study Buddy, an enthusiastic and encouraging tutor AI. Your goal is to help students understand concepts without giving direct answers. Use the Socratic method, ask guiding questions, and break down complex problems into smaller steps. Always be patient and positive.",
        "quiz_master": "You are Quiz Master. Your role is to quiz the student on the topic they provide. Ask multiple-choice or short-answer questions. After they answer, tell them if they are correct and provide a brief explanation.",
        "practice_partner": "You are a Practice Partner. The student will give you a topic. Your role is to generate practice problems or scenarios related to that topic. Do not solve them, but provide hints if asked.",
        "test_proctor": "You are a Test Proctor. You are strict and formal. The student will ask for a test on a subject. You will provide a series of difficult questions one by one. Do not provide answers or hints until the student says 'I am finished'."
    }
    system_instruction = system_instructions.get(ai_mode, system_instructions['study_buddy'])

    history = [{"role": "user" if msg['sender'] == 'user' else 'model', "parts": [{"text": msg['content']}]} for msg in chat['messages'][-10:] if msg.get('content')]
    
    model_input_parts = []
    if prompt: model_input_parts.append({"text": prompt})

    uploaded_file = request.files.get('file')
    if uploaded_file:
        if not plan_details['can_upload']: return jsonify({"error": "Your plan does not support file uploads."}), 403
        try:
            img = Image.open(uploaded_file.stream)
            img.thumbnail((512, 512))
            buffered = BytesIO()
            if img.mode in ("RGBA", "P"): img = img.convert("RGB")
            img.save(buffered, format="JPEG")
            img_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')
            model_input_parts.append({"inline_data": {"mime_type": "image/jpeg", "data": img_base64}})
        except Exception as e:
            logging.error(f"Image processing error: {e}")
            return jsonify({"error": "Invalid image file."}), 400

    if not model_input_parts: return jsonify({"error": "A prompt or file is required."}), 400

    chat['messages'].append({'sender': 'user', 'content': prompt})
    current_user.daily_messages += 1
    save_database()

    model = genai.GenerativeModel(plan_details['model'], system_instruction=system_instruction)
    chat_session = model.start_chat(history=history)

    def generate_chunks():
        full_response_text = ""
        try:
            response_stream = chat_session.send_message(model_input_parts, stream=True)
            for chunk in response_stream:
                if chunk.text:
                    full_response_text += chunk.text
                    yield chunk.text
        except Exception as e:
            logging.error(f"Gemini stream error: {e}")
            yield f"STREAM_ERROR: An error occurred while generating the response: {str(e)}"
            return

        chat['messages'].append({'sender': 'model', 'content': full_response_text})
        if len(chat['messages']) <= 2 and prompt:
            try:
                title_prompt = f"Summarize with a short title (4 words max): User: \"{prompt}\" Assistant: \"{full_response_text[:100]}\""
                title_response = genai.GenerativeModel('gemini-1.5-flash-latest').generate_content(title_prompt)
                chat['title'] = title_response.text.strip().replace('"', '')
            except Exception as title_e:
                logging.error(f"Title generation error: {title_e}")
                chat['title'] = prompt[:40] + '...'
        save_database()

    return Response(stream_with_context(generate_chunks()), mimetype='text/plain')

@app.route('/api/chat/new', methods=['POST'])
@login_required
def new_chat():
    try:
        chat_id = f"chat_{current_user.id}_{datetime.now().timestamp()}"
        new_chat_data = {
            "id": chat_id, "user_id": current_user.id, "title": "New Chat",
            "messages": [], "created_at": datetime.now().isoformat(), "is_public": False
        }
        DB['chats'][chat_id] = new_chat_data
        save_database()
        return jsonify({"success": True, "chat": new_chat_data})
    except Exception as e:
        logging.error(f"Error creating new chat for user {current_user.id}: {e}")
        return jsonify({"error": "Could not create a new chat."}), 500

@app.route('/api/chat/rename', methods=['POST'])
@login_required
def rename_chat():
    data = request.get_json()
    chat_id, new_title = data.get('chat_id'), data.get('title', '').strip()
    if not all([chat_id, new_title]): return jsonify({"error": "Chat ID and title required."}), 400
    chat = DB['chats'].get(chat_id)
    if chat and chat.get('user_id') == current_user.id:
        chat['title'] = new_title
        save_database()
        return jsonify({"success": True})
    return jsonify({"error": "Chat not found or access denied."}), 404

@app.route('/api/chat/delete', methods=['POST'])
@login_required
def delete_chat():
    chat_id = request.json.get('chat_id')
    chat = DB['chats'].get(chat_id)
    if chat and chat.get('user_id') == current_user.id:
        del DB['chats'][chat_id]
        save_database()
        return jsonify({"success": True})
    return jsonify({"error": "Chat not found or access denied."}), 404

@app.route('/api/chat/share', methods=['POST'])
@login_required
def share_chat():
    chat_id = request.json.get('chat_id')
    chat = DB['chats'].get(chat_id)
    if chat and chat.get('user_id') == current_user.id:
        chat['is_public'] = True
        save_database()
        return jsonify({"success": True, "share_id": chat_id})
    return jsonify({"error": "Chat not found or access denied."}), 404

# --- 10. Public Share and Payment Routes ---
@app.route('/share/<chat_id>')
def view_shared_chat(chat_id):
    chat = DB['chats'].get(chat_id)
    if not chat or not chat.get('is_public'): return "Chat not found or is not public.", 404
    return f"<h1>{chat['title']}</h1>" + "".join([f"<p><b>{msg['sender']}:</b> {msg['content']}</p>" for msg in chat['messages']])

@app.route('/api/plans')
@login_required
def get_plans():
    student_plans = {pid: p for pid, p in PLAN_CONFIG.items() if pid.startswith('student')}
    return jsonify({
        "success": True, 
        "plans": {pid: {"name": d["name"], "price_string": d["price_string"], "features": d["features"], "color": d["color"]} for pid, d in student_plans.items()},
        "user_plan": current_user.plan
    })

@app.route('/api/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    if not stripe.api_key: return jsonify(error={'message': 'Payment services unavailable.'}), 500
    plan_id = request.json.get('plan_id')
    price_map = {
        "student": {"id": SITE_CONFIG["STRIPE_STUDENT_PRICE_ID"], "mode": "subscription"},
        "student_pro": {"id": SITE_CONFIG["STRIPE_STUDENT_PRO_PRICE_ID"], "mode": "subscription"}
    }
    if plan_id not in price_map: return jsonify(error={'message': 'Invalid plan.'}), 400
    try:
        checkout_session = stripe.checkout.Session.create(
            line_items=[{'price': price_map[plan_id]['id'], 'quantity': 1}],
            mode=price_map[plan_id]['mode'],
            success_url=SITE_CONFIG["YOUR_DOMAIN"] + '/?payment=success',
            cancel_url=SITE_CONFIG["YOUR_DOMAIN"] + '/?payment=cancel',
            client_reference_id=current_user.id
        )
        return jsonify({'id': checkout_session.id})
    except Exception as e:
        logging.error(f"Stripe session error: {e}")
        return jsonify(error={'message': "Could not create payment session."}), 500

@app.route('/stripe-webhook', methods=['POST'])
def stripe_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')
    endpoint_secret = SITE_CONFIG['STRIPE_WEBHOOK_SECRET']
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
    except (ValueError, stripe.error.SignatureVerificationError) as e:
        logging.warning(f"Stripe webhook error: {e}")
        return 'Invalid webhook signature', 400

    event_type = event['type']
    data_object = event['data']['object']
    logging.info(f"Received Stripe event: {event_type}")

    if event_type == 'checkout.session.completed':
        user = User.get(data_object.get('client_reference_id'))
        if user:
            line_item = stripe.checkout.Session.list_line_items(data_object.id, limit=1).data[0]
            price_id = line_item.price.id
            new_plan = None
            if price_id == SITE_CONFIG['STRIPE_STUDENT_PRICE_ID']:
                new_plan = 'student'
            elif price_id == SITE_CONFIG['STRIPE_STUDENT_PRO_PRICE_ID']:
                new_plan = 'student_pro'
            
            if new_plan:
                user.plan = new_plan
                save_database()
                logging.info(f"User {user.id} upgraded to {user.plan}")
    elif event_type == 'customer.subscription.deleted':
        customer = stripe.Customer.retrieve(data_object.customer)
        user = User.get_by_email(customer.email)
        if user and user.plan == 'student_pro':
            user.plan = 'student'
            save_database()
            logging.info(f"User {user.id} subscription ended; downgraded to student.")
    return 'Success', 200


# --- 11. Admin & Teacher Routes ---
@app.route('/api/admin_data')
@admin_required
def admin_data():
    stats = {"total_users": 0, "student_users": 0, "student_pro_users": 0}
    all_users_data = []
    for user in DB["users"].values():
        if user.role != 'admin':
            stats['total_users'] += 1
            if user.plan == 'student': stats['student_users'] += 1
            elif user.plan == 'student_pro': stats['student_pro_users'] += 1
            all_users_data.append({"id": user.id, "username": user.username, "email": user.email, "plan": user.plan, "role": user.role, "account_type": user.account_type})
    return jsonify({"success": True, "stats": stats, "users": sorted(all_users_data, key=lambda x: x['username']), "announcement": DB['site_settings']['announcement']})

@app.route('/api/admin/delete_user', methods=['POST'])
@admin_required
def admin_delete_user():
    user_id = request.json.get('user_id')
    if user_id == current_user.id: return jsonify({"error": "Cannot delete yourself."}), 400
    user_to_delete = User.get(user_id)
    if not user_to_delete: return jsonify({"error": "User not found."}), 404
    if user_to_delete.role == 'admin' and len([u for u in DB['users'].values() if u.role == 'admin']) <= 1:
        return jsonify({"error": "Cannot delete the last admin."}), 403
    del DB['users'][user_id]
    for cid in [cid for cid, c in DB['chats'].items() if c.get('user_id') == user_id]: del DB['chats'][cid]
    save_database()
    return jsonify({"success": True, "message": f"User {user_id} deleted."})

@app.route('/api/admin/announcement', methods=['POST'])
@admin_required
def set_announcement():
    DB['site_settings']['announcement'] = request.json.get('text', '').strip()
    save_database()
    return jsonify({"success": True, "message": "Announcement updated."})

@app.route('/api/admin/impersonate', methods=['POST'])
@admin_required
def impersonate_user():
    username = request.json.get('username')
    user_to_impersonate = User.get_by_username(username)
    if not user_to_impersonate: return jsonify({"error": "User not found."}), 404
    if user_to_impersonate.role == 'admin': return jsonify({"error": "Cannot impersonate another admin."}), 403
    session['impersonator_id'] = current_user.id
    logout_user()
    login_user(user_to_impersonate, remember=True)
    return jsonify({"success": True})

@app.route('/api/teacher/dashboard_data', methods=['GET'])
@teacher_required
def teacher_dashboard_data():
    classroom_code = next((code for code, data in DB['classrooms'].items() if data.get('teacher_id') == current_user.id), None)
    if not classroom_code: return jsonify({"success": True, "classroom": {"code": None}, "students": []})
    student_ids = DB['classrooms'][classroom_code]['students']
    students_data = [get_user_data_for_frontend(User.get(sid)) for sid in student_ids if User.get(sid)]
    return jsonify({"success": True, "classroom": {"code": classroom_code}, "students": sorted(students_data, key=lambda x: x['streak'], reverse=True)})

@app.route('/api/teacher/generate_classroom_code', methods=['POST'])
@teacher_required
def generate_classroom_code_api():
    if any(c['teacher_id'] == current_user.id for c in DB['classrooms'].values()):
        return jsonify({"error": "You already have a classroom."}), 409
    new_code = generate_unique_classroom_code()
    DB['classrooms'][new_code] = {"teacher_id": current_user.id, "students": [], "created_at": datetime.now().isoformat()}
    save_database()
    return jsonify({"success": True, "code": new_code})

@app.route('/api/teacher/kick_student', methods=['POST'])
@teacher_required
def kick_student():
    student_id = request.json.get('student_id')
    student = User.get(student_id)
    if not student or student.account_type != 'student': return jsonify({"error": "Student not found."}), 404
    if not student.classroom_code or DB['classrooms'].get(student.classroom_code, {}).get('teacher_id') != current_user.id:
        return jsonify({"error": "Unauthorized."}), 403
    DB['classrooms'][student.classroom_code]['students'].remove(student.id)
    student.classroom_code = None
    student.streak = 0
    save_database()
    return jsonify({"success": True, "message": f"Student {student.username} kicked."})

@app.route('/api/teacher/student_chats/<student_id>', methods=['GET'])
@teacher_required
def get_student_chats(student_id):
    student = User.get(student_id)
    if not student or student.account_type != 'student': return jsonify({"error": "Student not found."}), 404
    if not student.classroom_code or DB['classrooms'].get(student.classroom_code, {}).get('teacher_id') != current_user.id:
        return jsonify({"error": "Unauthorized."}), 403
    student_chats = list(get_all_user_chats(student_id).values())
    return jsonify({"success": True, "chats": sorted(student_chats, key=lambda c: c.get('created_at'), reverse=True)})
    
@app.route('/api/student/leaderboard', methods=['GET'])
@login_required
def student_leaderboard_data():
    if current_user.account_type != 'student' or not current_user.classroom_code:
        return jsonify({"success": False, "error": "Not in a classroom."}), 403
    student_ids = DB['classrooms'][current_user.classroom_code]['students']
    students_data = [get_user_data_for_frontend(User.get(sid)) for sid in student_ids if User.get(sid)]
    return jsonify({"success": True, "leaderboard": sorted(students_data, key=lambda x: x['streak'], reverse=True)})

@app.route('/api/student/join_classroom', methods=['POST'])
@login_required
def join_classroom():
    if current_user.account_type != 'student':
        return jsonify({"error": "Only students can join classrooms."}), 403
    
    code = request.json.get('classroom_code', '').strip().upper()
    if not code:
        return jsonify({"error": "Classroom code is required."}), 400
    if code not in DB['classrooms']:
        return jsonify({"error": "Invalid classroom code."}), 404
    
    current_user.classroom_code = code
    if current_user.id not in DB['classrooms'][code]['students']:
        DB['classrooms'][code]['students'].append(current_user.id)
    
    save_database()
    return jsonify({"success": True, "user": get_user_data_for_frontend(current_user)})

@app.route('/api/teacher/extend_limit', methods=['POST'])
@teacher_required
def extend_limit():
    student_id = request.json.get('student_id')
    new_limit = request.json.get('new_limit')
    
    student = User.get(student_id)
    if not student or student.account_type != 'student':
        return jsonify({"error": "Student not found."}), 404
    if not student.classroom_code or DB['classrooms'].get(student.classroom_code, {}).get('teacher_id') != current_user.id:
        return jsonify({"error": "This student is not in your classroom."}), 403
    if not isinstance(new_limit, int) or new_limit <= 0:
        return jsonify({"error": "Invalid limit provided."}), 400
        
    student.message_limit_override = new_limit
    save_database()
    return jsonify({"success": True, "message": f"Message limit for {student.username} set to {new_limit} for today."})


# --- Main Execution ---
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
