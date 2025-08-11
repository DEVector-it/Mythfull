# app.py

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
from flask_talisman import Talisman
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
# This line loads the variables from your .env file into the environment
load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Security Check for Essential Keys ---
# This check ensures that the .env file is present and has the required keys
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
# In a real production environment with HTTPS, uncomment the line below
# app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'


# --- Site & API Configuration (Loaded from Environment) ---
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

# --- Security Headers (CSP) ---
csp = {
    'default-src': ["'self'"],
    'script-src': [
        "'self'",
        "https://js.stripe.com",
        "https://cdn.tailwindcss.com",
        "https://cdnjs.cloudflare.com",
        "https://accounts.google.com/gsi/client",
        "https://pagead2.googlesyndication.com"
    ],
    'style-src': ["'self'", "https://cdn.tailwindcss.com", "https://fonts.googleapis.com", "'unsafe-inline'", "https://accounts.google.com/gsi/style"],
    'font-src': ["'self'", "https://fonts.gstatic.com"],
    'img-src': ["'self'", "data:", "https://*.stripe.com", "https://lh3.googleusercontent.com"],
    'connect-src': ["'self'", "https://api.stripe.com", "https://accounts.google.com/gsi/"],
    'frame-src': ["https://js.stripe.com", "https://accounts.google.com/gsi/"]
}
Talisman(app, content_security_policy=csp)

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


# --- 2. Database Management (with Backups) ---
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
    # Create a backup before saving
    if os.path.exists(DATABASE_FILE):
        backup_file = os.path.join(DATA_DIR, f"database_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json.bak")
        try:
            os.rename(DATABASE_FILE, backup_file)
            # Clean up old backups, keeping the 5 most recent
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
        # Attempt to restore from the immediate backup if save fails
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
                os.rename(backup_to_load, DATABASE_FILE) # Restore the backup as the main file
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
    def __init__(self, id, username, email, password_hash=None, role='user', plan='student', account_type='student', daily_messages=0, last_message_date=None, classroom_code=None, streak=0, last_streak_date=None, message_limit_override=None):
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


# --- 4. Plan & Rate Limiting Configuration ---
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
        :root {
            --bg-gradient-start: #FDB813;
            --bg-gradient-end: #F99B28;
            --text-dark: #333333;
            --text-light: #ffffff;
            --container-bg: rgba(255, 255, 255, 0.25);
            --glass-border: rgba(255, 255, 255, 0.4);
            --brand-gradient-from: #FDB813;
            --brand-gradient-to: #F99B28;
        }
        body {
            background: linear-gradient(135deg, var(--bg-gradient-start), var(--bg-gradient-end));
            font-family: 'Inter', sans-serif;
            color: var(--text-dark);
        }
        .dark body { color: var(--text-light); }
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
        .prose code { color: #fff; background-color: rgba(0,0,0,0.2); padding: 0.2em 0.4em; border-radius: 0.25rem; }
        .prose pre { background-color: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.1); }
        .prose h1, .prose h2, .prose h3, .prose h4, .prose strong { color: #fff; }
        .prose a:hover { color: #fff; }
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
                <div id="google-signin-container" class="mt-4"></div>
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
    
    <!-- The rest of the templates (reset-password, student-signup, etc.) are identical to the previous version -->
    <!-- ... -->

    <script>
        // The entire 1000+ line JavaScript block from your original file goes here.
        // Make sure to update API endpoints, e.g., '/api/login' becomes '/api/auth/login'.
        // And add logic to handle the new Google Sign-In button.
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
        elif days_diff > 1:
            user.streak = 1
        
        user.last_streak_date = today.isoformat()

def get_user_data_for_frontend(user):
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
    return {chat_id: chat_data for chat_id, chat_data in DB['chats'].items() if chat_data.get('user_id') == user_id}

def generate_unique_classroom_code():
    while True:
        code = secrets.token_hex(4).upper()
        if code not in DB['classrooms']:
            return code


# --- 8. Core API Routes (Auth, Status, etc.) ---
@app.route('/')
@app.route('/reset-password/<token>')
@app.route('/share/<chat_id>')
def index(token=None, chat_id=None):
    return Response(HTML_CONTENT, mimetype='text/html')

@app.route('/api/status')
def status():
    config = {
        "google_oauth_enabled": GOOGLE_OAUTH_ENABLED, 
        "email_enabled": EMAIL_ENABLED
    }
    if current_user.is_authenticated:
        check_and_update_streak(current_user)
        save_database()
        return jsonify({
            "logged_in": True, "user": get_user_data_for_frontend(current_user),
            "chats": get_all_user_chats(current_user.id),
            "settings": DB['site_settings'],
            "config": config
        })
    return jsonify({"logged_in": False, "config": config, "settings": DB['site_settings']})

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
            "config": {"google_oauth_enabled": GOOGLE_OAUTH_ENABLED, "email_enabled": EMAIL_ENABLED}
        })
    return jsonify({"error": "Invalid username or password."}), 401

@app.route('/login/google')
def google_login():
    if not GOOGLE_OAUTH_ENABLED:
        return "Google Login is not configured.", 404
    redirect_uri = url_for('google_authorize', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route('/login/google/authorize')
def google_authorize():
    if not GOOGLE_OAUTH_ENABLED:
        return "Google Login is not configured.", 404
    try:
        token = oauth.google.authorize_access_token()
        user_info = oauth.google.get('https://www.googleapis.com/oauth2/v3/userinfo').json()
        email = user_info['email']
        
        user = User.get_by_email(email)
        if not user:
            # Create a new user if one doesn't exist
            username = user_info.get('given_name', email.split('@')[0])
            base_username = username
            counter = 1
            while User.get_by_username(username):
                username = f"{base_username}{counter}"
                counter += 1
            
            user = User(
                id=str(uuid.uuid4()), 
                username=username, 
                email=email, 
                password_hash=None # No password for OAuth users
            )
            DB['users'][user.id] = user
            save_database()
            
        login_user(user, remember=True)
        return redirect(url_for('index'))
    except Exception as e:
        logging.error(f"Google OAuth failed: {e}")
        return redirect(url_for('index', error="Google login failed."))

# --- The rest of the routes from your original file would go here ---
# ... (e.g., student_signup, teacher_signup, chat_api, admin_data, etc.) ...


# --- Main Execution ---
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    # For production, use a proper WSGI server like Gunicorn instead of app.run()
    # and set debug=False
    app.run(host='0.0.0.0', port=port, debug=True)
