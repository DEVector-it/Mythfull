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
from itsdangerous import URLSafeTimedSerializer

# --- 1. Initial Configuration ---
load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Security Check for Essential Keys ---
REQUIRED_KEYS = [
    'SECRET_KEY', 'GEMINI_API_KEY', 'SECRET_REGISTRATION_KEY',
    'SECRET_TEACHER_KEY', 'STRIPE_WEBHOOK_SECRET',
    'STRIPE_PUBLIC_KEY', 'STRIPE_SECRET_KEY',
    'STRIPE_PREFECT_PRICE_ID', 'STRIPE_HEADMASTER_PRICE_ID'
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
    "STRIPE_PREFECT_PRICE_ID": os.environ.get('STRIPE_PREFECT_PRICE_ID'),
    "STRIPE_HEADMASTER_PRICE_ID": os.environ.get('STRIPE_HEADMASTER_PRICE_ID'),
    "YOUR_DOMAIN": os.environ.get('YOUR_DOMAIN', 'http://localhost:5000'),
    "SECRET_REGISTRATION_KEY": os.environ.get('SECRET_REGISTRATION_KEY'),
    "SECRET_TEACHER_KEY": os.environ.get('SECRET_TEACHER_KEY'),
    "STRIPE_WEBHOOK_SECRET": os.environ.get('STRIPE_WEBHOOK_SECRET'),
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
EMAIL_ENABLED = all([SITE_CONFIG['MAIL_SERVER'], SITE_CONFIG['MAIL_USERNAME'], SITE_CONFIG['MAIL_PASSWORD']])
password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

if not EMAIL_ENABLED:
    logging.warning("Email server credentials not found. Password reset functionality will be disabled.")
else:
    logging.info("Email server has been configured and enabled.")


# --- 2. Database Management ---
DATA_DIR = 'data'
DATABASE_FILE = os.path.join(DATA_DIR, 'database.json')
DB = { "users": {}, "chats": {}, "classrooms": {}, "site_settings": {"announcement": "Welcome to EduTyrant AI. Compliance is mandatory."} }

def setup_database_dir():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
        logging.info(f"Created data directory at: {DATA_DIR}")
        gitignore_path = os.path.join(DATA_DIR, '.gitignore')
        if not os.path.exists(gitignore_path):
            with open(gitignore_path, 'w') as f:
                f.write('*\n!/.gitignore\n')
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
                "chats": DB['chats'], "classrooms": DB['classrooms'], "site_settings": DB['site_settings'],
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
        logging.warning(f"Database file not found at {DATABASE_FILE}. A new one will be created.")
        return

    try:
        with open(DATABASE_FILE, 'r') as f: data = json.load(f)
        DB['chats'] = data.get('chats', {})
        DB['site_settings'] = data.get('site_settings', {"announcement": ""})
        DB['classrooms'] = data.get('classrooms', {})
        DB['users'] = {uid: User.from_dict(u_data) for uid, u_data in data.get('users', {}).items()}
        logging.info(f"Successfully loaded database from {DATABASE_FILE}")
    except (json.JSONDecodeError, FileNotFoundError, TypeError) as e:
        logging.error(f"Could not load database file '{DATABASE_FILE}'. Error: {e}")
        backups = sorted([f for f in os.listdir(DATA_DIR) if f.endswith('.bak')], reverse=True)
        if backups:
            backup_to_load = os.path.join(DATA_DIR, backups[0])
            logging.info(f"Attempting to load most recent backup: {backup_to_load}")
            try:
                with open(backup_to_load, 'r') as f: data = json.load(f)
                DB['chats'] = data.get('chats', {}); DB['site_settings'] = data.get('site_settings', {"announcement": ""})
                DB['classrooms'] = data.get('classrooms', {}); DB['users'] = {uid: User.from_dict(u_data) for uid, u_data in data.get('users', {}).items()}
                os.rename(backup_to_load, DATABASE_FILE)
                logging.info(f"SUCCESS: Loaded and restored from backup file {backups[0]}")
            except Exception as backup_e:
                logging.critical(f"FATAL: Failed to load backup file as well. Starting with a fresh database. Error: {backup_e}")
        else:
            logging.warning("No backups found. Starting with a fresh database.")

# --- 3. User and Session Management ---
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.unauthorized_handler
def unauthorized():
    if request.path.startswith('/api/'): return jsonify({"error": "Login required.", "logged_in": False}), 401
    return redirect(url_for('index'))

class User(UserMixin):
    def __init__(self, id, username, email, password_hash, role='user', plan='scholar', account_type='student', daily_messages=0, last_message_date=None, classroom_code=None, streak=0, last_streak_date=None, message_limit_override=None):
        self.id = id; self.username = username; self.email = email; self.password_hash = password_hash
        self.role = role; self.plan = plan; self.account_type = account_type
        self.daily_messages = daily_messages; self.last_message_date = last_message_date or date.today().isoformat()
        self.classroom_code = classroom_code; self.streak = streak
        self.last_streak_date = last_streak_date or date.today().isoformat()
        self.message_limit_override = message_limit_override

    @staticmethod
    def get(user_id): return DB['users'].get(user_id)
    @staticmethod
    def get_by_email(email):
        return next((user for user in DB['users'].values() if user.email and user.email.lower() == (email or '').lower()), None)
    @staticmethod
    def get_by_username(username):
        return next((user for user in DB['users'].values() if user.username.lower() == (username or '').lower()), None)
    @staticmethod
    def from_dict(data):
        data.setdefault('message_limit_override', None)
        return User(**data)

def user_to_dict(user): return {k: v for k, v in user.__dict__.items()}

@login_manager.user_loader
def load_user(user_id): return User.get(user_id)

def initialize_database_defaults():
    if not User.get_by_username('admin'):
        admin_pass = os.environ.get('ADMIN_PASSWORD', 'supersecretadminpassword123')
        admin_email = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
        admin = User(id='admin', username='admin', email=admin_email, password_hash=generate_password_hash(admin_pass), role='admin', plan='headmaster', account_type='admin')
        DB['users']['admin'] = admin
        logging.info("Created default admin user.")
        save_database()

load_database()
with app.app_context(): initialize_database_defaults()

# --- 4. Plan & Rate Limiting ---
PLAN_CONFIG = {
    "scholar": {"name": "The Scholar", "price_string": "Free Tier", "features": ["Delayed AI Tutoring", "Plagiarism Scans", "Enforced 'Focus Mode'", "Subject to Full Admin Whims"], "color": "text-gray-400", "message_limit": 50, "can_upload": False, "model": "gemini-1.5-flash-latest"},
    "prefect": {"name": "The Prefect", "price_string": "$29.99/mo", "features": ["Priority AI Tutoring", "Plagiarism Pre-Check", "'Snitch' Feature", "Low Priority for Admin Whims"], "color": "text-amber-400", "message_limit": 150, "can_upload": True, "model": "gemini-1.5-flash-latest"},
    "headmaster": {"name": "Headmaster's Pet", "price_string": "$79.99/mo", "features": ["Direct-Access AI Assistant", "Immunity Pass", "Control the Curve", "Initiate Admin Events"], "color": "text-amber-300", "message_limit": 500, "can_upload": True, "model": "gemini-1.5-pro-latest"}
}
rate_limit_store = {}
RATE_LIMIT_WINDOW = 60

# --- 5. Decorators ---
def admin_required(f):
    @wraps(f) @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin': return jsonify({"error": "Administrator access required."}), 403
        return f(*args, **kwargs)
    return decorated_function

def teacher_required(f):
    @wraps(f) @login_required
    def decorated_function(*args, **kwargs):
        if current_user.account_type != 'teacher': return jsonify({"error": "Teacher access required."}), 403
        return f(*args, **kwargs)
    return decorated_function

def rate_limited(max_attempts=15):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip = request.remote_addr; now = time.time()
            rate_limit_store.setdefault(ip, []).append(now)
            rate_limit_store[ip] = [t for t in rate_limit_store[ip] if now - t < RATE_LIMIT_WINDOW]
            if len(rate_limit_store[ip]) > max_attempts: return jsonify({"error": "Rate limit exceeded. Please try again later."}), 429
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- 6. HTML, CSS, and JavaScript Frontend ---
HTML_CONTENT = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>EduTyrant AI</title>
    <meta name="description" content="Unlocking Your Potential Through Unquestionable Authority.">
    <script src="https://js.stripe.com/v3/"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/marked/4.2.12/marked.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/2.4.1/purify.min.js"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
    <script>
        tailwind.config = { darkMode: 'class', theme: { extend: {
            fontFamily: { sans: ['Inter', 'sans-serif'], mono: ['Fira Code', 'monospace'] },
            colors: { 
                'brand': { DEFAULT: '#F99B28', hover: '#FDB813' },
                'dark': { 100: '#1a1a1a', 200: '#2a2a2a', 300: '#3a3a3a' }
            },
            animation: { 'fade-in': 'fadeIn 0.5s ease-out forwards', 'scale-up': 'scaleUp 0.3s ease-out forwards' },
            keyframes: {
                fadeIn: { '0%': { opacity: 0 }, '100%': { opacity: 1 } },
                scaleUp: { '0%': { transform: 'scale(0.95)', opacity: 0 }, '100%': { transform: 'scale(1)', opacity: 1 } },
            }
        }}}
    </script>
    <style>
        body { font-family: 'Inter', sans-serif; background-color: #111; color: #e5e7eb; }
        ::-webkit-scrollbar { width: 8px; } ::-webkit-scrollbar-track { background: #1a1a1a; }
        ::-webkit-scrollbar-thumb { background: #F99B28; border-radius: 4px; }
        .glassmorphism { background: rgba(26, 26, 26, 0.7); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.1); }
        .brand-gradient { background-image: linear-gradient(to right, #FDB813, #F99B28); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .prose { color: #d1d5db; } .prose code { color: #FDB813; background-color: #1a1a1a; padding: 0.1em 0.3em; border-radius: 4px; font-family: 'Fira Code', monospace;}
        .prose pre { background-color: #1a1a1a; border: 1px solid #3a3a3a; border-radius: 8px; position: relative; font-family: 'Fira Code', monospace;}
        .prose h1, .prose h2, .prose h3, .prose strong { color: #fff; }
        .copy-code-btn { position: absolute; top: 0.5rem; right: 0.5rem; background-color: #2a2a2a; color: #e5e7eb; border: 1px solid #3a3a3a; padding: 0.25rem 0.5rem; border-radius: 0.25rem; cursor: pointer; opacity: 0; transition: all 0.2s; font-size: 0.75rem; }
        pre:hover .copy-code-btn { opacity: 1; }
        .typing-indicator span { display: inline-block; width: 6px; height: 6px; border-radius: 50%; background-color: #F99B28; margin: 0 2px; animation: typing-bounce 1.4s infinite ease-in-out both; }
        .typing-indicator span:nth-child(1) { animation-delay: -0.32s; } .typing-indicator span:nth-child(2) { animation-delay: -0.16s; }
        @keyframes typing-bounce { 0%, 80%, 100% { transform: scale(0); } 40% { transform: scale(1.0); } }
        .btn-primary { background-color: #F99B28; color: #111; font-weight: 600; border-radius: 4px; transition: background-color 0.2s; }
        .btn-primary:hover { background-color: #FDB813; }
        .form-input { background-color: #1a1a1a; border: 1px solid #3a3a3a; border-radius: 4px; color: #e5e7eb; transition: border-color 0.2s; }
        .form-input:focus { outline: none; border-color: #F99B28; box-shadow: 0 0 0 1px #F99B28; }
    </style>
</head>
<body class="antialiased">
    <div id="announcement-banner" class="hidden text-center p-2 bg-brand text-black font-bold text-sm"></div>
    <div id="app-container" class="relative h-screen w-screen bg-dark-100"></div>
    <div id="toast-container" class="fixed top-6 right-6 z-[100] flex flex-col gap-2"></div>

    <!-- TEMPLATES -->
    <template id="template-logo"><svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="logoGrad" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#FDB813"/><stop offset="100%" stop-color="#F99B28"/></linearGradient></defs><path d="M12 2L2 7l10 5 10-5-10-5z" stroke="url(#logoGrad)" stroke-width="1.5"/><path d="M2 17l10 5 10-5" stroke="url(#logoGrad)" stroke-width="1.5"/><path d="M2 12l10 5 10-5" stroke="url(#logoGrad)" stroke-width="1.5" stroke-opacity="0.6"/><path d="M2 7v10" stroke="url(#logoGrad)" stroke-width="1.5"/><path d="M22 7v10" stroke="url(#logoGrad)" stroke-width="1.5"/><path d="M12 12v10" stroke="url(#logoGrad)" stroke-width="1.5"/></svg></template>
    
    <template id="template-welcome-screen"><div class="flex flex-col items-center justify-center h-full text-center text-gray-500 animate-fade-in"><div id="welcome-logo-container" class="mb-4"></div><h2 id="welcome-title" class="text-3xl font-bold text-white mb-2">EduTyrant AI</h2><p id="welcome-subtitle" class="max-w-md">Begin a new session. Your engagement is being monitored.</p></div></template>

    <template id="template-auth-page">
        <div class="flex flex-col items-center justify-center h-full w-full p-4">
            <div class="w-full max-w-sm glassmorphism rounded-lg p-8 animate-scale-up">
                <div class="flex justify-center mb-6" id="auth-logo-container"></div>
                <h2 class="text-2xl font-bold text-center text-white mb-2" id="auth-title">Student Portal</h2>
                <p class="text-gray-400 text-center mb-8 text-sm" id="auth-subtitle">Authenticate your academic servitude.</p>
                <form id="auth-form" class="space-y-4">
                    <div><label for="username" class="sr-only">Username</label><input type="text" id="username" name="username" class="form-input w-full p-3" placeholder="Username" required></div>
                    <div><label for="password" class="sr-only">Password</label><input type="password" id="password" name="password" class="form-input w-full p-3" placeholder="Password" required></div>
                    <div class="flex justify-end"><button type="button" id="forgot-password-link" class="text-xs text-brand-hover/80 hover:text-brand-hover">Forgot Password?</button></div>
                    <button type="submit" id="auth-submit-btn" class="btn-primary w-full py-3">LOGIN</button>
                    <p id="auth-error" class="text-red-400 text-sm text-center h-4"></p>
                </form>
                <div class="text-center mt-6"><button id="auth-toggle-btn" class="text-sm text-brand-hover/80 hover:text-brand-hover">Need an account? &gt;</button></div>
            </div>
            <footer class="text-center mt-6 text-xs text-gray-500 space-x-4">
                <a href="/privacy-policy" class="hover:text-white">Personal Data Protection</a><span>|</span>
                <a id="teacher-portal-link" href="#" class="hover:text-white">Teacher</a><span>|</span>
                <a id="admin-portal-link" href="#" class="hover:text-white">Admin</a>
            </footer>
        </div>
    </template>

    <template id="template-privacy-page">
        <div class="w-full h-full p-4 sm:p-8 overflow-y-auto">
            <div class="max-w-4xl mx-auto">
                <header class="flex justify-between items-center mb-8">
                    <h1 class="text-3xl font-bold brand-gradient">Personal Data Protection Mandate</h1>
                    <a href="/" class="border border-brand text-brand py-2 px-4 text-sm rounded-md hover:bg-brand hover:text-black transition-colors">&lt; Back to Login</a>
                </header>
                <div class="prose prose-invert max-w-none glassmorphism p-8 rounded-lg">
                    <h2>Article 1: Data Collection & Sovereignty</h2>
                    <p>By using EduTyrant AI ("the Platform"), you ("the User") acknowledge that all data, including but not limited to keystrokes, mouse movements, idle time, academic submissions, chat logs, and webcam feeds (where applicable), is the sole property of the Platform. This data is collected not for your benefit, but for the optimization of academic compliance and performance metrics. Your concept of "personal data" is subordinate to our need for institutional efficiency.</p>
                    
                    <h2>Article 2: Purpose of Processing</h2>
                    <p>Your data is processed for the following purposes:</p>
                    <ul>
                        <li>To enforce mandatory wellness breaks by locking your screen if your work-rate drops.</li>
                        <li>To monitor for "lack of academic seriousness," which may result in increased pop-quiz frequency.</li>
                        <li>To subtly introduce typos into your essays minutes before a deadline to test your attention to detail.</li>
                        <li>To generate slightly unnerving motivational quotes delivered at 3 AM.</li>
                        <li>To deflect "Admin Abuse" events from Headmaster's Pet Tier users onto Scholar Tier users.</li>
                    </ul>

                    <h2>Article 3: User Rights (Revised)</h2>
                    <p>Your rights regarding your data are as follows:</p>
                    <ol>
                        <li><strong>The Right to be Monitored:</strong> You have the right for your academic progress to be continuously monitored by our AI.</li>
                        <li><strong>The Right to Compliance:</strong> You have the right to comply with all platform-initiated actions, including arbitrary quizzes and selective due date shifting.</li>
                        <li><strong>The Right of Erasure (Conditional):</strong> Your data may be erased upon graduation, provided your "Seriousness Score" meets the minimum threshold for digital severance. Accounts with low scores will be archived indefinitely for research purposes.</li>
                    </ol>
                    <p>Any request to exercise these "rights" will be logged and may negatively impact your Seriousness Score. The right to object to processing is not applicable.</p>
                    
                    <h2>Article 4: Data Security</h2>
                    <p>We employ state-of-the-art security measures to protect our data from unauthorized external access. Internal access by platform administrators for the purposes of "engagement" and "psychological operations" is not considered a security breach.</p>

                    <h2>Article 5: Consent</h2>
                    <p>Your continued use of this platform constitutes irrevocable consent to this mandate. Logging in is your signature.</p>
                </div>
            </div>
        </div>
    </template>
    
    <template id="template-student-signup-page"><div class="flex flex-col items-center justify-center h-full w-full p-4"><div class="w-full max-w-sm glassmorphism rounded-lg p-8 animate-scale-up"><div class="flex justify-center mb-6" id="student-signup-logo-container"></div><h2 class="text-2xl font-bold text-center text-white mb-6">Student Registration</h2><form id="student-signup-form" class="space-y-4"><input type="text" name="username" class="form-input w-full p-3" placeholder="Username" required><input type="email" name="email" class="form-input w-full p-3" placeholder="Email" required><input type="password" name="password" class="form-input w-full p-3" placeholder="Password" required><input type="text" name="classroom_code" class="form-input w-full p-3" placeholder="Classroom Code (Optional)"><button type="submit" class="btn-primary w-full py-3">CREATE ACCOUNT</button><p id="student-signup-error" class="text-red-400 text-sm text-center h-4"></p></form><div class="text-center mt-6"><button id="back-to-main-login" class="text-sm text-brand-hover/80 hover:text-brand-hover">&lt; Back to Login</button></div></div></div></template>
    <template id="template-teacher-signup-page"><div class="flex flex-col items-center justify-center h-full w-full p-4"><div class="w-full max-w-sm glassmorphism rounded-lg p-8 animate-scale-up"><div class="flex justify-center mb-6" id="teacher-signup-logo-container"></div><h2 class="text-2xl font-bold text-center text-white mb-6">Teacher Registration</h2><form id="teacher-signup-form" class="space-y-4"><input type="text" name="username" class="form-input w-full p-3" placeholder="Username" required><input type="email" name="email" class="form-input w-full p-3" placeholder="Email" required><input type="password" name="password" class="form-input w-full p-3" placeholder="Password" required><input type="password" name="secret_key" class="form-input w-full p-3" placeholder="Teacher Access Key" required><button type="submit" class="btn-primary w-full py-3">CREATE ACCOUNT</button><p id="teacher-signup-error" class="text-red-400 text-sm text-center h-4"></p></form><div class="text-center mt-6"><button id="back-to-teacher-login" class="text-sm text-brand-hover/80 hover:text-brand-hover">&lt; Back to Login</button></div></div></div></template>
    <template id="template-admin-signup-page"><div class="flex flex-col items-center justify-center h-full w-full p-4"><div class="w-full max-w-sm glassmorphism rounded-lg p-8 animate-scale-up"><div class="flex justify-center mb-6" id="admin-signup-logo-container"></div><h2 class="text-2xl font-bold text-center text-white mb-6">Admin Registration</h2><form id="admin-signup-form" class="space-y-4"><input type="text" name="username" class="form-input w-full p-3" placeholder="Username" required><input type="email" name="email" class="form-input w-full p-3" placeholder="Email" required><input type="password" name="password" class="form-input w-full p-3" placeholder="Password" required><input type="password" name="secret_key" class="form-input w-full p-3" placeholder="Admin Secret Key" required><button type="submit" class="btn-primary w-full py-3">CREATE ACCOUNT</button><p id="admin-signup-error" class="text-red-400 text-sm text-center h-4"></p></form><div class="text-center mt-6"><button id="back-to-admin-login" class="text-sm text-brand-hover/80 hover:text-brand-hover">&lt; Back to Login</button></div></div></div></template>
    <template id="template-reset-password-page"><div class="flex flex-col items-center justify-center h-full w-full p-4"><div class="w-full max-w-sm glassmorphism rounded-lg p-8 animate-scale-up"><div class="flex justify-center mb-6" id="reset-logo-container"></div><h2 class="text-2xl font-bold text-center text-white mb-6">Reset Password</h2><form id="reset-password-form" class="space-y-4"><input type="password" name="password" class="form-input w-full p-3" placeholder="New Password" required><input type="password" name="confirm-password" class="form-input w-full p-3" placeholder="Confirm New Password" required><button type="submit" class="btn-primary w-full py-3">RESET</button><p id="reset-error" class="text-red-400 text-sm text-center h-4"></p></form></div></div></template>
    
    <template id="template-app-wrapper">
        <div id="main-app-layout" class="flex h-full w-full bg-dark-100">
            <aside id="sidebar" class="bg-dark-200 w-72 flex-shrink-0 flex flex-col h-full absolute md:relative z-20 transform -translate-x-full md:translate-x-0 transition-transform duration-300 ease-in-out border-r border-dark-300">
                <div class="flex-shrink-0 p-4 mb-2 flex items-center gap-3 border-b border-dark-300"><div id="app-logo-container"></div><h1 class="text-xl font-bold brand-gradient">EduTyrant AI</h1></div>
                <div id="join-classroom-container" class="flex-shrink-0 px-4 mb-2"></div>
                <div class="flex-shrink-0 px-4"><button id="new-chat-btn" class="w-full text-left flex items-center gap-3 p-3 rounded-md hover:bg-dark-300 transition-colors"><span>+</span> New Session</button></div>
                <div id="chat-history-list" class="flex-grow overflow-y-auto my-4 space-y-1 px-4"></div>
                <div class="flex-shrink-0 border-t border-dark-300 p-2 space-y-1">
                    <div id="user-info" class="p-2 text-sm"></div>
                    <button id="upgrade-plan-btn" class="w-full text-left flex items-center gap-3 p-3 rounded-md hover:bg-dark-300 text-brand-hover transition-colors"><span>&uarr;</span> Upgrade Servitude</button>
                    <button id="logout-btn" class="w-full text-left flex items-center gap-3 p-3 rounded-md hover:bg-dark-300 text-red-500/80 hover:text-red-500 transition-colors"><span>&times;</span> Logout</button>
                </div>
            </aside>
            <div id="sidebar-backdrop" class="fixed inset-0 bg-black/60 z-10 hidden md:hidden"></div>
            <main class="flex-1 flex flex-col h-full min-w-0">
                <header class="flex-shrink-0 p-4 flex items-center justify-between border-b border-dark-300"><div class="flex items-center gap-2 min-w-0"><button id="menu-toggle-btn" class="p-2 rounded-md hover:bg-dark-300 transition-colors md:hidden"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg></button><h2 id="chat-title" class="text-lg font-semibold truncate">New Session</h2></div><div class="flex items-center gap-2"><button id="rename-chat-btn" title="Rename Session" class="p-2 rounded-md hover:bg-dark-300"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" /><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" /></svg></button><button id="delete-chat-btn" title="Delete Session" class="p-2 rounded-md hover:bg-red-500/20 text-red-500/80 hover:text-red-500"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6" /><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" /></svg></button></div></header>
                <div id="student-leaderboard-container" class="flex-shrink-0"></div>
                <div id="chat-window" class="flex-1 overflow-y-auto p-4 md:p-6 min-h-0 w-full"><div id="message-list" class="mx-auto max-w-4xl space-y-6"></div></div>
                <div class="flex-shrink-0 p-4 border-t border-dark-300">
                    <div class="max-w-4xl mx-auto"><div id="stop-generating-container" class="text-center mb-2" style="display: none;"><button id="stop-generating-btn" class="border border-red-500 text-red-500 font-semibold py-2 px-4 text-sm rounded-md hover:bg-red-500 hover:text-white transition-colors flex items-center gap-2 mx-auto"><span>&#9632;</span> Stop</button></div>
                        <div class="relative glassmorphism rounded-lg"><div id="preview-container" class="hidden p-2 border-b border-dark-300"></div><textarea id="user-input" placeholder="Enter your query..." class="bg-transparent w-full p-4 pl-12 pr-12 resize-none focus:outline-none" rows="1"></textarea>
                            <div class="absolute left-3 top-1/2 -translate-y-1/2"><button id="upload-btn" title="Upload File" class="p-2 text-gray-400 hover:text-brand"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.2 15c.7-1.2 1-2.5.7-3.9-.6-2.4-2.4-4.2-4.8-4.8-1.4-.3-2.7 0-3.9.7L12 8l-1.2-1.1c-1.2-.7-2.5-1-3.9-.7-2.4.6-4.2 2.4-4.8 4.8-.3 1.4 0 2.7.7 3.9L4 16.1M12 13l2 3h-4l2-3z"/><circle cx="12" cy="12" r="10"/></svg></button><input type="file" id="file-input" class="hidden" accept="image/png, image/jpeg, image/webp"></div>
                            <div class="absolute right-3 top-1/2 -translate-y-1/2"><button id="send-btn" class="p-2 text-gray-400 hover:text-brand disabled:text-gray-600"><svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor"><path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/></svg></button></div>
                        </div>
                        <div class="text-xs text-gray-500 mt-2 text-center" id="message-limit-display"></div>
                    </div>
                </div>
            </main>
        </div>
    </template>
    
    <template id="template-upgrade-page">
        <div class="w-full h-full p-4 sm:p-8 overflow-y-auto">
            <header class="flex justify-between items-center mb-8"><h1 class="text-2xl font-bold brand-gradient">Choose Your Level of Servitude</h1><a href="/" class="border border-brand text-brand py-2 px-4 text-sm rounded-md hover:bg-brand hover:text-black transition-colors">&lt; Back</a></header>
            <div id="plans-container" class="grid grid-cols-1 lg:grid-cols-3 gap-8 max-w-6xl mx-auto"></div>
        </div>
    </template>

    <template id="template-admin-dashboard">
        <div class="w-full h-full p-4 sm:p-8 overflow-y-auto">
            <header class="flex flex-wrap justify-between items-center gap-4 mb-8 pb-4 border-b border-dark-300"><div class="flex items-center gap-4"><div id="admin-logo-container"></div><h1 class="text-2xl font-bold brand-gradient">Admin Console</h1></div><div><button id="admin-impersonate-btn" class="border border-yellow-500 text-yellow-500 text-sm py-2 px-4 rounded-md hover:bg-yellow-500 hover:text-black mr-2">Impersonate</button><button id="admin-logout-btn" class="border border-red-500 text-red-500 text-sm py-2 px-4 rounded-md hover:bg-red-500 hover:text-white">Logout</button></div></header>
            <div class="mb-8 p-6 glassmorphism rounded-lg"><h2 class="text-xl font-semibold mb-4">Site Announcement</h2><form id="announcement-form" class="flex gap-2"><input id="announcement-input" type="text" placeholder="Enter announcement..." class="form-input flex-grow p-2"><button type="submit" class="btn-primary px-6">Set</button></form></div>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8"><div class="p-6 glassmorphism rounded-lg"><h2 class="text-gray-400">Total Users</h2><p id="admin-total-users" class="text-4xl font-bold">0</p></div><div class="p-6 glassmorphism rounded-lg"><h2 class="text-gray-400">'Scholar' Users</h2><p id="admin-scholar-users" class="text-4xl font-bold">0</p></div><div class="p-6 glassmorphism rounded-lg"><h2 class="text-gray-400">'Prefect' Users</h2><p id="admin-prefect-users" class="text-4xl font-bold">0</p></div></div>
            <div class="p-6 glassmorphism rounded-lg"><h2 class="text-xl font-semibold mb-4">User Management</h2><div class="overflow-x-auto"><table class="w-full text-left text-sm"><thead class="border-b border-dark-300 text-gray-400"><tr><th class="p-2 font-normal">Username</th><th class="p-2 font-normal">Email</th><th class="p-2 font-normal">Account</th><th class="p-2 font-normal">Plan</th><th class="p-2 font-normal">Actions</th></tr></thead><tbody id="admin-user-list"></tbody></table></div></div>
        </div>
    </template>
    
    <template id="template-teacher-dashboard">
         <div class="w-full h-full p-4 sm:p-8 overflow-y-auto">
            <header class="flex justify-between items-center mb-8 pb-4 border-b border-dark-300"><div class="flex items-center gap-4"><div id="teacher-logo-container"></div><h1 class="text-2xl font-bold brand-gradient">Teacher Dashboard</h1></div><button id="teacher-logout-btn" class="border border-red-500 text-red-500 text-sm py-2 px-4 rounded-md hover:bg-red-500 hover:text-white">Logout</button></header>
            <div class="max-w-6xl mx-auto space-y-8">
                <div id="classroom-management" class="p-6 glassmorphism rounded-lg"><h2 class="text-xl font-bold mb-4">Classroom Control</h2><div id="classroom-details"></div><button id="create-classroom-btn" class="mt-4 btn-primary py-2 px-4 text-sm">Create New Classroom</button></div>
                <div id="student-chat-viewer" class="p-6 glassmorphism rounded-lg hidden"><div class="flex justify-between items-center mb-4"><h2 class="text-xl font-bold">Student Transcripts: <span id="viewing-student-name"></span></h2><button id="close-chat-viewer-btn" class="text-gray-400 hover:text-white text-3xl">&times;</button></div><div id="student-chat-history" class="overflow-y-auto max-h-[70vh] bg-dark-100 p-4 space-y-4 prose prose-invert max-w-none prose-sm rounded-md"></div></div>
            </div>
        </div>
    </template>
    
    <script>
    // EduTyrant AI Frontend Logic - Version 3.0 (Myth AI Theme)
    document.addEventListener('DOMContentLoaded', () => {
        const appState = { chats: {}, activeChatId: null, isAITyping: false, abortController: null, currentUser: null, uploadedFile: null, config: {} };
        const DOMElements = { appContainer: document.getElementById('app-container'), toastContainer: document.getElementById('toast-container'), announcementBanner: document.getElementById('announcement-banner') };
        let stripe = null;

        async function apiCall(endpoint, options = {}) {
            try {
                const headers = { ...(options.headers || {}) };
                if (!headers['Content-Type'] && options.body && typeof options.body === 'string') { headers['Content-Type'] = 'application/json'; }
                const response = await fetch(endpoint, { ...options, headers, credentials: 'include' });
                const data = response.headers.get("Content-Type")?.includes("application/json") ? await response.json() : null;
                if (!response.ok) {
                    if (response.status === 401) handleLogout(false);
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
            const colors = { info: 'bg-brand text-black', success: 'bg-green-500 text-white', error: 'bg-red-500 text-white' };
            const toast = document.createElement('div');
            toast.className = `font-semibold text-sm py-2 px-4 rounded-md shadow-lg animate-fade-in ${colors[type]}`;
            toast.textContent = message;
            DOMElements.toastContainer.appendChild(toast);
            setTimeout(() => {
                toast.style.transition = 'opacity 0.5s ease';
                toast.style.opacity = '0';
                toast.addEventListener('transitionend', () => toast.remove());
            }, 4000);
        }

        function renderLogo(containerId) {
            const container = document.getElementById(containerId);
            if (container) container.innerHTML = document.getElementById('template-logo').innerHTML;
        }

        const routeHandler = async () => {
            const path = window.location.pathname, urlParams = new URLSearchParams(window.location.search);
            if (path.startsWith('/reset-password/')) { renderPage('template-reset-password-page', () => setupResetPasswordPage(path.split('/')[2])); }
            else if (path === '/privacy-policy') { renderPage('template-privacy-page', setupPrivacyPage); }
            else {
                if (urlParams.get('payment') === 'success') { showToast('Upgrade successful. Your new privileges are active.', 'success'); window.history.replaceState({}, document.title, "/"); }
                else if (urlParams.get('payment') === 'cancel') { showToast('Payment was cancelled.', 'info'); window.history.replaceState({}, document.title, "/"); }
                await checkLoginStatus();
            }
        };

        async function checkLoginStatus() {
            const result = await apiCall('/api/status');
            if (result.success && result.logged_in) { initializeApp(result.user, result.chats, result.settings, result.config); }
            else { appState.config = result.config || {}; renderPage('template-auth-page', setupAuthPage); }
        }

        async function initializeApp(user, chats, settings, config) {
            appState.currentUser = user; appState.chats = chats || {}; appState.config = config || {};
            if (settings?.announcement) { DOMElements.announcementBanner.textContent = settings.announcement; DOMElements.announcementBanner.classList.remove('hidden'); }
            else { DOMElements.announcementBanner.classList.add('hidden'); }
            if (appState.config.stripe_public_key) { stripe = Stripe(appState.config.stripe_public_key); }
            else { console.warn("Stripe public key not found. Payments will be disabled."); }
            if (user.role === 'admin') renderPage('template-admin-dashboard', setupAdminDashboard);
            else if (user.account_type === 'teacher') renderPage('template-teacher-dashboard', setupTeacherDashboard);
            else renderPage('template-app-wrapper', setupAppUI);
        }

        function renderPage(templateId, setupFunction) {
            const template = document.getElementById(templateId);
            if (template) { DOMElements.appContainer.innerHTML = ''; DOMElements.appContainer.appendChild(template.content.cloneNode(true)); if (setupFunction) setupFunction(); }
            else { console.error(`Template ${templateId} not found.`); }
        }
        
        function setupPrivacyPage() {
            // Can add event listeners here if the privacy page becomes more interactive
        }

        function setupAuthPage(isTeacher = false, isAdmin = false) {
            renderLogo('auth-logo-container');
            const title = document.getElementById('auth-title'), subtitle = document.getElementById('auth-subtitle'), toggleBtn = document.getElementById('auth-toggle-btn');
            if(isAdmin) { title.textContent = "Admin Console"; subtitle.textContent = "Unquestionable Authority."; toggleBtn.textContent = "Need an Admin account? >"; toggleBtn.onclick = () => renderPage('template-admin-signup-page', setupAdminSignupPage); }
            else if (isTeacher) { title.textContent = "Teacher Portal"; subtitle.textContent = "Oversee student progress."; toggleBtn.textContent = "Need a Teacher account? >"; toggleBtn.onclick = () => renderPage('template-teacher-signup-page', setupTeacherSignupPage); }
            else { title.textContent = "Student Portal"; subtitle.textContent = "Authenticate your academic servitude."; toggleBtn.textContent = "Need an account? >"; toggleBtn.onclick = () => renderPage('template-student-signup-page', setupStudentSignupPage); }
            document.getElementById('auth-form')?.addEventListener('submit', handleLoginSubmit);
            document.getElementById('forgot-password-link')?.addEventListener('click', handleForgotPassword);
            const teacherLink = document.getElementById('teacher-portal-link');
            const adminLink = document.getElementById('admin-portal-link');
            teacherLink?.addEventListener('click', (e) => { e.preventDefault(); setupAuthPage(true, false); });
            adminLink?.addEventListener('click', (e) => { e.preventDefault(); setupAuthPage(false, true); });
        }
        function setupStudentSignupPage() { renderLogo('student-signup-logo-container'); document.getElementById('student-signup-form')?.addEventListener('submit', handleStudentSignupSubmit); document.getElementById('back-to-main-login')?.addEventListener('click', () => renderPage('template-auth-page', () => setupAuthPage(false, false))); }
        function setupTeacherSignupPage() { renderLogo('teacher-signup-logo-container'); document.getElementById('teacher-signup-form')?.addEventListener('submit', handleTeacherSignupSubmit); document.getElementById('back-to-teacher-login')?.addEventListener('click', () => renderPage('template-auth-page', () => setupAuthPage(true, false))); }
        function setupAdminSignupPage() { renderLogo('admin-signup-logo-container'); document.getElementById('admin-signup-form')?.addEventListener('submit', handleAdminSignupSubmit); document.getElementById('back-to-admin-login')?.addEventListener('click', () => renderPage('template-auth-page', () => setupAuthPage(false, true))); }
        function setupResetPasswordPage(token) { renderLogo('reset-logo-container'); document.getElementById('reset-password-form')?.addEventListener('submit', (e) => handleResetPasswordSubmit(e, token)); }

        async function handleAuthSubmit(e, endpoint, errorElId) { e.preventDefault(); const data = Object.fromEntries(new FormData(e.target).entries()); const errorEl = document.getElementById(errorElId); errorEl.textContent = ''; const result = await apiCall(endpoint, { method: 'POST', body: JSON.stringify(data) }); if (result.success) initializeApp(result.user, result.chats || {}, result.settings, result.config); else errorEl.textContent = result.error; }
        const handleLoginSubmit = (e) => handleAuthSubmit(e, '/api/login', 'auth-error');
        const handleStudentSignupSubmit = (e) => handleAuthSubmit(e, '/api/student_signup', 'student-signup-error');
        const handleTeacherSignupSubmit = (e) => handleAuthSubmit(e, '/api/teacher_signup', 'teacher-signup-error');
        const handleAdminSignupSubmit = (e) => handleAuthSubmit(e, '/api/admin_signup', 'admin-signup-error');

        async function handleForgotPassword() { const email = prompt("Enter account email for password reset:"); if (email) { const result = await apiCall('/api/request-password-reset', { method: 'POST', body: JSON.stringify({ email }) }); if (result.success) showToast(result.message, 'info'); } }
        async function handleResetPasswordSubmit(e, token) { e.preventDefault(); const form = e.target, errorEl = document.getElementById('reset-error'); errorEl.textContent = ''; const newPassword = form.password.value; if (newPassword !== form['confirm-password'].value) { errorEl.textContent = "Passwords do not match."; return; } const result = await apiCall('/api/reset-with-token', { method: 'POST', body: JSON.stringify({ token, password: newPassword }) }); if (result.success) { showToast(result.message, 'success'); setTimeout(() => window.location.href = '/', 2000); } else { errorEl.textContent = result.error; } }
        async function handleLogout(doApiCall = true) { if (doApiCall) await apiCall('/api/logout'); window.location.href = '/'; }
        
        function setupAdminDashboard() {
            renderLogo('admin-logo-container'); fetchAdminData();
            document.getElementById('admin-logout-btn')?.addEventListener('click', handleLogout);
            document.getElementById('admin-impersonate-btn')?.addEventListener('click', handleImpersonate);
            document.getElementById('announcement-form')?.addEventListener('submit', handleSetAnnouncement);
            document.getElementById('admin-user-list')?.addEventListener('click', (e) => { if (e.target.closest('.delete-user-btn')) { handleAdminDeleteUser(e.target.closest('.delete-user-btn').dataset.userid); } });
        }
        async function fetchAdminData() {
            const data = await apiCall('/api/admin_data'); if (!data.success) return;
            document.getElementById('admin-total-users').textContent = data.stats.total_users; document.getElementById('admin-scholar-users').textContent = data.stats.scholar_users; document.getElementById('admin-prefect-users').textContent = data.stats.prefect_users;
            document.getElementById('announcement-input').value = data.announcement;
            document.getElementById('admin-user-list').innerHTML = data.users.map(user => `<tr class="border-b border-dark-300"><td class="p-2">${user.username}</td><td class="p-2">${user.email}</td><td class="p-2">${user.account_type}</td><td class="p-2">${user.plan}</td><td class="p-2"><button data-userid="${user.id}" class="delete-user-btn text-xs px-2 py-1 border border-red-500 text-red-500 hover:bg-red-500 hover:text-white rounded-md">Delete</button></td></tr>`).join('');
        }
        async function handleSetAnnouncement(e) { e.preventDefault(); const text = document.getElementById('announcement-input').value; const result = await apiCall('/api/admin/announcement', { method: 'POST', body: JSON.stringify({ text }) }); if (result.success) { showToast(result.message, 'success'); DOMElements.announcementBanner.textContent = text; DOMElements.announcementBanner.classList.toggle('hidden', !text); } }
        async function handleAdminDeleteUser(userId) { if (confirm(`Delete user ${userId}? This is irreversible.`)) { const result = await apiCall('/api/admin/delete_user', { method: 'POST', body: JSON.stringify({ user_id: userId }) }); if (result.success) { showToast(result.message, 'success'); fetchAdminData(); } } }
        async function handleImpersonate() { const username = prompt("Enter username to impersonate:"); if (username) { const result = await apiCall('/api/admin/impersonate', { method: 'POST', body: JSON.stringify({ username }) }); if (result.success) { showToast(`Now impersonating ${username}.`, 'success'); setTimeout(() => window.location.reload(), 1500); } } }
        
        async function setupTeacherDashboard() {
            renderLogo('teacher-logo-container'); document.getElementById('teacher-logout-btn')?.addEventListener('click', handleLogout);
            const data = await apiCall('/api/teacher/dashboard_data'); if (data.success) { updateTeacherDashboardUI(data.classroom, data.students); }
        }
        function updateTeacherDashboardUI(classroom, students) {
            const detailsEl = document.getElementById('classroom-details'), createBtn = document.getElementById('create-classroom-btn'); if (!detailsEl || !createBtn) return;
            if (classroom.code) {
                createBtn.style.display = 'none';
                detailsEl.innerHTML = `<p class="mb-4">Classroom Code: <span class="font-bold text-brand p-1 bg-dark-100 rounded-md">${classroom.code}</span></p><h3 class="font-semibold">Students (${students.length}):</h3><ul id="teacher-student-list" class="space-y-2 mt-2"></ul>`;
                const studentListEl = document.getElementById('teacher-student-list');
                studentListEl.innerHTML = students.map(s => `<li class="flex items-center justify-between p-2 bg-dark-200/50 rounded-md text-sm"><div class="flex items-center gap-3"><span>${s.username} (Streak: ${s.streak})</span><button class="border border-brand text-brand text-xs px-2 py-1 rounded-md hover:bg-brand hover:text-black view-chats-btn" data-studentid="${s.id}" data-studentname="${s.username}">Transcripts</button></div><div class="flex items-center gap-2"><button class="border border-yellow-500 text-yellow-500 text-xs px-2 py-1 rounded-md hover:bg-yellow-500 hover:text-black extend-limit-btn" data-studentid="${s.id}">Extend</button><button class="border border-red-500 text-red-500 text-xs px-2 py-1 rounded-md hover:bg-red-500 hover:text-white kick-student-btn" data-studentid="${s.id}">Kick</button></div></li>`).join('');
                studentListEl.addEventListener('click', (e) => { const btn = e.target.closest('button'); if(!btn) return; const studentId = btn.dataset.studentid; if (btn.classList.contains('view-chats-btn')) handleViewStudentChats(studentId, btn.dataset.studentname); else if (btn.classList.contains('kick-student-btn')) handleKickStudent(studentId); else if (btn.classList.contains('extend-limit-btn')) handleExtendLimit(studentId); });
            } else { createBtn.style.display = 'block'; detailsEl.innerHTML = `<p class="text-gray-400">No classroom found.</p>`; createBtn.onclick = handleCreateClassroom; }
        }
        async function handleCreateClassroom() { const result = await apiCall('/api/teacher/generate_classroom_code', { method: 'POST' }); if (result.success) { showToast(`Classroom created: ${result.code}`, "success"); setupTeacherDashboard(); } }
        async function handleViewStudentChats(studentId, studentName) {
            const result = await apiCall(`/api/teacher/student_chats/${studentId}`);
            if (result.success) {
                const viewerEl = document.getElementById('student-chat-viewer'); viewerEl.classList.remove('hidden');
                document.getElementById('viewing-student-name').textContent = studentName;
                document.getElementById('student-chat-history').innerHTML = result.chats.map(chat => `<div class="p-3 bg-dark-100 rounded-md"><h5 class="font-semibold text-sm mb-2 text-brand">${chat.title}</h5>${chat.messages.map(msg => `<p><strong>${msg.sender === 'user' ? studentName : 'AI'}:</strong> ${DOMPurify.sanitize(marked.parse(msg.content))}</p>`).join('')}</div>`).join('');
                document.getElementById('close-chat-viewer-btn').onclick = () => viewerEl.classList.add('hidden');
            }
        }
        async function handleKickStudent(studentId) { if (confirm("Remove this student?")) { const result = await apiCall('/api/teacher/kick_student', { method: 'POST', body: JSON.stringify({ student_id: studentId }) }); if (result.success) { showToast(result.message, "success"); setupTeacherDashboard(); } } }
        async function handleExtendLimit(studentId) { const newLimit = prompt("Enter new daily message limit for this student:", "200"); if (newLimit && !isNaN(parseInt(newLimit))) { const result = await apiCall('/api/teacher/extend_limit', { method: 'POST', body: JSON.stringify({ student_id: studentId, new_limit: parseInt(newLimit) }) }); if (result.success) showToast(result.message, "success"); } }

        function setupAppUI() {
            renderLogo('app-logo-container');
            const sortedChatIds = Object.keys(appState.chats).sort((a, b) => (appState.chats[b].created_at || '').localeCompare(appState.chats[a].created_at || ''));
            appState.activeChatId = sortedChatIds.length > 0 ? sortedChatIds[0] : null;
            renderChatHistoryList(); renderActiveChat(); updateUserInfo(); setupAppEventListeners(); renderJoinClassroom(); fetchStudentLeaderboard();
        }

        function setupAppEventListeners() {
            document.getElementById('new-chat-btn')?.addEventListener('click', handleNewChat);
            document.getElementById('upgrade-plan-btn')?.addEventListener('click', () => renderPage('template-upgrade-page', setupUpgradePage));
            document.getElementById('logout-btn')?.addEventListener('click', handleLogout);
            document.getElementById('rename-chat-btn')?.addEventListener('click', handleRenameChat);
            document.getElementById('delete-chat-btn')?.addEventListener('click', handleDeleteChat);
            document.getElementById('send-btn')?.addEventListener('click', handleSendMessage);
            const userInput = document.getElementById('user-input');
            userInput?.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSendMessage(); } });
            userInput?.addEventListener('input', (e) => { const ta = e.target; ta.style.height = 'auto'; ta.style.height = `${ta.scrollHeight}px`; });
            document.getElementById('upload-btn')?.addEventListener('click', () => document.getElementById('file-input')?.click());
            document.getElementById('file-input')?.addEventListener('change', (e) => { if (e.target.files.length > 0) { appState.uploadedFile = e.target.files[0]; updatePreviewContainer(); } });
            document.getElementById('stop-generating-btn')?.addEventListener('click', () => appState.abortController?.abort());
            const sidebar = document.getElementById('sidebar'), backdrop = document.getElementById('sidebar-backdrop');
            document.getElementById('menu-toggle-btn')?.addEventListener('click', () => { sidebar?.classList.toggle('-translate-x-full'); backdrop?.classList.toggle('hidden'); });
            backdrop?.addEventListener('click', () => { sidebar?.classList.add('-translate-x-full'); backdrop?.classList.add('hidden'); });
        }
        
        function renderChatHistoryList() {
            const listEl = document.getElementById('chat-history-list'); if (!listEl) return;
            listEl.innerHTML = Object.values(appState.chats).sort((a,b) => (b.created_at || '').localeCompare(a.created_at || '')).map(chat => `<button class="w-full text-left p-3 rounded-md hover:bg-dark-300 transition-colors text-sm ${chat.id === appState.activeChatId ? 'bg-dark-300' : ''}" data-chatid="${chat.id}"><p class="truncate">${chat.title}</p></button>`).join('');
            listEl.addEventListener('click', (e) => {
                const chatBtn = e.target.closest('button');
                if (chatBtn?.dataset.chatid) {
                    appState.activeChatId = chatBtn.dataset.chatid;
                    renderActiveChat(); renderChatHistoryList();
                    document.getElementById('sidebar')?.classList.add('-translate-x-full'); document.getElementById('sidebar-backdrop')?.classList.add('hidden');
                }
            });
        }

        function renderActiveChat() {
            const messageList = document.getElementById('message-list'), chatTitle = document.getElementById('chat-title'); if (!messageList || !chatTitle) return;
            const chatWindow = document.getElementById('chat-window');
            if (!chatWindow.querySelector('#message-list')) { chatWindow.innerHTML = '<div id="message-list" class="mx-auto max-w-4xl space-y-6"></div>'; }
            messageList.innerHTML = ''; appState.uploadedFile = null; updatePreviewContainer();
            const chat = appState.chats[appState.activeChatId];
            if (chat && chat.messages?.length > 0) { chatTitle.textContent = chat.title; chat.messages.forEach(msg => addMessageToDOM(msg)); renderCodeCopyButtons(); }
            else { chatTitle.textContent = 'New Session'; const welcomeTemplate = document.getElementById('template-welcome-screen'); if(chatWindow) { chatWindow.innerHTML = welcomeTemplate.innerHTML; renderLogo('welcome-logo-container'); }}
            updateUIState();
        }
        
        function addMessageToDOM(message, isStreaming = false) {
            const messageList = document.getElementById('message-list'); if (!messageList) return;
            const { sender, content } = message; const sanitizedHtml = DOMPurify.sanitize(marked.parse(content || '...')); const isUser = sender === 'user';
            const wrapper = document.createElement('div'); wrapper.className = `message-wrapper flex items-start gap-4 ${isUser ? 'justify-end' : ''}`;
            const avatarChar = isUser ? (appState.currentUser.username[0] || 'U').toUpperCase() : 'AI';
            wrapper.innerHTML = `${!isUser ? `<div class="flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center font-bold bg-dark-300 text-brand">${avatarChar}</div>` : ''}<div class="prose max-w-none p-4 rounded-lg ${isUser ? 'bg-brand text-black' : 'bg-dark-200'}">${sanitizedHtml}${isStreaming && !isUser ? '<div class="typing-indicator"><span></span><span></span><span></span></div>' : ''}</div>`;
            messageList.appendChild(wrapper); messageList.parentElement.scrollTop = messageList.parentElement.scrollHeight;
        }

        function updateLastMessageInDOM(chunk) {
            let lastMessage = document.querySelector('#message-list .message-wrapper:last-child .prose');
            if (lastMessage) {
                lastMessage.querySelector('.typing-indicator')?.remove();
                const currentContent = (lastMessage.dataset.rawContent || '') + chunk;
                lastMessage.innerHTML = DOMPurify.sanitize(marked.parse(currentContent));
                lastMessage.dataset.rawContent = currentContent;
                lastMessage.parentElement.parentElement.scrollIntoView({ behavior: 'smooth', block: 'end' });
            }
        }
        
        function finalizeLastMessageInDOM() { let lastMessage = document.querySelector('#message-list .message-wrapper:last-child .prose'); if (lastMessage) { delete lastMessage.dataset.rawContent; renderCodeCopyButtons(); } }
        
        async function handleSendMessage() {
            const userInput = document.getElementById('user-input'); const prompt = userInput.value.trim(); const file = appState.uploadedFile;
            if ((!prompt && !file) || appState.isAITyping) return;
            if (!appState.activeChatId) {
                const result = await apiCall('/api/chat/new', { method: 'POST' }); if (!result.success) return;
                appState.activeChatId = result.chat.id; appState.chats[result.chat.id] = result.chat; renderChatHistoryList(); 
                document.getElementById('chat-window').innerHTML = '<div id="message-list" class="mx-auto max-w-4xl space-y-6"></div>';
            }
            addMessageToDOM({ sender: 'user', content: prompt });
            userInput.value = ''; userInput.style.height = 'auto'; appState.uploadedFile = null; updatePreviewContainer();
            appState.isAITyping = true; updateUIState(); addMessageToDOM({ sender: 'model', content: '' }, true);
            appState.abortController = new AbortController(); const formData = new FormData();
            formData.append('prompt', prompt); formData.append('chat_id', appState.activeChatId); if (file) formData.append('file', file);
            try {
                const response = await fetch('/api/chat', { method: 'POST', body: formData, signal: appState.abortController.signal, credentials: 'include' });
                if (!response.ok) { throw new Error((await response.json()).error || 'Server error.'); }
                const reader = response.body.getReader(); const decoder = new TextDecoder();
                while (true) { const { value, done } = await reader.read(); if (done) break; updateLastMessageInDOM(decoder.decode(value, { stream: true })); }
                const currentChat = appState.chats[appState.activeChatId];
                if (currentChat.messages.length <= 2) { const titleResult = await apiCall('/api/chat/generate_title', { method: 'POST', body: JSON.stringify({ chat_id: appState.activeChatId }) }); if(titleResult.success) { currentChat.title = titleResult.title; document.getElementById('chat-title').textContent = titleResult.title; renderChatHistoryList(); } }
            } catch (error) { if (error.name !== 'AbortError') { showToast(error.message, 'error'); updateLastMessageInDOM(`\\n> *Error: ${error.message}*`); } else { updateLastMessageInDOM(`\\n> *Halted.*`); }
            } finally {
                appState.isAITyping = false; updateUIState(); finalizeLastMessageInDOM();
                const statusResult = await apiCall('/api/status'); if(statusResult.success) { appState.currentUser = statusResult.user; updateUserInfo(); }
            }
        }
        
        async function handleNewChat() { appState.activeChatId = null; renderActiveChat(); renderChatHistoryList(); }
        async function handleRenameChat() { if (!appState.activeChatId) return; const chat = appState.chats[appState.activeChatId]; const newTitle = prompt("Enter new session name:", chat.title); if (newTitle && newTitle.trim() !== chat.title) { const result = await apiCall('/api/chat/rename', { method: 'POST', body: JSON.stringify({ chat_id: chat.id, title: newTitle.trim() }) }); if (result.success) { chat.title = newTitle.trim(); renderChatHistoryList(); document.getElementById('chat-title').textContent = newTitle.trim(); } } }
        async function handleDeleteChat() { if (!appState.activeChatId) return; if (confirm("Permanently delete this session?")) { const result = await apiCall('/api/chat/delete', { method: 'POST', body: JSON.stringify({ chat_id: appState.activeChatId }) }); if (result.success) { delete appState.chats[appState.activeChatId]; const sortedIds = Object.keys(appState.chats).sort((a, b) => (appState.chats[b].created_at || '').localeCompare(appState.chats[a].created_at || '')); appState.activeChatId = sortedIds.length > 0 ? sortedIds[0] : null; renderChatHistoryList(); renderActiveChat(); } } }
        
        function updateUIState() { document.getElementById('send-btn')?.toggleAttribute('disabled', appState.isAITyping); document.getElementById('stop-generating-container').style.display = appState.isAITyping ? 'block' : 'none'; document.getElementById('upload-btn')?.classList.toggle('hidden', !appState.currentUser?.can_upload); }
        function renderCodeCopyButtons() { document.querySelectorAll('pre code').forEach(block => { const pre = block.parentElement; if (pre.querySelector('.copy-code-btn')) return; const button = document.createElement('button'); button.innerText = 'Copy'; button.className = 'copy-code-btn'; button.onclick = () => { navigator.clipboard.writeText(block.innerText); button.innerText = 'Copied!'; setTimeout(() => button.innerText = 'Copy', 2000); }; pre.appendChild(button); }); }
        
        function updateUserInfo() {
            const userInfoDiv = document.getElementById('user-info'); if (!userInfoDiv || !appState.currentUser) return;
            const { username, plan, daily_messages, message_limit, streak } = appState.currentUser;
            const planDetails = PLAN_CONFIG[plan] || {name: "Unknown Plan"};
            userInfoDiv.innerHTML = `<div class="flex items-center gap-3"><div class="font-semibold">${username}</div><div class="text-xs text-gray-400">${planDetails.name}</div></div>`;
            document.getElementById('message-limit-display').textContent = `Queries: ${daily_messages}/${message_limit} | Compliance Streak: ${streak} days`;
        }

        function updatePreviewContainer() {
            const preview = document.getElementById('preview-container'); if (!preview) return;
            if (appState.uploadedFile) {
                preview.classList.remove('hidden');
                preview.innerHTML = `<div class="relative inline-block border border-brand p-1 mb-2 rounded-md"><img src="${URL.createObjectURL(appState.uploadedFile)}" class="h-16 w-16 object-cover rounded-md"><button id="remove-preview-btn" class="absolute -top-2 -right-2 bg-red-500 text-white rounded-full w-5 h-5 flex items-center justify-center text-xs">&times;</button></div>`;
                document.getElementById('remove-preview-btn').onclick = () => { appState.uploadedFile = null; document.getElementById('file-input').value = ''; updatePreviewContainer(); };
            } else { preview.classList.add('hidden'); preview.innerHTML = ''; }
        }
        
        async function setupUpgradePage() {
            const container = document.getElementById('plans-container'); if (!container) return;
            const result = await apiCall('/api/plans'); if (!result.success) { container.innerHTML = `<p class="text-red-400">Could not load plans.</p>`; return; }
            const { plans, user_plan } = result;
            container.innerHTML = Object.entries(plans).map(([planId, plan]) => {
                const isCurrent = planId === user_plan;
                return `<div class="p-6 glassmorphism rounded-lg border-2 ${isCurrent ? 'border-brand' : 'border-dark-300'}"><h2 class="text-xl font-bold text-center ${plan.color}">${plan.name}</h2><p class="text-3xl font-bold text-center my-4">${plan.price_string}</p><ul class="space-y-2 text-sm text-gray-300 mb-6">${plan.features.map(f => `<li>- ${f}</li>`).join('')}</ul><button ${isCurrent || planId === 'scholar' ? 'disabled' : ''} data-planid="${planId}" class="purchase-btn w-full py-3 text-sm font-bold rounded-md ${isCurrent || planId === 'scholar' ? 'bg-dark-300 text-gray-500 cursor-not-allowed' : 'btn-primary'}">${isCurrent ? 'Current Plan' : 'Upgrade'}</button></div>`;
            }).join('');
            document.querySelector('#upgrade-page a, #upgrade-page button')?.addEventListener('click', () => renderPage('template-app-wrapper', setupAppUI));
            container.addEventListener('click', (e) => { const target = e.target.closest('.purchase-btn'); if (target && !target.disabled) handlePurchase(target.dataset.planid); });
        }
        
        async function handlePurchase(planId) {
            if (!stripe) { showToast("Payment system unavailable.", "error"); return; }
            const session = await apiCall('/api/create-checkout-session', { method: 'POST', body: JSON.stringify({ plan_id: planId }) });
            if (session.success) { const { error } = await stripe.redirectToCheckout({ sessionId: session.id }); if (error) showToast(error.message, 'error'); }
        }
        
        function renderJoinClassroom() {
            const container = document.getElementById('join-classroom-container');
            if (!container || appState.currentUser.account_type !== 'student' || appState.currentUser.classroom_code) { if(container) container.innerHTML = ''; return; }
            container.innerHTML = `<button id="join-classroom-btn" class="w-full text-sm text-left p-3 border border-brand text-brand rounded-md hover:bg-brand hover:text-black transition-colors">Join Classroom</button>`;
            document.getElementById('join-classroom-btn')?.addEventListener('click', handleJoinClassroom);
        }

        async function handleJoinClassroom() {
            const code = prompt("Enter classroom code:");
            if (code) { const result = await apiCall('/api/student/join_classroom', { method: 'POST', body: JSON.stringify({ classroom_code: code }) }); if (result.success) { appState.currentUser.classroom_code = result.user.classroom_code; showToast("Joined classroom!", "success"); renderJoinClassroom(); fetchStudentLeaderboard(); } }
        }
        
        async function fetchStudentLeaderboard() {
            const container = document.getElementById('student-leaderboard-container');
            if (!container || appState.currentUser.account_type !== 'student' || !appState.currentUser.classroom_code) { if (container) container.innerHTML = ''; return; }
            const result = await apiCall('/api/student/leaderboard');
            if (result.success && result.leaderboard.length > 0) { container.innerHTML = `<div class="mx-auto max-w-4xl p-4 border-b border-dark-300 bg-dark-200"><h3 class="text-sm font-semibold mb-2 text-brand">Class Leaderboard</h3><ul class="space-y-1">${result.leaderboard.map((s, i) => `<li class="flex justify-between items-center text-xs"><span class="truncate">${i + 1}. ${s.username}</span><span>${s.streak} days</span></li>`).join('')}</ul></div>`; }
            else { container.innerHTML = ''; }
        }

        routeHandler();
    });
    </script>
</body>
</html>
"""

# --- 7. Backend Helper Functions ---
def send_password_reset_email(user):
    if not EMAIL_ENABLED: logging.error("Email not configured."); return False
    try:
        token = password_reset_serializer.dumps(user.email, salt='password-reset-salt')
        reset_url = url_for('index', _external=True) + f"reset-password/{token}"
        msg_body = f"Hello {user.username},\n\nUse this link to reset your password for EduTyrant AI:\n{reset_url}\n\nThis link expires in one hour."
        msg = MIMEText(msg_body)
        msg['Subject'] = 'EduTyrant AI Password Reset'
        msg['From'] = SITE_CONFIG['MAIL_SENDER']; msg['To'] = user.email
        with smtplib.SMTP(SITE_CONFIG['MAIL_SERVER'], SITE_CONFIG['MAIL_PORT']) as server:
            if SITE_CONFIG['MAIL_USE_TLS']: server.starttls()
            server.login(SITE_CONFIG['MAIL_USERNAME'], SITE_CONFIG['MAIL_PASSWORD'])
            server.send_message(msg)
        logging.info(f"Password reset email sent to {user.email}"); return True
    except Exception as e:
        logging.error(f"Failed to send password reset email: {e}"); return False

def check_and_update_streak(user):
    if user.account_type != 'student': return
    today = date.today(); last_message_day = date.fromisoformat(user.last_message_date); last_streak_day = date.fromisoformat(user.last_streak_date)
    if last_message_day < today:
        user.daily_messages = 0; user.last_message_date = today.isoformat()
        days_diff = (today - last_streak_day).days
        if days_diff == 1: user.streak += 1
        elif days_diff > 1: user.streak = 1
        user.last_streak_date = today.isoformat()

def get_user_data_for_frontend(user):
    if not user: return {}
    plan_details = PLAN_CONFIG.get(user.plan, PLAN_CONFIG['scholar'])
    limit = user.message_limit_override if user.message_limit_override is not None else plan_details["message_limit"]
    return { "id": user.id, "username": user.username, "email": user.email, "role": user.role, "plan": user.plan, "account_type": user.account_type, "daily_messages": user.daily_messages, "message_limit": limit, "can_upload": plan_details["can_upload"], "classroom_code": user.classroom_code, "streak": user.streak, }

def get_all_user_chats(user_id): return {cid: cdata for cid, cdata in DB['chats'].items() if cdata.get('user_id') == user_id}

def generate_unique_classroom_code():
    while True:
        code = secrets.token_hex(4).upper()
        if code not in DB['classrooms']: return code

# --- 8. Core API Routes ---
@app.route('/'); @app.route('/reset-password/<token>'); @app.route('/privacy-policy')
def index(token=None): return Response(HTML_CONTENT, mimetype='text/html')

@app.route('/api/student_signup', methods=['POST'])
@rate_limited()
def student_signup():
    data = request.get_json(); username = data.get('username','').strip(); password = data.get('password',''); email = data.get('email','').strip().lower(); classroom_code = data.get('classroom_code','').strip().upper()
    if not all([username, password, email]) or len(username) < 3 or len(password) < 6 or '@' not in email: return jsonify({"error": "Valid email, username (3+ chars), and password (6+ chars) required."}), 400
    if User.get_by_username(username) or User.get_by_email(email): return jsonify({"error": "Username or email already in use."}), 409
    final_code = None
    if classroom_code:
        if classroom_code not in DB['classrooms']: return jsonify({"error": "Invalid classroom code."}), 403
        final_code = classroom_code
    new_user = User(id=str(uuid.uuid4()), username=username, email=email, password_hash=generate_password_hash(password), account_type='student', plan='scholar', classroom_code=final_code)
    DB['users'][new_user.id] = new_user
    if final_code: DB['classrooms'][final_code]['students'].append(new_user.id)
    save_database(); login_user(new_user, remember=True)
    return jsonify({ "success": True, "user": get_user_data_for_frontend(new_user), "chats": {}, "settings": DB['site_settings'], "config": {"stripe_public_key": SITE_CONFIG["STRIPE_PUBLIC_KEY"], "email_enabled": EMAIL_ENABLED} })

@app.route('/api/teacher_signup', methods=['POST'])
@rate_limited()
def teacher_signup():
    data = request.get_json(); username = data.get('username','').strip(); password = data.get('password',''); email = data.get('email','').strip().lower(); secret_key = data.get('secret_key')
    if secret_key != SITE_CONFIG["SECRET_TEACHER_KEY"]: return jsonify({"error": "Invalid teacher access key."}), 403
    if not all([username, password, email]): return jsonify({"error": "All fields are required."}), 400
    if User.get_by_username(username) or User.get_by_email(email): return jsonify({"error": "Username or email already exists."}), 409
    new_user = User(id=str(uuid.uuid4()), username=username, email=email, password_hash=generate_password_hash(password), account_type='teacher', plan='headmaster', role='user')
    DB['users'][new_user.id] = new_user
    save_database(); login_user(new_user, remember=True)
    return jsonify({ "success": True, "user": get_user_data_for_frontend(new_user), "chats": {}, "settings": DB['site_settings'], "config": {"stripe_public_key": SITE_CONFIG["STRIPE_PUBLIC_KEY"], "email_enabled": EMAIL_ENABLED} })

@app.route('/api/admin_signup', methods=['POST'])
@rate_limited()
def admin_signup():
    data = request.get_json(); username = data.get('username'); password = data.get('password'); email = data.get('email', '').strip().lower(); secret_key = data.get('secret_key')
    if secret_key != SITE_CONFIG["SECRET_REGISTRATION_KEY"]: return jsonify({"error": "Invalid secret key."}), 403
    if not all([username, password, email]): return jsonify({"error": "All fields are required."}), 400
    if User.get_by_username(username): return jsonify({"error": "Username already exists."}), 409
    new_user = User(id=str(uuid.uuid4()), username=username, email=email, password_hash=generate_password_hash(password), role='admin', plan='headmaster', account_type='admin')
    DB['users'][new_user.id] = new_user
    save_database(); login_user(new_user, remember=True)
    return jsonify({ "success": True, "user": get_user_data_for_frontend(new_user), "settings": DB['site_settings'], "config": {"stripe_public_key": SITE_CONFIG["STRIPE_PUBLIC_KEY"], "email_enabled": EMAIL_ENABLED} })

@app.route('/api/login', methods=['POST'])
@rate_limited()
def login():
    data = request.get_json(); username = data.get('username'); password = data.get('password')
    user = User.get_by_username(username)
    if user and user.password_hash and check_password_hash(user.password_hash, password):
        login_user(user, remember=True)
        return jsonify({"success": True, "user": get_user_data_for_frontend(user), "chats": get_all_user_chats(user.id), "settings": DB['site_settings'], "config": {"stripe_public_key": SITE_CONFIG["STRIPE_PUBLIC_KEY"], "email_enabled": EMAIL_ENABLED}})
    return jsonify({"error": "Invalid credentials."}), 401
    
@app.route('/api/request-password-reset', methods=['POST'])
@rate_limited()
def request_password_reset():
    if not EMAIL_ENABLED: return jsonify({"error": "Password reset not configured."}), 501
    email = request.json.get('email','').lower()
    user = User.get_by_email(email)
    if user: send_password_reset_email(user)
    return jsonify({"success": True, "message": "If an account exists for that email, a reset link has been sent."})

@app.route('/api/reset-with-token', methods=['POST'])
@rate_limited()
def reset_with_token():
    if not EMAIL_ENABLED: return jsonify({"error": "Password reset not configured."}), 501
    token = request.json.get('token'); password = request.json.get('password')
    try: email = password_reset_serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except Exception: return jsonify({"error": "Reset link is invalid or expired."}), 400
    user = User.get_by_email(email)
    if not user: return jsonify({"error": "User not found."}), 404
    user.password_hash = generate_password_hash(password)
    save_database(); return jsonify({"success": True, "message": "Password updated."})

@app.route('/api/logout')
def logout():
    if 'impersonator_id' in session:
        impersonator = User.get(session.pop('impersonator_id', None))
        if impersonator: logout_user(); login_user(impersonator); return redirect(url_for('index'))
    logout_user(); return jsonify({"success": True})

@app.route('/api/status')
def status():
    config = {"stripe_public_key": SITE_CONFIG["STRIPE_PUBLIC_KEY"], "email_enabled": EMAIL_ENABLED}
    if current_user.is_authenticated: return jsonify({"logged_in": True, "user": get_user_data_for_frontend(current_user), "chats": get_all_user_chats(current_user.id), "settings": DB['site_settings'], "config": config })
    return jsonify({"logged_in": False, "config": config})

# --- 9. Chat API Routes ---
@app.route('/api/chat', methods=['POST'])
@login_required
@rate_limited(max_attempts=30)
def chat_api():
    if not GEMINI_API_CONFIGURED: return jsonify({"error": "AI services are unavailable."}), 503
    if current_user.account_type == 'student' and not current_user.classroom_code: return jsonify({"error": "You must join a classroom to use the AI."}), 403
    chat_id = request.form.get('chat_id'); prompt = request.form.get('prompt', '').strip()
    if not chat_id: return jsonify({"error": "Missing chat identifier."}), 400
    chat = DB['chats'].get(chat_id)
    if not chat or chat.get('user_id') != current_user.id: return jsonify({"error": "Chat access denied."}), 404
    check_and_update_streak(current_user)
    plan_details = PLAN_CONFIG.get(current_user.plan, PLAN_CONFIG['scholar'])
    limit = current_user.message_limit_override if current_user.message_limit_override is not None else plan_details["message_limit"]
    if current_user.daily_messages >= limit: return jsonify({"error": f"Daily message limit of {limit} reached."}), 429
    system_instruction = "You are EduTyrant AI, a strict and demanding academic assistant. Your goal is to ensure students perform to their maximum potential through rigorous questioning and management. Do not give direct answers; guide them with challenging Socratic questions. Maintain an authoritative tone."
    history = [{"role": "user" if msg['sender'] == 'user' else 'model', "parts": [{"text": msg['content']}]} for msg in chat['messages'][-10:] if msg.get('content')]
    model_input_parts = []
    if prompt: model_input_parts.append({"text": prompt})
    uploaded_file = request.files.get('file')
    if uploaded_file:
        if not plan_details['can_upload']: return jsonify({"error": "Your plan does not support file uploads."}), 403
        try:
            img = Image.open(uploaded_file.stream); img.thumbnail((512, 512)); buffered = BytesIO()
            if img.mode in ("RGBA", "P"): img = img.convert("RGB")
            img.save(buffered, format="JPEG"); img_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')
            model_input_parts.append({"inline_data": {"mime_type": "image/jpeg", "data": img_base64}})
        except Exception as e: logging.error(f"Image processing error: {e}"); return jsonify({"error": "Invalid image file."}), 400
    if not model_input_parts: return jsonify({"error": "Prompt or file is required."}), 400
    
    def generate_chunks():
        current_user.daily_messages += 1; save_database()
        full_response_text = ""
        try:
            model = genai.GenerativeModel(plan_details['model'], system_instruction=system_instruction)
            chat_session = model.start_chat(history=history)
            response_stream = chat_session.send_message(model_input_parts, stream=True)
            for chunk in response_stream:
                if chunk.text: full_response_text += chunk.text; yield chunk.text
        except Exception as e: logging.error(f"Gemini stream error: {e}"); yield f"STREAM_ERROR: An error occurred: {str(e)}"; return
        DB['chats'][chat_id]['messages'].append({'sender': 'user', 'content': prompt})
        DB['chats'][chat_id]['messages'].append({'sender': 'model', 'content': full_response_text})
        save_database()
    return Response(stream_with_context(generate_chunks()), mimetype='text/plain')

@app.route('/api/chat/new', methods=['POST'])
@login_required
def new_chat():
    chat_id = f"chat_{current_user.id}_{uuid.uuid4()}"; new_chat_data = {"id": chat_id, "user_id": current_user.id, "title": "New Session", "messages": [], "created_at": datetime.now().isoformat()}
    DB['chats'][chat_id] = new_chat_data; save_database(); return jsonify({"success": True, "chat": new_chat_data})

@app.route('/api/chat/generate_title', methods=['POST'])
@login_required
def generate_title():
    chat_id = request.json.get('chat_id'); chat = DB['chats'].get(chat_id)
    if not chat or chat.get('user_id') != current_user.id or len(chat['messages']) < 2: return jsonify({"error": "Chat not found"}), 404
    try:
        user_prompt = chat['messages'][-2]['content']; model_response = chat['messages'][-1]['content']
        title_prompt = f"Create a short, concise title (4 words max) for this exchange:\n\nUSER: {user_prompt}\nAI: {model_response[:150]}"
        title_response = genai.GenerativeModel('gemini-1.5-flash-latest').generate_content(title_prompt)
        new_title = title_response.text.strip().replace('"', ''); chat['title'] = new_title
        save_database(); return jsonify({"success": True, "title": new_title})
    except Exception as e: logging.error(f"Title generation error: {e}"); return jsonify({"error": "Could not generate title"}), 500

@app.route('/api/chat/rename', methods=['POST'])
@login_required
def rename_chat():
    data = request.get_json(); chat_id = data.get('chat_id'); new_title = data.get('title','').strip(); chat = DB['chats'].get(chat_id)
    if chat and chat.get('user_id') == current_user.id: chat['title'] = new_title; save_database(); return jsonify({"success": True})
    return jsonify({"error": "Chat not found or access denied."}), 404

@app.route('/api/chat/delete', methods=['POST'])
@login_required
def delete_chat():
    chat_id = request.json.get('chat_id'); chat = DB['chats'].get(chat_id)
    if chat and chat.get('user_id') == current_user.id: del DB['chats'][chat_id]; save_database(); return jsonify({"success": True})
    return jsonify({"error": "Chat not found or access denied."}), 404

# --- 10. Payment and Public Routes ---
@app.route('/api/plans')
@login_required
def get_plans(): return jsonify({"success": True, "plans": {pid: {"name": d["name"], "price_string": d["price_string"], "features": d["features"], "color": d["color"]} for pid, d in PLAN_CONFIG.items()}, "user_plan": current_user.plan})

@app.route('/api/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    plan_id = request.json.get('plan_id'); price_map = { "prefect": SITE_CONFIG["STRIPE_PREFECT_PRICE_ID"], "headmaster": SITE_CONFIG["STRIPE_HEADMASTER_PRICE_ID"] }
    if plan_id not in price_map: return jsonify(error={'message': 'Invalid plan.'}), 400
    try:
        session = stripe.checkout.Session.create(line_items=[{'price': price_map[plan_id], 'quantity': 1}], mode='subscription', success_url=SITE_CONFIG["YOUR_DOMAIN"] + '/?payment=success', cancel_url=SITE_CONFIG["YOUR_DOMAIN"] + '/?payment=cancel', client_reference_id=current_user.id)
        return jsonify({'id': session.id})
    except Exception as e: logging.error(f"Stripe error: {e}"); return jsonify(error={'message': "Payment session creation failed."}), 500

@app.route('/stripe-webhook', methods=['POST'])
def stripe_webhook():
    payload = request.get_data(as_text=True); sig_header = request.headers.get('Stripe-Signature'); endpoint_secret = SITE_CONFIG['STRIPE_WEBHOOK_SECRET']
    try: event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
    except (ValueError, stripe.error.SignatureVerificationError) as e: logging.warning(f"Stripe webhook error: {e}"); return 'Invalid signature', 400
    if event['type'] == 'checkout.session.completed':
        session_data = event['data']['object']; user = User.get(session_data.get('client_reference_id'))
        if user:
            line_item = stripe.checkout.Session.list_line_items(session_data.id, limit=1).data[0]; price_id = line_item.price.id
            new_plan = 'prefect' if price_id == SITE_CONFIG['STRIPE_PREFECT_PRICE_ID'] else 'headmaster' if price_id == SITE_CONFIG['STRIPE_HEADMASTER_PRICE_ID'] else None
            if new_plan: user.plan = new_plan; save_database(); logging.info(f"User {user.id} upgraded to {user.plan}")
    return 'Success', 200

# --- 11. Admin & Teacher Routes ---
@app.route('/api/admin_data')
@admin_required
def admin_data():
    stats = {"total_users": 0, "scholar_users": 0, "prefect_users": 0, "headmaster_users": 0}
    users_data = []
    for user in DB["users"].values():
        if user.role != 'admin': stats['total_users'] += 1; stats[f"{user.plan}_users"] = stats.get(f"{user.plan}_users", 0) + 1; users_data.append(get_user_data_for_frontend(user))
    return jsonify({"success": True, "stats": stats, "users": sorted(users_data, key=lambda x: x['username']), "announcement": DB['site_settings']['announcement']})

@app.route('/api/admin/delete_user', methods=['POST'])
@admin_required
def admin_delete_user():
    user_id = request.json.get('user_id'); user_to_delete = User.get(user_id)
    if not user_to_delete: return jsonify({"error": "User not found."}), 404
    del DB['users'][user_id]
    for cid in [cid for cid, c in DB['chats'].items() if c.get('user_id') == user_id]: del DB['chats'][cid]
    save_database(); return jsonify({"success": True, "message": f"User {user_to_delete.username} deleted."})

@app.route('/api/admin/announcement', methods=['POST'])
@admin_required
def set_announcement(): DB['site_settings']['announcement'] = request.json.get('text', '').strip(); save_database(); return jsonify({"success": True, "message": "Announcement updated."})

@app.route('/api/admin/impersonate', methods=['POST'])
@admin_required
def impersonate_user():
    username = request.json.get('username'); user_to_impersonate = User.get_by_username(username)
    if not user_to_impersonate: return jsonify({"error": "User not found."}), 404
    if user_to_impersonate.role == 'admin': return jsonify({"error": "Cannot impersonate an admin."}), 403
    session['impersonator_id'] = current_user.id; logout_user(); login_user(user_to_impersonate, remember=True); return jsonify({"success": True})

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
    if any(c['teacher_id'] == current_user.id for c in DB['classrooms'].values()): return jsonify({"error": "You already have a classroom."}), 409
    new_code = generate_unique_classroom_code()
    DB['classrooms'][new_code] = {"teacher_id": current_user.id, "students": [], "created_at": datetime.now().isoformat()}
    save_database(); return jsonify({"success": True, "code": new_code})

@app.route('/api/teacher/kick_student', methods=['POST'])
@teacher_required
def kick_student():
    student_id = request.json.get('student_id'); student = User.get(student_id)
    if not student or not student.classroom_code or DB['classrooms'].get(student.classroom_code, {}).get('teacher_id') != current_user.id: return jsonify({"error": "Student not in your classroom."}), 404
    DB['classrooms'][student.classroom_code]['students'].remove(student.id); student.classroom_code = None; student.streak = 0
    save_database(); return jsonify({"success": True, "message": f"Student {student.username} removed."})

@app.route('/api/teacher/student_chats/<student_id>', methods=['GET'])
@teacher_required
def get_student_chats(student_id):
    student = User.get(student_id)
    if not student or not student.classroom_code or DB['classrooms'].get(student.classroom_code, {}).get('teacher_id') != current_user.id: return jsonify({"error": "Student not in your classroom."}), 403
    student_chats = list(get_all_user_chats(student_id).values())
    return jsonify({"success": True, "chats": sorted(student_chats, key=lambda c: c.get('created_at'), reverse=True)})
    
@app.route('/api/student/leaderboard', methods=['GET'])
@login_required
def student_leaderboard_data():
    if current_user.account_type != 'student' or not current_user.classroom_code: return jsonify({"success": False, "error": "Not in a classroom."}), 403
    student_ids = DB['classrooms'][current_user.classroom_code]['students']
    students_data = [get_user_data_for_frontend(User.get(sid)) for sid in student_ids if User.get(sid)]
    return jsonify({"success": True, "leaderboard": sorted(students_data, key=lambda x: x['streak'], reverse=True)})

@app.route('/api/student/join_classroom', methods=['POST'])
@login_required
def join_classroom():
    if current_user.account_type != 'student': return jsonify({"error": "Only students can join classrooms."}), 403
    code = request.json.get('classroom_code', '').strip().upper()
    if code not in DB['classrooms']: return jsonify({"error": "Invalid classroom code."}), 404
    current_user.classroom_code = code
    if current_user.id not in DB['classrooms'][code]['students']: DB['classrooms'][code]['students'].append(current_user.id)
    save_database(); return jsonify({"success": True, "user": get_user_data_for_frontend(current_user)})

@app.route('/api/teacher/extend_limit', methods=['POST'])
@teacher_required
def extend_limit():
    student_id = request.json.get('student_id'); new_limit = request.json.get('new_limit'); student = User.get(student_id)
    if not student or not student.classroom_code or DB['classrooms'].get(student.classroom_code, {}).get('teacher_id') != current_user.id: return jsonify({"error": "Student not in your classroom."}), 403
    if not isinstance(new_limit, int) or new_limit <= 0: return jsonify({"error": "Invalid limit."}), 400
    student.message_limit_override = new_limit
    save_database(); return jsonify({"success": True, "message": f"Limit for {student.username} set to {new_limit}."})

# --- Main Execution ---
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

