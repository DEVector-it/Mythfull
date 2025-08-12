import os
import json
import logging
import base64
import time
import uuid
import secrets
import requests
from io import BytesIO
from flask import Flask, Response, request, stream_with_context, session, jsonify, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
import stripe
from PIL import Image
from flask_mail import Mail, Message

# --- 1. Initial Configuration ---
load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Security Check for Essential Keys ---
REQUIRED_KEYS = ['SECRET_KEY', 'DEEPSEEK_API_KEY', 'SECRET_REGISTRATION_KEY', 'SECRET_STUDENT_KEY', 'SECRET_TEACHER_KEY', 'STRIPE_WEBHOOK_SECRET', 'MAIL_SERVER', 'MAIL_USERNAME', 'MAIL_PASSWORD']
for key in REQUIRED_KEYS:
    if not os.environ.get(key):
        logging.critical(f"CRITICAL ERROR: Environment variable '{key}' is not set. Application cannot start securely.")
        exit(f"Error: Missing required environment variable '{key}'. Please set it in your .env file.")

# --- Application Setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
DATABASE_FILE = 'database.json'

# --- Site & API Configuration ---
SITE_CONFIG = {
    "DEEPSEEK_API_KEY": os.environ.get("DEEPSEEK_API_KEY"),
    "DEEPSEEK_API_URL": "https://api.deepseek.com/v1/chat/completions",
    "STRIPE_SECRET_KEY": os.environ.get('STRIPE_SECRET_KEY'),
    "STRIPE_PUBLIC_KEY": os.environ.get('STRIPE_PUBLIC_KEY'),
    "STRIPE_PRO_PRICE_ID": "price_1Ou3jXBSm9qhr9Evw6G6jLd5",  # Example ID, replace with yours
    "STRIPE_ULTRA_PRICE_ID": "price_1Ou4b1BSm9qhr9Ev7bK7f6iF",  # Example ID, replace with yours
    "STRIPE_STUDENT_PRICE_ID": "price_1Ou4cCBSm9qhr9Ev9K7m3O8R",  # Example ID, replace with yours
    "YOUR_DOMAIN": os.environ.get('YOUR_DOMAIN', 'http://localhost:5000'),
    "SECRET_REGISTRATION_KEY": os.environ.get('SECRET_REGISTRATION_KEY'),
    "SECRET_STUDENT_KEY": os.environ.get('SECRET_STUDENT_KEY'),
    "SECRET_TEACHER_KEY": os.environ.get('SECRET_TEACHER_KEY'),
    "STRIPE_WEBHOOK_SECRET": os.environ.get('STRIPE_WEBHOOK_SECRET')
}

stripe.api_key = SITE_CONFIG["STRIPE_SECRET_KEY"]
if not stripe.api_key:
    logging.warning("Stripe Secret Key is not set. Payment flows will fail.")

# --- Mail Configuration for Password Reset ---
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_SENDER', 'Myth AI <noreply@example.com>')
mail = Mail(app)

# --- 2. Database Management ---
DB = {
    "users": {},
    "chats": {},
    "classrooms": {},
    "site_settings": {"announcement": "Welcome! Student and Teacher signups are now available."},
    "reset_tokens": {} # New field for password reset tokens
}

def save_database():
    """Saves the entire in-memory DB to a JSON file atomically."""
    temp_file = f"{DATABASE_FILE}.tmp"
    try:
        with open(temp_file, 'w') as f:
            serializable_db = {
                "users": {uid: user_to_dict(u) for uid, u in DB['users'].items()},
                "chats": DB['chats'],
                "classrooms": DB['classrooms'],
                "site_settings": DB['site_settings'],
                "reset_tokens": DB['reset_tokens'],
            }
            json.dump(serializable_db, f, indent=4)
        os.replace(temp_file, DATABASE_FILE)
    except Exception as e:
        logging.error(f"Failed to save database: {e}")
        if os.path.exists(temp_file):
            os.remove(temp_file)

def load_database():
    """Loads the database from a JSON file if it exists."""
    global DB
    if not os.path.exists(DATABASE_FILE):
        return
    try:
        with open(DATABASE_FILE, 'r') as f:
            data = json.load(f)
            DB['chats'] = data.get('chats', {})
            DB['site_settings'] = data.get('site_settings', {"announcement": ""})
            DB['classrooms'] = data.get('classrooms', {})
            DB['users'] = {uid: User.from_dict(u_data) for uid, u_data in data.get('users', {}).items()}
            DB['reset_tokens'] = data.get('reset_tokens', {})
    except (json.JSONDecodeError, FileNotFoundError) as e:
        logging.error(f"Could not load database file. Starting fresh. Error: {e}")


# --- 3. User and Session Management ---
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.unauthorized_handler
def unauthorized():
    return jsonify({"error": "Login required.", "logged_in": False}), 401

class User(UserMixin):
    def __init__(self, id, username, password_hash, role='user', plan='free', account_type='general', daily_messages=0, last_message_date=None, classrooms=None, streak=0, last_streak_date=None, email=None):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.role = role
        self.plan = plan
        self.account_type = account_type
        self.daily_messages = daily_messages
        self.last_message_date = last_message_date or datetime.now().strftime("%Y-%m-%d")
        self.classrooms = classrooms or []
        self.streak = streak
        self.last_streak_date = last_streak_date or datetime.now().strftime("%Y-%m-%d")
        self.email = email

    @staticmethod
    def get(user_id):
        return DB['users'].get(user_id)

    @staticmethod
    def get_by_username(username):
        for user in DB['users'].values():
            if user.username.lower() == username.lower():
                return user
        return None

    @staticmethod
    def get_by_email(email):
        for user in DB['users'].values():
            if user.email and user.email.lower() == email.lower():
                return user
        return None

    @staticmethod
    def from_dict(data):
        return User(**data)

def user_to_dict(user):
    return {
        'id': user.id, 'username': user.username, 'password_hash': user.password_hash,
        'role': user.role, 'plan': user.plan, 'account_type': user.account_type,
        'daily_messages': user.daily_messages, 'last_message_date': user.last_message_date,
        'classrooms': user.classrooms, 'streak': user.streak,
        'last_streak_date': user.last_streak_date, 'email': user.email
    }

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

def initialize_database_defaults():
    made_changes = False
    if not User.get_by_username('admin'):
        admin_pass = os.environ.get('ADMIN_PASSWORD', 'supersecretadminpassword123')
        admin = User(id='admin', username='admin', password_hash=generate_password_hash(admin_pass), role='admin', plan='ultra', account_type='general')
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
    "free": {"name": "Free", "price_string": "Free", "features": ["15 Daily Messages", "Standard Model Access", "No Image Uploads"], "color": "text-gray-300", "message_limit": 15, "can_upload": False, "model": "deepseek-chat", "can_tts": False, "available_models": ["deepseek-chat"]},
    "pro": {"name": "Pro", "price_string": "$9.99 / month", "features": ["50 Daily Messages", "Image Uploads", "Priority Support", "Voice Chat"], "color": "text-indigo-400", "message_limit": 50, "can_upload": True, "model": "deepseek-chat", "can_tts": True, "available_models": ["deepseek-chat", "deepseek-reasoner"]},
    "ultra": {"name": "Ultra", "price_string": "$100 one-time", "features": ["Unlimited Messages", "Image Uploads", "Access to All Models", "Voice Chat"], "color": "text-purple-400", "message_limit": 10000, "can_upload": True, "model": "deepseek-reasoner", "can_tts": True, "available_models": ["deepseek-chat", "deepseek-reasoner"]},
    "student": {"name": "Student", "price_string": "$4.99 / month", "features": ["50 Daily Messages", "Image Uploads", "Study Buddy Persona", "Streak & Leaderboard", "Practice Mode", "Hardcore Mode"], "color": "text-green-400", "message_limit": 50, "can_upload": True, "model": "deepseek-chat", "can_tts": False, "available_models": ["deepseek-chat", "deepseek-reasoner", "practice-mode", "hardcore-mode"]}
}

# Simple in-memory rate limiting
rate_limit_store = {}
RATE_LIMIT_WINDOW = 60  # seconds

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

def send_password_reset_email(user):
    token = secrets.token_urlsafe(16)
    DB['reset_tokens'][token] = {"user_id": user.id, "expires": time.time() + 3600} # 1 hour expiration
    save_database()
    reset_url = url_for('index', _external=True) + f"?reset_token={token}"
    msg = Message("Password Reset Request",
                  sender=app.config['MAIL_DEFAULT_SENDER'],
                  recipients=[user.email])
    msg.body = f"""Hello {user.username},

To reset your password, visit the following link:
{reset_url}

If you did not make this request, simply ignore this email. This link is valid for 1 hour.

Thank you,
The Myth AI Team
"""
    try:
        mail.send(msg)
        return True
    except Exception as e:
        logging.error(f"Failed to send password reset email to {user.email}: {e}")
        return False


# --- 6. HTML, CSS, and JavaScript Frontend ---
HTML_CONTENT = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Myth AI</title>
    <meta name="description" content="An advanced, feature-rich AI chat application with multiple personas and user roles.">
    <script src="https://js.stripe.com/v3/"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/marked/4.2.12/marked.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/2.4.1/purify.min.js"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
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
        body { background-color: #111827; transition: background-color 0.5s ease; }
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: #1f2937; }
        ::-webkit-scrollbar-thumb { background: #4b5563; border-radius: 10px; }
        .glassmorphism { background: rgba(31, 41, 55, 0.5); backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px); border: 1px solid rgba(255, 255, 255, 0.1); }
        .brand-gradient { background-image: linear-gradient(to right, #3b82f6, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .message-wrapper { animation: fadeIn 0.4s ease-out forwards; }
        pre { position: relative; }
        .copy-code-btn { position: absolute; top: 0.5rem; right: 0.5rem; background-color: #374151; color: white; border: none; padding: 0.25rem 0.5rem; border-radius: 0.25rem; cursor: pointer; opacity: 0; transition: opacity 0.2s; font-size: 0.75rem; }
        pre:hover .copy-code-btn { opacity: 1; }
        #sidebar.hidden { transform: translateX(-100%); }
        /* Study Buddy Theme - Updated for yellow to orange gradient */
        .study-buddy-mode { background-image: linear-gradient(to bottom right, #f59e0b, #ef4444); background-attachment: fixed; background-size: cover; color: #111827; }
        .study-buddy-mode #sidebar { background: rgba(251, 191, 36, 0.7); }
        .study-buddy-mode #chat-window { color: #1f2937; }
        .study-buddy-mode .glassmorphism { background: rgba(253, 230, 138, 0.5); border-color: rgba(253, 186, 116, 0.2); }
        .study-buddy-mode .brand-gradient { background-image: linear-gradient(to right, #92400e, #7c2d12); }
        .study-buddy-mode #send-btn { background-image: linear-gradient(to right, #f97316, #f59e0b); }
        .study-buddy-mode #user-input { color: #1f2937; }
        .study-buddy-mode #user-input::placeholder { color: #44403c; }
        .study-buddy-mode .message-wrapper .font-bold { color: #7c2d12; }
        .study-buddy-mode .ai-avatar { background-image: linear-gradient(to right, #f97316, #f59e0b); }
        .study-buddy-mode ::-webkit-scrollbar-track { background: #fde68a; }
        .study-buddy-mode ::-webkit-scrollbar-thumb { background: #d97706; }
        .study-buddy-mode #sidebar button:hover { background-color: rgba(251, 146, 60, 0.3); }
        .study-buddy-mode #sidebar .bg-blue-600\\/30 { background-color: rgba(249, 115, 22, 0.4); }
        .typing-indicator span { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background-color: currentColor; margin: 0 2px; animation: typing-bounce 1.4s infinite ease-in-out both; }
        .typing-indicator span:nth-child(1) { animation-delay: -0.32s; }
        .typing-indicator span:nth-child(2) { animation-delay: -0.16s; }
        @keyframes typing-bounce { 0%, 80%, 100% { transform: scale(0); } 40% { transform: scale(1.0); } }
    </style>
</head>
<body class="font-sans text-gray-200 antialiased">
    <div id="announcement-banner" class="hidden text-center p-2 bg-indigo-600 text-white text-sm"></div>
    <div id="app-container" class="relative h-screen w-screen"></div>
    <div id="modal-container"></div>
    <div id="toast-container" class="fixed top-6 right-6 z-[100] flex flex-col gap-2"></div>

    <template id="template-logo">
        <svg width="48" height="48" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
            <defs>
                <linearGradient id="logoGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#3b82f6;" />
                    <stop offset="100%" style="stop-color:#8b5cf6;" />
                </linearGradient>
            </defs>
            <path d="M50 10 C 27.9 10 10 27.9 10 50 C 10 72.1 27.9 90 50 90 C 72.1 90 90 72.1 90 50 C 90 27.9 72.1 10 50 10 Z M 50 15 C 69.3 15 85 30.7 85 50 C 85 69.3 69.3 85 50 85 C 30.7 85 15 69.3 15 50 C 15 30.7 30.7 15 50 15 Z" fill="url(#logoGradient)"/>
            <path d="M35 65 L35 35 L50 50 L65 35 L65 65" stroke="white" stroke-width="5" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    </template>

    <template id="template-auth-page">
        <div class="flex flex-col items-center justify-center h-full w-full bg-gray-900 p-4">
            <div class="w-full max-w-md glassmorphism rounded-2xl p-8 shadow-2xl animate-scale-up">
                <div class="flex justify-center mb-6" id="auth-logo-container"></div>
                <h2 class="text-3xl font-bold text-center text-white mb-2" id="auth-title">Welcome Back</h2>
                <p class="text-gray-400 text-center mb-8" id="auth-subtitle">Sign in to continue to Myth AI.</p>
                <form id="auth-form">
                    <div class="mb-4">
                        <label for="username" class="block text-sm font-medium text-gray-300 mb-1">Username</label>
                        <input type="text" id="username" name="username" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all" required>
                    </div>
                    <div class="mb-6">
                        <label for="password" class="block text-sm font-medium text-gray-300 mb-1">Password</label>
                        <input type="password" id="password" name="password" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all" required>
                    </div>
                    <button type="submit" id="auth-submit-btn" class="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:opacity-90 text-white font-bold py-3 px-4 rounded-lg transition-opacity">Login</button>
                    <p id="auth-error" class="text-red-400 text-sm text-center h-4 mt-3"></p>
                </form>
                <div class="text-center mt-6">
                    <button id="auth-toggle-btn" class="text-sm text-blue-400 hover:text-blue-300">Don't have an account? Sign Up</button>
                </div>
                <div class="text-center mt-4">
                    <a href="#" id="forgot-password-link" class="text-sm text-gray-500 hover:text-gray-400">Forgot Password?</a>
                </div>
                <div class="text-center mt-6 border-t border-gray-700 pt-4">
                    <button id="google-login-btn" class="w-full py-3 px-4 bg-gray-700/50 hover:bg-gray-700 rounded-lg flex items-center justify-center gap-2 transition-colors">
                        <svg class="w-5 h-5" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M43.611 20.083H42V20H24v8.083h11.096c-1.125 4.88-5.556 8.528-11.096 8.528-6.66 0-12.083-5.423-12.083-12.083s5.423-12.083 12.083-12.083c3.313 0 6.273 1.344 8.497 3.31l6.471-6.47c-4.464-4.14-10.428-6.68-18.068-6.68C11.968 4 2 13.968 2 26s9.968 22 22 22c12.164 0 20.315-8.625 20.315-22.016 0-1.305-.205-2.671-.444-4.001z" fill="#FFC107"/><path d="M6.306 14.691L14.75 21.018l-.916 2.062c-2.457 5.518-1.57 12.434 2.502 16.506l-4.717 3.656C4.4 39.73 2.19 32.222 2.19 26 2.19 21.68 3.324 17.513 5.485 14.47z" fill="#FBBC05"/><path d="M24 8.083c2.977 0 5.617 1.018 7.708 2.89l-6.471 6.471C26.273 14.507 24.313 14.083 24 14.083c-6.66 0-12.083 5.423-12.083 12.083s5.423 12.083 12.083 12.083c5.486 0 9.877-3.69 11.077-8.528H24V20.083h20.083a21.464 21.464 0 0 0 .444-4.001c-.131-6.643-3.682-12.42-8.918-16.148L31.096 4.77C28.272 2.65 25.109 1.556 21.75 1.556 12.247 1.556 4.3 8.441 4.3 19.34L6.306 14.69z" fill="#4285F4"/><path d="M43.611 20.083H42V20H24v8.083h11.096c-.464 4.88-3.689 8.528-11.096 8.528-6.66 0-12.083-5.423-12.083-12.083s5.423-12.083 12.083-12.083c3.313 0 6.273 1.344 8.497 3.31l6.471-6.471c-4.464-4.14-10.428-6.68-18.068-6.68C11.968 4 2 13.968 2 26s9.968 22 22 22c12.164 0 20.315-8.625 20.315-22.016 0-1.305-.205-2.671-.444-4.001z" fill="#188038"/><path d="M21.75 1.556c-3.359 0-6.522 1.094-9.346 3.214l6.471 6.471c2.224-1.966 5.184-3.31 8.497-3.31 6.66 0 12.083 5.423 12.083 12.083a12.083 12.083 0 0 1-12.083 12.083c-1.285 0-2.529-.26-3.69-.736l-3.084 3.084c4.686 2.668 10.42 2.668 15.106 0 2.224-1.966 4.174-4.57 5.603-7.514a22.087 22.087 0 0 0 3.39-7.917h-20.083z" fill="#34A853"/><path d="M43.611 20.083H42V20H24v8.083h11.096c-.464 4.88-3.689 8.528-11.096 8.528-6.66 0-12.083-5.423-12.083-12.083s5.423-12.083 12.083-12.083c3.313 0 6.273 1.344 8.497 3.31l6.471-6.471c-4.464-4.14-10.428-6.68-18.068-6.68C11.968 4 2 13.968 2 26s9.968 22 22 22c12.164 0 20.315-8.625 20.315-22.016 0-1.305-.205-2.671-.444-4.001z" fill="#EA4335"/><path d="M31.096 4.77C28.272 2.65 25.109 1.556 21.75 1.556 12.247 1.556 4.3 8.441 4.3 19.34L6.306 14.69C4.4 17.513 3.324 21.68 3.324 26c0 7.222 2.19 14.73 6.012 18.397L13.03 40.73c3.83-3.045 4.717-9.962 2.26-15.48L6.306 14.691z" fill="#FFC107"/></svg>
                        Sign in with Google
                    </button>
                </div>
            </div>
            <div class="text-center mt-4 flex justify-center gap-4">
                <button id="student-signup-link" class="text-xs text-gray-500 hover:text-gray-400">Student Sign Up</button>
                <button id="teacher-signup-link" class="text-xs text-gray-500 hover:text-gray-400">Teacher Sign Up</button>
                <button id="special-auth-link" class="text-xs text-gray-500 hover:text-gray-400">Admin Portal</button>
            </div>
        </div>
    </template>

    <template id="template-student-signup-page">
        <div class="flex flex-col items-center justify-center h-full w-full bg-gray-900 p-4">
            <div class="w-full max-w-md glassmorphism rounded-2xl p-8 shadow-2xl animate-scale-up">
                <div class="flex justify-center mb-6" id="student-signup-logo-container"></div>
                <h2 class="text-3xl font-bold text-center text-white mb-2">Student Account Signup</h2>
                <p class="text-gray-400 text-center mb-8">Create a student account. You can join classes later.</p>
                <form id="student-signup-form">
                    <div class="mb-4">
                        <label for="student-username" class="block text-sm font-medium text-gray-300 mb-1">Username</label>
                        <input type="text" id="student-username" name="username" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" required>
                    </div>
                    <div class="mb-4">
                        <label for="student-password" class="block text-sm font-medium text-gray-300 mb-1">Password</label>
                        <input type="password" id="student-password" name="password" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" required>
                    </div>
                    <div class="mb-6">
                        <label for="student-classroom-code" class="block text-sm font-medium text-gray-300 mb-1">Classroom Code (Optional)</label>
                        <input type="text" id="student-classroom-code" name="classroom_code" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600">
                    </div>
                    <button type="submit" class="w-full bg-gradient-to-r from-green-500 to-teal-500 hover:opacity-90 text-white font-bold py-3 px-4 rounded-lg">Create Student Account</button>
                    <p id="student-signup-error" class="text-red-400 text-sm text-center h-4 mt-3"></p>
                </form>
            </div>
            <div class="text-center mt-4">
                <button id="back-to-main-login" class="text-xs text-gray-500 hover:text-gray-400">Back to Main Login</button>
            </div>
        </div>
    </template>

    <template id="template-teacher-signup-page">
        <div class="flex flex-col items-center justify-center h-full w-full bg-gray-900 p-4">
            <div class="w-full max-w-md glassmorphism rounded-2xl p-8 shadow-2xl animate-scale-up">
                <div class="flex justify-center mb-6" id="teacher-signup-logo-container"></div>
                <h2 class="text-3xl font-bold text-center text-white mb-2">Teacher Account Signup</h2>
                <p class="text-gray-400 text-center mb-8">Create a teacher account to manage student progress.</p>
                <form id="teacher-signup-form">
                    <div class="mb-4">
                        <label for="teacher-username" class="block text-sm font-medium text-gray-300 mb-1">Username</label>
                        <input type="text" id="teacher-username" name="username" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" required>
                    </div>
                    <div class="mb-4">
                        <label for="teacher-password" class="block text-sm font-medium text-gray-300 mb-1">Password</label>
                        <input type="password" id="teacher-password" name="password" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" required>
                    </div>
                    <div class="mb-6">
                        <label for="teacher-secret-key" class="block text-sm font-medium text-gray-300 mb-1">Teacher Access Key</label>
                        <input type="password" id="teacher-secret-key" name="secret_key" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" required>
                    </div>
                    <button type="submit" class="w-full bg-gradient-to-r from-blue-500 to-indigo-500 hover:opacity-90 text-white font-bold py-3 px-4 rounded-lg">Create Teacher Account</button>
                    <p id="teacher-signup-error" class="text-red-400 text-sm text-center h-4 mt-3"></p>
                </form>
            </div>
            <div class="text-center mt-4">
                <button id="back-to-main-login" class="text-xs text-gray-500 hover:text-gray-400">Back to Main Login</button>
            </div>
        </div>
    </template>

    <template id="template-forgot-password">
        <div class="flex flex-col items-center justify-center h-full w-full bg-gray-900 p-4">
            <div class="w-full max-w-md glassmorphism rounded-2xl p-8 shadow-2xl animate-scale-up">
                <div class="flex justify-center mb-6" id="forgot-password-logo-container"></div>
                <h2 class="text-3xl font-bold text-center text-white mb-2">Forgot Password</h2>
                <p class="text-gray-400 text-center mb-8">Enter your username to receive a password reset email.</p>
                <form id="forgot-password-form">
                    <div class="mb-4">
                        <label for="forgot-password-username" class="block text-sm font-medium text-gray-300 mb-1">Username</label>
                        <input type="text" id="forgot-password-username" name="username" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" required>
                    </div>
                    <button type="submit" class="w-full bg-gradient-to-r from-orange-500 to-red-500 hover:opacity-90 text-white font-bold py-3 px-4 rounded-lg">Send Reset Link</button>
                    <p id="forgot-password-error" class="text-red-400 text-sm text-center h-4 mt-3"></p>
                </form>
            </div>
            <div class="text-center mt-4">
                <button id="back-to-main-login" class="text-xs text-gray-500 hover:text-gray-400">Back to Main Login</button>
            </div>
        </div>
    </template>
    
    <template id="template-reset-password">
        <div class="flex flex-col items-center justify-center h-full w-full bg-gray-900 p-4">
            <div class="w-full max-w-md glassmorphism rounded-2xl p-8 shadow-2xl animate-scale-up">
                <div class="flex justify-center mb-6" id="reset-password-logo-container"></div>
                <h2 class="text-3xl font-bold text-center text-white mb-2">Reset Password</h2>
                <p class="text-gray-400 text-center mb-8">Enter a new password for your account.</p>
                <form id="reset-password-form">
                    <input type="hidden" name="token" id="reset-password-token">
                    <div class="mb-4">
                        <label for="reset-password" class="block text-sm font-medium text-gray-300 mb-1">New Password</label>
                        <input type="password" id="reset-password" name="new_password" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" required>
                    </div>
                    <div class="mb-6">
                        <label for="confirm-reset-password" class="block text-sm font-medium text-gray-300 mb-1">Confirm New Password</label>
                        <input type="password" id="confirm-reset-password" name="confirm_new_password" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" required>
                    </div>
                    <button type="submit" class="w-full bg-gradient-to-r from-orange-500 to-red-500 hover:opacity-90 text-white font-bold py-3 px-4 rounded-lg">Reset Password</button>
                    <p id="reset-password-error" class="text-red-400 text-sm text-center h-4 mt-3"></p>
                </form>
            </div>
        </div>
    </template>

    <template id="template-app-wrapper">
        <div id="main-app-layout" class="flex h-full w-full transition-colors duration-500">
            <aside id="sidebar" class="bg-gray-900/70 backdrop-blur-lg w-72 flex-shrink-0 flex flex-col p-2 h-full absolute md:relative z-20 transform transition-transform duration-300 ease-in-out -translate-x-full md:translate-x-0">
                <div class="flex-shrink-0 p-2 mb-2 flex items-center gap-3">
                    <div id="app-logo-container"></div>
                    <h1 class="text-2xl font-bold brand-gradient">Myth AI</h1>
                </div>
                <div id="study-mode-toggle-container" class="hidden flex-shrink-0 p-2 mb-2"></div>
                
                <div class="flex-shrink-0"><button id="new-chat-btn" class="w-full text-left flex items-center gap-3 p-3 rounded-lg hover:bg-gray-700/50 transition-colors duration-200"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14" /><path d="M5 12h14" /></svg> New Chat</button></div>
                <div id="chat-history-list" class="flex-grow overflow-y-auto my-4 space-y-1 pr-1"></div>
                <div id="my-classes-section" class="hidden flex-shrink-0 border-t border-gray-700 pt-2 space-y-1">
                    <button id="my-classes-btn" class="w-full text-left flex items-center gap-3 p-3 rounded-lg hover:bg-gray-700/50 transition-colors duration-200"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2H2v8h10V2zM22 2h-8v8h8V2zM12 14H2v8h10v-8zM22 14h-8v8h8v-8z"/></svg> My Classes</button>
                </div>
                
                <div class="flex-shrink-0 border-t border-gray-700 pt-2 space-y-1">
                    <button id="profile-page-btn" class="w-full text-left flex items-center gap-3 p-3 rounded-lg hover:bg-gray-700/50 transition-colors duration-200"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg> Profile</button>
                    <div id="user-info" class="p-3 text-sm"></div>
                    <button id="upgrade-plan-btn" class="w-full text-left flex items-center gap-3 p-3 rounded-lg hover:bg-indigo-500/20 text-indigo-400 transition-colors duration-200"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14m-6-6h12"/></svg> Upgrade Plan</button>
                    <button id="logout-btn" class="w-full text-left flex items-center gap-3 p-3 rounded-lg hover:bg-red-500/20 text-red-400 transition-colors duration-200"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" /><polyline points="16 17 21 12 16 7" /><line x1="21" x2="9" y1="12" y2="12" /></svg> Logout</button>
                </div>
            </aside>
            <div id="sidebar-backdrop" class="fixed inset-0 bg-black/60 z-10 hidden md:hidden"></div>
            <main class="flex-1 flex flex-col bg-gray-800 h-full">
                <header class="flex-shrink-0 p-4 flex items-center justify-between border-b border-gray-700/50">
                    <div class="flex items-center gap-2">
                        <button id="menu-toggle-btn" class="p-2 rounded-lg hover:bg-gray-700/50 transition-colors md:hidden">
                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>
                        </button>
                        <h2 id="chat-title" class="text-xl font-semibold truncate">New Chat</h2>
                    </div>
                    <div class="flex items-center gap-4">
                        <div id="model-selection-container" class="hidden"></div>
                        <button id="share-chat-btn" title="Share Chat" class="p-2 rounded-lg hover:bg-gray-700/50 transition-colors"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8"/><polyline points="16 6 12 2 8 6"/><line x1="12" y1="2" x2="12" y2="15"/></svg></button>
                        <button id="rename-chat-btn" title="Rename Chat" class="p-2 rounded-lg hover:bg-gray-700/50 transition-colors"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" /><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" /></svg></button>
                        <button id="delete-chat-btn" title="Delete Chat" class="p-2 rounded-lg hover:bg-red-500/20 text-red-400 transition-colors"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6" /><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" /><line x1="10" y1="11" x2="10" y2="17" /><line x1="14" y1="11" x2="14" y2="17" /></svg></button>
                        <button id="download-chat-btn" title="Download Chat" class="p-2 rounded-lg hover:bg-gray-700/50 transition-colors"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg></button>
                    </div>
                </header>
                <div id="chat-window" class="flex-1 overflow-y-auto p-4 md:p-6 space-y-6 min-h-0"></div>
                <div class="flex-shrink-0 p-2 md:p-4 md:px-6 border-t border-gray-700/50">
                    <div class="max-w-4xl mx-auto">
                         <div id="student-leaderboard-container" class="glassmorphism p-4 rounded-lg hidden mb-2"></div>
                        <div id="stop-generating-container" class="text-center mb-2" style="display: none;">
                            <button id="stop-generating-btn" class="bg-red-600/50 hover:bg-red-600/80 text-white font-semibold py-2 px-4 rounded-lg transition-colors flex items-center gap-2 mx-auto"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><rect width="10" height="10" x="3" y="3" rx="1"/></svg> Stop Generating</button>
                        </div>
                        <div class="relative glassmorphism rounded-2xl shadow-lg">
                            <div id="preview-container" class="hidden p-2 border-b border-gray-600"></div>
                            <textarea id="user-input" placeholder="Message Myth AI..." class="w-full bg-transparent p-4 pl-14 pr-16 resize-none rounded-2xl focus:outline-none" rows="1"></textarea>
                            <div class="absolute left-3 top-1/2 -translate-y-1/2 flex items-center">
                                <button id="upload-btn" title="Upload Image" class="p-2 rounded-full hover:bg-gray-600/50 transition-colors"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21.2 15c.7-1.2 1-2.5 .7-3.9-.6-2.4-2.4-4.2-4.8-4.8-1.4-.3-2.7 0-3.9.7L12 8l-1.2-1.1c-1.2-.7-2.5-1-3.9-.7-2.4.6-4.2 2.4-4.8 4.8-.3 1.4 0 2.7.7 3.9L4 16.1M12 13l2 3h-4l2-3z"/><circle cx="12" cy="12" r="10"/></svg></button>
                                <input type="file" id="file-input" class="hidden" accept="image/png, image/jpeg, image/webp">
                            </div>
                            <div class="absolute right-3 top-1/2 -translate-y-1/2 flex items-center">
                                <button id="send-btn" class="p-2 rounded-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:opacity-90 transition-opacity disabled:from-gray-500 disabled:to-gray-600 disabled:cursor-not-allowed"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="white"><path d="M2 22l20-10L2 2z"/></svg></button>
                            </div>
                        </div>
                        <div class="text-xs text-gray-400 mt-2 text-center" id="message-limit-display"></div>
                    </div>
                </div>
            </main>
        </div>
    </template>

    <template id="template-profile-page">
        <div class="w-full h-full bg-gray-900 p-4 sm:p-6 md:p-8 overflow-y-auto">
            <header class="flex justify-between items-center mb-8">
                <h1 class="text-3xl font-bold brand-gradient">My Profile</h1>
                <button id="back-to-chat-btn" class="bg-gray-700 hover:bg-gray-600 text-white font-bold py-2 px-4 rounded-lg transition-colors">Back to Chat</button>
            </header>
            <div class="max-w-3xl mx-auto space-y-8">
                <div class="glassmorphism rounded-lg p-6 flex items-center gap-6">
                    <div id="profile-avatar-container" class="flex-shrink-0 w-24 h-24 rounded-full flex items-center justify-center font-bold text-white text-4xl"></div>
                    <div>
                        <h2 id="profile-username" class="text-2xl font-bold text-white"></h2>
                        <p class="text-gray-400">Account Type: <span id="profile-account-type" class="font-semibold"></span></p>
                        <p class="text-gray-400">Plan: <span id="profile-plan" class="font-semibold"></span></p>
                        <p class="text-gray-400">Daily Messages: <span id="profile-daily-messages" class="font-semibold"></span></p>
                    </div>
                </div>
                <div id="profile-plan-details" class="glassmorphism rounded-lg p-6">
                    <h3 class="text-xl font-bold text-white mb-4">Plan Details</h3>
                    <div id="plan-features" class="space-y-2 text-gray-300"></div>
                    <button id="profile-upgrade-btn" class="mt-6 w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:opacity-90 text-white font-bold py-3 px-4 rounded-lg">Upgrade Your Plan</button>
                </div>
            </div>
        </div>
    </template>

    <template id="template-upgrade-page">
        <div class="w-full h-full bg-gray-900 p-4 sm:p-6 md:p-8 overflow-y-auto">
            <header class="flex justify-between items-center mb-8">
                <h1 class="text-3xl font-bold brand-gradient">Choose Your Plan</h1>
                <button id="back-to-chat-btn" class="bg-gray-700 hover:bg-gray-600 text-white font-bold py-2 px-4 rounded-lg transition-colors">Back to Chat</button>
            </header>
            <div id="plans-container" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8 max-w-6xl mx-auto">
                </div>
        </div>
    </template>
    
    <template id="template-admin-dashboard">
        <div class="w-full h-full bg-gray-900 p-4 sm:p-6 md:p-8 overflow-y-auto">
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

            <div class="mb-8 p-6 glassmorphism rounded-lg">
                <h2 class="text-xl font-semibold mb-4 text-white">Site Announcement</h2>
                <form id="announcement-form" class="flex flex-col sm:flex-row gap-2">
                    <input id="announcement-input" type="text" placeholder="Enter announcement text (leave empty to clear)" class="flex-grow p-2 bg-gray-700/50 rounded-lg border border-gray-600">
                    <button type="submit" class="bg-indigo-600 hover:bg-indigo-500 text-white font-bold px-4 py-2 rounded-lg">Set Banner</button>
                </form>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
                <div class="p-6 glassmorphism rounded-lg"><h2 class="text-gray-400 text-lg">Total Users</h2><p id="admin-total-users" class="text-4xl font-bold text-white">0</p></div>
                <div class="p-6 glassmorphism rounded-lg"><h2 class="text-gray-400 text-lg">Pro Users</h2><p id="admin-pro-users" class="text-4xl font-bold text-white">0</p></div>
                <div class="p-6 glassmorphism rounded-lg"><h2 class="text-gray-400 text-lg">Ultra Users</h2><p id="admin-ultra-users" class="text-4xl font-bold text-white">0</p></div>
            </div>

            <div class="p-6 glassmorphism rounded-lg">
                <h2 class="text-xl font-semibold mb-4 text-white">User Management</h2>
                <div class="overflow-x-auto">
                    <table class="w-full text-left">
                        <thead class="border-b border-gray-600">
                            <tr>
                                <th class="p-2">Username</th>
                                <th class="p-2">Role</th>
                                <th class="p-2">Plan</th>
                                <th class="p-2">Account Type</th>
                                <th class="p-2">Daily Messages</th>
                                <th class="p-2">Actions</th>
                            </tr>
                        </thead>
                        <tbody id="admin-user-list"></tbody>
                    </table>
                </div>
            </div>
        </div>
    </template>
    
    <template id="template-modal">
        <div class="modal-backdrop fixed inset-0 bg-black/60 animate-fade-in"></div>
        <div class="modal-content fixed inset-0 flex items-center justify-center p-4">
            <div class="w-full max-w-md glassmorphism rounded-2xl p-8 shadow-2xl animate-scale-up relative">
                <button class="close-modal-btn absolute top-4 right-4 text-gray-400 hover:text-white text-3xl leading-none">&times;</button>
                <h3 id="modal-title" class="text-2xl font-bold text-center mb-4">Modal Title</h3>
                <div id="modal-body" class="text-center text-gray-300">Modal content goes here.</div>
            </div>
        </div>
    </template>

    <template id="template-welcome-screen">
        <div class="flex flex-col items-center justify-center h-full text-center p-4 animate-fade-in">
            <div class="w-24 h-24 mb-6" id="welcome-logo-container"></div>
            <h2 id="welcome-title" class="text-3xl md:text-4xl font-bold mb-4">Welcome to Myth AI</h2>
            <p id="welcome-subtitle" class="text-gray-400 max-w-md">Start a new conversation or select one from the sidebar. How can I help you today?</p>
    
            <div id="model-selection-wrapper" class="flex items-center gap-2 mt-4 hidden">
                <label for="model-select" class="text-gray-400 text-sm">Model:</label>
                <select id="model-select" class="bg-gray-700/50 text-white rounded-lg p-1 text-sm border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500">
                </select>
            </div>
        </div>
    </template>
    
    <template id="template-special-auth-page">
        <div class="flex flex-col items-center justify-center h-full w-full bg-gray-900 p-4">
            <div class="w-full max-w-md glassmorphism rounded-2xl p-8 shadow-2xl animate-scale-up">
                <div class="flex justify-center mb-6" id="special-auth-logo-container"></div>
                <h2 class="text-3xl font-bold text-center text-white mb-2">Special Access Signup</h2>
                <p class="text-gray-400 text-center mb-8">Create an Admin account.</p>
                <form id="special-auth-form">
                    <div class="mb-4">
                        <label for="special-username" class="block text-sm font-medium text-gray-300 mb-1">Username</label>
                        <input type="text" id="special-username" name="username" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" required>
                    </div>
                    <div class="mb-4">
                        <label for="special-password" class="block text-sm font-medium text-gray-300 mb-1">Password</label>
                        <input type="password" id="special-password" name="password" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" required>
                    </div>
                    <div class="mb-6">
                        <label for="secret-key" class="block text-sm font-medium text-gray-300 mb-1">Secret Key</label>
                        <input type="password" id="secret-key" name="secret_key" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" required>
                    </div>
                    <button type="submit" class="w-full bg-gradient-to-r from-purple-600 to-indigo-600 hover:opacity-90 text-white font-bold py-3 px-4 rounded-lg">Create Account</button>
                    <p id="special-auth-error" class="text-red-400 text-sm text-center h-4 mt-3"></p>
                </form>
            </div>
            <div class="text-center mt-4">
                <button id="back-to-main-login" class="text-xs text-gray-500 hover:text-gray-400">Back to Main Login</button>
            </div>
        </div>
    </template>
    
    <template id="template-admin-action-modal">
        <div class="modal-backdrop fixed inset-0 bg-black/60 animate-fade-in"></div>
        <div class="modal-content fixed inset-0 flex items-center justify-center p-4">
            <div class="w-full max-w-sm glassmorphism rounded-2xl p-8 shadow-2xl animate-scale-up relative">
                <button class="close-modal-btn absolute top-4 right-4 text-gray-400 hover:text-white text-3xl leading-none">&times;</button>
                <h3 class="text-2xl font-bold text-center mb-4" id="admin-modal-title"></h3>
                <form id="admin-action-form">
                    <input type="hidden" id="admin-action-user-id" name="user_id">
                    <div class="mb-4 hidden" id="admin-plan-select-container">
                        <label for="admin-plan-select" class="block text-sm font-medium text-gray-300 mb-1">Change Plan</label>
                        <select id="admin-plan-select" name="plan" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600"></select>
                    </div>
                    <button type="submit" id="admin-modal-submit" class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-3 px-4 rounded-lg">Update</button>
                </form>
            </div>
        </div>
    </template>

    <template id="template-teacher-dashboard">
        <div class="w-full h-full bg-gray-900 p-4 sm:p-6 md:p-8 overflow-y-auto">
            <header class="flex flex-wrap justify-between items-center gap-4 mb-8">
                <h1 class="text-3xl font-bold brand-gradient">Teacher Dashboard</h1>
                <div class="flex items-center gap-2">
                    <button id="teacher-create-class-btn" class="bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-2 px-4 rounded-lg transition-colors">Create New Class</button>
                    <button id="teacher-logout-btn" class="bg-red-600 hover:bg-red-500 text-white font-bold py-2 px-4 rounded-lg transition-colors">Logout</button>
                </div>
            </header>
            <div class="glassmorphism rounded-lg p-6 mt-8">
                <h2 class="text-xl font-bold text-white mb-4">My Classes</h2>
                <div id="teacher-classes-list" class="space-y-4">
                    <p class="text-gray-400">You have no classes yet. Create one above.</p>
                </div>
            </div>
            <div class="glassmorphism rounded-lg p-6 mt-8">
                <h2 class="text-xl font-semibold mb-4 text-white">Student Activity</h2>
                <div class="overflow-x-auto">
                    <table class="w-full text-left">
                        <thead class="border-b border-gray-600">
                            <tr>
                                <th class="p-2">Student</th>
                                <th class="p-2">Class</th>
                                <th class="p-2">Plan</th>
                                <th class="p-2">Daily Messages</th>
                                <th class="p-2">Streak</th>
                                <th class="p-2">Last Active</th>
                                <th class="p-2">Actions</th>
                            </tr>
                        </thead>
                        <tbody id="teacher-student-list"></tbody>
                    </table>
                </div>
            </div>
            
            <div class="glassmorphism rounded-lg p-6 mt-8">
                <h2 class="text-xl font-bold text-white mb-4">Student Chats</h2>
                <div id="teacher-student-chats" class="space-y-4">
                    <p class="text-gray-400">Select a student to view their chats.</p>
                </div>
            </div>
        </div>
    </template>

    <template id="template-my-classes-page">
        <div class="w-full h-full bg-gray-900 p-4 sm:p-6 md:p-8 overflow-y-auto">
            <header class="flex justify-between items-center mb-8">
                <h1 class="text-3xl font-bold brand-gradient">My Classes</h1>
                <button id="back-to-chat-btn" class="bg-gray-700 hover:bg-gray-600 text-white font-bold py-2 px-4 rounded-lg transition-colors">Back to Chat</button>
            </header>
            <div class="glassmorphism rounded-lg p-6">
                <div class="flex justify-between items-center mb-4">
                    <h2 class="text-xl font-bold text-white">Joined Classes</h2>
                    <button id="add-class-btn" class="bg-green-600 hover:bg-green-500 text-white font-bold py-2 px-4 rounded-lg transition-colors">Add Class</button>
                </div>
                <div id="my-classes-list" class="space-y-4"></div>
            </div>
        </div>
    </template>

    <script>
/****************************************************************************
 * JAVASCRIPT FRONTEND LOGIC (MYTH AI V3 - DeepSeek & Features)
 ****************************************************************************/
document.addEventListener('DOMContentLoaded', () => {
    const appState = {
        chats: {}, activeChatId: null, isAITyping: false,
        abortController: null, currentUser: null,
        isStudyMode: false, uploadedFile: null,
        teacherData: { classrooms: [], students: [] },
        audio: null,
        selectedModel: 'deepseek-chat',
    };

    const DOMElements = {
        appContainer: document.getElementById('app-container'),
        modalContainer: document.getElementById('modal-container'),
        toastContainer: document.getElementById('toast-container'),
        announcementBanner: document.getElementById('announcement-banner'),
    };

    // --- UTILITY FUNCTIONS ---
    function showToast(message, type = 'info') {
        const colors = { info: 'bg-blue-600', success: 'bg-green-600', error: 'bg-red-600' };
        const toast = document.createElement('div');
        toast.className = `toast text-white text-sm py-2 px-4 rounded-lg shadow-lg animate-fade-in ${colors[type]}`;
        toast.textContent = message;
        DOMElements.toastContainer.appendChild(toast);
        setTimeout(() => toast.remove(), 4000);
    }

    function renderLogo(containerId) {
        const logoTemplate = document.getElementById('template-logo');
        const container = document.getElementById(containerId);
        if (container && logoTemplate) {
            container.innerHTML = '';
            container.appendChild(logoTemplate.content.cloneNode(true));
        }
    }
    
    async function apiCall(endpoint, options = {}) {
        try {
            const response = await fetch(endpoint, {
                ...options,
                credentials: 'include'
            });
            const data = response.headers.get("Content-Type")?.includes("application/json") ? await response.json() : null;
            
            if (!response.ok) {
                if (response.status === 401) handleLogout(false);
                throw new Error(data?.error || `Server error: ${response.statusText}`);
            }
            return { success: true, ...(data || {}) };
        } catch (error) {
            console.error("API Call Error:", error);
            showToast(error.message, 'error');
            return { success: false, error: error.message };
        }
    }

    function openModal(title, bodyContent, onConfirm, confirmText = 'Confirm') {
        const template = document.getElementById('template-modal');
        const modalWrapper = document.createElement('div');
        modalWrapper.id = 'modal-instance';
        modalWrapper.appendChild(template.content.cloneNode(true));
        DOMElements.modalContainer.appendChild(modalWrapper);
        modalWrapper.querySelector('#modal-title').textContent = title;
        const modalBody = modalWrapper.querySelector('#modal-body');
        if (typeof bodyContent === 'string') {
            modalBody.innerHTML = `<p>${bodyContent}</p>`;
        } else {
            modalBody.innerHTML = '';
            modalBody.appendChild(bodyContent);
        }
        if (onConfirm) {
            const confirmBtn = document.createElement('button');
            confirmBtn.className = 'w-full mt-6 bg-blue-600 hover:bg-blue-500 text-white font-bold py-2 px-4 rounded-lg';
            confirmBtn.textContent = confirmText;
            confirmBtn.onclick = () => { onConfirm(); closeModal(); };
            modalBody.appendChild(confirmBtn);
        }
        const closeModal = () => modalWrapper.remove();
        modalWrapper.querySelector('.close-modal-btn').addEventListener('click', closeModal);
        modalWrapper.querySelector('.modal-backdrop').addEventListener('click', closeModal);
    }

    function closeModal() {
        document.getElementById('modal-instance')?.remove();
    }
    
    // --- AUTHENTICATION & INITIALIZATION ---
    function renderAuthPage(isLogin = true) {
        const template = document.getElementById('template-auth-page');
        DOMElements.appContainer.innerHTML = '';
        DOMElements.appContainer.appendChild(template.content.cloneNode(true));
        renderLogo('auth-logo-container');
        
        document.getElementById('auth-title').textContent = isLogin ? 'Welcome Back' : 'Create Account';
        document.getElementById('auth-subtitle').textContent = isLogin ? 'Sign in to continue to Myth AI.' : 'Create a new general account.';
        document.getElementById('auth-submit-btn').textContent = isLogin ? 'Login' : 'Sign Up';
        document.getElementById('auth-toggle-btn').textContent = isLogin ? "Don't have an account? Sign Up" : "Already have an account? Login";

        document.getElementById('auth-toggle-btn').onclick = () => renderAuthPage(!isLogin);
        document.getElementById('student-signup-link').onclick = renderStudentSignupPage;
        document.getElementById('teacher-signup-link').onclick = renderTeacherSignupPage;
        document.getElementById('special-auth-link').onclick = renderSpecialAuthPage;
        document.getElementById('forgot-password-link').onclick = renderForgotPasswordPage;

        document.getElementById('auth-form').onsubmit = async (e) => {
            e.preventDefault();
            const form = e.target;
            const errorEl = document.getElementById('auth-error');
            errorEl.textContent = '';
            const formData = new FormData(form);
            const data = Object.fromEntries(formData.entries());
            
            const endpoint = isLogin ? '/api/login' : '/api/signup';
            
            const result = await apiCall(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data),
            });

            if (result.success) {
                initializeApp(result.user, result.chats, result.settings);
            } else {
                errorEl.textContent = result.error;
            }
        };
    }
    
    function renderSpecialAuthPage() {
        const template = document.getElementById('template-special-auth-page');
        DOMElements.appContainer.innerHTML = '';
        DOMElements.appContainer.appendChild(template.content.cloneNode(true));
        renderLogo('special-auth-logo-container');
        document.getElementById('back-to-main-login').onclick = () => renderAuthPage(true);
        const form = document.getElementById('special-auth-form');
        form.onsubmit = async (e) => {
            e.preventDefault();
            const errorEl = document.getElementById('special-auth-error');
            errorEl.textContent = '';
            const formData = new FormData(form);
            const data = Object.fromEntries(formData.entries());
            const result = await apiCall('/api/special_signup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data),
            });
            if (result.success) {
                initializeApp(result.user, {}, {});
            } else {
                errorEl.textContent = result.error;
            }
        };
    }

    function renderStudentSignupPage() {
        const template = document.getElementById('template-student-signup-page');
        DOMElements.appContainer.innerHTML = '';
        DOMElements.appContainer.appendChild(template.content.cloneNode(true));
        renderLogo('student-signup-logo-container');
        document.getElementById('back-to-main-login').onclick = () => renderAuthPage(true);
        
        document.getElementById('student-signup-form').onsubmit = async (e) => {
            e.preventDefault();
            const form = e.target;
            const errorEl = document.getElementById('student-signup-error');
            errorEl.textContent = '';
            const formData = new FormData(form);
            const data = Object.fromEntries(formData.entries());
            
            const result = await apiCall('/api/student_signup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data),
            });

            if (result.success) {
                initializeApp(result.user, result.chats, result.settings);
            } else {
                errorEl.textContent = result.error;
            }
        };
    }

    function renderTeacherSignupPage() {
        const template = document.getElementById('template-teacher-signup-page');
        DOMElements.appContainer.innerHTML = '';
        DOMElements.appContainer.appendChild(template.content.cloneNode(true));
        renderLogo('teacher-signup-logo-container');
        document.getElementById('back-to-main-login').onclick = () => renderAuthPage(true);
        
        document.getElementById('teacher-signup-form').onsubmit = async (e) => {
            e.preventDefault();
            const form = e.target;
            const errorEl = document.getElementById('teacher-signup-error');
            errorEl.textContent = '';
            const formData = new FormData(form);
            const data = Object.fromEntries(formData.entries());
            
            const result = await apiCall('/api/teacher_signup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data),
            });

            if (result.success) {
                initializeApp(result.user, result.chats, result.settings);
            } else {
                errorEl.textContent = result.error;
            }
        };
    }
    
    function renderForgotPasswordPage() {
        const template = document.getElementById('template-forgot-password');
        DOMElements.appContainer.innerHTML = '';
        DOMElements.appContainer.appendChild(template.content.cloneNode(true));
        renderLogo('forgot-password-logo-container');
        document.getElementById('back-to-main-login').onclick = () => renderAuthPage(true);

        document.getElementById('forgot-password-form').onsubmit = async (e) => {
            e.preventDefault();
            const username = document.getElementById('forgot-password-username').value;
            const errorEl = document.getElementById('forgot-password-error');
            errorEl.textContent = '';
            const result = await apiCall('/api/forgot_password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username }),
            });
            if (result.success) {
                showToast(result.message, 'success');
                renderAuthPage(true); // Redirect back to login
            } else {
                errorEl.textContent = result.error;
            }
        };
    }

    function renderResetPasswordPage(token) {
        const template = document.getElementById('template-reset-password');
        DOMElements.appContainer.innerHTML = '';
        DOMElements.appContainer.appendChild(template.content.cloneNode(true));
        renderLogo('reset-password-logo-container');
        document.getElementById('reset-password-token').value = token;

        document.getElementById('reset-password-form').onsubmit = async (e) => {
            e.preventDefault();
            const newPassword = document.getElementById('reset-password').value;
            const confirmPassword = document.getElementById('confirm-reset-password').value;
            const errorEl = document.getElementById('reset-password-error');
            errorEl.textContent = '';

            if (newPassword !== confirmPassword) {
                errorEl.textContent = "Passwords do not match.";
                return;
            }
            const result = await apiCall('/api/reset_password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: token, new_password: newPassword }),
            });
            if (result.success) {
                showToast(result.message, 'success');
                renderAuthPage(true);
            } else {
                errorEl.textContent = result.error;
            }
        };
    }

    async function checkLoginStatus() {
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.get('payment') === 'success') {
            showToast('Upgrade successful!', 'success');
            window.history.replaceState({}, document.title, "/");
        } else if (urlParams.get('payment') === 'cancel') {
            showToast('Payment was cancelled.', 'info');
            window.history.replaceState({}, document.title, "/");
        }
        if (urlParams.has('reset_token')) {
            renderResetPasswordPage(urlParams.get('reset_token'));
            return;
        }

        const result = await apiCall('/api/status');
        if (result.success && result.logged_in) {
            initializeApp(result.user, result.chats, result.settings);
        } else {
            renderAuthPage();
        }
    }

    function initializeApp(user, chats, settings) {
        appState.currentUser = user;
        appState.chats = chats;
        if (settings.announcement) {
            DOMElements.announcementBanner.textContent = settings.announcement;
            DOMElements.announcementBanner.classList.remove('hidden');
        } else {
            DOMElements.announcementBanner.classList.add('hidden');
        }
        if (user.role === 'admin') {
            renderAdminDashboard();
        } else if (user.account_type === 'teacher') {
            renderTeacherDashboard();
        } else {
            renderAppUI();
        }
    }

    // --- UI RENDERING ---
    function renderAppUI() {
        const template = document.getElementById('template-app-wrapper');
        DOMElements.appContainer.innerHTML = '';
        DOMElements.appContainer.appendChild(template.content.cloneNode(true));
        renderLogo('app-logo-container');
        
        const sortedChatIds = Object.keys(appState.chats).sort((a, b) =>
            (appState.chats[b].created_at || '').localeCompare(appState.chats[a].created_at || '')
        );
        appState.activeChatId = sortedChatIds.length > 0 ? sortedChatIds[0] : null;
        
        // Initialize the selected model from user's plan default
        const planDetails = { ...PLAN_CONFIG[appState.currentUser.plan] };
        appState.selectedModel = planDetails.model;

        renderChatHistoryList();
        renderActiveChat();
        updateUserInfo();
        setupAppEventListeners();
        renderStudyModeToggle();
        renderModelSelection();
        
        // Show My Classes section for students
        if (appState.currentUser.account_type === 'student') {
            document.getElementById('my-classes-section').classList.remove('hidden');
            fetchStudentLeaderboard(); // For the first class or general
        }
    }

    function renderModelSelection() {
        const modelSelectionContainer = document.getElementById('model-selection-container');
        const planDetails = { ...PLAN_CONFIG[appState.currentUser.plan] };

        if (!modelSelectionContainer) return;
        
        if (planDetails.available_models && planDetails.available_models.length > 1) {
            modelSelectionContainer.classList.remove('hidden');
            let selectHtml = `<label for="model-select" class="text-gray-400 text-sm">Model:</label><select id="model-select" class="bg-gray-700/50 text-white rounded-lg p-1 text-sm border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500">`;
            planDetails.available_models.forEach(model => {
                selectHtml += `<option value="${model}" ${model === appState.selectedModel ? 'selected' : ''}>${model}</option>`;
            });
            selectHtml += `</select>`;
            modelSelectionContainer.innerHTML = selectHtml;

            const modelSelect = document.getElementById('model-select');
            if (modelSelect) {
                modelSelect.addEventListener('change', (e) => {
                    appState.selectedModel = e.target.value;
                });
            }
        } else {
            modelSelectionContainer.classList.add('hidden');
        }
    }

    async function renderActiveChat() {
        const chatWindow = document.getElementById('chat-window');
        const chatTitle = document.getElementById('chat-title');
        if (!chatWindow || !chatTitle) return;

        chatWindow.innerHTML = '';
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
        const chatWindow = document.getElementById('chat-window');
        if (!chatWindow) return;
        const template = document.getElementById('template-welcome-screen');
        chatWindow.innerHTML = '';
        chatWindow.appendChild(template.content.cloneNode(true));
        renderLogo('welcome-logo-container');
        
        if (appState.currentUser?.account_type === 'student') {
            const subContainer = document.createElement('div');
            subContainer.className = 'mt-4 text-center';
            if (appState.currentUser.classrooms.length === 0) {
                subContainer.innerHTML = `
                    <p class="text-gray-400 mb-4">You are not part of any classroom yet. Join your teacher's class to see the leaderboard and track your progress.</p>
                    <button id="join-classroom-btn" class="bg-green-600 hover:bg-green-500 text-white font-bold py-2 px-4 rounded-lg transition-colors">Join Classroom</button>
                `;
            }
            chatWindow.appendChild(subContainer);
        }
        
        if (appState.isStudyMode) {
            document.getElementById('welcome-title').textContent = "Welcome to Study Buddy!";
            document.getElementById('welcome-subtitle').textContent = "Let's learn something new. Ask me a question about your homework.";
        } else {
            document.getElementById('welcome-title').textContent = "Welcome to Myth AI";
            document.getElementById('welcome-subtitle').textContent = "How can I help you today?";
        }
        renderModelSelection();
    }

    function renderChatHistoryList() {
        const listEl = document.getElementById('chat-history-list');
        if (!listEl) return;
        listEl.innerHTML = '';
        Object.values(appState.chats)
            .sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''))
            .forEach(chat => {
                const itemWrapper = document.createElement('div');
                itemWrapper.className = `w-full flex items-center justify-between p-3 rounded-lg hover:bg-gray-700/50 transition-colors duration-200 group ${chat.id === appState.activeChatId ? 'bg-blue-600/30' : ''}`;
                
                const chatButton = document.createElement('button');
                chatButton.className = 'flex-grow text-left truncate text-sm font-semibold';
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

                const actionsContainer = document.createElement('div');
                actionsContainer.className = 'flex-shrink-0 flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity';

                // Rename Button
                const renameBtn = document.createElement('button');
                renameBtn.className = 'p-1 rounded-full hover:bg-blue-500/20 text-blue-400';
                renameBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" /><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" /></svg>';
                renameBtn.onclick = (e) => {
                    e.stopPropagation();
                    const newTitle = prompt("Enter a new name for this chat:", chat.title);
                    if (newTitle && newTitle.trim() !== chat.title) {
                        apiCall('/api/chat/rename', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ chat_id: chat.id, title: newTitle.trim() }),
                        }).then(result => {
                            if (result.success) {
                                appState.chats[chat.id].title = newTitle.trim();
                                renderChatHistoryList();
                                if (appState.activeChatId === chat.id) {
                                    document.getElementById('chat-title').textContent = newTitle.trim();
                                }
                                showToast("Chat renamed!", "success");
                            }
                        });
                    }
                };
                actionsContainer.appendChild(renameBtn);

                // Delete Button
                const deleteBtn = document.createElement('button');
                deleteBtn.className = 'p-1 rounded-full hover:bg-red-500/20 text-red-400';
                deleteBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6" /><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" /><line x1="10" y1="11" x2="10" y2="17" /><line x1="14" y1="11" x2="14" y2="17" /></svg>';
                deleteBtn.onclick = (e) => {
                    e.stopPropagation();
                    if (confirm("Are you sure you want to delete this chat? This action cannot be undone.")) {
                        apiCall('/api/chat/delete', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ chat_id: chat.id }),
                        }).then(result => {
                            if (result.success) {
                                const wasActive = appState.activeChatId === chat.id;
                                delete appState.chats[chat.id];
                                if (wasActive) {
                                    const sortedChatIds = Object.keys(appState.chats).sort((a, b) => (appState.chats[b].created_at || '').localeCompare(appState.chats[a].created_at || ''));
                                    appState.activeChatId = sortedChatIds.length > 0 ? sortedChatIds[0] : null;
                                }
                                renderChatHistoryList();
                                if (wasActive) {
                                    renderActiveChat();
                                }
                                showToast("Chat deleted.", "success");
                            }
                        });
                    }
                };
                actionsContainer.appendChild(deleteBtn);

                itemWrapper.appendChild(chatButton);
                itemWrapper.appendChild(actionsContainer);
                listEl.appendChild(itemWrapper);
            });
    }

    function updateUserInfo() {
        const userInfoDiv = document.getElementById('user-info');
        if (!userInfoDiv || !appState.currentUser) return;

        const { username, plan, account_type } = appState.currentUser;
        const planDetails = PLAN_CONFIG[plan] || PLAN_CONFIG['free'];
        const planName = planDetails.name;
        const planColor = planDetails.color;
        const avatarChar = username[0].toUpperCase();
        let avatarColor = `hsl(${username.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0) % 360}, 50%, 60%)`;
        
        if (appState.isStudyMode) {
            avatarColor = `linear-gradient(to right, #f97316, #f59e0b)`;
        }
        
        userInfoDiv.innerHTML = `
            <div class="flex items-center gap-3">
                <div class="flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center font-bold text-white" style="background: ${avatarColor};">
                    ${avatarChar}
                </div>
                <div>
                    <div class="font-semibold">${username}</div>
                    <div class="text-xs ${planColor}">${planName} Plan (${account_type.charAt(0).toUpperCase() + account_type.slice(1)})</div>
                </div>
            </div>`;
        
        const limitDisplay = document.getElementById('message-limit-display');
        if(limitDisplay) limitDisplay.textContent = `Daily Messages: ${appState.currentUser.daily_messages} / ${planDetails.message_limit}`;
    }

    function updateUIState() {
        const sendBtn = document.getElementById('send-btn');
        const stopContainer = document.getElementById('stop-generating-container');
        const chatActionButtons = ['share-chat-btn', 'rename-chat-btn', 'delete-chat-btn', 'download-chat-btn'];
        const uploadBtn = document.getElementById('upload-btn');

        if (sendBtn) sendBtn.disabled = appState.isAITyping;
        if (stopContainer) stopContainer.style.display = appState.isAITyping ? 'block' : 'none';
        
        const chatExists = !!appState.activeChatId;
        chatActionButtons.forEach(id => {
            const btn = document.getElementById(id);
            if (btn) btn.style.display = chatExists ? 'flex' : 'none';
        });

        if (uploadBtn) {
            const planDetails = PLAN_CONFIG[appState.currentUser.plan] || PLAN_CONFIG['free'];
            uploadBtn.style.display = planDetails.can_upload ? 'block' : 'none';
        }
    }

    function renderStudyModeToggle() {
        const container = document.getElementById('study-mode-toggle-container');
        if (!container || appState.currentUser.account_type !== 'student') return;

        container.classList.remove('hidden');
        container.innerHTML = `
            <div class="flex items-center gap-2">
                <label for="model-select" class="text-gray-400 text-sm">Mode:</label>
                <select id="model-select" class="bg-gray-700/50 text-white rounded-lg p-1 text-sm border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500">
                    <option value="deepseek-chat" ${appState.selectedModel === 'deepseek-chat' ? 'selected' : ''}>Standard</option>
                    <option value="practice-mode" ${appState.selectedModel === 'practice-mode' ? 'selected' : ''}>Practice Mode</option>
                    <option value="hardcore-mode" ${appState.selectedModel === 'hardcore-mode' ? 'selected' : ''}>Hardcore Mode</option>
                </select>
            </div>
            <label for="study-mode-toggle" class="flex items-center cursor-pointer p-2 rounded-lg bg-yellow-900/50 border border-yellow-700">
                <div class="relative">
                    <input type="checkbox" id="study-mode-toggle" class="sr-only">
                    <div class="block bg-gray-600 w-14 h-8 rounded-full"></div>
                    <div class="dot absolute left-1 top-1 bg-white w-6 h-6 rounded-full transition"></div>
                </div>
                <div class="ml-3 font-medium text-yellow-300">Study Buddy Mode</div>
            </label>
        `;
        const toggle = document.getElementById('study-mode-toggle');
        const dot = toggle.parentElement.querySelector('.dot');
        const block = toggle.parentElement.querySelector('.block');
        
        toggle.checked = appState.isStudyMode;
        if (appState.isStudyMode) {
            dot.classList.add('translate-x-full');
            block.classList.add('bg-orange-500');
        }

        toggle.addEventListener('change', () => {
            appState.isStudyMode = toggle.checked;
            document.body.classList.toggle('study-buddy-mode', appState.isStudyMode);
            dot.classList.toggle('translate-x-full', appState.isStudyMode);
            block.classList.toggle('bg-orange-500', appState.isStudyMode);
            renderActiveChat();
        });
    }
    
    function updatePreviewContainer() {
        const previewContainer = document.getElementById('preview-container');
        if (!previewContainer) return;

        if (appState.uploadedFile) {
            previewContainer.classList.remove('hidden');
            const objectURL = URL.createObjectURL(appState.uploadedFile);
            previewContainer.innerHTML = `
                <div class="relative inline-block">
                    <img src="${objectURL}" alt="Image preview" class="h-16 w-16 object-cover rounded-md">
                    <button id="remove-preview-btn" class="absolute -top-2 -right-2 bg-red-600 text-white rounded-full w-5 h-5 flex items-center justify-center text-xs">&times;</button>
                </div>
            `;
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

    // --- CHAT LOGIC ---
    async function handleSendMessage() {
        const userInput = document.getElementById('user-input');
        if (!userInput) return;
        const prompt = userInput.value.trim();
        if ((!prompt && !appState.uploadedFile) || appState.isAITyping) return;

        appState.isAITyping = true;
        appState.abortController = new AbortController();
        updateUIState();
        
        try {
            if (!appState.activeChatId) {
                const chatCreated = await createNewChat(false);
                if (!chatCreated) {
                    showToast("Could not start a new chat session.", "error");
                    throw new Error("Chat creation failed.");
                }
            }
            
            if (appState.chats[appState.activeChatId]?.messages.length === 0) {
                document.getElementById('chat-window').innerHTML = '';
            }

            const userMessage = { sender: 'user', content: prompt };
            addMessageToDOM(userMessage);

            const aiMessage = { sender: 'model', content: '' };
            const aiContentEl = addMessageToDOM(aiMessage, true).querySelector('.message-content');

            userInput.value = '';
            userInput.style.height = 'auto';
            
            const fileToSend = appState.uploadedFile;
            appState.uploadedFile = null;
            updatePreviewContainer();

            const formData = new FormData();
            formData.append('chat_id', appState.activeChatId);
            formData.append('prompt', prompt);
            formData.append('is_study_mode', appState.isStudyMode);
            formData.append('model_name', appState.selectedModel);
            if (fileToSend) {
                formData.append('file', fileToSend);
            }

            const response = await fetch('/api/chat', {
                method: 'POST',
                body: formData,
                signal: appState.abortController.signal,
            });

            if (!response.ok) {
                const errorData = await response.json();
                if (response.status === 401) handleLogout(false);
                throw new Error(errorData.error || `Server error: ${response.status}`);
            }

            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let fullResponse = '';
            const chatWindow = document.getElementById('chat-window');

            while (true) {
                const { value, done } = await reader.read();
                if (done) break;
                const chunk = decoder.decode(value, {stream: true});
                fullResponse += chunk;
                aiContentEl.innerHTML = DOMPurify.sanitize(marked.parse(fullResponse + '<span class="animate-pulse">▍</span>'));
                if(chatWindow) chatWindow.scrollTop = chatWindow.scrollHeight;
            }
            
            if (!fullResponse.trim()) {
                fullResponse = "I'm sorry, I couldn't generate a response. Please try again.";
            }

            aiContentEl.innerHTML = DOMPurify.sanitize(marked.parse(fullResponse));
            renderCodeCopyButtons();
            const ttsButton = aiContentEl.parentElement.querySelector('.tts-btn');
            if (ttsButton) ttsButton.style.display = 'block';

            const updatedData = await apiCall('/api/status');
            if (updatedData.success) {
                appState.currentUser = updatedData.user;
                appState.chats = updatedData.chats;
                renderChatHistoryList();
                updateUserInfo();
                const activeChat = appState.chats[appState.activeChatId];
                if (activeChat) {
                    document.getElementById('chat-title').textContent = activeChat.title;
                }
            }
        } catch (err) {
            if (err.name !== 'AbortError') {
                const lastMessage = document.querySelector('#chat-window .message-wrapper:last-child .message-content');
                if (lastMessage) lastMessage.innerHTML = `<p class="text-red-400 mt-2"><strong>Error:</strong> ${err.message}</p>`;
                showToast(err.message, 'error');
            }
        } finally {
            appState.isAITyping = false;
            appState.abortController = null;
            updateUIState();
        }
    }

    function addMessageToDOM(msg, isStreaming = false) {
        const chatWindow = document.getElementById('chat-window');
        if (!chatWindow || !appState.currentUser) return null;

        const wrapper = document.createElement('div');
        wrapper.className = 'message-wrapper flex items-start gap-4';
        const senderIsAI = msg.sender === 'model';
        const avatarChar = senderIsAI ? 'M' : appState.currentUser.username[0].toUpperCase();
        const userAvatarColor = `background-color: hsl(${appState.currentUser.username.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0) % 360}, 50%, 60%)`;

        const aiAvatarSVG = `<svg width="20" height="20" viewBox="0 0 100 100"><path d="M35 65 L35 35 L50 50 L65 35 L65 65" stroke="white" stroke-width="8" fill="none"/></svg>`;
        const userAvatarHTML = `<div class="flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center font-bold text-white" style="${userAvatarColor}">${avatarChar}</div>`;
        const aiAvatarHTML = `<div class="ai-avatar flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center font-bold text-white bg-gradient-to-br from-blue-500 to-indigo-600">${aiAvatarSVG}</div>`;
        
        let ttsButtonHTML = '';
        const canTTS = (appState.currentUser.plan === 'pro' || appState.currentUser.plan === 'ultra');
        if (senderIsAI && canTTS) {
             ttsButtonHTML = `
                <button class="tts-btn p-1 rounded-full text-gray-400 hover:text-white transition-colors" title="Listen to response" style="display: none;">
                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polygon points="10 8 16 12 10 16 10 8"></polygon></svg>
                </button>
            `;
        }

        wrapper.innerHTML = `
            ${senderIsAI ? aiAvatarHTML : userAvatarHTML}
            <div class="flex-1 min-w-0">
                <div class="font-bold flex items-center gap-2">${senderIsAI ? (appState.isStudyMode ? 'Study Buddy' : 'Myth AI') : 'You'} ${ttsButtonHTML}</div>
                <div class="prose prose-invert max-w-none message-content">
                    ${isStreaming ? '<div class="typing-indicator"><span></span><span></span><span></span></div>' : DOMPurify.sanitize(marked.parse(msg.content))}
                </div>
            </div>`;
        chatWindow.appendChild(wrapper);
        chatWindow.scrollTop = chatWindow.scrollHeight;
        
        const ttsBtn = wrapper.querySelector('.tts-btn');
        if (ttsBtn) {
            ttsBtn.onclick = () => handleTTS(msg.content, ttsBtn);
        }

        return wrapper;
    }

    function handleTTS(text, button) {
        showToast("TTS is not yet implemented for the DeepSeek API.", "info");
        button.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polygon points="10 8 16 12 10 16 10 8"></polygon></svg>`;
    }
    
    async function createNewChat(shouldRender = true) {
        const result = await apiCall('/api/chat/new', { method: 'POST' });
        if (result.success) {
            appState.chats[result.chat.id] = result.chat;
            appState.activeChatId = result.chat.id;
            if (shouldRender) {
                renderActiveChat();
                renderChatHistoryList();
            }
            return true;
        }
        return false;
    }

    function renderCodeCopyButtons() {
        document.querySelectorAll('pre').forEach(pre => {
            if (pre.querySelector('.copy-code-btn')) return;
            const button = document.createElement('button');
            button.className = 'copy-code-btn';
            button.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>';
            button.onclick = () => {
                navigator.clipboard.writeText(pre.querySelector('code')?.innerText || '').then(() => {
                    button.innerHTML = 'Copied!';
                    setTimeout(() => button.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>', 2000);
                });
            };
            pre.appendChild(button);
        });
    }

    // --- EVENT LISTENERS & HANDLERS ---
    function setupAppEventListeners() {
        const appContainer = DOMElements.appContainer;
        
        // This single, delegated event listener handles all button clicks.
        appContainer.onclick = (e) => {
            const target = e.target.closest('button');
            if (!target) return;

            switch (target.id) {
                case 'new-chat-btn': createNewChat(true); break;
                case 'logout-btn': handleLogout(); break;
                case 'teacher-logout-btn': handleLogout(); break;
                case 'admin-logout-btn': handleLogout(); break;
                case 'send-btn': handleSendMessage(); break;
                case 'stop-generating-btn': appState.abortController?.abort(); break;
                case 'rename-chat-btn': handleRenameChat(); break;
                case 'delete-chat-btn': handleDeleteChat(); break;
                case 'share-chat-btn': handleShareChat(); break;
                case 'download-chat-btn': handleDownloadChat(); break;
                case 'upgrade-plan-btn': renderUpgradePage(); break;
                case 'profile-page-btn': renderProfilePage(); break;
                case 'back-to-chat-btn': renderAppUI(); break;
                case 'upload-btn': document.getElementById('file-input')?.click(); break;
                case 'menu-toggle-btn': 
                    document.getElementById('sidebar')?.classList.toggle('-translate-x-full');
                    document.getElementById('sidebar-backdrop')?.classList.toggle('hidden');
                    break;
                case 'admin-impersonate-btn': handleImpersonate(); break;
                case 'back-to-main-login': renderAuthPage(true); break;
                case 'teacher-create-class-btn': handleCreateClass(); break;
                case 'copy-code-btn': handleCopyClassroomCode(target.dataset.code); break;
                case 'teacher-edit-class-btn': handleEditClass(target.dataset.code); break;
                case 'teacher-regenerate-code-btn': handleRegenerateClassCode(target.dataset.code); break;
                case 'google-login-btn': window.location.href = '/api/google_login'; break;
                case 'join-classroom-btn': handleJoinClassroom(); break;
                case 'add-class-btn': handleJoinClassroom(); break;
                case 'leave-class-btn': handleLeaveClass(target.dataset.code); break;
                case 'view-leaderboard-btn': handleViewLeaderboard(target.dataset.code); break;
                case 'my-classes-btn': renderMyClassesPage(); break;
            }

            if (target.classList.contains('delete-user-btn')) {
                handleAdminDeleteUser(target.dataset.userid);
            }
            if (target.classList.contains('admin-edit-user-btn')) {
                const { userid, username, plan } = target.dataset;
                openAdminEditModal(userid, username, plan);
            }
            if (target.classList.contains('admin-reset-messages-btn')) {
                handleAdminResetMessages(target.dataset.userid);
            }
            if (target.classList.contains('purchase-btn') && !target.disabled) {
                handlePurchase(target.dataset.planid);
            }
            if (target.classList.contains('view-student-chats-btn')) {
                handleViewStudentChats(target.dataset.userid);
            }
            if (target.classList.contains('kick-student-btn')) {
                handleKickStudent(target.dataset.userid, target.dataset.classcode);
            }
        };

        // These listeners are set up once when the main app UI is rendered.
        const userInput = document.getElementById('user-input');
        if (userInput) {
            userInput.onkeydown = (e) => { 
                if (e.key === 'Enter' && !e.shiftKey) { 
                    e.preventDefault(); 
                    handleSendMessage(); 
                } 
            };
            userInput.oninput = () => { 
                userInput.style.height = 'auto'; 
                userInput.style.height = `${userInput.scrollHeight}px`; 
            };
        }
        
        const backdrop = document.getElementById('sidebar-backdrop');
        if (backdrop) {
            backdrop.onclick = () => {
                document.getElementById('sidebar')?.classList.add('-translate-x-full');
                backdrop.classList.add('hidden');
            };
        }

        const fileInput = document.getElementById('file-input');
        if (fileInput) {
            fileInput.onchange = (e) => {
                if (e.target.files.length > 0) {
                    const planDetails = PLAN_CONFIG[appState.currentUser.plan] || PLAN_CONFIG['free'];
                    if (!planDetails.can_upload) {
                        showToast("Your current plan does not support image uploads.", "error");
                        e.target.value = null;
                        return;
                    }
                    appState.uploadedFile = e.target.files[0];
                    updatePreviewContainer();
                }
            };
        }
        
        const announcementForm = document.getElementById('announcement-form');
        if(announcementForm) {
            announcementForm.onsubmit = handleSetAnnouncement;
        }
    }

    async function handleLogout(doApiCall = true) {
        if(doApiCall) await apiCall('/api/logout');
        appState.currentUser = null;
        appState.chats = {};
        appState.activeChatId = null;
        DOMElements.announcementBanner.classList.add('hidden');
        renderAuthPage();
    }
    
    function handleRenameChat() {
        if (!appState.activeChatId) return;
        const oldTitle = appState.chats[appState.activeChatId].title;
        const newTitle = prompt("Enter a new name for this chat:", oldTitle);
        if (newTitle && newTitle.trim() !== oldTitle) {
            apiCall('/api/chat/rename', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ chat_id: appState.activeChatId, title: newTitle.trim() }),
            }).then(result => {
                if (result.success) {
                    appState.chats[appState.activeChatId].title = newTitle.trim();
                    renderChatHistoryList();
                    document.getElementById('chat-title').textContent = newTitle.trim();
                    showToast("Chat renamed!", "success");
                }
            });
        }
    }

    function handleDeleteChat() {
        if (!appState.activeChatId) return;
        if (confirm("Are you sure you want to delete this chat? This action cannot be undone.")) {
            apiCall('/api/chat/delete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ chat_id: appState.activeChatId }),
            }).then(result => {
                if (result.success) {
                    delete appState.chats[appState.activeChatId];
                    const sortedChatIds = Object.keys(appState.chats).sort((a, b) => (appState.chats[b].created_at || '').localeCompare(appState.chats[a].created_at || ''));
                    appState.activeChatId = sortedChatIds.length > 0 ? sortedChatIds[0] : null;
                    renderChatHistoryList();
                    renderActiveChat();
                    showToast("Chat deleted.", "success");
                }
            });
        }
    }
    
    async function handleShareChat() {
        if (!appState.activeChatId) return;
        const result = await apiCall('/api/chat/share', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: appState.activeChatId }),
        });
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

    async function handleDownloadChat() {
        if (!appState.activeChatId) return;
        const chat = appState.chats[appState.activeChatId];
        if (!chat || chat.messages.length === 0) {
            showToast("No chat content to download.", "info");
            return;
        }

        let content = `# ${chat.title}\\n\\n`;
        chat.messages.forEach(msg => {
            const sender = msg.sender === 'user' ? 'You' : 'AI';
            content += `**${sender}:**\\n${msg.content}\\n\\n`;
        });

        const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `${chat.title.replace(/[^a-z0-9]/gi, '_')}_chat.txt`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        showToast("Chat downloaded!", "success");
    }

    // --- UPGRADE & PAYMENT LOGIC ---
    async function renderUpgradePage() {
        const template = document.getElementById('template-upgrade-page');
        DOMElements.appContainer.innerHTML = '';
        DOMElements.appContainer.appendChild(template.content.cloneNode(true));
        setupAppEventListeners();

        const plansContainer = document.getElementById('plans-container');
        const plansResult = await apiCall('/api/plans');
        if (!plansResult.success) {
            plansContainer.innerHTML = `<p class="text-red-400">Could not load plans.</p>`;
            return;
        }

        const { plans, user_plan } = plansResult;
        plansContainer.innerHTML = '';

        const planOrder = ['free', 'pro', 'ultra', 'student'];
        planOrder.forEach(planId => {
            if (!plans[planId]) return;
            
            const plan = plans[planId];
            const card = document.createElement('div');
            const isCurrentUserPlan = planId === user_plan;
            
            card.className = `p-8 glassmorphism rounded-lg border-2 ${isCurrentUserPlan ? 'border-green-500' : 'border-gray-600'}`;
            card.innerHTML = `
                <h2 class="text-2xl font-bold text-center ${plan.color}">${plan.name}</h2>
                <p class="text-4xl font-bold text-center my-4 text-white">${plan.price_string}</p>
                <ul class="space-y-2 text-gray-300 mb-6">${plan.features.map(f => `<li>✓ ${f}</li>`).join('')}</ul>
                <button ${isCurrentUserPlan || planId === 'free' ? 'disabled' : ''} data-planid="${planId}" class="purchase-btn w-full mt-6 font-bold py-3 px-4 rounded-lg transition-opacity ${isCurrentUserPlan ? 'bg-gray-600 cursor-not-allowed' : 'bg-gradient-to-r from-blue-600 to-indigo-600 hover:opacity-90'}">
                    ${isCurrentUserPlan ? 'Current Plan' : 'Upgrade'}
                </button>
            `;
            plansContainer.appendChild(card);
        });
    }

    async function handlePurchase(planId) {
        try {
            const config = await apiCall('/api/config');
            if (!config.success || !config.stripe_public_key) throw new Error("Could not retrieve payment configuration.");
            
            const stripe = Stripe(config.stripe_public_key);
            const sessionResult = await apiCall('/api/create-checkout-session', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ plan_id: planId })
            });

            if (!sessionResult.success) throw new Error(sessionResult.error || "Could not create payment session.");
            
            const { error } = await stripe.redirectToCheckout({ sessionId: sessionResult.id });
            if (error) showToast(error.message, 'error');

        } catch (error) {
            showToast(error.message, 'error');
        }
    }

    // --- PROFILE PAGE LOGIC ---
    function renderProfilePage() {
        const template = document.getElementById('template-profile-page');
        DOMElements.appContainer.innerHTML = '';
        DOMElements.appContainer.appendChild(template.content.cloneNode(true));
        setupAppEventListeners();

        const user = appState.currentUser;
        const planDetails = PLAN_CONFIG[user.plan] || PLAN_CONFIG['free'];
        
        document.getElementById('profile-username').textContent = user.username;
        document.getElementById('profile-account-type').textContent = user.account_type.charAt(0).toUpperCase() + user.account_type.slice(1);
        document.getElementById('profile-plan').textContent = planDetails.name;
        document.getElementById('profile-daily-messages').textContent = `${user.daily_messages} / ${planDetails.message_limit}`;

        const avatarContainer = document.getElementById('profile-avatar-container');
        const avatarChar = user.username[0].toUpperCase();
        const avatarColor = `hsl(${user.username.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0) % 360}, 50%, 60%)`;
        avatarContainer.textContent = avatarChar;
        avatarContainer.style.background = avatarColor;

        const featuresList = document.getElementById('plan-features');
        featuresList.innerHTML = planDetails.features.map(f => `<li>✓ ${f}</li>`).join('');

        const upgradeBtn = document.getElementById('profile-upgrade-btn');
        if (user.plan === 'ultra') {
            upgradeBtn.textContent = 'You have the Ultra plan!';
            upgradeBtn.disabled = true;
            upgradeBtn.classList.add('bg-gray-600', 'cursor-not-allowed');
            upgradeBtn.classList.remove('from-blue-600', 'to-indigo-600', 'hover:opacity-90');
        } else {
            upgradeBtn.onclick = renderUpgradePage;
        }
    }

    // --- ADMIN & TEACHER LOGIC ---
    function renderAdminDashboard() {
        const template = document.getElementById('template-admin-dashboard');
        DOMElements.appContainer.innerHTML = '';
        DOMElements.appContainer.appendChild(template.content.cloneNode(true));
        renderLogo('admin-logo-container');
        setupAppEventListeners();
        fetchAdminData();
    }

    async function openAdminEditModal(userId, username, currentPlan) {
        const modalTemplate = document.getElementById('template-admin-action-modal');
        const modalWrapper = document.createElement('div');
        modalWrapper.id = 'admin-modal-instance';
        modalWrapper.appendChild(modalTemplate.content.cloneNode(true));
        DOMElements.modalContainer.appendChild(modalWrapper);
        
        modalWrapper.querySelector('#admin-modal-title').textContent = `Manage ${username}`;
        modalWrapper.querySelector('#admin-action-user-id').value = userId;

        const planSelectContainer = modalWrapper.querySelector('#admin-plan-select-container');
        const planSelect = modalWrapper.querySelector('#admin-plan-select');
        planSelectContainer.classList.remove('hidden');

        const plans = Object.keys(PLAN_CONFIG);
        planSelect.innerHTML = '';
        plans.forEach(planId => {
            const option = document.createElement('option');
            option.value = planId;
            option.textContent = planId.charAt(0).toUpperCase() + planId.slice(1);
            if (planId === currentPlan) option.selected = true;
            planSelect.appendChild(option);
        });

        const form = modalWrapper.querySelector('#admin-action-form');
        form.onsubmit = async (e) => {
            e.preventDefault();
            const newPlan = planSelect.value;
            const result = await apiCall('/api/admin/update_user_plan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: userId, plan: newPlan }),
            });
            if (result.success) {
                showToast(result.message, 'success');
                fetchAdminData();
                closeModal();
            } else {
                showToast(result.error, 'error');
            }
        };

        modalWrapper.querySelector('.close-modal-btn').addEventListener('click', closeModal);
        modalWrapper.querySelector('.modal-backdrop').addEventListener('click', closeModal);
    }
    
    async function handleAdminResetMessages(userId) {
        const result = await apiCall('/api/admin/reset_user_messages', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_id: userId }),
        });
        if (result.success) {
            showToast(result.message, 'success');
            fetchAdminData();
        }
    }

    async function renderTeacherDashboard() {
        const template = document.getElementById('template-teacher-dashboard');
        DOMElements.appContainer.innerHTML = '';
        DOMElements.appContainer.appendChild(template.content.cloneNode(true));
        renderLogo('app-logo-container');
        setupAppEventListeners();
        await fetchTeacherData();
    }
    
    async function fetchStudentLeaderboard(classCode = null) {
        const leaderboardContainer = document.getElementById('student-leaderboard-container');
        if (!leaderboardContainer) return;

        let endpoint = '/api/student/leaderboard';
        if (classCode) endpoint += `/${classCode}`;
        const result = await apiCall(endpoint);
        if (result.success && result.leaderboard.length > 0) {
            leaderboardContainer.classList.remove('hidden');
            let leaderboardHTML = `<h3 class="text-lg font-bold mb-2">Class Leaderboard${classCode ? ` (${classCode})` : ''}</h3><ul class="space-y-1">`;
            result.leaderboard.forEach((student, index) => {
                leaderboardHTML += `<li class="flex justify-between items-center text-sm"><span class="truncate"><strong>${index + 1}.</strong> ${student.username}</span><span class="font-mono text-yellow-400">${student.streak} days</span></li>`;
            });
            leaderboardHTML += `</ul>`;
            leaderboardContainer.innerHTML = leaderboardHTML;
        } else {
            leaderboardContainer.classList.add('hidden');
        }
    }

    async function fetchAdminData() {
        const data = await apiCall('/api/admin_data');
        if (!data.success) return;
        
        document.getElementById('admin-total-users').textContent = data.stats.total_users;
        document.getElementById('admin-pro-users').textContent = data.stats.pro_users;
        document.getElementById('admin-ultra-users').textContent = data.stats.ultra_users;
        document.getElementById('announcement-input').value = data.announcement;

        const userList = document.getElementById('admin-user-list');
        userList.innerHTML = '';
        data.users.forEach(user => {
            const tr = document.createElement('tr');
            tr.className = 'border-b border-gray-700/50';
            tr.innerHTML = `
                <td class="p-2">${user.username}</td>
                <td class="p-2">${user.role}</td>
                <td class="p-2">${user.plan}</td>
                <td class="p-2">${user.account_type}</td>
                <td class="p-2">${user.daily_messages}/${user.message_limit}</td>
                <td class="p-2 flex gap-2">
                    <button data-userid="${user.id}" data-username="${user.username}" data-plan="${user.plan}" class="admin-edit-user-btn text-xs px-2 py-1 rounded bg-indigo-600 hover:bg-indigo-500 text-white">Edit</button>
                    <button data-userid="${user.id}" class="admin-reset-messages-btn text-xs px-2 py-1 rounded bg-yellow-600 hover:bg-yellow-500 text-white">Reset Msgs</button>
                    <button data-userid="${user.id}" class="delete-user-btn text-xs px-2 py-1 rounded bg-red-600">Delete</button>
                </td>`;
            userList.appendChild(tr);
        });
    }
    
    async function fetchTeacherData() {
        const data = await apiCall('/api/teacher/dashboard_data');
        if (!data.success) return;

        const { classrooms, students } = data;
        appState.teacherData.classrooms = classrooms;
        appState.teacherData.students = students;

        const classesListEl = document.getElementById('teacher-classes-list');
        if (classesListEl) {
            classesListEl.innerHTML = '';
            if (classrooms.length === 0) {
                classesListEl.innerHTML = '<p class="text-gray-400">You have no classes yet. Create one above.</p>';
            } else {
                classrooms.forEach(cls => {
                    const classEl = document.createElement('div');
                    classEl.className = 'bg-gray-800 p-4 rounded-lg border border-gray-700 space-y-2';
                    classEl.innerHTML = `
                        <h3 class="text-lg font-bold flex justify-between items-center">
                            ${cls.name}
                            <div class="flex gap-2">
                                <button id="teacher-edit-class-btn" data-code="${cls.code}" class="text-blue-400 hover:text-blue-300"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" /><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" /></svg></button>
                                <button id="teacher-regenerate-code-btn" data-code="${cls.code}" class="text-yellow-400 hover:text-yellow-300"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"></path><path d="M21 3v5h-5"></path><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"></path><path d="M8 16H3v5"></path></svg></button>
                            </div>
                        </h3>
                        <p class="text-gray-400">${cls.desc}</p>
                        <p class="text-lg font-mono text-green-400 bg-gray-800 p-3 rounded-lg flex items-center justify-between">
                            <span>${cls.code}</span>
                            <button id="copy-code-btn" data-code="${cls.code}" class="text-gray-400 hover:text-white transition-colors">
                                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                            </button>
                        </p>
                        <div class="mt-2">
                            <h4 class="text-sm font-semibold mb-1">Leaderboard</h4>
                            <ul class="space-y-1 text-sm text-gray-300">
                                ${cls.students.sort((a, b) => b.streak - a.streak).map((s, i) => `<li class="flex justify-between"><span>${i + 1}. ${s.username}</span><span>${s.streak} days</span></li>`).join('') || '<li>No students yet</li>'}
                            </ul>
                        </div>
                    `;
                    classesListEl.appendChild(classEl);
                });
            }
        }

        const studentListEl = document.getElementById('teacher-student-list');
        if (studentListEl) {
            studentListEl.innerHTML = '';
            students.forEach(student => {
                const tr = document.createElement('tr');
                tr.className = 'border-b border-gray-700/50';
                tr.innerHTML = `
                    <td class="p-2">${student.username}</td>
                    <td class="p-2">${student.class_name}</td>
                    <td class="p-2">${student.plan}</td>
                    <td class="p-2">${student.daily_messages}/${student.message_limit}</td>
                    <td class="p-2">${student.streak} days</td>
                    <td class="p-2">${student.last_message_date}</td>
                    <td class="p-2 flex gap-2">
                        <button data-userid="${student.id}" class="view-student-chats-btn text-xs px-2 py-1 rounded bg-blue-600 hover:bg-blue-500 text-white">View Chats</button>
                        <button data-userid="${student.id}" data-classcode="${student.class_code}" class="kick-student-btn text-xs px-2 py-1 rounded bg-red-600 hover:bg-red-500 text-white">Kick</button>
                    </td>
                `;
                studentListEl.appendChild(tr);
            });
        }
    }
    
    async function handleCreateClass() {
        const name = prompt("Enter class name:");
        if (!name) return;
        const desc = prompt("Enter class description:");
        const result = await apiCall('/api/teacher/create_class', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, desc }),
        });
        if (result.success) {
            showToast('Class created!', 'success');
            fetchTeacherData();
        } else {
            showToast(result.error, 'error');
        }
    }

    async function handleEditClass(code) {
        const cls = appState.teacherData.classrooms.find(c => c.code === code);
        if (!cls) return;
        const newName = prompt("Enter new class name:", cls.name);
        if (!newName) return;
        const newDesc = prompt("Enter new class description:", cls.desc);
        const result = await apiCall('/api/teacher/edit_class', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code, name: newName, desc: newDesc }),
        });
        if (result.success) {
            showToast('Class updated!', 'success');
            fetchTeacherData();
        } else {
            showToast(result.error, 'error');
        }
    }

    async function handleRegenerateClassCode(code) {
        if (confirm("Are you sure? This will generate a new code, old code will be invalid.")) {
            const result = await apiCall('/api/teacher/regenerate_code', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code }),
            });
            if (result.success) {
                showToast('New code generated!', 'success');
                fetchTeacherData();
            } else {
                showToast(result.error, 'error');
            }
        }
    }

    function handleCopyClassroomCode(code) {
        if (code && code !== 'Loading...') {
            navigator.clipboard.writeText(code);
            showToast('Classroom code copied to clipboard!', 'success');
        }
    }

    async function handleViewStudentChats(studentId) {
        const result = await apiCall(`/api/teacher/student_chats/${studentId}`);
        if (result.success) {
            const chatsContainer = document.getElementById('teacher-student-chats');
            chatsContainer.innerHTML = '';
            if (result.chats.length > 0) {
                result.chats.forEach(chat => {
                    const chatEl = document.createElement('div');
                    chatEl.className = 'bg-gray-800 p-4 rounded-lg border border-gray-700 space-y-4';
                    chatEl.innerHTML = `<h3 class="text-lg font-bold">${chat.title}</h3>`;
                    chat.messages.forEach(msg => {
                        const contentHTML = DOMPurify.sanitize(marked.parse(msg.content || ''));
                        chatEl.innerHTML += `
                            <div class="p-2 rounded-lg ${msg.sender === 'user' ? 'bg-blue-900/30' : 'bg-gray-700/30'}">
                                <strong>${msg.sender === 'user' ? 'Student' : 'AI'}:</strong> ${contentHTML}
                            </div>
                        `;
                    });
                    chatsContainer.appendChild(chatEl);
                });
            } else {
                chatsContainer.innerHTML = '<p class="text-gray-400">This student has no chat history yet.</p>';
            }
        }
    }

    async function handleKickStudent(studentId, classCode) {
        if (confirm("Are you sure you want to kick this student from the class?")) {
            const result = await apiCall('/api/teacher/kick_student', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ student_id: studentId, class_code: classCode }),
            });
            if (result.success) {
                showToast(result.message, 'success');
                await fetchTeacherData();
            } else {
                 showToast(result.error, 'error');
            }
        }
    }

    // --- STUDENT MY CLASSES PAGE ---
    function renderMyClassesPage() {
        const template = document.getElementById('template-my-classes-page');
        DOMElements.appContainer.innerHTML = '';
        DOMElements.appContainer.appendChild(template.content.cloneNode(true));
        setupAppEventListeners();
        fetchMyClasses();
    }

    async function fetchMyClasses() {
        const result = await apiCall('/api/student/my_classes');
        if (result.success) {
            const listEl = document.getElementById('my-classes-list');
            listEl.innerHTML = '';
            if (result.classes.length === 0) {
                listEl.innerHTML = '<p class="text-gray-400">You are not joined to any classes yet.</p>';
            } else {
                result.classes.forEach(cls => {
                    const classEl = document.createElement('div');
                    classEl.className = 'bg-gray-800 p-4 rounded-lg border border-gray-700 space-y-2';
                    classEl.innerHTML = `
                        <h3 class="text-lg font-bold flex justify-between items-center">
                            ${cls.name}
                            <div class="flex gap-2">
                                <button id="view-leaderboard-btn" data-code="${cls.code}" class="text-green-400 hover:text-green-300"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v4"/><path d="M4 2v4"/><path d="M20 2v4"/><path d="M5.2 4h13.6c1 0 1.8.8 1.8 1.8v14.4c0 1-.8 1.8-1.8 1.8H5.2c-1 0-1.8-.8-1.8-1.8V5.8c0-1 .8-1.8 1.8-1.8z"/><path d="M8 15v1h8v-1"/><path d="M8 15v-2a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M8 15V9a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v6"/></svg> Leaderboard</button>
                                <button id="leave-class-btn" data-code="${cls.code}" class="text-red-400 hover:text-red-300"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" /><polyline points="16 17 21 12 16 7" /><line x1="21" x2="9" y1="12" y2="12" /></svg></button>
                            </div>
                        </h3>
                        <p class="text-gray-400">${cls.desc}</p>
                        <p class="text-sm text-gray-500">Teacher: ${cls.teacher_username}</p>
                    `;
                    listEl.appendChild(classEl);
                });
            }
        }
    }

    async function handleJoinClassroom() {
        const code = prompt("Enter classroom code:");
        if (!code) return;
        const result = await apiCall('/api/student/join_class', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code }),
        });
        if (result.success) {
            showToast('Joined class!', 'success');
            fetchMyClasses();
            fetchStudentLeaderboard();
        } else {
            showToast(result.error, 'error');
        }
    }

    async function handleLeaveClass(code) {
        if (confirm("Are you sure you want to leave this class?")) {
            const result = await apiCall('/api/student/leave_class', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code }),
            });
            if (result.success) {
                showToast('Left class.', 'success');
                fetchMyClasses();
                fetchStudentLeaderboard();
            } else {
                showToast(result.error, 'error');
            }
        }
    }

    function handleViewLeaderboard(code) {
        fetchStudentLeaderboard(code);
    }

    // --- ADMIN ACTIONS ---
    async function handleSetAnnouncement(e) {
        e.preventDefault();
        const text = document.getElementById('announcement-input').value;
        const result = await apiCall('/api/admin/announcement', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text }),
        });
        if (result.success) {
            showToast(result.message, 'success');
            if (text) {
                DOMElements.announcementBanner.textContent = text;
                DOMElements.announcementBanner.classList.remove('hidden');
            } else {
                DOMElements.announcementBanner.classList.add('hidden');
            }
        }
    }

    function handleAdminDeleteUser(userId) {
        if (confirm(`Are you sure you want to delete this user? This is irreversible.`)) {
            apiCall('/api/admin/delete_user', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: userId }),
            }).then(result => {
                if (result.success) {
                    showToast(result.message, 'success');
                    fetchAdminData();
                }
            });
        }
    }
    
    async function handleImpersonate() {
        const username = prompt("Enter the username of the user to impersonate:");
        if (!username) return;
        const result = await apiCall('/api/admin/impersonate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: username }),
        });
        if (result.success) {
            showToast(`Now impersonating ${username}. You will be logged in as them.`, 'success');
            setTimeout(() => window.location.reload(), 1500);
        }
    }

    // --- INITIAL LOAD ---
    checkLoginStatus();
});
</script>
</body>
</html>
"""


@app.route('/', methods=['GET'])
def index():
    return HTML_CONTENT


@app.route('/api/status', methods=['GET'])
def status():
    if current_user.is_authenticated:
        user_chats = DB['chats'].get(current_user.id, {})
        return jsonify({
            'logged_in': True,
            'user': user_to_dict(current_user),
            'chats': user_chats,
            'settings': DB['site_settings']
        })
    else:
        return jsonify({'logged_in': False})


@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user = User.get_by_username(data['username'])
    if user and check_password_hash(user.password_hash, data['password']):
        login_user(user)
        user_chats = DB['chats'].get(user.id, {})
        return jsonify({
            'success': True,
            'user': user_to_dict(user),
            'chats': user_chats,
            'settings': DB['site_settings']
        })
    return jsonify({'success': False, 'error': 'Invalid username or password'}), 401


@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.json
    username = data['username']
    password = data['password']
    if User.get_by_username(username):
        return jsonify({'error': 'Username taken'}), 400
    user_id = str(uuid.uuid4())
    user = User(id=user_id, username=username, password_hash=generate_password_hash(password))
    DB['users'][user_id] = user
    DB['chats'][user_id] = {}
    save_database()
    login_user(user)
    return jsonify({'success': True, 'user': user_to_dict(user), 'chats': {}, 'settings': DB['site_settings']})


@app.route('/api/special_signup', methods=['POST'])
def special_signup():
    data = request.json
    username = data['username']
    password = data['password']
    secret_key = data['secret_key']
    if secret_key != SITE_CONFIG['SECRET_REGISTRATION_KEY']:
        return jsonify({'error': 'Invalid secret key'}), 403
    if User.get_by_username(username):
        return jsonify({'error': 'Username taken'}), 400
    user_id = str(uuid.uuid4())
    user = User(id=user_id, username=username, password_hash=generate_password_hash(password), role='admin', plan='ultra')
    DB['users'][user_id] = user
    DB['chats'][user_id] = {}
    save_database()
    login_user(user)
    return jsonify({'success': True, 'user': user_to_dict(user), 'chats': {}, 'settings': DB['site_settings']})


@app.route('/api/student_signup', methods=['POST'])
def student_signup():
    data = request.json
    username = data['username']
    password = data['password']
    classroom_code = data.get('classroom_code')
    if User.get_by_username(username):
        return jsonify({'error': 'Username taken'}), 400
    user_id = str(uuid.uuid4())
    user = User(id=user_id, username=username, password_hash=generate_password_hash(password), account_type='student', plan='student')
    if classroom_code and classroom_code in DB['classrooms']:
        user.classrooms.append(classroom_code)
        DB['classrooms'][classroom_code]['students'].append(user_id)
    DB['users'][user_id] = user
    DB['chats'][user_id] = {}
    save_database()
    login_user(user)
    return jsonify({'success': True, 'user': user_to_dict(user), 'chats': {}, 'settings': DB['site_settings']})


@app.route('/api/teacher_signup', methods=['POST'])
def teacher_signup():
    data = request.json
    username = data['username']
    password = data['password']
    secret_key = data['secret_key']
    if secret_key != SITE_CONFIG['SECRET_TEACHER_KEY']:
        return jsonify({'error': 'Invalid secret key'}), 403
    if User.get_by_username(username):
        return jsonify({'error': 'Username taken'}), 400
    user_id = str(uuid.uuid4())
    user = User(id=user_id, username=username, password_hash=generate_password_hash(password), account_type='teacher', plan='ultra')
    classroom_code = secrets.token_hex(4).upper()
    user.classrooms.append(classroom_code)
    DB['classrooms'][classroom_code] = {'teacher_id': user_id, 'name': 'My First Class', 'desc': 'Welcome to my class!', 'students': []}
    DB['users'][user_id] = user
    DB['chats'][user_id] = {}
    save_database()
    login_user(user)
    return jsonify({'success': True, 'user': user_to_dict(user), 'chats': {}, 'settings': DB['site_settings']})


@app.route('/api/forgot_password', methods=['POST'])
def forgot_password():
    data = request.json
    username = data['username']
    user = User.get_by_username(username)
    if user and user.email:
        if send_password_reset_email(user):
            return jsonify({'success': True, 'message': 'Password reset email sent.'})
        else:
            return jsonify({'success': False, 'error': 'Failed to send email.'}), 500
    return jsonify({'success': False, 'error': 'User not found or no email associated.'}), 404


@app.route('/api/reset_password', methods=['POST'])
def reset_password():
    data = request.json
    token = data['token']
    new_password = data['new_password']
    if token in DB['reset_tokens']:
        info = DB['reset_tokens'][token]
        if time.time() < info['expires']:
            user = User.get(info['user_id'])
            if user:
                user.password_hash = generate_password_hash(new_password)
                del DB['reset_tokens'][token]
                save_database()
                return jsonify({'success': True, 'message': 'Password reset successfully.'})
    return jsonify({'success': False, 'error': 'Invalid or expired token.'}), 400


@app.route('/api/logout', methods=['GET'])
def logout():
    logout_user()
    return jsonify({'success': True})


@app.route('/api/chat/new', methods=['POST'])
@login_required
def new_chat():
    chat_id = str(uuid.uuid4())
    chat = {"id": chat_id, "title": "New Chat", "created_at": datetime.now().isoformat(), "messages": []}
    if current_user.id not in DB['chats']:
        DB['chats'][current_user.id] = {}
    DB['chats'][current_user.id][chat_id] = chat
    save_database()
    return jsonify({'success': True, 'chat': chat})


@app.route('/api/chat/rename', methods=['POST'])
@login_required
def rename_chat():
    data = request.json
    chat_id = data['chat_id']
    title = data['title']
    if chat_id in DB['chats'].get(current_user.id, {}):
        DB['chats'][current_user.id][chat_id]['title'] = title
        save_database()
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Chat not found'}), 404


@app.route('/api/chat/delete', methods=['POST'])
@login_required
def delete_chat():
    data = request.json
    chat_id = data['chat_id']
    if chat_id in DB['chats'].get(current_user.id, {}):
        del DB['chats'][current_user.id][chat_id]
        save_database()
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Chat not found'}), 404


@app.route('/api/chat/share', methods=['POST'])
@login_required
def share_chat():
    data = request.json
    chat_id = data['chat_id']
    if chat_id not in DB['chats'].get(current_user.id, {}):
        return jsonify({'error': 'Chat not found'}), 404
    share_id = secrets.token_hex(8)
    if 'shares' not in DB:
        DB['shares'] = {}
    DB['shares'][share_id] = {'user_id': current_user.id, 'chat_id': chat_id}
    save_database()
    return jsonify({'success': True, 'share_id': share_id})


@app.route('/api/chat', methods=['POST'])
@login_required
def chat():
    chat_id = request.form['chat_id']
    prompt = request.form['prompt']
    is_study_mode = request.form.get('is_study_mode', 'false') == 'true'
    model_name = request.form.get('model_name', 'deepseek-chat')
    file = request.files.get('file')

    plan_details = PLAN_CONFIG[current_user.plan]
    today = datetime.now().strftime("%Y-%m-%d")
    if current_user.last_message_date != today:
        current_user.daily_messages = 0
        current_user.last_message_date = today
    if current_user.daily_messages >= plan_details['message_limit']:
        return jsonify({'error': 'Daily message limit reached'}), 429
    current_user.daily_messages += 1

    if current_user.account_type == 'student':
        last_date = datetime.strptime(current_user.last_streak_date, "%Y-%m-%d")
        delta = datetime.now() - last_date
        if delta.days == 1:
            current_user.streak += 1
        elif delta.days > 1:
            current_user.streak = 1
        current_user.last_streak_date = today

    save_database()

    image_b64 = None
    if file:
        return jsonify({'error': 'Image support not implemented'}), 501  # Placeholder, as DeepSeek doesn't support vision

    system_prompt = "You are a helpful AI assistant."
    if is_study_mode:
        system_prompt = "You are Study Buddy, a friendly tutor helping with studies."
    if model_name == 'practice-mode':
        system_prompt = "You are in practice mode, explain concepts step by step and ask questions to test understanding."
    elif model_name == 'hardcore-mode':
        system_prompt = "You are in hardcore mode, provide challenging problems and rigorous explanations."

    if chat_id not in DB['chats'].get(current_user.id, {}):
        return jsonify({'error': 'Chat not found'}), 404

    chat = DB['chats'][current_user.id][chat_id]
    chat['messages'].append({'sender': 'user', 'content': prompt})
    save_database()

    def generate():
        try:
            payload = {
                "model": model_name,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    *[{"role": "user" if m['sender'] == 'user' else "assistant", "content": m['content']} for m in chat['messages']]
                ],
                "stream": True
            }
            headers = {
                "Authorization": f"Bearer {SITE_CONFIG['DEEPSEEK_API_KEY']}",
                "Content-Type": "application/json"
            }
            response = requests.post(SITE_CONFIG['DEEPSEEK_API_URL'], json=payload, headers=headers, stream=True)
            response.raise_for_status()
            for line in response.iter_lines():
                if line:
                    decoded = line.decode('utf-8')
                    if decoded.startswith("data: "):
                        try:
                            data = json.loads(decoded[6:])
                            if 'choices' in data and data['choices']:
                                yield data['choices'][0]['delta'].get('content', '')
                        except json.JSONDecodeError:
                            continue # Ignore empty or malformed lines
        except Exception as e:
            logging.error(f"Error during API call: {e}")
            yield f"Error: Could not connect to the AI model. Please try again later."

    ai_msg = {'sender': 'model', 'content': ''}
    chat['messages'].append(ai_msg)

    def stream_response():
        content = ''
        for chunk in generate():
            content += chunk
            yield chunk
        ai_msg['content'] = content
        # Auto-generate title for new chats
        if len(chat['messages']) == 2 and (chat['title'] == 'New Chat' or not chat['title']):
             title_prompt = f"Generate a very short, concise title (4 words max) for the following conversation:\n\nUser: {prompt}\nAI: {content[:100]}..."
             try:
                 title_response = requests.post(
                     SITE_CONFIG['DEEPSEEK_API_URL'],
                     json={
                         "model": "deepseek-chat",
                         "messages": [{"role": "user", "content": title_prompt}]
                     },
                     headers={"Authorization": f"Bearer {SITE_CONFIG['DEEPSEEK_API_KEY']}", "Content-Type": "application/json"}
                 )
                 title_response.raise_for_status()
                 chat['title'] = title_response.json()['choices'][0]['message']['content'].strip().strip('"')
             except Exception as e:
                 logging.error(f"Could not auto-generate title: {e}")
                 chat['title'] = prompt[:30] + '...' if len(prompt) > 30 else prompt
        save_database()

    return Response(stream_with_context(stream_response()), mimetype='text/plain')


@app.route('/api/plans', methods=['GET'])
def get_plans():
    user_plan = current_user.plan if current_user.is_authenticated else 'free'
    return jsonify({'success': True, 'plans': PLAN_CONFIG, 'user_plan': user_plan})


@app.route('/api/config', methods=['GET'])
def get_config():
    return jsonify({'success': True, 'stripe_public_key': SITE_CONFIG['STRIPE_PUBLIC_KEY']})


@app.route('/api/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    data = request.json
    plan_id = data['plan_id']
    price_id_map = {
        'pro': SITE_CONFIG['STRIPE_PRO_PRICE_ID'],
        'ultra': SITE_CONFIG['STRIPE_ULTRA_PRICE_ID'],
        'student': SITE_CONFIG['STRIPE_STUDENT_PRICE_ID']
    }
    if plan_id not in price_id_map:
        return jsonify({'error': 'Invalid plan'}), 400
    price_id = price_id_map[plan_id]
    mode = 'payment' if plan_id == 'ultra' else 'subscription'
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{'price': price_id, 'quantity': 1}],
            mode=mode,
            success_url=SITE_CONFIG['YOUR_DOMAIN'] + '/?payment=success',
            cancel_url=SITE_CONFIG['YOUR_DOMAIN'] + '/?payment=cancel',
            metadata={'user_id': current_user.id, 'plan_id': plan_id}
        )
        return jsonify({'success': True, 'id': session.id})
    except Exception as e:
        logging.error(f"Stripe session creation failed: {e}")
        return jsonify({'error': str(e)}), 400


@app.route('/webhook/stripe', methods=['POST'])
def stripe_webhook():
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, SITE_CONFIG['STRIPE_WEBHOOK_SECRET'])
    except ValueError:
        return 'Invalid payload', 400
    except stripe.error.SignatureVerificationError:
        return 'Invalid signature', 400
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        # print(session) # Debugging line
        user_id = session['metadata'].get('user_id')
        plan_id = session['metadata'].get('plan_id')
        user = User.get(user_id)
        if user:
            user.plan = plan_id
            save_database()
    return '', 200


@app.route('/api/admin_data', methods=['GET'])
@admin_required
def admin_data():
    users = [user_to_dict(u) for u in DB['users'].values()]
    for u in users:
        u['message_limit'] = PLAN_CONFIG[u['plan']]['message_limit']
    stats = {
        'total_users': len(users),
        'pro_users': sum(1 for u in users if u['plan'] == 'pro'),
        'ultra_users': sum(1 for u in users if u['plan'] == 'ultra'),
    }
    announcement = DB['site_settings'].get('announcement', '')
    return jsonify({'success': True, 'users': users, 'stats': stats, 'announcement': announcement})


@app.route('/api/admin/announcement', methods=['POST'])
@admin_required
def set_announcement():
    data = request.json
    text = data['text']
    DB['site_settings']['announcement'] = text
    save_database()
    return jsonify({'success': True, 'message': 'Announcement updated'})


@app.route('/api/admin/delete_user', methods=['POST'])
@admin_required
def delete_user_route():
    data = request.json
    user_id = data['user_id']
    if user_id not in DB['users']:
        return jsonify({'error': 'User not found'}), 404
    user = DB['users'][user_id]
    if user_id in DB['chats']:
        del DB['chats'][user_id]
    if user.account_type == 'teacher':
        for code in user.classrooms:
            if code in DB['classrooms']:
                for sid in DB['classrooms'][code]['students']:
                    s = User.get(sid)
                    if s:
                        s.classrooms.remove(code)
                del DB['classrooms'][code]
    if user.account_type == 'student':
        for code in user.classrooms:
            if code in DB['classrooms']:
                if user_id in DB['classrooms'][code]['students']:
                    DB['classrooms'][code]['students'].remove(user_id)
    del DB['users'][user_id]
    save_database()
    return jsonify({'success': True, 'message': 'User deleted'})


@app.route('/api/admin/update_user_plan', methods=['POST'])
@admin_required
def update_user_plan():
    data = request.json
    user_id = data['user_id']
    plan = data['plan']
    if plan not in PLAN_CONFIG:
        return jsonify({'error': 'Invalid plan'}), 400
    user = User.get(user_id)
    if user:
        user.plan = plan
        save_database()
        return jsonify({'success': True, 'message': 'Plan updated'})
    return jsonify({'error': 'User not found'}), 404


@app.route('/api/admin/reset_user_messages', methods=['POST'])
@admin_required
def reset_user_messages():
    data = request.json
    user_id = data['user_id']
    user = User.get(user_id)
    if user:
        user.daily_messages = 0
        save_database()
        return jsonify({'success': True, 'message': 'Messages reset'})
    return jsonify({'error': 'User not found'}), 404


@app.route('/api/admin/impersonate', methods=['POST'])
@admin_required
def impersonate():
    data = request.json
    username = data['username']
    user = User.get_by_username(username)
    if user:
        login_user(user)
        return jsonify({'success': True})
    return jsonify({'error': 'User not found'}), 404


@app.route('/api/teacher/dashboard_data', methods=['GET'])
@teacher_required
def teacher_dashboard_data():
    classrooms = []
    students = []
    for code in current_user.classrooms:
        classroom = DB['classrooms'].get(code)
        if classroom:
            cls_students = []
            for sid in classroom['students']:
                s = User.get(sid)
                if s:
                    cls_students.append({
                        'id': s.id,
                        'username': s.username,
                        'plan': s.plan,
                        'daily_messages': s.daily_messages,
                        'message_limit': PLAN_CONFIG[s.plan]['message_limit'],
                        'streak': s.streak,
                        'last_message_date': s.last_message_date,
                        'class_code': code,
                        'class_name': classroom['name']
                    })
            students.extend(cls_students)
            classrooms.append({
                'code': code,
                'name': classroom['name'],
                'desc': classroom['desc'],
                'students': cls_students
            })
    return jsonify({
        'success': True,
        'classrooms': classrooms,
        'students': students
    })


@app.route('/api/teacher/create_class', methods=['POST'])
@teacher_required
def teacher_create_class():
    data = request.json
    name = data['name']
    desc = data.get('desc', '')
    code = secrets.token_hex(4).upper()
    DB['classrooms'][code] = {'teacher_id': current_user.id, 'name': name, 'desc': desc, 'students': []}
    current_user.classrooms.append(code)
    save_database()
    return jsonify({'success': True})


@app.route('/api/teacher/edit_class', methods=['POST'])
@teacher_required
def teacher_edit_class():
    data = request.json
    code = data['code']
    if code not in current_user.classrooms:
        return jsonify({'error': 'Class not found'}), 404
    classroom = DB['classrooms'][code]
    classroom['name'] = data['name']
    classroom['desc'] = data['desc']
    save_database()
    return jsonify({'success': True})


@app.route('/api/teacher/regenerate_code', methods=['POST'])
@teacher_required
def teacher_regenerate_code():
    data = request.json
    old_code = data['code']
    if old_code not in current_user.classrooms:
        return jsonify({'error': 'Class not found'}), 404
    new_code = secrets.token_hex(4).upper()
    DB['classrooms'][new_code] = DB['classrooms'][old_code]
    del DB['classrooms'][old_code]
    current_user.classrooms[current_user.classrooms.index(old_code)] = new_code
    for sid in DB['classrooms'][new_code]['students']:
        s = User.get(sid)
        if s:
            s.classrooms[s.classrooms.index(old_code)] = new_code
    save_database()
    return jsonify({'success': True, 'new_code': new_code})


@app.route('/api/teacher/student_chats/<student_id>', methods=['GET'])
@teacher_required
def student_chats(student_id):
    # Check if student is in any of teacher's classes
    is_in_class = any(student_id in DB['classrooms'][code]['students'] for code in current_user.classrooms if code in DB['classrooms'])
    if not is_in_class:
        return jsonify({'error': 'This student is not in your classroom.'}), 403
    chats = DB['chats'].get(student_id, {})
    return jsonify({'success': True, 'chats': list(chats.values())})


@app.route('/api/teacher/kick_student', methods=['POST'])
@teacher_required
def kick_student():
    data = request.json
    student_id = data['student_id']
    class_code = data['class_code']
    if class_code not in current_user.classrooms:
        return jsonify({'error': 'You do not own this class.'}), 400
    if class_code in DB['classrooms'] and student_id in DB['classrooms'][class_code]['students']:
        DB['classrooms'][class_code]['students'].remove(student_id)
        user = User.get(student_id)
        if user and class_code in user.classrooms:
            user.classrooms.remove(class_code)
        save_database()
        return jsonify({'success': True, 'message': 'Student removed from classroom.'})
    return jsonify({'error': 'Student not found in your classroom.'}), 404


@app.route('/api/student/my_classes', methods=['GET'])
@login_required
def student_my_classes():
    if current_user.account_type != 'student':
        return jsonify({'success': False, 'error': 'Not a student.'}), 403
    classes = []
    for code in current_user.classrooms:
        classroom = DB['classrooms'].get(code)
        if classroom:
            teacher = User.get(classroom['teacher_id'])
            classes.append({
                'code': code,
                'name': classroom['name'],
                'desc': classroom['desc'],
                'teacher_username': teacher.username if teacher else 'Unknown'
            })
    return jsonify({'success': True, 'classes': classes})


@app.route('/api/student/join_class', methods=['POST'])
@login_required
def student_join_class():
    if current_user.account_type != 'student':
        return jsonify({'error': 'Not a student'}), 403
    data = request.json
    code = data['code']
    if code not in DB['classrooms']:
        return jsonify({'error': 'Invalid classroom code'}), 400
    if code in current_user.classrooms:
        return jsonify({'error': 'Already joined'}), 400
    current_user.classrooms.append(code)
    DB['classrooms'][code]['students'].append(current_user.id)
    save_database()
    return jsonify({'success': True})


@app.route('/api/student/leave_class', methods=['POST'])
@login_required
def student_leave_class():
    if current_user.account_type != 'student':
        return jsonify({'error': 'Not a student'}), 403
    data = request.json
    code = data['code']
    if code not in current_user.classrooms:
        return jsonify({'error': 'Not joined to this class'}), 400
    current_user.classrooms.remove(code)
    if code in DB['classrooms'] and current_user.id in DB['classrooms'][code]['students']:
        DB['classrooms'][code]['students'].remove(current_user.id)
    save_database()
    return jsonify({'success': True})


@app.route('/api/student/leaderboard', methods=['GET'])
@app.route('/api/student/leaderboard/<class_code>', methods=['GET'])
@login_required
def student_leaderboard(class_code=None):
    if current_user.account_type != 'student':
        return jsonify({'success': False, 'error': 'Not a student.'}), 403
    if class_code and class_code not in current_user.classrooms:
        return jsonify({'success': False, 'error': 'Not joined to this class.'}), 404
    if not class_code and current_user.classrooms:
        class_code = current_user.classrooms[0]  # Default to first class
    if not class_code:
        return jsonify({'success': False, 'error': 'Not in any classroom.'}), 404
    classroom = DB['classrooms'].get(class_code)
    if not classroom:
        return jsonify({'success': False, 'error': 'Classroom not found.'}), 404
    students = [User.get(sid) for sid in classroom['students']]
    leaderboard = sorted([{'username': s.username, 'streak': s.streak} for s in students if s], key=lambda x: x['streak'], reverse=True)
    return jsonify({'success': True, 'leaderboard': leaderboard})


@app.route('/api/google_login', methods=['GET'])
def google_login():
    # Placeholder for Google login implementation
    return jsonify({'error': 'Google login not implemented'}), 501


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
