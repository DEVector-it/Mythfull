# --- Imports ---
import os
import logging
import secrets
import uuid
from functools import wraps
from datetime import datetime

# Flask and Extensions
from flask import Flask, request, jsonify, render_template_string, url_for
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_mail import Mail, Message
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# SQLAlchemy and Werkzeug
from sqlalchemy import event
from sqlalchemy.orm import joinedload
from sqlalchemy.exc import IntegrityError
from sqlalchemy.engine import Engine
from werkzeug.security import generate_password_hash, check_password_hash

# Other Libraries
import stripe
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature

# ==============================================================================
# --- 1. INITIAL CONFIGURATION & SETUP ---
# ==============================================================================
load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Flask App Initialization ---
app = Flask(__name__)

# --- App Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-very-secret-key-for-dev')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get('SECURITY_PASSWORD_SALT', 'a-fallback-salt-for-dev')
# --- SECURITY: Set cookies to be sent only over HTTPS in production ---
is_production = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_SECURE'] = is_production
app.config['REMEMBER_COOKIE_SECURE'] = is_production
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_HTTPONLY'] = True


# --- Security, CORS, and Rate Limiting ---
CORS(app, supports_credentials=True, origins="*") # In production, restrict this to your frontend domain
csrf = CSRFProtect(app)

### NEW: Rate Limiting to prevent brute-force attacks
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

### FIX: Corrected the Content Security Policy (CSP) to prevent startup crash.
csp = {
    'default-src': '\'self\'',
    'script-src': [
        '\'self\'',
        'https://cdn.tailwindcss.com',
        'https://cdnjs.cloudflare.com',
        'https://js.stripe.com'
    ],
    'style-src': [
        '\'self\'',
        '\'unsafe-inline\'', # Allowed for simplicity, but for higher security try to move all styles to CSS files
        'https://cdn.tailwindcss.com',
        'https://fonts.googleapis.com'
    ],
    'font-src': [
        '\'self\'',
        'https://fonts.gstatic.com'
    ],
    'img-src': '*', # Allows images from any source for avatars etc.
    'connect-src': '\'self\'' # Allows API calls and WebSockets to the same origin.
}
Talisman(app, content_security_policy=csp)


# --- Site-wide Configuration Dictionary ---
SITE_CONFIG = {
    "STRIPE_SECRET_KEY": os.environ.get('STRIPE_SECRET_KEY'),
    "STRIPE_PUBLIC_KEY": os.environ.get('STRIPE_PUBLIC_KEY'),
    "STRIPE_STUDENT_PRICE_ID": os.environ.get('STRIPE_STUDENT_PRICE_ID'),
    "STRIPE_STUDENT_PRO_PRICE_ID": os.environ.get('STRIPE_STUDENT_PRO_PRICE_ID'),
    "YOUR_DOMAIN": os.environ.get('YOUR_DOMAIN', 'http://localhost:5000'),
    "SECRET_TEACHER_KEY": os.environ.get('SECRET_TEACHER_KEY', 'SUPER-SECRET-TEACHER-KEY'),
    "ADMIN_SECRET_KEY": os.environ.get('ADMIN_SECRET_KEY', 'SUPER-SECRET-ADMIN-KEY'),
    "STRIPE_WEBHOOK_SECRET": os.environ.get('STRIPE_WEBHOOK_SECRET'),
    "GEMINI_API_KEY": os.environ.get('GEMINI_API_KEY'),
    "SUPPORT_EMAIL": os.environ.get('MAIL_SENDER')
}

# --- Initialize Extensions with the App ---
stripe.api_key = SITE_CONFIG.get("STRIPE_SECRET_KEY")
password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")
mail = Mail(app)

# --- Flask-Mail Configuration ---
app.config.update(
    MAIL_SERVER=os.environ.get('MAIL_SERVER'),
    MAIL_PORT=int(os.environ.get('MAIL_PORT', 587)),
    MAIL_USE_TLS=os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true',
    MAIL_USERNAME=os.environ.get('MAIL_USERNAME'),
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD'),
    MAIL_DEFAULT_SENDER=os.environ.get('MAIL_SENDER')
)

@app.teardown_appcontext
def shutdown_session(exception=None):
    """Remove database session at the end of the request to prevent leaks."""
    db.session.remove()

# ==============================================================================
# --- 2. DATABASE MODELS ---
# ==============================================================================
### FIX: Re-enabled this for better data integrity with SQLite.
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Enable foreign key support for SQLite for data integrity."""
    if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite'):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

# --- Association Tables ---
student_class_association = db.Table('student_class_association',
    db.Column('user_id', db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True),
    db.Column('class_id', db.String(36), db.ForeignKey('class.id', ondelete='CASCADE'), primary_key=True)
)

team_member_association = db.Table('team_member_association',
    db.Column('user_id', db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True),
    db.Column('team_id', db.String(36), db.ForeignKey('team.id', ondelete='CASCADE'), primary_key=True)
)

# --- Main Database Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=True)
    role = db.Column(db.String(20), nullable=False, default='student')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    has_subscription = db.Column(db.Boolean, default=False)
    stripe_customer_id = db.Column(db.String(120), nullable=True, index=True)
    ai_persona = db.Column(db.String(500), nullable=True, default=None)
    theme_preference = db.Column(db.String(50), nullable=True, default='dark')

    profile = db.relationship('Profile', back_populates='user', uselist=False, cascade="all, delete-orphan")
    taught_classes = db.relationship('Class', back_populates='teacher', lazy=True, foreign_keys='Class.teacher_id', cascade="all, delete-orphan")
    enrolled_classes = db.relationship('Class', secondary=student_class_association, back_populates='students', lazy='dynamic')
    teams = db.relationship('Team', secondary=team_member_association, back_populates='members', lazy='dynamic')
    submissions = db.relationship('Submission', back_populates='student', lazy=True, cascade="all, delete-orphan")
    quiz_attempts = db.relationship('QuizAttempt', back_populates='student', lazy=True, cascade="all, delete-orphan")
    notifications = db.relationship('Notification', back_populates='user', lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        profile_data = {'bio': '', 'avatar': ''}
        if self.profile:
            profile_data['bio'] = self.profile.bio or ''
            profile_data['avatar'] = self.profile.avatar or ''
        return {
            'id': self.id, 'username': self.username, 'email': self.email, 'role': self.role,
            'created_at': self.created_at.isoformat(), 'has_subscription': self.has_subscription,
            'profile': profile_data, 'ai_persona': self.ai_persona, 'theme_preference': self.theme_preference
        }

class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False, unique=True)
    bio = db.Column(db.Text, nullable=True)
    avatar = db.Column(db.String(500), nullable=True)
    user = db.relationship('User', back_populates='profile')

class Team(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(8), unique=True, nullable=False, index=True)
    owner_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False, index=True)
    owner = db.relationship('User', foreign_keys=[owner_id])
    members = db.relationship('User', secondary=team_member_association, back_populates='teams', lazy='dynamic')

class Class(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(8), unique=True, nullable=False, index=True)
    teacher_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False, index=True)
    teacher = db.relationship('User', back_populates='taught_classes', foreign_keys=[teacher_id])
    students = db.relationship('User', secondary=student_class_association, back_populates='enrolled_classes', lazy='dynamic')
    messages = db.relationship('ChatMessage', back_populates='class_obj', lazy=True, cascade="all, delete-orphan")
    assignments = db.relationship('Assignment', back_populates='class_obj', lazy=True, cascade="all, delete-orphan")
    quizzes = db.relationship('Quiz', back_populates='class_obj', lazy=True, cascade="all, delete-orphan")

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    class_id = db.Column(db.String(36), db.ForeignKey('class.id', ondelete='CASCADE'), nullable=False)
    sender_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    class_obj = db.relationship('Class', back_populates='messages')
    sender = db.relationship('User')

class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    class_id = db.Column(db.String(36), db.ForeignKey('class.id', ondelete='CASCADE'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    due_date = db.Column(db.DateTime, nullable=False)
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

class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    class_id = db.Column(db.String(36), db.ForeignKey('class.id', ondelete='CASCADE'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    time_limit = db.Column(db.Integer, nullable=False) # In minutes
    class_obj = db.relationship('Class', back_populates='quizzes')
    questions = db.relationship('Question', back_populates='quiz', lazy=True, cascade="all, delete-orphan")
    attempts = db.relationship('QuizAttempt', back_populates='quiz', lazy='dynamic', cascade="all, delete-orphan")

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id', ondelete='CASCADE'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    question_type = db.Column(db.String(50), nullable=False, default='multiple_choice') # e.g., 'multiple_choice', 'short_answer'
    quiz = db.relationship('Quiz', back_populates='questions')
    choices = db.Column(db.JSON, nullable=True) # e.g., {"options": ["A", "B", "C"], "correct": "A"}

class QuizAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id', ondelete='CASCADE'), nullable=False)
    student_id = db.Column(db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    score = db.Column(db.Float, nullable=True)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    answers = db.Column(db.JSON, nullable=True) # Store student's answers
    quiz = db.relationship('Quiz', back_populates='attempts')
    student = db.relationship('User', back_populates='quiz_attempts')

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', back_populates='notifications')

class SiteSettings(db.Model):
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.String(500))

class BackgroundMusic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    uploaded_by = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)

# ==============================================================================
# --- 3. USER & SESSION MANAGEMENT ---
# ==============================================================================
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@login_manager.unauthorized_handler
def unauthorized():
    return jsonify({"error": "Login required.", "logged_in": False}), 401

def role_required(role_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({"error": "Login required."}), 401
            if current_user.role != role_name and current_user.role != 'admin':
                return jsonify({"error": f"{role_name.capitalize()} access required."}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

admin_required = role_required('admin')
teacher_required = role_required('teacher')

# ==============================================================================
# --- 4. FRONTEND & CORE ROUTES ---
# ==============================================================================
# The HTML_CONTENT variable is very large and has not changed.
# To keep this response focused, I'm omitting it.
# Please use the HTML_CONTENT from the file I provided in the previous turn.
# The JavaScript inside has been updated and is included below.

HTML_CONTENT = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Myth AI Portal</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <script src="https://js.stripe.com/v3/"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="shortcut icon" href="/favicon.ico">
    <style>
        :root {
            --brand-hue: 220; --bg-dark: #0F172A; --bg-med: #1E293B; --bg-light: #334155;
            --glow-color: hsl(var(--brand-hue), 100%, 70%); --text-color: #E2E8F0; --text-secondary-color: #94A3B8;
        }
        body { background-color: var(--bg-dark); font-family: 'Inter', sans-serif; color: var(--text-color); }
        .glassmorphism { background: rgba(31, 41, 55, 0.5); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.1); }
        .brand-gradient-text { background-image: linear-gradient(120deg, hsl(var(--brand-hue), 90%, 60%), hsl(var(--brand-hue), 90%, 65%)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .brand-gradient-bg { background-image: linear-gradient(120deg, hsl(var(--brand-hue), 90%, 55%), hsl(var(--brand-hue), 90%, 60%)); }
        .shiny-button { transition: all 0.3s ease; box-shadow: 0 0 5px rgba(0,0,0,0.5), 0 0 10px var(--glow-color, #fff) inset; }
        .shiny-button:hover { transform: translateY(-2px); box-shadow: 0 4px 15px hsla(var(--brand-hue), 80%, 50%, 0.4), 0 0 5px var(--glow-color, #fff) inset; }
        .fade-in { animation: fadeIn 0.5s ease-out forwards; } @keyframes fadeIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
        .active-tab { background-color: var(--bg-light) !important; color: white !important; position:relative; }
        .active-tab::after { content: ''; position: absolute; bottom: 0; left: 10%; width: 80%; height: 2px; background: var(--glow-color); border-radius: 2px; }
        .modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); display: flex; align-items: center; justify-content: center; z-index: 1000; }
        .ai-message .chat-bubble { background-color: #2E1A47; border-color: #8B5CF6; }
        .user-message .chat-bubble { background-color: #1E40AF; border-color: #3B82F6; }
        .dynamic-bg { background: linear-gradient(-45deg, #0f172a, #1e3a8a, #4c1d95, #0f172a); background-size: 400% 400%; animation: gradientBG 20s ease infinite; }
        @keyframes gradientBG { 0% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } 100% { background-position: 0% 50%; } }
        .full-screen-loader { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(15, 23, 42, 0.9); backdrop-filter: blur(8px); display: flex; align-items: center; justify-content: center; flex-direction: column; z-index: 1001; transition: opacity 0.3s ease; }
        .loader-dots { display: flex; gap: 1rem; }
        .loader-dots div { width: 1rem; height: 1rem; background-color: hsl(var(--brand-hue), 90%, 60%); border-radius: 50%; animation: bounce 1.4s infinite ease-in-out both; }
        .loader-dots .dot1 { animation-delay: -0.32s; }
        .loader-dots .dot2 { animation-delay: -0.16s; }
        @keyframes bounce { 0%, 80%, 100% { transform: scale(0); } 40% { transform: scale(1.0); } }
        .waiting-text { margin-top: 2rem; font-size: 1.25rem; color: var(--text-secondary-color); animation: pulse 2s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.7; } }
    </style>
</head>
<body class="text-gray-200 antialiased">
    <div id="app-container" class="relative h-screen w-screen overflow-hidden flex flex-col"></div>
    <div id="toast-container" class="fixed top-6 right-6 z-[100] flex flex-col gap-2"></div>
    <div id="modal-container"></div>
    <div class="fixed bottom-4 left-4 text-xs text-gray-500">&copy; <span id="current-year"></span> Myth AI</div>
    <audio id="background-music" loop autoplay></audio>

    <template id="template-full-screen-loader"><div class="full-screen-loader fade-in"><div class="loader-dots"><div class="dot1"></div><div class="dot2"></div><div class="dot3"></div></div><div class="waiting-text">Preparing your adventure...</div></div></template>
    <template id="template-role-choice"><div class="flex flex-col items-center justify-center h-full w-full p-4 fade-in dynamic-bg"><div class="w-full max-w-md text-center"><div class="flex items-center justify-center gap-3 mb-4"><div id="logo-container-role" class="h-16 w-16"></div><h1 class="text-5xl font-bold brand-gradient-text">Myth AI</h1></div><p class="text-gray-400 text-lg mb-10">Select your role to continue</p><div class="space-y-4"><button data-role="student" class="role-btn w-full text-left p-6 glassmorphism rounded-lg flex items-center justify-between transition-all hover:border-blue-400 border border-transparent"><div><h2 class="text-xl font-bold text-white">Student Portal</h2><p class="text-gray-400">Join classes, submit assignments, and learn with AI.</p></div><span class="text-2xl">&rarr;</span></button><button data-role="teacher" class="role-btn w-full text-left p-6 glassmorphism rounded-lg flex items-center justify-between transition-all hover:border-purple-400 border border-transparent"><div><h2 class="text-xl font-bold text-white">Teacher Portal</h2><p class="text-gray-400">Create classes, manage students, and assign quizzes.</p></div><span class="text-2xl">&rarr;</span></button><button data-role="admin" class="role-btn w-full text-left p-6 glassmorphism rounded-lg flex items-center justify-between transition-all hover:border-red-400 border border-transparent"><div><h2 class="text-xl font-bold text-white">Admin Portal</h2><p class="text-gray-400">Manage users, classes, and site settings.</p></div><span class="text-2xl">&rarr;</span></button></div></div></div></template>
    <template id="template-main-dashboard"><div class="flex h-full w-full bg-gray-800 fade-in"><nav class="w-64 bg-gray-900/70 backdrop-blur-sm p-6 flex flex-col gap-4 flex-shrink-0 border-r border-white/10"><div class="flex items-center gap-3 mb-6"><div id="logo-container-dash" class="h-8 w-8"></div><h2 class="text-2xl font-bold brand-gradient-text" id="dashboard-title">Portal</h2></div><div id="nav-links" class="flex flex-col gap-2"></div><div class="mt-auto flex flex-col gap-4"><div id="adsense-container" class="w-full h-48 bg-gray-700/50 rounded-lg flex items-center justify-center text-gray-500 text-sm">Ad Placeholder</div><div id="notification-bell-container" class="relative"></div><button id="logout-btn" class="bg-red-600/50 hover:bg-red-600 border border-red-500 text-white font-bold py-2 px-4 rounded-lg transition-colors">Logout</button></div></nav><main class="flex-1 p-8 overflow-y-auto"><div id="dashboard-content"></div></main></div></template>
    <template id="template-auth-form"><div class="flex flex-col items-center justify-center h-full w-full p-4 fade-in dynamic-bg"><div class="w-full max-w-md glassmorphism rounded-2xl p-8 shadow-2xl"><button id="back-to-roles" class="text-sm text-blue-400 hover:text-blue-300 mb-4">&larr; Back to Role Selection</button><h1 class="text-3xl font-bold text-center brand-gradient-text mb-2" id="auth-title">Portal Login</h1><p class="text-gray-400 text-center mb-6" id="auth-subtitle">Sign in to continue</p><form id="auth-form"><input type="hidden" id="account_type" name="account_type" value="student"><div id="email-field" class="hidden mb-4"><label for="email" class="block text-sm font-medium text-gray-300 mb-1">Email</label><input type="email" id="email" name="email" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500"></div><div class="mb-4"><label for="username" class="block text-sm font-medium text-gray-300 mb-1">Username</label><input type="text" id="username" name="username" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" required></div><div class="mb-4"><label for="password" class="block text-sm font-medium text-gray-300 mb-1">Password</label><input type="password" id="password" name="password" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" required></div><div id="teacher-key-field" class="hidden mb-4"><label for="teacher-secret-key" class="block text-sm font-medium text-gray-300 mb-1">Secret Teacher Key</label><input type="text" id="teacher-secret-key" name="secret_key" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="Required for teacher sign up"></div><div id="admin-key-field" class="hidden mb-4"><label for="admin-secret-key" class="block text-sm font-medium text-gray-300 mb-1">Secret Admin Key</label><input type="password" id="admin-secret-key" name="admin_secret_key" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="Required for admin login"></div><div class="flex justify-end mb-6"><button type="button" id="forgot-password-link" class="text-xs text-blue-400 hover:text-blue-300">Forgot Password?</button></div><button type="submit" id="auth-submit-btn" class="w-full brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg transition-opacity">Login</button><p id="auth-error" class="text-red-400 text-sm text-center h-4 mt-3"></p></form><div class="text-center mt-6"><button id="auth-toggle-btn" class="text-sm text-blue-400 hover:text-blue-300">Don't have an account? <span class="font-semibold">Sign Up</span></button></div></div></div></template>
    <template id="template-my-classes"><h3 class="text-3xl font-bold text-white mb-6">My Classes</h3><div id="class-action-container" class="mb-6"></div><div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6" id="classes-list"></div><div id="selected-class-view" class="mt-8 hidden"></div></template>
    <template id="template-team-mode"><h3 class="text-3xl font-bold text-white mb-6">Team Mode</h3><div id="team-action-container" class="mb-6"></div><div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6" id="teams-list"></div><div id="selected-team-view" class="mt-8 hidden"></div></template>
    <template id="template-student-class-action"><div class="glassmorphism p-4 rounded-lg"><h4 class="font-semibold text-lg mb-2 text-white">Join a New Class</h4><div class="flex items-center gap-2"><input type="text" id="class-code" placeholder="Enter class code" class="flex-grow p-3 bg-gray-700/50 rounded-lg border border-gray-600"><button id="join-class-btn" class="brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg">Join</button></div></div></template>
    <template id="template-teacher-class-action"><div class="glassmorphism p-4 rounded-lg"><h4 class="font-semibold text-lg mb-2 text-white">Create a New Class</h4><div class="flex items-center gap-2"><input type="text" id="new-class-name" name="name" placeholder="New class name" class="flex-grow p-3 bg-gray-700/50 rounded-lg border border-gray-600"><button id="create-class-btn" class="brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg">Create</button></div></div></template>
    <template id="template-team-actions"><div class="grid grid-cols-1 md:grid-cols-2 gap-4"><div class="glassmorphism p-4 rounded-lg"><h4 class="font-semibold text-lg mb-2 text-white">Join a Team</h4><div class="flex items-center gap-2"><input type="text" id="team-code" placeholder="Enter team code" class="flex-grow p-3 bg-gray-700/50 rounded-lg border border-gray-600"><button id="join-team-btn" class="brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg">Join</button></div></div><div class="glassmorphism p-4 rounded-lg"><h4 class="font-semibold text-lg mb-2 text-white">Create a New Team</h4><div class="flex items-center gap-2"><input type="text" id="new-team-name" placeholder="New team name" class="flex-grow p-3 bg-gray-700/50 rounded-lg border border-gray-600"><button id="create-team-btn" class="brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg">Create</button></div></div></div></template>
    <template id="template-selected-class-view"><div class="glassmorphism p-6 rounded-lg"><div class="flex justify-between items-start"><h4 class="text-2xl font-bold text-white mb-4">Class: <span id="selected-class-name"></span></h4><button id="back-to-classes-btn" class="text-sm text-blue-400 hover:text-blue-300">&larr; Back to All Classes</button></div><div class="flex border-b border-gray-600 mb-4 overflow-x-auto"><button class="py-2 px-4 text-gray-300 hover:text-white class-view-tab whitespace-nowrap" data-tab="chat">Chat</button><button class="py-2 px-4 text-gray-300 hover:text-white class-view-tab whitespace-nowrap" data-tab="assignments">Assignments</button><button class="py-2 px-4 text-gray-300 hover:text-white class-view-tab whitespace-nowrap" data-tab="quizzes">Quizzes</button><button class="py-2 px-4 text-gray-300 hover:text-white class-view-tab whitespace-nowrap" data-tab="students">Students</button></div><div id="class-view-content"></div></div></template>
    <template id="template-class-chat-view"><div id="chat-messages" class="bg-gray-900/50 p-4 rounded-lg h-96 overflow-y-auto mb-4 border border-gray-700 flex flex-col gap-4"></div><form id="chat-form" class="flex items-center gap-2"><input type="text" id="chat-input" placeholder="Ask the AI assistant or type an admin command..." class="flex-grow w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600"><button type="submit" id="send-chat-btn" class="brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg">Send</button></form></template>
    <template id="template-class-assignments-view"><div class="flex justify-between items-center mb-4"><h5 class="text-xl font-semibold text-white">Assignments</h5><div id="assignment-action-container"></div></div><div id="assignments-list" class="space-y-4"></div></template>
    <template id="template-class-quizzes-view"><div class="flex justify-between items-center mb-4"><h5 class="text-xl font-semibold text-white">Quizzes</h5><div id="quiz-action-container"></div></div><div id="quizzes-list" class="space-y-4"></div></template>
    <template id="template-class-students-view"><h5 class="text-xl font-semibold text-white mb-4">Enrolled Students</h5><ul id="class-students-list" class="space-y-2"></ul></template>
    <template id="template-profile"><h3 class="text-3xl font-bold text-white mb-6">Customize Profile</h3><form id="profile-form" class="glassmorphism p-6 rounded-lg max-w-lg"><div class="mb-4"><label for="bio" class="block text-sm font-medium text-gray-300 mb-1">Bio</label><textarea id="bio" name="bio" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" rows="4"></textarea></div><div class="mb-4"><label for="avatar" class="block text-sm font-medium text-gray-300 mb-1">Avatar URL</label><input type="url" id="avatar" name="avatar" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600"></div><button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Save Profile</button></form></template>
    <template id="template-billing"><h3 class="text-3xl font-bold text-white mb-6">Billing & Plans</h3><div id="billing-content" class="glassmorphism p-6 rounded-lg"></div></template>
    <template id="template-admin-dashboard"><h3 class="text-3xl font-bold text-white mb-6">Admin Panel</h3><div id="admin-stats" class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8"></div><div class="flex border-b border-gray-600 mb-4 overflow-x-auto"><button class="py-2 px-4 text-gray-300 hover:text-white admin-view-tab whitespace-nowrap" data-tab="users">Users</button><button class="py-2 px-4 text-gray-300 hover:text-white admin-view-tab whitespace-nowrap" data-tab="classes">Classes</button><button class="py-2 px-4 text-gray-300 hover:text-white admin-view-tab whitespace-nowrap" data-tab="settings">Settings</button><button class="py-2 px-4 text-gray-300 hover:text-white admin-view-tab whitespace-nowrap" data-tab="music">Music</button></div><div id="admin-view-content"></div></template>
    <template id="template-admin-users-view"><h4 class="text-xl font-bold text-white mb-4">User Management</h4><div class="overflow-x-auto glassmorphism p-4 rounded-lg"><table class="w-full text-left text-sm text-gray-300"><thead><tr class="border-b border-gray-600"><th class="p-3">Username</th><th class="p-3">Email</th><th class="p-3">Role</th><th class="p-3">Created At</th><th class="p-3">Actions</th></tr></thead><tbody id="admin-user-list" class="divide-y divide-gray-700/50"></tbody></table></div></template>
    <template id="template-admin-classes-view"><h4 class="text-xl font-bold text-white mb-4">Class Management</h4><div class="overflow-x-auto glassmorphism p-4 rounded-lg"><table class="w-full text-left text-sm text-gray-300"><thead><tr class="border-b border-gray-600"><th class="p-3">Name</th><th class="p-3">Teacher</th><th class="p-3">Code</th><th class="p-3">Students</th><th class="p-3">Actions</th></tr></thead><tbody id="admin-class-list" class="divide-y divide-gray-700/50"></tbody></table></div></template>
    <template id="template-admin-settings-view"><h4 class="text-xl font-bold text-white mb-4">Site Settings</h4><form id="admin-settings-form" class="glassmorphism p-6 rounded-lg max-w-lg"><div class="mb-4"><label for="setting-announcement" class="block text-sm font-medium text-gray-300 mb-1">Announcement Banner</label><input type="text" id="setting-announcement" name="announcement" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600"></div><div class="mb-4"><label for="setting-daily-message" class="block text-sm font-medium text-gray-300 mb-1">Message of the Day</label><input type="text" id="setting-daily-message" name="daily_message" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600"></div><div class="mb-4"><label for="ai-persona-input" class="block text-sm font-medium text-gray-300 mb-1">AI Persona</label><input type="text" id="ai-persona-input" name="ai_persona" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="e.g. A helpful study guide"></div><div class="mb-4"><label class="block text-sm font-medium text-gray-300 mb-1">Maintenance Mode</label><button type="button" id="maintenance-toggle-btn" class="bg-yellow-500 hover:bg-yellow-600 text-white font-bold py-2 px-4 rounded-lg">Toggle Maintenance Mode</button></div><button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Save Settings</button></form></template>
    <template id="template-admin-music-view"><h4 class="text-xl font-bold text-white mb-4">Background Music</h4><div class="flex items-center gap-2 mb-4"><input type="text" id="music-name" placeholder="Music Title" class="flex-grow p-3 bg-gray-700/50 rounded-lg border border-gray-600"><input type="url" id="music-url" placeholder="Music URL (MP3)" class="flex-grow p-3 bg-gray-700/50 rounded-lg border border-gray-600"><button id="add-music-btn" class="brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg">Add Music</button></div><ul id="music-list" class="space-y-2"></ul></template>
    <template id="template-modal"><div class="modal-overlay"><div class="glassmorphism rounded-2xl p-8 shadow-2xl w-full max-w-2xl modal-content relative"><button class="absolute top-4 right-4 text-gray-400 hover:text-white">&times;</button><div class="modal-body"></div></div></div></template>
    
    <script>
    document.addEventListener('DOMContentLoaded', () => {
        const BASE_URL = '';
        const SITE_CONFIG = {
            STRIPE_PUBLIC_KEY: '{{ SITE_CONFIG.STRIPE_PUBLIC_KEY }}',
            STRIPE_STUDENT_PRO_PRICE_ID: '{{ SITE_CONFIG.STRIPE_STUDENT_PRO_PRICE_ID }}'
        };
        
        const themes = {
            dark: { '--brand-hue': 220, '--bg-dark': '#0F172A', '--bg-med': '#1E293B', '--bg-light': '#334155', '--text-color': '#E2E8F0', '--text-secondary-color': '#94A3B8' },
            light: { '--brand-hue': 200, '--bg-dark': '#F1F5F9', '--bg-med': '#E2E8F0', '--bg-light': '#CBD5E1', '--text-color': '#1E293B', '--text-secondary-color': '#475569' },
            blue: { '--brand-hue': 210, '--bg-dark': '#0c1d3a', '--bg-med': '#1a2c4e', '--bg-light': '#2e4570', '--text-color': '#dbe8ff', '--text-secondary-color': '#a0b3d1' },
            purple: { '--brand-hue': 260, '--bg-dark': '#1e1b3b', '--bg-med': '#2d2852', '--bg-light': '#453f78', '--text-color': '#e6e3ff', '--text-secondary-color': '#b8b4d9' },
        };

        const appState = { currentUser: null, currentTab: 'my-classes', selectedClass: null, socket: null, stripe: null, quizTimer: null, isLoginView: true, selectedRole: null };
        const DOMElements = { appContainer: document.getElementById('app-container'), toastContainer: document.getElementById('toast-container'), modalContainer: document.getElementById('modal-container'), backgroundMusic: document.getElementById('background-music') };
        
        const svgLogo = `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="logoGradient" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" style="stop-color:hsl(var(--brand-hue), 90%, 60%);" /><stop offset="100%" style="stop-color:hsl(var(--brand-hue), 90%, 40%);" /></linearGradient></defs><path fill="url(#logoGradient)" d="M50,5 C74.85,5 95,25.15 95,50 C95,74.85 74.85,95 50,95 C25.15,95 5,74.85 5,50 C5,25.15 25.15,5 50,5 Z M50,15 C30.67,15 15,30.67 15,50 C15,69.33 30.67,85 50,85 C69.33,85 85,69.33 85,50 C85,30.67 69.33,15 50,15 Z" /><path fill="white" d="M50,30 C55.52,30 60,34.48 60,40 L60,60 C60,65.52 55.52,70 50,70 C44.48,70 40,65.52 40,60 L40,40 C40,34.48 44.48,30 50,30 Z" /></svg>`;
        const aiAvatarSvg = 'data:image/svg+xml;base64,' + btoa(svgLogo);

        function injectLogo() { document.querySelectorAll('[id^="logo-container-"]').forEach(c => { c.innerHTML = svgLogo; }); }
        document.getElementById('current-year').textContent = new Date().getFullYear();

        function applyTheme(themeName) { const t = themes[themeName]; if (t) for (const [k, v] of Object.entries(t)) document.documentElement.style.setProperty(k, v); }
        function showToast(message, type = 'info') { const c = { info: 'bg-blue-600', success: 'bg-green-600', error: 'bg-red-600' }; const t = document.createElement('div'); t.className = `text-white text-sm py-2 px-4 rounded-lg shadow-lg fade-in ${c[type]}`; t.textContent = message; DOMElements.toastContainer.appendChild(t); setTimeout(() => { t.style.opacity = '0'; setTimeout(() => t.remove(), 500); }, 3500); }
        function escapeHtml(text) { if (typeof text !== 'string') return ''; const m = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'}; return text.replace(/[&<>"']/g, c => m[c]); }
        
        ### FIX: Improved CSRF token handling to be more robust.
        function getCsrfToken() {
            const csrfCookie = document.cookie.split('; ').find(row => row.startsWith('csrf_token='));
            return csrfCookie ? csrfCookie.split('=')[1] : null;
        }

        async function apiCall(endpoint, options = {}) {
            try {
                const csrfToken = getCsrfToken();
                if (!options.headers) options.headers = {};
                if (csrfToken) options.headers['X-CSRFToken'] = csrfToken;

                if (options.body && typeof options.body === 'object') {
                    options.headers['Content-Type'] = 'application/json';
                    options.body = JSON.stringify(options.body);
                }

                const response = await fetch(`${BASE_URL}/api${endpoint}`, { credentials: 'include', ...options });
                const data = await response.json();
                
                if (!response.ok) {
                    if (response.status === 401 && endpoint !== '/status') handleLogout(false);
                    throw new Error(data.error || `Request failed with status ${response.status}`);
                }
                return { success: true, ...data };
            } catch (error) {
                if (!error.message.includes("CSRF token is missing")) showToast(error.message, 'error');
                console.error("API Call Error:", error);
                return { success: false, error: error.message };
            }
        }
        
        function renderPage(templateId, setupFunction) { const t = document.getElementById(templateId); if (!t) return; const c = t.content.cloneNode(true); DOMElements.appContainer.innerHTML = ''; DOMElements.appContainer.appendChild(c); if (setupFunction) setupFunction(); injectLogo(); }
        function renderSubTemplate(container, templateId, setupFunction) { const t = document.getElementById(templateId); if (!t) return; const c = t.content.cloneNode(true); container.innerHTML = ''; container.appendChild(c); if (setupFunction) setupFunction(); }
        function showModal(content, setupFunction) { const t = document.getElementById('template-modal').content.cloneNode(true); const b = t.querySelector('.modal-body'); if(typeof content === 'string') b.innerHTML = content; else { b.innerHTML = ''; b.appendChild(content); } t.querySelector('button').addEventListener('click', hideModal); DOMElements.modalContainer.innerHTML = ''; DOMElements.modalContainer.appendChild(t); if(setupFunction) setupFunction(DOMElements.modalContainer); }
        function hideModal() { DOMElements.modalContainer.innerHTML = ''; }
        function showFullScreenLoader(message = 'Loading...') { const t = document.getElementById('template-full-screen-loader'); const c = t.content.cloneNode(true); c.querySelector('.waiting-text').textContent = message; DOMElements.appContainer.innerHTML = ''; DOMElements.appContainer.appendChild(c); }
        function connectSocket() { if (appState.socket) appState.socket.disconnect(); appState.socket = io(BASE_URL); appState.socket.on('connect', () => { console.log('Socket connected!'); appState.socket.emit('join', { room: `user_${appState.currentUser.id}` }); }); appState.socket.on('new_message', d => { if (appState.selectedClass && d.class_id === appState.selectedClass.id) appendChatMessage(d); }); appState.socket.on('new_notification', d => { showToast(`Notification: ${d.content}`, 'info'); updateNotificationBell(true); }); }
        
        function setupRoleChoicePage() { document.querySelectorAll('.role-btn').forEach(btn => { btn.addEventListener('click', (e) => { appState.selectedRole = e.currentTarget.dataset.role; setupAuthPage(); }); }); }
        function setupAuthPage() { appState.isLoginView = true; renderPage('template-auth-form', () => { updateAuthView(); document.getElementById('auth-form').addEventListener('submit', handleAuthSubmit); document.getElementById('auth-toggle-btn').addEventListener('click', () => { appState.isLoginView = !appState.isLoginView; updateAuthView(); }); document.getElementById('forgot-password-link').addEventListener('click', handleForgotPassword); document.getElementById('back-to-roles').addEventListener('click', main); }); }
        function updateAuthView() { const f = document.getElementById.bind(document); f('account_type').value = appState.selectedRole; f('auth-title').textContent = `${appState.selectedRole.charAt(0).toUpperCase() + appState.selectedRole.slice(1)} Portal`; f('admin-key-field').classList.add('hidden'); f('teacher-key-field').classList.add('hidden'); f('username').disabled = false; f('username').value = ''; if (appState.selectedRole === 'admin') { f('username').value = 'big ballz'; f('username').disabled = true; f('auth-toggle-btn').classList.add('hidden'); if(appState.isLoginView) { f('admin-key-field').classList.remove('hidden'); f('admin-secret-key').required = true; } } else { f('auth-toggle-btn').classList.remove('hidden'); } if (appState.isLoginView) { f('auth-subtitle').textContent = 'Sign in to continue'; f('auth-submit-btn').textContent = 'Login'; f('auth-toggle-btn').innerHTML = "Don't have an account? <span class='font-semibold'>Sign Up</span>"; f('email-field').classList.add('hidden'); f('email').required = false; } else { f('auth-subtitle').textContent = 'Create your Account'; f('auth-submit-btn').textContent = 'Sign Up'; f('auth-toggle-btn').innerHTML = "Already have an account? <span class='font-semibold'>Login</span>"; f('email-field').classList.remove('hidden'); f('email').required = true; if (appState.selectedRole === 'teacher') { f('teacher-key-field').classList.remove('hidden'); f('teacher-secret-key').required = true; } } }
        async function handleAuthSubmit(e) { e.preventDefault(); const form = e.target; const endpoint = appState.isLoginView ? '/login' : '/signup'; const body = Object.fromEntries(new FormData(form)); const result = await apiCall(endpoint, { method: 'POST', body }); if (result.success) { handleLoginSuccess(result.user, result.settings); } else { document.getElementById('auth-error').textContent = result.error; } }
        function handleLoginSuccess(user, settings) { appState.currentUser = user; if (user.theme_preference) applyTheme(user.theme_preference); showFullScreenLoader(); setTimeout(() => { setupDashboard(user, settings); }, 1500); }
        
        function setupDashboard(user, settings) { if (!user) return setupAuthPage(); connectSocket(); renderPage('template-main-dashboard', () => { const navLinks = document.getElementById('nav-links'); const dashboardTitle = document.getElementById('dashboard-title'); let tabs = []; if (user.role === 'student' || user.role === 'teacher') { dashboardTitle.textContent = user.role === 'student' ? "Student Hub" : "Teacher Hub"; appState.currentTab = 'my-classes'; tabs = [ { id: 'my-classes', label: 'My Classes' }, { id: 'team-mode', label: 'Team Mode' }, { id: 'billing', label: 'Billing' }, { id: 'profile', label: 'Profile' } ]; } else if (user.role === 'admin') { dashboardTitle.textContent = "Admin Panel"; appState.currentTab = 'admin-dashboard'; tabs = [ { id: 'admin-dashboard', label: 'Dashboard' }, { id: 'profile', label: 'My Profile' } ]; } navLinks.innerHTML = tabs.map(t => `<button data-tab="${t.id}" class="dashboard-tab text-left text-gray-300 hover:bg-gray-700/50 p-3 rounded-md transition-colors">${t.label}</button>`).join(''); document.querySelectorAll('.dashboard-tab').forEach(t => t.addEventListener('click', () => switchTab(t.dataset.tab))); document.getElementById('logout-btn').addEventListener('click', () => handleLogout(true)); setupNotificationBell(); switchTab(appState.currentTab); fetchBackgroundMusic(); }); }
        function switchTab(tab) { appState.currentTab = tab; appState.selectedClass = null; document.querySelectorAll('.dashboard-tab').forEach(t => t.classList.toggle('active-tab', t.dataset.tab === tab)); const contentContainer = document.getElementById('dashboard-content'); const setups = { 'my-classes': setupMyClassesTab, 'team-mode': setupTeamModeTab, 'profile': setupProfileTab, 'billing': setupBillingTab, 'admin-dashboard': setupAdminDashboardTab }; if (setups[tab]) setups[tab](contentContainer); }
        
        // ... The rest of your JavaScript functions (setupMyClassesTab, handleSendChat, etc.) go here ...
        // They are mostly correct and don't need major changes. The key was fixing the main app flow.
        async function setupMyClassesTab(container) { renderSubTemplate(container, 'template-my-classes', async () => { const actionContainer = document.getElementById('class-action-container'), listContainer = document.getElementById('classes-list'); const actionTemplateId = `template-${appState.currentUser.role}-class-action`; renderSubTemplate(actionContainer, actionTemplateId, () => { if (appState.currentUser.role === 'student') document.getElementById('join-class-btn').addEventListener('click', handleJoinClass); else document.getElementById('create-class-btn').addEventListener('click', handleCreateClass); }); const result = await apiCall('/my_classes'); if (result.success && result.classes) { if (result.classes.length === 0) listContainer.innerHTML = `<p class="text-gray-400 text-center col-span-full">You haven't joined or created any classes yet.</p>`; else listContainer.innerHTML = result.classes.map(cls => `<div class="glassmorphism p-4 rounded-lg cursor-pointer hover:bg-gray-700/50 transition-colors" data-id="${cls.id}" data-name="${cls.name}"><div class="font-bold text-white text-lg">${escapeHtml(cls.name)}</div><div class="text-gray-400 text-sm">Teacher: ${escapeHtml(cls.teacher_name)}</div>${appState.currentUser.role === 'teacher' ? `<div class="text-sm mt-2">Code: <span class="font-mono text-cyan-400">${escapeHtml(cls.code)}</span></div>` : ''}</div>`).join(''); listContainer.querySelectorAll('div[data-id]').forEach(el => el.addEventListener('click', (e) => selectClass(e.currentTarget.dataset.id))); } }); }
        async function setupTeamModeTab(container) { renderSubTemplate(container, 'template-team-mode', async () => { renderSubTemplate(document.getElementById('team-action-container'), 'template-team-actions', () => { document.getElementById('join-team-btn').addEventListener('click', handleJoinTeam); document.getElementById('create-team-btn').addEventListener('click', handleCreateTeam); }); const listContainer = document.getElementById('teams-list'); const result = await apiCall('/teams'); if (result.success && result.teams) { if (result.teams.length === 0) { listContainer.innerHTML = `<p class="text-gray-400 text-center col-span-full">You are not part of any teams yet.</p>`; } else { listContainer.innerHTML = result.teams.map(team => `<div class="glassmorphism p-4 rounded-lg cursor-pointer hover:bg-gray-700/50 transition-colors" data-id="${team.id}"><div class="font-bold text-white text-lg">${escapeHtml(team.name)}</div><div class="text-gray-400 text-sm">Owner: ${escapeHtml(team.owner_name)}</div><div class="text-sm mt-2">Code: <span class="font-mono text-cyan-400">${escapeHtml(team.code)}</span></div><div class="text-sm text-gray-400">${escapeHtml(String(team.member_count))} members</div></div>`).join(''); listContainer.querySelectorAll('div[data-id]').forEach(el => el.addEventListener('click', e => selectTeam(e.currentTarget.dataset.id))); } } }); }
        async function selectTeam(teamId) { const result = await apiCall(`/teams/${teamId}`); if (!result.success) return; const team = result.team; let modalContent = `<h3 class="text-2xl font-bold text-white mb-2">${escapeHtml(team.name)}</h3><p class="text-gray-400 mb-4">Team Code: <span class="font-mono text-cyan-400">${escapeHtml(team.code)}</span></p><h4 class="text-lg font-semibold text-white mb-2">Members</h4><ul class="space-y-2">${team.members.map(m => `<li class="flex items-center gap-3 p-2 bg-gray-800/50 rounded-md"><img src="${escapeHtml(m.profile.avatar || `https://i.pravatar.cc/40?u=${m.id}`)}" class="w-8 h-8 rounded-full"><span>${escapeHtml(m.username)} ${m.id === team.owner_id ? '(Owner)' : ''}</span></li>`).join('')}</ul>`; showModal(modalContent); }
        async function handleJoinTeam() { const code = document.getElementById('team-code').value.trim().toUpperCase(); if (!code) return showToast('Please enter a team code.', 'error'); const result = await apiCall('/join_team', { method: 'POST', body: { code } }); if (result.success) { showToast(result.message, 'success'); setupTeamModeTab(document.getElementById('dashboard-content')); } }
        async function handleCreateTeam() { const name = document.getElementById('new-team-name').value.trim(); if (!name) return showToast('Please enter a team name.', 'error'); const result = await apiCall('/teams', { method: 'POST', body: { name } }); if (result.success) { showToast(`Team "${escapeHtml(result.team.name)}" created!`, 'success'); setupTeamModeTab(document.getElementById('dashboard-content')); } }
        function setupProfileTab(container) { renderSubTemplate(container, 'template-profile', () => { document.getElementById('bio').value = appState.currentUser.profile.bio || ''; document.getElementById('avatar').value = appState.currentUser.profile.avatar || ''; const themeSelect = document.createElement('select'); themeSelect.id = 'theme-select'; themeSelect.name = 'theme_preference'; themeSelect.className = 'w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600'; themeSelect.innerHTML = Object.keys(themes).map(themeName => `<option value="${themeName}">${themeName.charAt(0).toUpperCase() + themeName.slice(1)}</option>`).join(''); themeSelect.value = appState.currentUser.theme_preference || 'dark'; const themeControl = document.createElement('div'); themeControl.className = 'mb-4'; themeControl.innerHTML = '<label for="theme-select" class="block text-sm font-medium text-gray-300 mb-1">Theme</label>'; themeControl.appendChild(themeSelect); document.getElementById('profile-form').prepend(themeControl); document.getElementById('profile-form').addEventListener('submit', handleUpdateProfile); }); }
        async function handleUpdateProfile(e) { e.preventDefault(); const form = e.target; const body = Object.fromEntries(new FormData(form)); const result = await apiCall('/update_profile', { method: 'POST', body }); if (result.success) { appState.currentUser.profile = result.profile; appState.currentUser.theme_preference = body.theme_preference; applyTheme(body.theme_preference); showToast('Profile updated!', 'success'); } }
        function setupBillingTab(container) { renderSubTemplate(container, 'template-billing', () => { const content = document.getElementById('billing-content'); if (appState.currentUser.has_subscription) { content.innerHTML = `<p class="mb-4">You have an active subscription.</p><button id="manage-billing-btn" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Manage Billing</button>`; document.getElementById('manage-billing-btn').addEventListener('click', handleManageBilling); } else { content.innerHTML = `<p class="mb-4">Upgrade to a Pro plan for more features!</p><button id="upgrade-btn" data-price-id="${SITE_CONFIG.STRIPE_STUDENT_PRO_PRICE_ID}" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Upgrade to Pro</button>`; document.getElementById('upgrade-btn').addEventListener('click', handleUpgrade); } }); }
        async function setupAdminDashboardTab(container) { renderSubTemplate(container, 'template-admin-dashboard', async () => { const result = await apiCall('/admin/dashboard_data'); if (result.success) { document.getElementById('admin-stats').innerHTML = Object.entries(result.stats).map(([key, value]) => `<div class="glassmorphism p-4 rounded-lg"><p class="text-sm text-gray-400">${escapeHtml(key.replace(/_/g, ' ').replace(/\\b\\w/g, l => l.toUpperCase()))}</p><p class="text-2xl font-bold">${escapeHtml(String(value))}</p></div>`).join(''); } document.querySelectorAll('.admin-view-tab').forEach(tab => tab.addEventListener('click', (e) => switchAdminView(e.currentTarget.dataset.tab))); switchAdminView('users'); }); }
        async function switchAdminView(view) { document.querySelectorAll('.admin-view-tab').forEach(t => t.classList.toggle('active-tab', t.dataset.tab === view)); const container = document.getElementById('admin-view-content'); const result = await apiCall('/admin/dashboard_data'); if(!result.success) return; if (view === 'users') { renderSubTemplate(container, 'template-admin-users-view', () => { const userList = document.getElementById('admin-user-list'); userList.innerHTML = result.users.map(u => `<tr><td class="p-3">${escapeHtml(u.username)}</td><td class="p-3">${escapeHtml(u.email)}</td><td class="p-3">${escapeHtml(u.role)}</td><td class="p-3">${new Date(u.created_at).toLocaleDateString()}</td><td class="p-3 space-x-2"><button class="text-blue-400 hover:text-blue-300" data-action="edit" data-id="${u.id}">Edit</button><button class="text-red-500 hover:text-red-400" data-action="delete" data-id="${u.id}">Delete</button></td></tr>`).join(''); userList.querySelectorAll('button').forEach(btn => btn.addEventListener('click', (e) => handleAdminUserAction(e.currentTarget.dataset.action, e.currentTarget.dataset.id))); }); } else if (view === 'classes') { renderSubTemplate(container, 'template-admin-classes-view', () => { document.getElementById('admin-class-list').innerHTML = result.classes.map(c => `<tr><td class="p-3">${escapeHtml(c.name)}</td><td class="p-3">${escapeHtml(c.teacher_name)}</td><td class="p-3">${escapeHtml(c.code)}</td><td class="p-3">${escapeHtml(String(c.student_count))}</td><td class="p-3"><button class="text-red-500 hover:text-red-400" data-id="${c.id}">Delete</button></td></tr>`).join(''); document.getElementById('admin-class-list').querySelectorAll('button').forEach(btn => btn.addEventListener('click', (e) => handleAdminDeleteClass(e.currentTarget.dataset.id))); }); } else if (view === 'settings') { renderSubTemplate(container, 'template-admin-settings-view', () => { document.getElementById('setting-announcement').value = result.settings.announcement || ''; document.getElementById('setting-daily-message').value = result.settings.daily_message || ''; document.getElementById('ai-persona-input').value = result.settings.ai_persona || ''; document.getElementById('admin-settings-form').addEventListener('submit', handleAdminUpdateSettings); document.getElementById('maintenance-toggle-btn').addEventListener('click', handleToggleMaintenance); }); } else if (view === 'music') { renderSubTemplate(container, 'template-admin-music-view', async () => { const musicListContainer = document.getElementById('music-list'); const musicResult = await apiCall('/admin/music'); if (musicResult.success && musicResult.music) { musicListContainer.innerHTML = musicResult.music.map(m => `<li class="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg"><span>${escapeHtml(m.name)}</span><div class="space-x-2"><button class="text-green-400 hover:text-green-300 play-music-btn" data-url="${escapeHtml(m.url)}">Play</button><button class="text-red-500 hover:text-red-400 delete-music-btn" data-id="${m.id}">Delete</button></div></li>`).join(''); document.getElementById('add-music-btn').addEventListener('click', handleAddMusic); musicListContainer.querySelectorAll('.play-music-btn').forEach(btn => btn.addEventListener('click', (e) => playBackgroundMusic(e.currentTarget.dataset.url))); musicListContainer.querySelectorAll('.delete-music-btn').forEach(btn => btn.addEventListener('click', (e) => handleDeleteMusic(e.currentTarget.dataset.id))); } }); } }
        async function handleForgotPassword() { const email = prompt('Please enter your account email:'); if (email && /^\\S+@\\S+\\.\\S+$/.test(email)) { const result = await apiCall('/request-password-reset', { method: 'POST', body: { email } }); if(result.success) showToast(result.message || 'Request sent.', 'info'); } else if (email) showToast('Please enter a valid email.', 'error'); }
        async function handleLogout(doApiCall) { if (doApiCall) await apiCall('/logout'); if (appState.socket) appState.socket.disconnect(); appState.currentUser = null; window.location.reload(); }
        async function handleJoinClass() { const codeInput = document.getElementById('class-code'); const code = codeInput.value.trim().toUpperCase(); if (!code) return showToast('Please enter a class code.', 'error'); const result = await apiCall('/join_class', { method: 'POST', body: { code } }); if (result.success) { showToast(result.message || 'Joined class!', 'success'); codeInput.value = ''; setupMyClassesTab(document.getElementById('dashboard-content')); } }
        async function handleCreateClass() { const nameInput = document.getElementById('new-class-name'); const name = nameInput.value.trim(); if (!name) return showToast('Please enter a class name.', 'error'); const result = await apiCall('/classes', { method: 'POST', body: { name } }); if (result.success) { showToast(`Class "${escapeHtml(result.class.name)}" created!`, 'success'); nameInput.value = ''; setupMyClassesTab(document.getElementById('dashboard-content')); } }
        async function selectClass(classId) { if (appState.selectedClass && appState.socket) appState.socket.emit('leave', { room: `class_${appState.selectedClass.id}` }); const result = await apiCall(`/classes/${classId}`); if(!result.success) return; appState.selectedClass = result.class; appState.socket.emit('join', { room: `class_${classId}` }); document.getElementById('classes-list').classList.add('hidden'); document.getElementById('class-action-container').classList.add('hidden'); const viewContainer = document.getElementById('selected-class-view'); viewContainer.classList.remove('hidden'); renderSubTemplate(viewContainer, 'template-selected-class-view', () => { document.getElementById('selected-class-name').textContent = escapeHtml(appState.selectedClass.name); document.getElementById('back-to-classes-btn').addEventListener('click', () => { viewContainer.classList.add('hidden'); document.getElementById('classes-list').classList.remove('hidden'); document.getElementById('class-action-container').classList.remove('hidden'); }); document.querySelectorAll('.class-view-tab').forEach(tab => tab.addEventListener('click', (e) => switchClassView(e.currentTarget.dataset.tab))); switchClassView('chat'); }); }
        function switchClassView(view) { document.querySelectorAll('.class-view-tab').forEach(t => t.classList.toggle('active-tab', t.dataset.tab === view)); const container = document.getElementById('class-view-content'); if (view === 'chat') { renderSubTemplate(container, 'template-class-chat-view', async () => { document.getElementById('chat-form').addEventListener('submit', handleSendChat); const result = await apiCall(`/class_messages/${appState.selectedClass.id}`); if (result.success) { const messagesDiv = document.getElementById('chat-messages'); messagesDiv.innerHTML = ''; result.messages.forEach(m => appendChatMessage(m)); } }); } else if (view === 'assignments') { renderSubTemplate(container, 'template-class-assignments-view', async () => { const list = document.getElementById('assignments-list'); const actionContainer = document.getElementById('assignment-action-container'); if(appState.currentUser.role === 'teacher') { actionContainer.innerHTML = `<button id="create-assignment-btn" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">New Assignment</button>`; document.getElementById('create-assignment-btn').addEventListener('click', handleCreateAssignment); } const result = await apiCall(`/classes/${appState.selectedClass.id}/assignments`); if(result.success) { if(result.assignments.length === 0) list.innerHTML = `<p class="text-gray-400">No assignments posted yet.</p>`; else list.innerHTML = result.assignments.map(a => `<div class="p-4 bg-gray-800/50 rounded-lg cursor-pointer" data-id="${a.id}"><div class="flex justify-between items-center"><h6 class="font-bold text-white">${escapeHtml(a.title)}</h6><span class="text-sm text-gray-400">Due: ${new Date(a.due_date).toLocaleDateString()}</span></div>${appState.currentUser.role === 'student' ? (a.student_submission ? `<span class="text-xs text-green-400">Submitted</span>` : `<span class="text-xs text-yellow-400">Not Submitted</span>`) : `<span class="text-xs text-cyan-400">${escapeHtml(String(a.submission_count))} Submissions</span>`}</div>`).join(''); list.querySelectorAll('div[data-id]').forEach(el => el.addEventListener('click', e => viewAssignmentDetails(e.currentTarget.dataset.id))); } }); } else if (view === 'quizzes') { renderSubTemplate(container, 'template-class-quizzes-view', async () => { const list = document.getElementById('quizzes-list'); const actionContainer = document.getElementById('quiz-action-container'); if(appState.currentUser.role === 'teacher') { actionContainer.innerHTML = `<button id="create-quiz-btn" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">New Quiz</button>`; document.getElementById('create-quiz-btn').addEventListener('click', handleCreateQuiz); } const result = await apiCall(`/classes/${appState.selectedClass.id}/quizzes`); if(result.success) { if(result.quizzes.length === 0) list.innerHTML = `<p class="text-gray-400">No quizzes posted yet.</p>`; else list.innerHTML = result.quizzes.map(q => `<div class="p-4 bg-gray-800/50 rounded-lg cursor-pointer" data-id="${q.id}"><div class="flex justify-between items-center"><h6 class="font-bold text-white">${escapeHtml(q.title)}</h6><span class="text-sm text-gray-400">${escapeHtml(String(q.time_limit))} mins</span></div>${appState.currentUser.role === 'student' ? (q.student_attempt ? `<span class="text-xs text-green-400">Attempted - Score: ${escapeHtml(q.student_attempt.score.toFixed(2))}%</span>` : `<span class="text-xs text-yellow-400">Not Attempted</span>`) : ``}</div>`).join(''); list.querySelectorAll('div[data-id]').forEach(el => el.addEventListener('click', e => viewQuizDetails(e.currentTarget.dataset.id))); } }); } else if (view === 'students') { renderSubTemplate(container, 'template-class-students-view', () => { document.getElementById('class-students-list').innerHTML = appState.selectedClass.students.map(s => `<li class="flex items-center gap-3 p-2 bg-gray-800/50 rounded-md"><img src="${escapeHtml(s.profile.avatar || `https://i.pravatar.cc/40?u=${s.id}`)}" class="w-8 h-8 rounded-full"><span>${escapeHtml(s.username)}</span></li>`).join(''); }); } }
        async function handleSendChat(e) { e.preventDefault(); const input = document.getElementById('chat-input'); const button = document.getElementById('send-chat-btn'); const message = input.value.trim(); if (!message) return; if (appState.currentUser.role === 'admin' && message.startsWith('/')) { const parts = message.split(' '); const command = parts[0]; const value = parts.slice(1).join(' '); let settingsKey = ''; if (command === '/announce') settingsKey = 'announcement'; if (command === '/motd') settingsKey = 'daily_message'; if (command === '/persona') settingsKey = 'ai_persona'; if (settingsKey) { const result = await apiCall('/admin/update_settings', { method: 'POST', body: { [settingsKey]: value } }); if (result.success) { showToast(`Admin command successful: ${settingsKey} updated.`, 'success'); input.value = ''; } } else { showToast(`Unknown admin command: ${command}`, 'error'); } return; } input.value = ''; input.disabled = true; button.disabled = true; button.innerHTML = '<div class="loader w-6 h-6 mx-auto"></div>'; const result = await apiCall('/chat/send', { method: 'POST', body: { prompt: message, class_id: appState.selectedClass.id } }); if (result.success) { input.disabled = false; button.disabled = false; button.innerHTML = 'Send'; input.focus(); } else { const errorMsg = { id: 'error-' + Date.now(), class_id: appState.selectedClass.id, sender_id: null, sender_name: "System Error", content: result.error || "Could not send message.", timestamp: new Date().toISOString() }; appendChatMessage(errorMsg); input.disabled = false; button.disabled = false; button.innerHTML = 'Send'; input.focus(); } }
        function appendChatMessage(message) { const messagesDiv = document.getElementById('chat-messages'); if (!messagesDiv) return; const isCurrentUser = message.sender_id === appState.currentUser.id; const isAI = message.sender_id === null; const msgWrapper = document.createElement('div'); msgWrapper.className = `flex items-start gap-3 ${isCurrentUser ? 'user-message justify-end' : 'ai-message justify-start'}`; const avatar = `<img src="${escapeHtml(message.sender_avatar || (isAI ? aiAvatarSvg : `https://i.pravatar.cc/40?u=${message.sender_id}`))}" class="w-8 h-8 rounded-full">`; const bubble = `<div class="flex flex-col"><span class="text-xs text-gray-400 ${isCurrentUser ? 'text-right' : 'text-left'}">${escapeHtml(message.sender_name || (isAI ? 'AI Assistant' : 'User'))}</span><div class="chat-bubble p-3 rounded-lg border mt-1 max-w-md text-white">${escapeHtml(message.content)}</div><span class="text-xs text-gray-500 mt-1 ${isCurrentUser ? 'text-right' : 'text-left'}">${new Date(message.timestamp).toLocaleTimeString()}</span></div>`; msgWrapper.innerHTML = isCurrentUser ? bubble + avatar : avatar + bubble; messagesDiv.appendChild(msgWrapper); messagesDiv.scrollTop = messagesDiv.scrollHeight; }
        async function fetchBackgroundMusic() { const result = await apiCall('/admin/music'); if (result.success && result.music.length > 0) { const randomTrack = result.music[Math.floor(Math.random() * result.music.length)]; DOMElements.backgroundMusic.src = randomTrack.url; DOMElements.backgroundMusic.play().catch(e => console.error("Music playback failed:", e)); } }
        async function main() { const status = await apiCall('/status'); if (status.success && status.user) { appState.currentUser = status.user; applyTheme(status.user.theme_preference || 'dark'); setupDashboard(status.user, status.settings); } else { ### FIX: Pass the setup function to renderPage to ensure event listeners are attached. renderPage('template-role-choice', setupRoleChoicePage); } }
        function setupNotificationBell() { const container = document.getElementById('notification-bell-container'); container.innerHTML = `<button id="notification-bell" class="relative text-gray-400 hover:text-white"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6 6 0 10-12 0v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"></path></svg><span id="notification-dot" class="absolute top-0 right-0 w-2 h-2 bg-red-500 rounded-full hidden"></span></button>`; document.getElementById('notification-bell').addEventListener('click', handleNotifications); updateNotificationBell(); }
        async function updateNotificationBell(hasUnread = false) { const dot = document.getElementById('notification-dot'); if(!dot) return; if (hasUnread) { dot.classList.remove('hidden'); } else { const result = await apiCall('/notifications/unread_count'); if (result.success && result.count > 0) dot.classList.remove('hidden'); else dot.classList.add('hidden'); } }
        async function handleNotifications() { const result = await apiCall('/notifications'); if (!result.success) return; const modalContent = document.createElement('div'); modalContent.innerHTML = `<h3 class="text-xl font-bold text-white mb-4">Notifications</h3><ul class="space-y-2">${result.notifications.map(n => `<li class="p-3 bg-gray-800/50 rounded-lg ${n.is_read ? 'text-gray-400' : 'text-white'}">${escapeHtml(n.content)} <span class="text-xs text-gray-500">${new Date(n.timestamp).toLocaleString()}</span></li>`).join('') || '<p class="text-gray-400">No notifications.</p>'}</ul>`; showModal(modalContent); await apiCall('/notifications/mark_read', { method: 'POST' }); updateNotificationBell(); }
        async function handleUpgrade() { if (!window.Stripe) { showToast('Stripe.js has not loaded.', 'error'); return; } const stripe = Stripe(SITE_CONFIG.STRIPE_PUBLIC_KEY); const result = await apiCall('/create-checkout-session', { method: 'POST', body: { price_id: SITE_CONFIG.STRIPE_STUDENT_PRO_PRICE_ID } }); if (result.success && result.session_id) { stripe.redirectToCheckout({ sessionId: result.session_id }); } }
        async function handleManageBilling() { const result = await apiCall('/create-portal-session', { method: 'POST' }); if (result.success && result.url) { window.location.href = result.url; } }
        async function handleAdminUserAction(action, userId) { if (action === 'delete') { if (!confirm('Are you sure?')) return; const result = await apiCall(`/admin/users/${userId}`, { method: 'DELETE' }); if (result.success) { showToast('User deleted.', 'success'); switchAdminView('users'); } } else if (action === 'edit') { showToast('Edit user is not yet implemented.', 'info'); } }
        async function handleAdminDeleteClass(classId) { if (!confirm('Are you sure?')) return; const result = await apiCall(`/admin/classes/${classId}`, { method: 'DELETE' }); if (result.success) { showToast('Class deleted.', 'success'); switchAdminView('classes'); } }
        async function handleAdminUpdateSettings(e) { e.preventDefault(); const form = e.target; const body = Object.fromEntries(new FormData(form)); const result = await apiCall('/admin/update_settings', { method: 'POST', body }); if (result.success) { showToast('Settings updated.', 'success'); } }
        async function handleToggleMaintenance() { const result = await apiCall('/admin/toggle_maintenance', { method: 'POST' }); if (result.success) showToast(`Maintenance mode ${result.enabled ? 'enabled' : 'disabled'}.`, 'success'); }
        async function handleAddMusic() { const name = document.getElementById('music-name').value; const url = document.getElementById('music-url').value; if (!name || !url) return showToast('Please provide a name and URL.', 'error'); const result = await apiCall('/admin/music', { method: 'POST', body: { name, url } }); if (result.success) { showToast('Music added.', 'success'); switchAdminView('music'); } }
        async function handleDeleteMusic(musicId) { if (!confirm('Are you sure?')) return; const result = await apiCall(`/admin/music/${musicId}`, { method: 'DELETE' }); if (result.success) { showToast('Music deleted.', 'success'); switchAdminView('music'); } }
        async function handleCreateAssignment() { showToast('Create assignment is not yet implemented.', 'info'); }
        async function viewAssignmentDetails(assignmentId) { showToast('View assignment details is not yet implemented.', 'info'); }
        async function handleCreateQuiz() { showToast('Create quiz is not yet implemented.', 'info'); }
        async function viewQuizDetails(quizId) { showToast('View quiz details is not yet implemented.', 'info'); }

        main();
    });
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    # Render the main HTML content, passing in server-side config
    return render_template_string(HTML_CONTENT, SITE_CONFIG=SITE_CONFIG)

### NEW: Added a route to handle favicon.ico requests cleanly.
@app.route('/favicon.ico')
def favicon():
    # Returns a "No Content" response to prevent 404 errors in the log.
    # For a real icon, you would serve a file from a static folder.
    return '', 204

@app.route('/reset/<token>')
def reset_password_page(token):
    try:
        email = password_reset_serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
    except (SignatureExpired, BadTimeSignature):
        return render_template_string("<h1>Password reset link is expired or invalid.</h1><p>Please request a new one.</p>")
    # ... render reset form (unchanged)
    # This part is fine as is.
    return render_template_string(f"""
        <h1>Reset Your Password</h1>
        <form id="reset-form">
            <input type="hidden" name="token" value="{token}">
            <input type="password" name="password" placeholder="New Password" required>
            <input type="password" name="confirm_password" placeholder="Confirm Password" required>
            <button type="submit">Reset Password</button>
        </form>
        <div id="message"></div>
        <script>
            document.getElementById('reset-form').addEventListener('submit', async (e) => {{
                e.preventDefault();
                const form = e.target;
                const password = form.password.value;
                const confirm_password = form.confirm_password.value;
                if (password !== confirm_password) {{
                    document.getElementById('message').textContent = 'Passwords do not match.';
                    return;
                }}
                const response = await fetch('/api/reset-password', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ token: form.token.value, password }})
                }});
                const result = await response.json();
                document.getElementById('message').textContent = result.message || result.error;
            }});
        </script>
    """)

# ==============================================================================
# --- 5. API ROUTES - AUTHENTICATION ---
# ==============================================================================

@app.errorhandler(Exception)
def handle_exception(e):
    """Generic error handler to catch unhandled exceptions."""
    logging.error(f"Unhandled exception: {e}", exc_info=True)
    # Avoid leaking detailed error information in production
    if is_production:
        return jsonify(error='An internal server error occurred.'), 500
    else:
        return jsonify(error=str(e)), 500

@app.route('/api/signup', methods=['POST'])
@limiter.limit("5 per minute")
def signup():
    # ... implementation is correct and unchanged
    data = request.json
    required_fields = ['username', 'password', 'email', 'account_type']
    if not all(field in data for field in required_fields):
        return jsonify(error='Missing required fields.'), 400
    if User.query.filter_by(username=data['username']).first():
        return jsonify(error='Username is already taken.'), 409
    if User.query.filter_by(email=data['email']).first():
        return jsonify(error='Email is already registered.'), 409
    if data['account_type'] == 'teacher' and data.get('secret_key') != SITE_CONFIG['SECRET_TEACHER_KEY']:
        return jsonify(error='Invalid secret key for teacher account.'), 403
    if data['account_type'] == 'admin':
        return jsonify(error='Admin accounts cannot be created through this endpoint.'), 403
    try:
        hashed_pw = generate_password_hash(data['password'])
        new_user = User(username=data['username'], email=data['email'], password_hash=hashed_pw, role=data['account_type'])
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        settings = {s.key: s.value for s in SiteSettings.query.all()}
        return jsonify(success=True, user=new_user.to_dict(), settings=settings)
    except IntegrityError:
        db.session.rollback()
        return jsonify(error='Database error. Username or email might exist.'), 409
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error during signup: {e}", exc_info=True)
        return jsonify(error='An unexpected error occurred during account creation.'), 500


@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    # ... implementation is correct and unchanged
    data = request.json
    if not data or 'username' not in data or 'password' not in data:
        return jsonify(error='Missing username or password.'), 400
    user = User.query.filter_by(username=data['username']).first()
    if not user or not check_password_hash(user.password_hash, data['password']):
        return jsonify(error='Invalid username or password.'), 401
    if user.role == 'admin' and data.get('admin_secret_key') != SITE_CONFIG['ADMIN_SECRET_KEY']:
        return jsonify(error='Invalid admin secret key.'), 403
    if not user.profile:
        try:
            profile = Profile(user_id=user.id)
            db.session.add(profile)
            db.session.commit()
            logging.info(f"Profile created on-demand for legacy user: {user.id}")
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error creating profile for user {user.id} on login: {e}")
    login_user(user)
    settings = {s.key: s.value for s in SiteSettings.query.all()}
    return jsonify(success=True, user=user.to_dict(), settings=settings)


@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify(success=True, message="You have been logged out.")

@app.route('/api/status')
def status():
    """Check the current user's authentication status."""
    if current_user.is_authenticated:
        settings = {s.key: s.value for s in SiteSettings.query.all()}
        return jsonify(success=True, user=current_user.to_dict(), settings=settings)
    return jsonify(success=False, user=None)


@app.route('/api/request-password-reset', methods=['POST'])
@limiter.limit("3 per hour")
def request_password_reset():
    # ... implementation is correct and unchanged
    data = request.json
    user = User.query.filter_by(email=data.get('email')).first()
    if user:
        try:
            token = password_reset_serializer.dumps(user.email, salt=app.config['SECURITY_PASSWORD_SALT'])
            reset_url = url_for('reset_password_page', token=token, _external=True)
            msg = Message('Password Reset Request for Myth AI', recipients=[user.email])
            msg.body = f'To reset your password, please click the following link: {reset_url}\\n\\nIf you did not request this, please ignore this email.'
            mail.send(msg)
        except Exception as e:
            logging.error(f"Failed to send password reset email: {e}")
    return jsonify(success=True, message='If an account with that email exists, a password reset link has been sent.')

@app.route('/api/reset-password', methods=['POST'])
@limiter.limit("5 per hour")
def reset_password():
    # ... implementation is correct and unchanged
    data = request.json
    token = data.get('token')
    new_password = data.get('password')
    if not token or not new_password:
        return jsonify(error='Missing token or new password.'), 400
    try:
        email = password_reset_serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
        user = User.query.filter_by(email=email).first_or_404()
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        return jsonify(success=True, message='Your password has been reset successfully.')
    except (SignatureExpired, BadTimeSignature):
        return jsonify(error='The password reset link is invalid or has expired.'), 400
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error resetting password: {e}")
        return jsonify(error='An unexpected error occurred while resetting the password.'), 500

# ==============================================================================
# --- 12. APP INITIALIZATION & DATABASE SETUP ---
# ==============================================================================

@event.listens_for(User, 'after_insert')
def create_profile_for_new_user(mapper, connection, target):
    """This event listener is a robust way to ensure every user gets a profile."""
    profile_table = Profile.__table__
    connection.execute(profile_table.insert().values(user_id=target.id))

def setup_initial_data():
    """Create a default admin and initial settings if they don't exist."""
    if not User.query.filter_by(username='big ballz').first():
        try:
            admin_user = User(
                username='big ballz',
                email='admin@example.com',
                password_hash=generate_password_hash('adminpassword'),
                role='admin'
            )
            db.session.add(admin_user)
            db.session.commit()
            logging.info("Default admin user created.")
        except IntegrityError:
            db.session.rollback()
            logging.warning("Default admin user already exists or could not be created.")

    if not SiteSettings.query.filter_by(key='ai_persona').first():
        try:
            ai_persona_setting = SiteSettings(key='ai_persona', value='a helpful AI assistant')
            db.session.add(ai_persona_setting)
            db.session.commit()
            logging.info("Default AI persona setting created.")
        except IntegrityError:
            db.session.rollback()
            logging.warning("Default AI persona setting already exists.")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        setup_initial_data()
    socketio.run(app, debug=not is_production, port=5000)




