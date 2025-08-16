# --- Imports ---
import os
import json
import logging
import time
import uuid
import secrets
import requests
from flask import Flask, Response, request, session, jsonify, redirect, url_for, render_template_string, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from datetime import datetime, timedelta
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
import google.generativeai as genai

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
if os.environ.get('FLASK_ENV') == 'production':
    required_secrets = ['SECRET_KEY', 'DATABASE_URL', 'SECURITY_PASSWORD_SALT', 'STRIPE_SECRET_KEY', 'YOUR_DOMAIN', 'SECRET_TEACHER_KEY', 'ADMIN_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET', 'GEMINI_API_KEY', 'MAIL_SENDER', 'MAIL_USERNAME', 'MAIL_PASSWORD']
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
    "STRIPE_STUDENT_PRICE_ID": os.environ.get('STRIPE_STUDENT_PRICE_ID'),
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
CORS(app, supports_credentials=True, origins=[prod_origin] if os.environ.get('FLASK_ENV') == 'production' else "*")

# --- SECURITY: Content Security Policy (CSP) ---
# FIXED: The value for 'img-src' must be a list.
csp = {
    'default-src': '\'self\'',
    'script-src': [
        '\'self\'',
        '\'unsafe-inline\'',
        'https://cdn.tailwindcss.com',
        'https://cdnjs.cloudflare.com',
        'https://js.stripe.com',
        'https://pagead2.googlesyndication.com',
        'https://www.googletagmanager.com'
    ],
    'style-src': [
        '\'self\'',
        '\'unsafe-inline\'',
        'https://cdn.tailwindcss.com',
        'https://fonts.googleapis.com'
    ],
    'font-src': [
        '\'self\'',
        'https://fonts.gstatic.com'
    ],
    'img-src': ['*', 'data:'],
    'connect-src': ['\'self\'', f'wss://{prod_origin.split("//")[-1]}' if 'localhost' not in prod_origin else 'ws://localhost:5000', 'https://api.stripe.com', 'https://www.google-analytics.com']
}
Talisman(app, content_security_policy=csp)
csrf = CSRFProtect(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# --- Initialize Other Extensions ---
stripe.api_key = SITE_CONFIG.get("STRIPE_SECRET_KEY")
password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins=prod_origin if os.environ.get('FLASK_ENV') == 'production' else "*")
mail = Mail(app)
if SITE_CONFIG.get("GEMINI_API_KEY"):
    genai.configure(api_key=SITE_CONFIG.get("GEMINI_API_KEY"))

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
    password_hash = db.Column(db.String(256), nullable=True) # Nullable for Google-only users
    google_id = db.Column(db.String(255), unique=True, nullable=True, index=True)
    role = db.Column(db.String(20), nullable=False, default='student')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    has_subscription = db.Column(db.Boolean, default=False)
    stripe_customer_id = db.Column(db.String(120), nullable=True, index=True)
    points = db.Column(db.Integer, default=0)
    profile = db.relationship('Profile', back_populates='user', uselist=False, cascade="all, delete-orphan")
    taught_classes = db.relationship('Class', back_populates='teacher', lazy=True, foreign_keys='Class.teacher_id', cascade="all, delete-orphan")
    enrolled_classes = db.relationship('Class', secondary=student_class_association, back_populates='students', lazy='dynamic')
    teams = db.relationship('Team', secondary=team_member_association, back_populates='members', lazy='dynamic')
    submissions = db.relationship('Submission', back_populates='student', lazy=True, cascade="all, delete-orphan")
    quiz_attempts = db.relationship('QuizAttempt', back_populates='student', lazy=True, cascade="all, delete-orphan")
    notifications = db.relationship('Notification', back_populates='user', lazy=True, cascade="all, delete-orphan")
    achievements = db.relationship('UserAchievement', back_populates='user', lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        profile_data = {
            'bio': self.profile.bio or '' if self.profile else '',
            'avatar': self.profile.avatar or '' if self.profile else '',
            'theme_preference': self.profile.theme_preference or 'golden' if self.profile else 'golden',
            'ai_persona': self.profile.ai_persona or '' if self.profile else ''
        }
        return {
            'id': self.id, 'username': self.username, 'email': self.email, 'role': self.role,
            'created_at': self.created_at.isoformat(), 'has_subscription': self.has_subscription,
            'profile': profile_data, 'points': self.points
        }

class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False, unique=True)
    bio = db.Column(db.Text, nullable=True)
    avatar = db.Column(db.String(500), nullable=True)
    theme_preference = db.Column(db.String(50), nullable=True, default='golden')
    ai_persona = db.Column(db.String(500), nullable=True)
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
    sender = db.relationship('User', backref='sent_messages')

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
    question_type = db.Column(db.String(50), nullable=False, default='multiple_choice')
    choices = db.Column(db.JSON, nullable=False) # e.g., {'options': ['A', 'B', 'C'], 'correct_answer': 'A'}
    quiz = db.relationship('Quiz', back_populates='questions')

class QuizAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id', ondelete='CASCADE'), nullable=False)
    student_id = db.Column(db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    score = db.Column(db.Float, nullable=True)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    answers = db.Column(db.JSON, nullable=True) # e.g., {'question_id': 'student_answer'}
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
    uploaded_by_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)

class AdminSignupToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(128), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_used = db.Column(db.Boolean, default=False)

class Achievement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=False)
    points = db.Column(db.Integer, nullable=False)

class UserAchievement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    achievement_id = db.Column(db.Integer, db.ForeignKey('achievement.id', ondelete='CASCADE'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', back_populates='achievements')
    achievement = db.relationship('Achievement')

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
    if request.path.startswith('/api/'):
        return jsonify({"error": "Login required."}), 401
    return redirect(url_for('index'))

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
# FIXED: The entire HTML content is now a single static string.
# The f-string formatting was causing Python syntax errors due to the curly braces in JS and CSS.
# Jinja2 variables like {{ csrf_token() }} and {{ SITE_CONFIG.VAR }} are now used for dynamic data.
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
    <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-1136294351029434" crossorigin="anonymous"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Cinzel+Decorative:wght@700&display=swap" rel="stylesheet">
    <style>
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
        .modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); display: flex; align-items: center; justify-content: center; z-index: 1000; }
        .ai-message .chat-bubble { background-color: #4a3f35; border-color: #AE8E6A; }
        .user-message .chat-bubble { background-color: #2c241e; border-color: #F5EFE6; }
        .dynamic-bg {
            background: linear-gradient(-45deg, #1a120b, #4a3f35, #b48a4f, #1a120b);
            background-size: 400% 400%;
            animation: gradientBG 20s ease infinite;
        }
        @keyframes gradientBG { 0% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } 100% { background-position: 0% 50%; } }
        .full-screen-loader {
            position: fixed; top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(26, 18, 11, 0.9); backdrop-filter: blur(8px);
            display: flex; align-items: center; justify-content: center;
            flex-direction: column; z-index: 1001; transition: opacity 0.3s ease;
        }
    </style>
    <meta name="csrf-token" content="{{ csrf_token() }}">
</head>
<body class="text-gray-200 antialiased">
    <div id="app-container" class="relative min-h-screen w-full overflow-x-hidden flex flex-col"></div>
    <div id="toast-container" class="fixed top-6 right-6 z-[100] flex flex-col gap-2"></div>
    <div id="modal-container"></div>
    <div class="fixed bottom-4 left-4 text-xs text-gray-500">Made by DeVector</div>
    <audio id="background-music" loop></audio>
    <script>
        const SITE_CONFIG = {
            STRIPE_PUBLIC_KEY: '{{ SITE_CONFIG.STRIPE_PUBLIC_KEY }}',
            STRIPE_STUDENT_PRO_PRICE_ID: '{{ SITE_CONFIG.STRIPE_STUDENT_PRO_PRICE_ID }}'
        };
    </script>
    
    <template id="template-full-screen-loader">
        <div class="full-screen-loader fade-in">
            <div id="logo-container-loader" class="h-16 w-16 mx-auto mb-4"></div>
            <div class="text-2xl font-title brand-gradient-text mb-4">Myth AI</div>
            <div class="waiting-text">Loading Portal...</div>
        </div>
    </template>
    
    <template id="template-maintenance-page">
        <div class="h-screen w-screen flex flex-col items-center justify-center dynamic-bg p-4 text-center">
            <div class="glassmorphism p-8 rounded-2xl max-w-lg w-full">
                <div id="logo-container-maintenance" class="w-20 h-20 mx-auto mb-4"></div>
                <h1 class="text-4xl font-title brand-gradient-text mb-2">Under Maintenance</h1>
                <p class="text-gray-300 mb-6">We're currently performing some upgrades to improve your experience. We'll be back online shortly!</p>
                <button id="admin-login-btn" class="text-sm text-gray-500 hover:text-gray-300">Admin Login</button>
            </div>
        </div>
    </template>

    <template id="template-role-choice">
        <div class="h-screen w-screen flex flex-col items-center justify-center dynamic-bg p-4">
            <div class="text-center mb-8">
                 <div id="logo-container-role" class="w-24 h-24 mx-auto mb-2"></div>
                <h1 class="text-5xl font-title brand-gradient-text">Welcome to Myth AI</h1>
                <p class="text-lg text-gray-300 mt-2">The AI-powered learning portal.</p>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-4xl w-full">
                <div class="role-btn glassmorphism p-6 rounded-lg text-center cursor-pointer hover:scale-105 transition-transform" data-role="student">
                    <h2 class="text-2xl font-bold text-white mb-2">Student</h2>
                    <p class="text-gray-400">Join classes, complete assignments, and use AI tools to study.</p>
                </div>
                <div class="role-btn glassmorphism p-6 rounded-lg text-center cursor-pointer hover:scale-105 transition-transform" data-role="teacher">
                    <h2 class="text-2xl font-bold text-white mb-2">Teacher</h2>
                    <p class="text-gray-400">Create classes, manage students, and post assignments.</p>
                </div>
                <div class="role-btn glassmorphism p-6 rounded-lg text-center cursor-pointer hover:scale-105 transition-transform" data-role="admin">
                    <h2 class="text-2xl font-bold text-white mb-2">Admin</h2>
                    <p class="text-gray-400">Manage the platform, users, and site settings.</p>
                </div>
            </div>
        </div>
    </template>
    
    <template id="template-auth-form">
        <div class="min-h-screen flex items-center justify-center dynamic-bg px-4">
            <div class="max-w-md w-full glassmorphism p-8 rounded-2xl">
                <button id="back-to-roles" class="text-sm text-gray-400 hover:text-white mb-4">&larr; Back to Role Selection</button>
                <div class="text-center">
                    <div id="logo-container-auth" class="w-16 h-16 mx-auto mb-2"></div>
                    <h2 id="auth-title" class="text-3xl font-bold text-white"></h2>
                    <p id="auth-subtitle" class="mt-2 text-gray-300"></p>
                </div>
                <form id="auth-form" class="mt-8 space-y-6">
                    <input type="hidden" name="account_type" id="account_type">
                    <input type="hidden" name="admin_signup_token" id="admin_signup_token" value="">
                    <div class="rounded-md shadow-sm -space-y-px">
                        <div>
                            <label for="username" class="sr-only">Username</label>
                            <input id="username" name="username" type="text" autocomplete="username" required class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:ring-2 focus:ring-yellow-500 focus:outline-none" placeholder="Username">
                        </div>
                        <div id="email-field" class="pt-4">
                            <label for="email" class="sr-only">Email address</label>
                            <input id="email" name="email" type="email" autocomplete="email" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:ring-2 focus:ring-yellow-500 focus:outline-none" placeholder="Email address">
                        </div>
                         <div class="pt-4">
                            <label for="password" class="sr-only">Password</label>
                            <input id="password" name="password" type="password" autocomplete="current-password" required class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:ring-2 focus:ring-yellow-500 focus:outline-none" placeholder="Password">
                        </div>
                        <div id="teacher-key-field" class="pt-4 hidden">
                             <input id="teacher-secret-key" name="secret_key" type="password" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="Teacher Secret Key">
                        </div>
                         <div id="admin-key-field" class="pt-4 hidden">
                             <input id="admin-secret-key" name="secret_key" type="password" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="Admin Secret Key">
                        </div>
                    </div>
                    <p id="auth-error" class="text-red-400 text-sm text-center"></p>
                    <div>
                        <button id="auth-submit-btn" type="submit" class="w-full brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg">Sign In</button>
                    </div>
                </form>
                <div class="mt-4 text-sm text-center">
                    <button id="auth-toggle-btn" class="font-medium text-yellow-400 hover:text-yellow-300"></button>
                    <a href="#" id="forgot-password-link" class="text-gray-400 hover:text-white ml-2">Forgot Password?</a>
                </div>
            </div>
        </div>
    </template>

    <script>
        // FULL JAVASCRIPT LOGIC HERE, UNCHANGED...
    </script>
</body>
</html>
"""

@app.route('/')
@app.route('/<path:path>')
def index(path=None):
    # Pass SITE_CONFIG to the template so JS can access public keys
    return render_template_string(HTML_CONTENT, SITE_CONFIG=SITE_CONFIG)

# ==============================================================================
# --- 6. API ROUTES ---
# ==============================================================================
@app.route('/api/status')
def status():
    settings_raw = SiteSettings.query.all()
    settings = {s.key: s.value for s in settings_raw}
    if current_user.is_authenticated:
        return jsonify({"user": current_user.to_dict(), "settings": settings})
    return jsonify({"user": None, "settings": settings})

# --- AUTHENTICATION API ---
@app.route('/api/signup', methods=['POST'])
@limiter.limit("5 per minute")
def signup():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role = data.get('account_type', 'student')
    secret_key = data.get('secret_key')
    admin_token = data.get('admin_signup_token')
    
    if User.query.filter(or_(User.username == username, User.email == email)).first():
        return jsonify({"error": "Username or email already exists."}), 409
        
    if role == 'teacher' and secret_key != SITE_CONFIG['SECRET_TEACHER_KEY']:
        return jsonify({"error": "Invalid teacher secret key."}), 403
        
    if role == 'admin':
        if not admin_token:
            return jsonify({"error": "Admin sign up requires a special link."}), 403
        token_obj = AdminSignupToken.query.filter_by(token=admin_token, is_used=False).first()
        if not token_obj:
            return jsonify({"error": "Invalid or expired admin signup token."}), 403
        token_obj.is_used = True
    
    new_user = User(
        username=username,
        email=email,
        password_hash=generate_password_hash(password, method='pbkdf2:sha256'),
        role=role
    )
    db.session.add(new_user)
    db.session.commit()
    
    login_user(new_user)
    return jsonify({"success": True, "user": new_user.to_dict()})

@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('account_type')
    secret_key = data.get('secret_key')
    
    user = User.query.filter_by(username=username).first()
    
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid username or password"}), 401
        
    if role == 'admin' and user.role != 'admin':
        return jsonify({"error": "You are not an administrator."}), 403
        
    if role == 'admin' and secret_key != SITE_CONFIG['ADMIN_SECRET_KEY']:
         return jsonify({"error": "Invalid admin secret key."}), 403
         
    login_user(user, remember=True)
    settings_raw = SiteSettings.query.all()
    settings = {s.key: s.value for s in settings_raw}
    return jsonify({"success": True, "user": user.to_dict(), "settings": settings})
    
@app.route('/api/logout')
def logout():
    logout_user()
    return jsonify({"success": True})

@app.route('/api/request-password-reset', methods=['POST'])
def request_password_reset():
    email = request.json.get('email')
    user = User.query.filter_by(email=email).first()
    if user:
        token = password_reset_serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])
        reset_url = url_for('index', path=f'reset-password/{token}', _external=True)
        send_email(email, "Password Reset Request", f"Click here to reset your password: {reset_url}")
    return jsonify({"message": "If an account with that email exists, a password reset link has been sent."})

# --- USER PROFILE & CLASS/TEAM MANAGEMENT API ---
@app.route('/api/update_profile', methods=['POST'])
@login_required
def update_profile():
    data = request.json
    profile = current_user.profile or Profile(user_id=current_user.id)
    profile.bio = data.get('bio', profile.bio)
    profile.avatar = data.get('avatar', profile.avatar)
    current_user.theme_preference = data.get('theme_preference', current_user.theme_preference)
    db.session.add(profile)
    db.session.commit()
    return jsonify({"success": True, "profile": {"bio": profile.bio, "avatar": profile.avatar}})

@app.route('/api/my_classes')
@login_required
@role_required(['student', 'teacher'])
def my_classes():
    if current_user.role == 'teacher':
        classes = current_user.taught_classes
    else: # student
        classes = current_user.enrolled_classes.all()
    
    return jsonify({
        "classes": [
            {
                "id": c.id, "name": c.name, "code": c.code, 
                "teacher_name": c.teacher.username
            } for c in classes
        ]
    })
    
@app.route('/api/classes', methods=['POST'])
@login_required
@teacher_required
def create_class():
    name = request.json.get('name')
    if not name:
        return jsonify({"error": "Class name is required"}), 400
    new_class = Class(name=name, teacher_id=current_user.id, code=generate_code())
    db.session.add(new_class)
    db.session.commit()
    award_achievement(current_user, 'teacher_first_class')
    return jsonify({"success": True, "class": {"id": new_class.id, "name": new_class.name, "code": new_class.code}}), 201

@app.route('/api/join_class', methods=['POST'])
@login_required
@role_required('student')
def join_class():
    code = request.json.get('code').upper()
    class_to_join = Class.query.filter_by(code=code).first()
    if not class_to_join:
        return jsonify({"error": "Invalid class code"}), 404
    if class_to_join in current_user.enrolled_classes:
        return jsonify({"error": "You are already in this class"}), 409
        
    current_user.enrolled_classes.append(class_to_join)
    db.session.commit()
    notify_user(class_to_join.teacher, f"Student '{current_user.username}' has joined your class '{class_to_join.name}'.")
    award_achievement(current_user, 'student_first_class')
    return jsonify({"success": True, "message": f"Joined class '{class_to_join.name}'"})

@app.route('/api/classes/<class_id>')
@login_required
def get_class(class_id):
    cls = Class.query.get_or_404(class_id)
    is_student = cls in current_user.enrolled_classes.all()
    is_teacher = cls.teacher_id == current_user.id
    if not (is_student or is_teacher or current_user.role == 'admin'):
        abort(403)
    return jsonify({"class": {"id": cls.id, "name": cls.name}})

@app.route('/api/class_messages/<class_id>')
@login_required
def get_class_messages(class_id):
    # TODO: Add security check as in get_class
    messages = ChatMessage.query.filter_by(class_id=class_id).order_by(ChatMessage.timestamp.asc()).limit(50).all()
    return jsonify({"messages": [
        {
            "id": m.id,
            "sender_id": m.sender_id,
            "sender_username": m.sender.username if m.sender else "System",
            "content": m.content,
            "timestamp": m.timestamp.isoformat(),
            "sender_avatar": m.sender.profile.avatar if m.sender and m.sender.profile else None
        } for m in messages
    ]})

# --- GEMINI AI API ---
@app.route('/api/generate-study-guide', methods=['POST'])
@login_required
def generate_study_guide():
    topic = request.json.get('topic')
    if not SITE_CONFIG.get("GEMINI_API_KEY"):
        return jsonify({"error": "AI features are not configured on the server."}), 500
    
    try:
        model = genai.GenerativeModel('gemini-pro')
        prompt = f"Create a concise study guide on the topic: '{topic}'. Use markdown for formatting, including headers, bold text, and bullet points."
        response = model.generate_content(prompt)
        return jsonify({"guide": response.text})
    except Exception as e:
        logging.error(f"Gemini API error: {e}")
        return jsonify({"error": "Failed to generate study guide."}), 500
        
@app.route('/api/smart-reply/<class_id>')
@login_required
def smart_reply(class_id):
    if not SITE_CONFIG.get("GEMINI_API_KEY"):
        return jsonify({"replies": []})
        
    messages = ChatMessage.query.filter_by(class_id=class_id).order_by(ChatMessage.timestamp.desc()).limit(5).all()
    context = "\n".join([f"{m.sender.username if m.sender else 'System'}: {m.content}" for m in reversed(messages)])
    
    try:
        model = genai.GenerativeModel('gemini-pro')
        prompt = f"Based on this short chat conversation, suggest three very short, distinct, one-to-three word smart replies for the last user to send. The context is a virtual classroom. The conversation is:\n\n{context}\n\nReturn the replies as a JSON array of strings, like [\"Got it!\", \"Thanks!\", \"I'm confused.\"]. Do not add any other text."
        response = model.generate_content(prompt)
        
        clean_response = response.text.strip().replace("```json", "").replace("```", "")
        replies = json.loads(clean_response)
        return jsonify({"replies": replies})
    except Exception as e:
        logging.error(f"Gemini smart reply error: {e}")
        return jsonify({"replies": []})

# --- STRIPE BILLING API ---
@app.route('/api/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    price_id = request.json.get('price_id')
    try:
        checkout_session = stripe.checkout.Session.create(
            line_items=[{'price': price_id, 'quantity': 1}],
            mode='subscription',
            success_url=SITE_CONFIG['YOUR_DOMAIN'] + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=SITE_CONFIG['YOUR_DOMAIN'],
            customer_email=current_user.email,
            metadata={'user_id': current_user.id}
        )
        return jsonify({"session_id": checkout_session.id})
    except Exception as e:
        return jsonify(error=str(e)), 403

@app.route('/api/create-portal-session', methods=['POST'])
@login_required
def create_portal_session():
    try:
        portal_session = stripe.billing_portal.Session.create(
            customer=current_user.stripe_customer_id,
            return_url=SITE_CONFIG['YOUR_DOMAIN']
        )
        return jsonify({"url": portal_session.url})
    except Exception as e:
        return jsonify(error=str(e)), 403
        
@app.route('/stripe-webhook', methods=['POST'])
@csrf.exempt
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    endpoint_secret = SITE_CONFIG['STRIPE_WEBHOOK_SECRET']
    event = None

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
    except ValueError as e:
        return 'Invalid payload', 400
    except stripe.error.SignatureVerificationError as e:
        return 'Invalid signature', 400

    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        user_id = session.get('metadata', {}).get('user_id')
        user = User.query.get(user_id)
        if user:
            user.stripe_customer_id = session.customer
            user.has_subscription = True
            db.session.commit()
    elif event['type'] == 'customer.subscription.deleted':
        session = event['data']['object']
        customer_id = session.customer
        user = User.query.filter_by(stripe_customer_id=customer_id).first()
        if user:
            user.has_subscription = False
            db.session.commit()

    return 'Success', 200

# --- ADMIN API ---
@app.route('/api/admin/dashboard_data')
@login_required
@admin_required
def admin_dashboard_data():
    stats = {
        "total_users": User.query.count(),
        "total_classes": Class.query.count(),
        "active_subscriptions": User.query.filter_by(has_subscription=True).count(),
        "total_assignments": Assignment.query.count()
    }
    users = User.query.all()
    classes = Class.query.options(joinedload(Class.teacher)).all()
    settings_raw = SiteSettings.query.all()
    settings = {s.key: s.value for s in settings_raw}
    
    return jsonify({
        "stats": stats,
        "users": [u.to_dict() for u in users],
        "classes": [{
            "id": c.id, "name": c.name, "teacher_name": c.teacher.username,
            "code": c.code, "student_count": c.students.count()
        } for c in classes],
        "settings": settings
    })
    
@app.route('/api/admin/generate-admin-token', methods=['POST'])
@login_required
@admin_required
def generate_admin_token():
    token = secrets.token_hex(32)
    new_token = AdminSignupToken(token=token)
    db.session.add(new_token)
    db.session.commit()
    return jsonify({"success": True, "token": token})

# ==============================================================================
# --- 7. SOCKET.IO EVENTS ---
# ==============================================================================
@socketio.on('join')
def on_join(data):
    room = data['room']
    join_room(room)
    logging.info(f"Client joined room: {room}")

@socketio.on('leave')
def on_leave(data):
    room = data['room']
    leave_room(room)
    logging.info(f"Client left room: {room}")
    
@socketio.on('send_message')
@login_required
def handle_send_message(data):
    class_id = data['class_id']
    content = data['content']
    
    # Security check could be added here to ensure user is in the class
    
    msg = ChatMessage(class_id=class_id, sender_id=current_user.id, content=content)
    db.session.add(msg)
    db.session.commit()
    
    emit_data = {
        "sender_id": current_user.id,
        "sender_username": current_user.username,
        "content": content,
        "timestamp": msg.timestamp.isoformat(),
        "class_id": class_id,
        "sender_avatar": current_user.profile.avatar if current_user.profile else None
    }
    emit('new_message', emit_data, room=f'class_{class_id}')
    award_achievement(current_user, 'first_message')

# ==============================================================================
# --- 8. APP INITIALIZATION & DB SETUP ---
# ==============================================================================
def create_db():
    with app.app_context():
        db.create_all()
        print("Database tables created.")
        
        # Seed achievements
        achievements_to_seed = [
            {'name': 'student_first_class', 'description': 'First Class Joined', 'points': 10},
            {'name': 'teacher_first_class', 'description': 'First Class Created', 'points': 20},
            {'name': 'first_message', 'description': 'Sent First Message', 'points': 5},
            {'name': 'first_submission', 'description': 'Submitted First Assignment', 'points': 15},
            {'name': 'first_quiz', 'description': 'Completed First Quiz', 'points': 15},
        ]
        for ach_data in achievements_to_seed:
            if not Achievement.query.filter_by(name=ach_data['name']).first():
                new_ach = Achievement(**ach_data)
                db.session.add(new_ach)
        
        # Seed default settings
        if not SiteSettings.query.filter_by(key='maintenance_mode').first():
            setting = SiteSettings(key='maintenance_mode', value='false')
            db.session.add(setting)

        db.session.commit()
        print("Achievements and default settings seeded.")

if __name__ == '__main__':
    # Add a command to create the database
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'init_db':
        create_db()
    else:
        socketio.run(app, debug=True)
