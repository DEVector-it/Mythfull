# --- Imports ---
import os
import json
import logging
import time
import uuid
import secrets
import requests
from flask import Flask, request, jsonify, redirect, url_for, render_template_string, abort
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
csp = {
    'default-src': '\'self\'',
    'script-src': [
        '\'self\'',
        '\'unsafe-inline\'', # Needed for inline script block
        'https://cdn.tailwindcss.com',
        'https://cdnjs.cloudflare.com',
        'https://js.stripe.com',
    ],
    'style-src': [
        '\'self\'',
        '\'unsafe-inline\'', # Needed for inline style block
        'https://cdn.tailwindcss.com',
        'https://fonts.googleapis.com'
    ],
    'font-src': [
        '\'self\'',
        'https://fonts.gstatic.com'
    ],
    'img-src': ['*', 'data:'],
    'connect-src': ['\'self\'', f'wss://{prod_origin.split("//")[-1]}' if 'localhost' not in prod_origin else 'ws://localhost:5000', 'https://api.stripe.com']
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
    password_hash = db.Column(db.String(256), nullable=True)
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
            'bio': self.profile.bio if self.profile else '',
            'avatar': self.profile.avatar if self.profile else '',
            'theme_preference': self.profile.theme_preference if self.profile else 'golden',
            'ai_persona': self.profile.ai_persona if self.profile else None
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
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'code': self.code,
            'teacher_name': self.teacher.username
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
    time_limit = db.Column(db.Integer, nullable=False)
    class_obj = db.relationship('Class', back_populates='quizzes')
    questions = db.relationship('Question', back_populates='quiz', lazy=True, cascade="all, delete-orphan")
    attempts = db.relationship('QuizAttempt', back_populates='quiz', lazy='dynamic', cascade="all, delete-orphan")

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id', ondelete='CASCADE'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    question_type = db.Column(db.String(50), nullable=False, default='multiple_choice')
    choices = db.Column(db.JSON, nullable=False)
    quiz = db.relationship('Quiz', back_populates='questions')

class QuizAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id', ondelete='CASCADE'), nullable=False)
    student_id = db.Column(db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    score = db.Column(db.Float, nullable=True)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    answers = db.Column(db.JSON, nullable=True)
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
    return redirect(url_for('render_spa'))

def role_required(role_names):
    if not isinstance(role_names, list):
        role_names = [role_names]
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({"error": "Login required."}), 401
            if current_user.role != 'admin' and current_user.role not in role_names:
                return jsonify({"error": "Access denied."}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

admin_required = role_required('admin')
teacher_required = role_required('teacher')

# ==============================================================================
# --- 4. FRONTEND & CORE ROUTES ---
# ==============================================================================
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
        .waiting-text { margin-top: 1rem; font-size: 1.25rem; color: var(--text-secondary-color); animation: pulse 2s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.7; } }
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
            STRIPE_STUDENT_PRO_PRICE_ID: '{{ SITE_CONFIG.STRIPE_STUDENT_PRO_PRICE_ID }}',
        };
    </script>

    <!-- TEMPLATES START -->
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
            <div class="text-2xl font-title brand-gradient-text mb-4">Myth AI</div>
            <div class="waiting-text">Loading Portal...</div>
        </div>
    </template>
    
    <template id="template-maintenance-page">
        <div class="h-screen w-screen flex flex-col items-center justify-center dynamic-bg p-4 text-center">
            <div class="glassmorphism p-8 rounded-2xl max-w-lg w-full">
                <div id="logo-container-maintenance" class="w-20 h-20 mx-auto mb-4"></div>
                <h1 class="text-4xl font-title brand-gradient-text mb-2">Under Maintenance</h1>
                <p class="text-gray-300 mb-6">We're currently performing some upgrades. We'll be back online shortly!</p>
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

    <template id="template-main-dashboard">
        <div class="flex h-screen bg-bg-dark">
            <aside class="w-64 bg-bg-med p-4 flex flex-col glassmorphism border-r border-gray-700/50">
                <div class="flex items-center gap-2 mb-8">
                    <div id="logo-container-dash" class="w-10 h-10"></div>
                    <h1 id="dashboard-title" class="text-xl font-bold text-white"></h1>
                </div>
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
                <button id="back-to-roles" class="text-sm text-gray-400 hover:text-white mb-4">&larr; Back to Role Selection</button>
                <div class="text-center">
                    <div id="logo-container-auth" class="w-16 h-16 mx-auto mb-2"></div>
                    <h2 id="auth-title" class="text-3xl font-bold text-white"></h2>
                    <p id="auth-subtitle" class="mt-2 text-gray-300"></p>
                </div>
                <form id="auth-form" class="mt-8 space-y-4">
                    <input type="hidden" name="account_type" id="account_type">
                    <input type="hidden" name="admin_signup_token" id="admin_signup_token" value="">
                    <div>
                        <label for="username" class="sr-only">Username</label>
                        <input id="username" name="username" type="text" autocomplete="username" required class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="Username">
                    </div>
                    <div id="email-field">
                        <label for="email" class="sr-only">Email address</label>
                        <input id="email" name="email" type="email" autocomplete="email" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="Email address">
                    </div>
                    <div>
                        <label for="password" class="sr-only">Password</label>
                        <input id="password" name="password" type="password" autocomplete="current-password" required class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="Password">
                    </div>
                    <div id="teacher-key-field" class="hidden">
                        <input id="teacher-secret-key" name="secret_key" type="password" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="Teacher Secret Key">
                    </div>
                    <div id="admin-key-field" class="hidden">
                        <input id="admin-secret-key" name="admin_secret_key" type="password" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="Admin Secret Key">
                    </div>
                    <p id="auth-error" class="text-red-400 text-sm text-center h-4"></p>
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
            <div id="selected-class-view" class="hidden"></div>
        </div>
    </template>

    <template id="template-student-class-action">
        <form id="join-class-form" class="glassmorphism p-4 rounded-lg flex gap-2">
            <input type="text" name="code" placeholder="Enter Class Code" class="flex-grow p-2 bg-gray-700/50 rounded-md border border-gray-600" required>
            <button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Join Class</button>
        </form>
    </template>

    <template id="template-teacher-class-action">
        <form id="create-class-form" class="glassmorphism p-4 rounded-lg flex gap-2">
            <input type="text" name="name" placeholder="Enter New Class Name" class="flex-grow p-2 bg-gray-700/50 rounded-md border border-gray-600" required>
            <button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Create Class</button>
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
            <div id="admin-view-container"></div>
        </div>
    </template>

    <template id="template-admin-users-view">
        <h3 class="text-2xl font-bold mb-4">User Management</h3>
        <div class="overflow-x-auto glassmorphism rounded-lg">
            <table class="w-full text-left">
                <thead class="bg-bg-light">
                    <tr>
                        <th class="p-3">Username</th>
                        <th class="p-3">Email</th>
                        <th class="p-3">Role</th>
                        <th class="p-3">Created At</th>
                    </tr>
                </thead>
                <tbody id="users-table-body"></tbody>
            </table>
        </div>
    </template>
    <!-- TEMPLATES END -->

    <script>
    // ==========================================================================
    // --- SPA (Single Page Application) Logic ---
    // ==========================================================================
    document.addEventListener('DOMContentLoaded', () => {
        // --- Core State and Elements ---
        const BASE_URL = '';
        const DOMElements = { 
            appContainer: document.getElementById('app-container'), 
            toastContainer: document.getElementById('toast-container'),
        };
        let appState = { currentUser: null, isLoginView: true, selectedRole: 'student', currentTab: 'my-classes', selectedClass: null };
        
        const themes = {
            golden: { '--brand-hue': 45, '--bg-dark': '#1A120B', '--bg-med': '#2c241e', '--bg-light': '#4a3f35', '--text-color': '#F5EFE6', '--text-secondary-color': '#AE8E6A' },
            dark: { '--brand-hue': 220, '--bg-dark': '#0F172A', '--bg-med': '#1E293B', '--bg-light': '#334155', '--text-color': '#E2E8F0', '--text-secondary-color': '#94A3B8' },
            brainrot: { '--brand-hue': 270, '--bg-dark': '#1a112a', '--bg-med': '#2a214a', '--bg-light': '#3a417a', '--text-color': '#e0d8ff', '--text-secondary-color': '#6b95ff' }
        };

        const svgLogo = `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="logoGradient" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" style="stop-color:hsl(var(--brand-hue), 90%, 60%);" /><stop offset="100%" style="stop-color:hsl(var(--brand-hue), 80%, 50%);" /></linearGradient></defs><path fill="url(#logoGradient)" d="M50,5 C74.85,5 95,25.15 95,50 C95,74.85 74.85,95 50,95 C25.15,95 5,74.85 5,50 C5,25.15 25.15,5 50,5 Z M50,15 C30.67,15 15,30.67 15,50 C15,69.33 30.67,85 50,85 C69.33,85 85,69.33 85,50 C85,30.67 69.33,15 50,15 Z" /><path fill="white" d="M50,30 C55.52,30 60,34.48 60,40 L60,60 C60,65.52 55.52,70 50,70 C44.48,70 40,65.52 40,60 L40,40 C40,34.48 44.48,30 50,30 Z" /></svg>`;
        
        // --- Utility Functions ---
        function escapeHtml(unsafe) { if (typeof unsafe !== 'string') return ''; return unsafe.replace(/[&<>"']/g, m => ({'&': '&amp;','<': '&lt;','>': '&gt;','"': '&quot;',"'": '&#039;'})[m]); }
        function injectLogo() { document.querySelectorAll('[id^="logo-container-"]').forEach(c => c.innerHTML = svgLogo); }
        function applyTheme(themeName) { const t = themes[themeName] || themes.golden; Object.entries(t).forEach(([k, v]) => document.documentElement.style.setProperty(k, v)); }
        function showToast(message, type = 'info') { const colors = { info: 'bg-blue-600', success: 'bg-green-600', error: 'bg-red-600' }; const toast = document.createElement('div'); toast.className = `text-white text-sm py-2 px-4 rounded-lg shadow-lg fade-in ${colors[type]}`; toast.textContent = message; DOMElements.toastContainer.appendChild(toast); setTimeout(() => { toast.style.transition = 'opacity 0.5s ease'; toast.style.opacity = '0'; setTimeout(() => toast.remove(), 500); }, 3500); }
        async function apiCall(endpoint, options = {}) { try { const csrfToken = document.querySelector('meta[name="csrf-token"]').content; if (!options.headers) options.headers = {}; options.headers['X-CSRFToken'] = csrfToken; if (options.body && typeof options.body === 'object' && !(options.body instanceof FormData)) { options.headers['Content-Type'] = 'application/json'; options.body = JSON.stringify(options.body); } const response = await fetch(`${BASE_URL}/api${endpoint}`, { credentials: 'include', ...options }); const data = await response.json(); if (!response.ok) { if (response.status === 401 && endpoint !== '/status') handleLogout(false); throw new Error(data.error || `Request failed`); } return { success: true, ...data }; } catch (error) { showToast(error.message, 'error'); return { success: false, error: error.message }; } }
        function renderPage(templateId, setupFunction) { const template = document.getElementById(templateId); if (!template) return; DOMElements.appContainer.innerHTML = ''; DOMElements.appContainer.appendChild(template.content.cloneNode(true)); if (setupFunction) setupFunction(); injectLogo(); }
        function renderSubTemplate(container, templateId, setupFunction) { const template = document.getElementById(templateId); if (!container || !template) return; container.innerHTML = ''; container.appendChild(template.content.cloneNode(true)); if (setupFunction) setupFunction(); }
        function showFullScreenLoader(message = 'Loading...') { renderPage('template-full-screen-loader', () => { document.querySelector('.waiting-text').textContent = message; }); }

        // --- Authentication and Page Flow ---
        function handleLoginSuccess(user, settings) { appState.currentUser = user; if (user.profile && user.profile.theme_preference) { applyTheme(user.profile.theme_preference); } showFullScreenLoader(); setTimeout(() => { setupDashboard(user, settings); }, 1000); }
        function handleLogout(doApiCall = true) { if (doApiCall) apiCall('/logout', { method: 'POST' }); appState.currentUser = null; window.location.reload(); }
        function setupRoleChoicePage() { renderPage('template-role-choice', () => { document.querySelectorAll('.role-btn').forEach(btn => btn.addEventListener('click', () => { appState.selectedRole = btn.dataset.role; setupAuthPage(); })); }); }
        function setupAuthPage(token = null) { appState.isLoginView = !token; renderPage('template-auth-form', () => { if(token) document.getElementById('admin_signup_token').value = token; updateAuthView(); document.getElementById('auth-form').addEventListener('submit', handleAuthSubmit); document.getElementById('auth-toggle-btn').addEventListener('click', () => { appState.isLoginView = !appState.isLoginView; updateAuthView(); }); document.getElementById('forgot-password-link').addEventListener('click', handleForgotPassword); document.getElementById('back-to-roles').addEventListener('click', main); }); }
        function updateAuthView() {
            const isLogin = appState.isLoginView, role = appState.selectedRole;
            const title = document.getElementById('auth-title'), subtitle = document.getElementById('auth-subtitle');
            const submitBtn = document.getElementById('auth-submit-btn'), toggleBtn = document.getElementById('auth-toggle-btn');
            const emailField = document.getElementById('email-field'), teacherKeyField = document.getElementById('teacher-key-field');
            const adminKeyField = document.getElementById('admin-key-field'), adminTokenInput = document.getElementById('admin_signup_token');
            document.getElementById('account_type').value = role;
            title.textContent = `${role.charAt(0).toUpperCase() + role.slice(1)} Portal`;
            document.getElementById('back-to-roles').classList.toggle('hidden', !!adminTokenInput.value);
            toggleBtn.classList.toggle('hidden', role === 'admin' && !adminTokenInput.value);
            emailField.classList.toggle('hidden', isLogin);
            document.getElementById('email').required = !isLogin;
            subtitle.textContent = isLogin ? 'Sign in to continue' : 'Create your Account';
            submitBtn.textContent = isLogin ? 'Login' : 'Sign Up';
            toggleBtn.innerHTML = isLogin ? "Don't have an account? <span class='font-semibold'>Sign Up</span>" : "Already have an account? <span class='font-semibold'>Login</span>";
            teacherKeyField.classList.toggle('hidden', isLogin || role !== 'teacher');
            document.getElementById('teacher-secret-key').required = !isLogin && role === 'teacher';
            adminKeyField.classList.toggle('hidden', !isLogin || role !== 'admin');
            document.getElementById('admin-secret-key').required = isLogin && role === 'admin';
        }
        async function handleAuthSubmit(e) { e.preventDefault(); const form = e.target; const endpoint = appState.isLoginView ? '/login' : '/signup'; const body = Object.fromEntries(new FormData(form)); const result = await apiCall(endpoint, { method: 'POST', body }); if (result.success) { handleLoginSuccess(result.user, result.settings); } else { document.getElementById('auth-error').textContent = result.error; } }
        async function handleForgotPassword() { const email = prompt('Enter your account email:'); if (email) { const result = await apiCall('/request-password-reset', { method: 'POST', body: { email }}); showToast(result.message || 'If an account with that email exists, a reset link has been sent.', 'info'); } }
        
        // --- Dashboard and Tab Management ---
        function setupDashboard(user, settings) {
            renderPage('template-main-dashboard', () => {
                const navLinks = document.getElementById('nav-links');
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
                navLinks.innerHTML = tabs.map(tab => `<button data-tab="${escapeHtml(tab.id)}" class="dashboard-tab text-left text-gray-300 hover:bg-gray-700/50 p-3 rounded-md transition-colors">${escapeHtml(tab.label)}</button>`).join('');
                document.querySelectorAll('.dashboard-tab').forEach(tab => tab.addEventListener('click', (e) => switchTab(e.currentTarget.dataset.tab)));
                document.getElementById('logout-btn').addEventListener('click', () => handleLogout(true));
                switchTab(appState.currentTab);
            });
        }

        function switchTab(tab) {
            const setups = { 'my-classes': setupMyClassesTab, 'profile': setupProfileTab, 'admin-dashboard': setupAdminDashboardTab };
            if(setups[tab]) {
                appState.currentTab = tab;
                appState.selectedClass = null; // Reset selected class when switching main tabs
                document.querySelectorAll('.dashboard-tab').forEach(t => t.classList.toggle('active-tab', t.dataset.tab === tab));
                setups[tab](document.getElementById('dashboard-content'));
            }
        }

        // --- Specific Tab Setup Functions ---
        async function setupProfileTab(container) {
            renderSubTemplate(container, 'template-profile', () => {
                const profile = appState.currentUser.profile;
                document.getElementById('bio').value = profile.bio || '';
                document.getElementById('avatar').value = profile.avatar || '';
                const themeSelect = document.getElementById('theme-select');
                themeSelect.innerHTML = Object.keys(themes).map(name => `<option value="${name}">${name.charAt(0).toUpperCase() + name.slice(1)}</option>`).join('');
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
        
        async function setupMyClassesTab(container) {
            renderSubTemplate(container, 'template-my-classes', async () => {
                const actionContainer = document.getElementById('class-action-container');
                const role = appState.currentUser.role;
                if (role === 'student') {
                    renderSubTemplate(actionContainer, 'template-student-class-action', () => {
                        document.getElementById('join-class-form').addEventListener('submit', async e => {
                            e.preventDefault();
                            const code = e.target.elements.code.value;
                            const result = await apiCall('/classes/join', { method: 'POST', body: { code } });
                            if (result.success) {
                                showToast(`Successfully joined ${result.class_name}!`, 'success');
                                setupMyClassesTab(container); // Refresh list
                            }
                        });
                    });
                } else if (role === 'teacher') {
                    renderSubTemplate(actionContainer, 'template-teacher-class-action', () => {
                        document.getElementById('create-class-form').addEventListener('submit', async e => {
                            e.preventDefault();
                            const name = e.target.elements.name.value;
                            const result = await apiCall('/classes/create', { method: 'POST', body: { name } });
                            if (result.success) {
                                showToast(`Class "${result.class.name}" created!`, 'success');
                                setupMyClassesTab(container); // Refresh list
                            }
                        });
                    });
                }
                
                const result = await apiCall('/classes');
                if (result.success) {
                    const classesList = document.getElementById('classes-list');
                    if (result.classes.length === 0) {
                        classesList.innerHTML = `<p class="text-gray-400">You are not enrolled in any classes yet.</p>`;
                    } else {
                        classesList.innerHTML = result.classes.map(c => `
                            <div class="class-card glassmorphism p-4 rounded-lg cursor-pointer hover:scale-105 transition-transform" data-class-id="${escapeHtml(c.id)}">
                                <h3 class="text-xl font-bold">${escapeHtml(c.name)}</h3>
                                <p class="text-sm text-gray-400">Teacher: ${escapeHtml(c.teacher_name)}</p>
                                <p class="text-sm text-gray-400 mt-2">Code: <span class="font-mono bg-bg-dark p-1 rounded">${escapeHtml(c.code)}</span></p>
                            </div>
                        `).join('');
                        document.querySelectorAll('.class-card').forEach(card => {
                            card.addEventListener('click', () => viewClass(card.dataset.classId));
                        });
                    }
                }
            });
        }

        function viewClass(classId) {
            appState.selectedClass = classId;
            document.getElementById('classes-main-view').classList.add('hidden');
            const selectedClassView = document.getElementById('selected-class-view');
            selectedClassView.classList.remove('hidden');
            selectedClassView.innerHTML = `<h3 class="text-2xl">Details for class ${classId}</h3><p>Assignments, quizzes, and chat will be shown here.</p>`; // Placeholder
            
            const backButton = document.getElementById('back-to-classes-list');
            backButton.classList.remove('hidden');
            backButton.onclick = () => {
                appState.selectedClass = null;
                document.getElementById('classes-main-view').classList.remove('hidden');
                selectedClassView.classList.add('hidden');
                backButton.classList.add('hidden');
            };
        }
        
        async function setupAdminDashboardTab(container) {
            renderSubTemplate(container, 'template-admin-dashboard', () => {
                const adminContainer = document.getElementById('admin-view-container');
                renderSubTemplate(adminContainer, 'template-admin-users-view', async () => {
                    const result = await apiCall('/admin/users');
                    if(result.success) {
                        const tableBody = document.getElementById('users-table-body');
                        tableBody.innerHTML = result.users.map(user => `
                            <tr class="border-b border-gray-700/50">
                                <td class="p-3">${escapeHtml(user.username)}</td>
                                <td class="p-3">${escapeHtml(user.email)}</td>
                                <td class="p-3">${escapeHtml(user.role)}</td>
                                <td class="p-3">${new Date(user.created_at).toLocaleDateString()}</td>
                            </tr>
                        `).join('');
                    }
                });
            });
        }

        // --- Application Entry Point ---
        async function main() {
            renderPage('template-welcome-screen');
            setTimeout(async () => {
                const result = await apiCall('/status');
                if (result.success && result.settings.maintenance_mode === "true" && (!result.user || result.user.role !== 'admin')) {
                    renderPage('template-maintenance-page', () => {
                        document.getElementById('admin-login-btn').addEventListener('click', () => { appState.selectedRole = 'admin'; setupAuthPage(); });
                    });
                } else if (result.success && result.user) {
                    handleLoginSuccess(result.user, result.settings);
                } else {
                    const path = window.location.pathname;
                    if (path.startsWith('/admin-signup/')) {
                        const token = path.split('/')[2];
                        appState.selectedRole = 'admin';
                        setupAuthPage(token);
                    } else {
                        setupRoleChoicePage();
                    }
                }
            }, 1500); // Show welcome screen
        }

        main();
    });
    </script>
</body>
</html>
"""

# ==============================================================================
# --- 5. CORE API ROUTES ---
# ==============================================================================
@app.route('/')
@app.route('/<path:path>')
def render_spa(path=None):
    return render_template_string(HTML_CONTENT, SITE_CONFIG=SITE_CONFIG, csrf_token=generate_csrf)

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
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role = data.get('account_type', 'student')
    
    if not all([username, email, password]):
        return jsonify({"error": "Missing required fields."}), 400

    if User.query.filter(or_(User.username == username, User.email == email)).first():
        return jsonify({"error": "Username or email already exists."}), 409
        
    new_user = User(
        username=username,
        email=email,
        password_hash=generate_password_hash(password),
        role=role
    )
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
    
    if not user or not user.password_hash or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid username or password"}), 401
        
    login_user(user, remember=True)
    settings = {s.key: s.value for s in SiteSettings.query.all()}
    return jsonify({"success": True, "user": user.to_dict(), "settings": settings})
    
@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
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
        
    profile.bio = data.get('bio', profile.bio)
    profile.avatar = data.get('avatar', profile.avatar)
    profile.theme_preference = data.get('theme_preference', profile.theme_preference)
    db.session.commit()
    return jsonify({"success": True, "profile": {"bio": profile.bio, "avatar": profile.avatar, "theme_preference": profile.theme_preference}})

# ==============================================================================
# --- 6. CLASS MANAGEMENT API ROUTES ---
# ==============================================================================
@app.route('/api/classes', methods=['GET'])
@login_required
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
    name = data.get('name')
    if not name:
        return jsonify({"error": "Class name is required."}), 400
    
    # Generate a unique 8-character code
    while True:
        code = secrets.token_urlsafe(6).upper()
        if not Class.query.filter_by(code=code).first():
            break
            
    new_class = Class(name=name, teacher_id=current_user.id, code=code)
    db.session.add(new_class)
    db.session.commit()
    
    return jsonify({"success": True, "class": new_class.to_dict()}), 201

@app.route('/api/classes/join', methods=['POST'])
@login_required
def join_class():
    if current_user.role != 'student':
        return jsonify({"error": "Only students can join classes."}), 403
        
    data = request.json
    code = data.get('code')
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
    users = User.query.all()
    return jsonify({"success": True, "users": [user.to_dict() for user in users]})

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
        if not SiteSettings.query.filter_by(key='maintenance_mode').first():
            db.session.add(SiteSettings(key='maintenance_mode', value='false'))
        db.session.commit()
        logging.info("Default settings seeded.")

@app.cli.command("init-db")
def init_db():
    init_db_command()

if __name__ == '__main__':
    socketio.run(app, debug=(os.environ.get('FLASK_ENV') != 'production'))
