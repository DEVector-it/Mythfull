# --- Imports ---
import os
import json
import logging
import time
import uuid
import secrets
import requests
from flask import Flask, Response, request, session, jsonify, redirect, url_for, render_template_string
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
from sqlalchemy import event, or_, func, desc
from sqlalchemy.orm import joinedload # --- OPTIMIZATION: Import for efficient querying
from sqlalchemy.engine import Engine
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

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

# --- Security & CORS ---
CORS(app, supports_credentials=True, origins="*")
Talisman(app, content_security_policy=None)

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
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_SENDER')


@app.teardown_appcontext
def shutdown_session(exception=None):
    """Remove database session at the end of the request to prevent leaks."""
    db.session.remove()

# ==============================================================================
# --- 2. DATABASE MODELS ---
# ==============================================================================
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
    time_limit = db.Column(db.Integer, nullable=False)
    class_obj = db.relationship('Class', back_populates='quizzes')
    questions = db.relationship('Question', back_populates='quiz', lazy=True, cascade="all, delete-orphan")
    attempts = db.relationship('QuizAttempt', back_populates='quiz', lazy='dynamic', cascade="all, delete-orphan")

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id', ondelete='CASCADE'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    question_type = db.Column(db.String(50), nullable=False, default='multiple_choice')
    quiz = db.relationship('Quiz', back_populates='questions')
    choices = db.Column(db.JSON, nullable=False)

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
        
        /* --- REWORKED ANIMATIONS & BACKGROUNDS --- */
        .welcome-bg {
            background: linear-gradient(-45deg, #0f172a, #1e3a8a, #4c1d95, #0f172a);
            background-size: 400% 400%;
            animation: gradientBG 20s ease infinite;
        }
        @keyframes gradientBG { 0% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } 100% { background-position: 0% 50%; } }

        .full-screen-loader {
            position: fixed; top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(15, 23, 42, 0.9); backdrop-filter: blur(8px);
            display: flex; align-items: center; justify-content: center;
            flex-direction: column; z-index: 1001; transition: opacity 0.3s ease;
        }
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

    <template id="template-welcome-anime">
        <div class="flex flex-col items-center justify-center h-full w-full p-4 fade-in welcome-bg">
            <div class="glassmorphism p-8 rounded-xl text-center max-w-2xl">
                <div id="logo-container-welcome" class="mx-auto mb-4 h-24 w-24"></div>
                <h1 class="text-4xl font-bold text-white mb-4">AI for Curiosity, Not Cheating.</h1>
                <p class="text-gray-300 mb-6">
                    We've built a platform where AI fosters genuine understanding. Teachers can create private classrooms, track student progress, and see what questions are being asked. Our specialized AI tutors are designed to guide, not just give away the solution.
                </p>
                <button id="get-started-btn" class="brand-gradient-bg shiny-button text-white font-bold py-3 px-6 rounded-lg">Get Started</button>
            </div>
        </div>
        <audio id="welcome-audio" src="https://www.soundhelix.com/examples/mp3/SoundHelix-Song-2.mp3" preload="auto"></audio>
    </template>
    
    <template id="template-full-screen-loader">
        <div class="full-screen-loader fade-in">
            <div class="loader-dots">
                <div class="dot1"></div>
                <div class="dot2"></div>
                <div class="dot3"></div>
            </div>
            <div class="waiting-text">Preparing your adventure...</div>
        </div>
    </template>

    <template id="template-role-choice">
        <div class="flex flex-col items-center justify-center h-full w-full p-4 fade-in welcome-bg">
            <div class="w-full max-w-md text-center">
                <div class="flex items-center justify-center gap-3 mb-4">
                    <div id="logo-container-role" class="h-16 w-16"></div>
                    <h1 class="text-5xl font-bold brand-gradient-text">Myth AI</h1>
                </div>
                <p class="text-gray-400 text-lg mb-10">Select your role to continue</p>
                <div class="space-y-4">
                    <button data-role="student" class="role-btn w-full text-left p-6 glassmorphism rounded-lg flex items-center justify-between transition-all hover:border-blue-400 border border-transparent">
                        <div><h2 class="text-xl font-bold text-white">Student Portal</h2><p class="text-gray-400">Join classes, submit assignments, and learn with AI.</p></div><span class="text-2xl">&rarr;</span>
                    </button>
                    <button data-role="teacher" class="role-btn w-full text-left p-6 glassmorphism rounded-lg flex items-center justify-between transition-all hover:border-purple-400 border border-transparent">
                        <div><h2 class="text-xl font-bold text-white">Teacher Portal</h2><p class="text-gray-400">Create classes, manage students, and assign quizzes.</p></div><span class="text-2xl">&rarr;</span>
                    </button>
                    <button data-role="admin" class="role-btn w-full text-left p-6 glassmorphism rounded-lg flex items-center justify-between transition-all hover:border-red-400 border border-transparent">
                        <div><h2 class="text-xl font-bold text-white">Admin Portal</h2><p class="text-gray-400">Manage users, classes, and site settings.</p></div><span class="text-2xl">&rarr;</span>
                    </button>
                </div>
            </div>
        </div>
    </template>

    <template id="template-main-dashboard">
        <div class="flex h-full w-full bg-gray-800 fade-in">
            <nav class="w-64 bg-gray-900/70 backdrop-blur-sm p-6 flex flex-col gap-4 flex-shrink-0 border-r border-white/10">
                <div class="flex items-center gap-3 mb-6">
                    <div id="logo-container-dash" class="h-8 w-8"></div>
                    <h2 class="text-2xl font-bold brand-gradient-text" id="dashboard-title">Portal</h2>
                </div>
                <div id="nav-links" class="flex flex-col gap-2"></div>
                <div class="mt-auto flex flex-col gap-4">
                    <div id="adsense-container" class="w-full h-48 bg-gray-700/50 rounded-lg flex items-center justify-center text-gray-500 text-sm">
                        Ad Placeholder
                    </div>
                    <div id="notification-bell-container" class="relative"></div>
                    <button id="logout-btn" class="bg-red-600/50 hover:bg-red-600 border border-red-500 text-white font-bold py-2 px-4 rounded-lg transition-colors">Logout</button>
                </div>
            </nav>
            <main class="flex-1 p-8 overflow-y-auto">
                <div id="dashboard-content"></div>
            </main>
        </div>
    </template>
    
    <template id="template-auth-form"><div class="flex flex-col items-center justify-center h-full w-full p-4 fade-in welcome-bg"><div class="w-full max-w-md glassmorphism rounded-2xl p-8 shadow-2xl"><button id="back-to-roles" class="text-sm text-blue-400 hover:text-blue-300 mb-4">&larr; Back to Role Selection</button><h1 class="text-3xl font-bold text-center brand-gradient-text mb-2" id="auth-title">Portal Login</h1><p class="text-gray-400 text-center mb-6" id="auth-subtitle">Sign in to continue</p><form id="auth-form"><input type="hidden" id="account_type" name="account_type" value="student"><div id="email-field" class="hidden mb-4"><label for="email" class="block text-sm font-medium text-gray-300 mb-1">Email</label><input type="email" id="email" name="email" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500"></div><div class="mb-4"><label for="username" class="block text-sm font-medium text-gray-300 mb-1">Username</label><input type="text" id="username" name="username" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" required></div><div class="mb-4"><label for="password" class="block text-sm font-medium text-gray-300 mb-1">Password</label><input type="password" id="password" name="password" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" required></div><div id="teacher-key-field" class="hidden mb-4"><label for="teacher-secret-key" class="block text-sm font-medium text-gray-300 mb-1">Secret Teacher Key</label><input type="text" id="teacher-secret-key" name="secret_key" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="Required for teacher sign up"></div><div id="admin-key-field" class="hidden mb-4"><label for="admin-secret-key" class="block text-sm font-medium text-gray-300 mb-1">Secret Admin Key</label><input type="password" id="admin-secret-key" name="admin_secret_key" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="Required for admin login"></div><div class="flex justify-end mb-6"><button type="button" id="forgot-password-link" class="text-xs text-blue-400 hover:text-blue-300">Forgot Password?</button></div><button type="submit" id="auth-submit-btn" class="w-full brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg transition-opacity">Login</button><p id="auth-error" class="text-red-400 text-sm text-center h-4 mt-3"></p></form><div class="text-center mt-6"><button id="auth-toggle-btn" class="text-sm text-blue-400 hover:text-blue-300">Don't have an account? <span class="font-semibold">Sign Up</span></button></div></div></div></template>
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
    <template id="template-admin-dashboard"><h3 class="text-3xl font-bold text-white mb-6">Admin Panel</h3><div id="admin-stats" class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8"></div><div class="flex border-b border-gray-600 mb-4 overflow-x-auto"><button class="py-2 px-4 text-gray-300 hover:text-white admin-view-tab whitespace-nowrap" data-tab="users">Users</button><button class="py-2 px-4 text-gray-300 hover:text-white admin-view-tab whitespace-nowrap" data-tab="classes">Classes</button><button class="py-2 px-4 text-gray-300 hover:text-white admin-view-tab whitespace-nowrap" data-tab="settings">Settings</button><button class="py-2 px-4 text-gray-300 hover:text-white admin-view-tab whitespace-nowrap" data-tab="music">Music</button></div><div id="admin-view-content"></div></main></div></template>
    <template id="template-admin-users-view"><h4 class="text-xl font-bold text-white mb-4">User Management</h4><div class="overflow-x-auto glassmorphism p-4 rounded-lg"><table class="w-full text-left text-sm text-gray-300"><thead><tr class="border-b border-gray-600"><th class="p-3">Username</th><th class="p-3">Email</th><th class="p-3">Role</th><th class="p-3">Created At</th><th class="p-3">Actions</th></tr></thead><tbody id="admin-user-list" class="divide-y divide-gray-700/50"></tbody></table></div></template>
    <template id="template-admin-classes-view"><h4 class="text-xl font-bold text-white mb-4">Class Management</h4><div class="overflow-x-auto glassmorphism p-4 rounded-lg"><table class="w-full text-left text-sm text-gray-300"><thead><tr class="border-b border-gray-600"><th class="p-3">Name</th><th class="p-3">Teacher</th><th class="p-3">Code</th><th class="p-3">Students</th><th class="p-3">Actions</th></tr></thead><tbody id="admin-class-list" class="divide-y divide-gray-700/50"></tbody></table></div></template>
    <template id="template-admin-settings-view"><h4 class="text-xl font-bold text-white mb-4">Site Settings</h4><form id="admin-settings-form" class="glassmorphism p-6 rounded-lg max-w-lg"><div class="mb-4"><label for="setting-announcement" class="block text-sm font-medium text-gray-300 mb-1">Announcement Banner</label><input type="text" id="setting-announcement" name="announcement" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600"></div><div class="mb-4"><label for="setting-daily-message" class="block text-sm font-medium text-gray-300 mb-1">Message of the Day</label><input type="text" id="setting-daily-message" name="daily_message" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600"></div><div class="mb-4"><label for="ai-persona-input" class="block text-sm font-medium text-gray-300 mb-1">AI Persona</label><input type="text" id="ai-persona-input" name="ai_persona" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="e.g. A helpful study guide"></div><div class="mb-4"><label class="block text-sm font-medium text-gray-300 mb-1">Maintenance Mode</label><button type="button" id="maintenance-toggle-btn" class="bg-yellow-500 hover:bg-yellow-600 text-white font-bold py-2 px-4 rounded-lg">Toggle Maintenance Mode</button></div><button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Save Settings</button></form></template>
    <template id="template-admin-music-view"><h4 class="text-xl font-bold text-white mb-4">Background Music</h4><div class="flex items-center gap-2 mb-4"><input type="text" id="music-name" placeholder="Music Title" class="flex-grow p-3 bg-gray-700/50 rounded-lg border border-gray-600"><input type="url" id="music-url" placeholder="Music URL (MP3)" class="flex-grow p-3 bg-gray-700/50 rounded-lg border border-gray-600"><button id="add-music-btn" class="brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg">Add Music</button></div><ul id="music-list" class="space-y-2"></ul></template>
    <template id="template-modal"><div class="modal-overlay"><div class="glassmorphism rounded-2xl p-8 shadow-2xl w-full max-w-2xl modal-content relative"><button class="absolute top-4 right-4 text-gray-400 hover:text-white">&times;</button><div class="modal-body"></div></div></div></template>
    <template id="template-privacy-policy"><h2 class="text-2xl font-bold text-white mb-4">Privacy Policy</h2><p class="text-gray-300">This is a placeholder for your privacy policy. You should replace this with your actual policy, detailing how you collect, use, and protect user data. Make sure to comply with relevant regulations like GDPR and CCPA.</p></template>
    <template id="template-plans"><h2 class="text-2xl font-bold text-white mb-4">Subscription Plans</h2><div class="grid md:grid-cols-2 gap-6"><div class="glassmorphism p-6 rounded-lg"><h3 class="text-xl font-bold text-cyan-400">Free Plan</h3><p class="text-gray-400">Basic access for all users.</p></div><div class="glassmorphism p-6 rounded-lg border-2 border-purple-500"><h3 class="text-xl font-bold text-purple-400">Pro Plan</h3><p class="text-gray-400">Unlock unlimited AI interactions and advanced features.</p><button class="mt-4 brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg" id="upgrade-from-modal-btn">Upgrade Now</button></div></div></template>
    <template id="template-contact-form"><h2 class="text-2xl font-bold text-white mb-4">Contact Us</h2><form id="contact-form"><div class="mb-4"><label for="contact-name" class="block text-sm">Name</label><input type="text" id="contact-name" name="name" class="w-full p-2 bg-gray-800 rounded" required></div><div class="mb-4"><label for="contact-email" class="block text-sm">Email</label><input type="email" id="contact-email" name="email" class="w-full p-2 bg-gray-800 rounded" required></div><div class="mb-4"><label for="contact-message" class="block text-sm">Message</label><textarea id="contact-message" name="message" class="w-full p-2 bg-gray-800 rounded" rows="5" required></textarea></div><button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Send Message</button></form></template>
    
    <script>
    document.addEventListener('DOMContentLoaded', () => {
        const BASE_URL = '';
        const SITE_CONFIG = {
            STRIPE_PUBLIC_KEY: 'pk_test_YOUR_STRIPE_PUBLIC_KEY',
            STRIPE_STUDENT_PRO_PRICE_ID: 'price_YOUR_PRO_PRICE_ID'
        };
        
        const themes = {
            dark: { '--brand-hue': 220, '--bg-dark': '#0F172A', '--bg-med': '#1E293B', '--bg-light': '#334155', '--text-color': '#E2E8F0', '--text-secondary-color': '#94A3B8' },
            light: { '--brand-hue': 200, '--bg-dark': '#F1F5F9', '--bg-med': '#E2E8F0', '--bg-light': '#CBD5E1', '--text-color': '#1E293B', '--text-secondary-color': '#475569' },
            blue: { '--brand-hue': 210, '--bg-dark': '#0c1d3a', '--bg-med': '#1a2c4e', '--bg-light': '#2e4570', '--text-color': '#dbe8ff', '--text-secondary-color': '#a0b3d1' },
            purple: { '--brand-hue': 260, '--bg-dark': '#1e1b3b', '--bg-med': '#2d2852', '--bg-light': '#453f78', '--text-color': '#e6e3ff', '--text-secondary-color': '#b8b4d9' },
        };

        const appState = { currentUser: null, currentTab: 'my-classes', selectedClass: null, socket: null, stripe: null, quizTimer: null, isLoginView: true, selectedRole: null };
        const DOMElements = { appContainer: document.getElementById('app-container'), toastContainer: document.getElementById('toast-container'), modalContainer: document.getElementById('modal-container'), backgroundMusic: document.getElementById('background-music') };
        
        // *** FIX: SVG LOGO ***
        const svgLogo = `
            <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
                <defs>
                    <linearGradient id="logoGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" style="stop-color:hsl(var(--brand-hue), 90%, 60%);" />
                        <stop offset="100%" style="stop-color:hsl(var(--brand-hue), 90%, 40%);" />
                    </linearGradient>
                </defs>
                <path fill="url(#logoGradient)" d="M50,5 C74.85,5 95,25.15 95,50 C95,74.85 74.85,95 50,95 C25.15,95 5,74.85 5,50 C5,25.15 25.15,5 50,5 Z M50,15 C30.67,15 15,30.67 15,50 C15,69.33 30.67,85 50,85 C69.33,85 85,69.33 85,50 C85,30.67 69.33,15 50,15 Z" />
                <path fill="white" d="M50,30 C55.52,30 60,34.48 60,40 L60,60 C60,65.52 55.52,70 50,70 C44.48,70 40,65.52 40,60 L40,40 C40,34.48 44.48,30 50,30 Z" />
            </svg>`;
        
        const aiAvatarSvg = 'data:image/svg+xml;base64,' + btoa(svgLogo);

        function injectLogo() {
            document.querySelectorAll('[id^="logo-container-"]').forEach(container => {
                container.innerHTML = svgLogo;
            });
        }
        
        document.getElementById('current-year').textContent = new Date().getFullYear();

        function applyTheme(themeName) { const theme = themes[themeName]; if (theme) { for (const [key, value] of Object.entries(theme)) { document.documentElement.style.setProperty(key, value); } } }
        function playAudio(id) { const audio = document.getElementById(id); if (audio) { audio.play().catch(e => console.error("Audio playback failed:", e)); } }
        function showToast(message, type = 'info') { const colors = { info: 'bg-blue-600', success: 'bg-green-600', error: 'bg-red-600' }; const toast = document.createElement('div'); toast.className = `text-white text-sm py-2 px-4 rounded-lg shadow-lg fade-in ${colors[type]}`; toast.textContent = message; DOMElements.toastContainer.appendChild(toast); setTimeout(() => { toast.style.opacity = '0'; setTimeout(() => toast.remove(), 500); }, 3500); }
        function escapeHtml(text) { if (typeof text !== 'string') return ''; const map = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'}; return text.replace(/[&<>"']/g, m => map[m]); }
        async function apiCall(endpoint, options = {}) { try { if (options.body && typeof options.body === 'object') { options.headers = { 'Content-Type': 'application/json', ...options.headers }; options.body = JSON.stringify(options.body); } const response = await fetch(`${BASE_URL}/api${endpoint}`, { credentials: 'include', ...options }); const contentType = response.headers.get("content-type"); if (contentType && contentType.indexOf("application/json") !== -1) { const data = await response.json(); if (!response.ok) { if (response.status === 401 && endpoint !== '/status') handleLogout(false); throw new Error(data.error || `Request failed with status ${response.status}`); } return { success: true, ...data }; } else { const text = await response.text(); throw new Error(`Server returned non-JSON response: ${text.substring(0, 100)}`); } } catch (error) { showToast(error.message, 'error'); console.error("API Call Error:", error); return { success: false, error: error.message }; } }
        function renderPage(templateId, setupFunction) { const template = document.getElementById(templateId); if (!template) { console.error(`Template ${templateId} not found.`); return; } const content = template.content.cloneNode(true); DOMElements.appContainer.innerHTML = ''; DOMElements.appContainer.appendChild(content); if (setupFunction) setupFunction(); injectLogo(); }
        function renderSubTemplate(container, templateId, setupFunction) { const template = document.getElementById(templateId); if (!template) return; const content = template.content.cloneNode(true); container.innerHTML = ''; container.appendChild(content); if (setupFunction) setupFunction(); }
        function showModal(content, setupFunction, maxWidth = 'max-w-2xl') { const template = document.getElementById('template-modal').content.cloneNode(true); const modalBody = template.querySelector('.modal-body'); if(typeof content === 'string') { modalBody.innerHTML = content; } else { modalBody.innerHTML = ''; modalBody.appendChild(content); } template.querySelector('.modal-content').classList.replace('max-w-2xl', maxWidth); template.querySelector('button').addEventListener('click', hideModal); DOMElements.modalContainer.innerHTML = ''; DOMElements.modalContainer.appendChild(template); if(setupFunction) setupFunction(DOMElements.modalContainer); }
        function hideModal() { DOMElements.modalContainer.innerHTML = ''; }
        function showFullScreenLoader(message = 'Loading...') { const loaderTemplate = document.getElementById('template-full-screen-loader'); const loaderContent = loaderTemplate.content.cloneNode(true); loaderContent.querySelector('.waiting-text').textContent = message; DOMElements.appContainer.innerHTML = ''; DOMElements.appContainer.appendChild(loaderContent); }
        function connectSocket() { if (appState.socket) appState.socket.disconnect(); appState.socket = io(BASE_URL); appState.socket.on('connect', () => { console.log('Socket connected!'); appState.socket.emit('join', { room: `user_${appState.currentUser.id}` }); }); appState.socket.on('new_message', (data) => { if (appState.selectedClass && data.class_id === appState.selectedClass.id) appendChatMessage(data); }); appState.socket.on('new_notification', (data) => { showToast(`Notification: ${data.content}`, 'info'); updateNotificationBell(true); }); }
        function setupRoleChoicePage() { renderPage('template-role-choice', () => { document.querySelectorAll('.role-btn').forEach(btn => { btn.addEventListener('click', (e) => { appState.selectedRole = e.currentTarget.dataset.role; setupAuthPage(); }); }); }); }
        function setupAuthPage() { appState.isLoginView = true; renderPage('template-auth-form', () => { updateAuthView(); document.getElementById('auth-form').addEventListener('submit', handleAuthSubmit); document.getElementById('auth-toggle-btn').addEventListener('click', () => { appState.isLoginView = !appState.isLoginView; updateAuthView(); }); document.getElementById('forgot-password-link').addEventListener('click', handleForgotPassword); document.getElementById('back-to-roles').addEventListener('click', main); }); }
        function updateAuthView() { const title = document.getElementById('auth-title'); const subtitle = document.getElementById('auth-subtitle'); const submitBtn = document.getElementById('auth-submit-btn'); const toggleBtn = document.getElementById('auth-toggle-btn'); const emailField = document.getElementById('email-field'); const teacherKeyField = document.getElementById('teacher-key-field'); const adminKeyField = document.getElementById('admin-key-field'); const usernameInput = document.getElementById('username'); document.getElementById('account_type').value = appState.selectedRole; title.textContent = `${appState.selectedRole.charAt(0).toUpperCase() + appState.selectedRole.slice(1)} Portal`; adminKeyField.classList.add('hidden'); teacherKeyField.classList.add('hidden'); usernameInput.disabled = false; usernameInput.value = ''; if (appState.selectedRole === 'admin') { usernameInput.value = 'big ballz'; usernameInput.disabled = true; toggleBtn.classList.add('hidden'); if(appState.isLoginView) { adminKeyField.classList.remove('hidden'); document.getElementById('admin-secret-key').required = true; } } else { toggleBtn.classList.remove('hidden'); } if (appState.isLoginView) { subtitle.textContent = 'Sign in to continue'; submitBtn.textContent = 'Login'; toggleBtn.innerHTML = "Don't have an account? <span class='font-semibold'>Sign Up</span>"; emailField.classList.add('hidden'); document.getElementById('email').required = false; } else { subtitle.textContent = 'Create your Account'; submitBtn.textContent = 'Sign Up'; toggleBtn.innerHTML = "Already have an account? <span class='font-semibold'>Login</span>"; emailField.classList.remove('hidden'); document.getElementById('email').required = true; if (appState.selectedRole === 'teacher') { teacherKeyField.classList.remove('hidden'); document.getElementById('teacher-secret-key').required = true; } } }
        async function handleAuthSubmit(e) { e.preventDefault(); const form = e.target; const endpoint = appState.isLoginView ? '/login' : '/signup'; const body = Object.fromEntries(new FormData(form)); const result = await apiCall(endpoint, { method: 'POST', body }); if (result.success) { handleLoginSuccess(result.user, {}); } else { document.getElementById('auth-error').textContent = result.error; } }
        function handleLoginSuccess(user, settings) { appState.currentUser = user; if (user.theme_preference) { applyTheme(user.theme_preference); } renderPage('template-full-screen-loader', () => { setTimeout(() => { setupDashboard(user, settings); }, 1500); }); }
        function setupDashboard(user, settings) { if (!user) return setupAuthPage(); connectSocket(); renderPage('template-main-dashboard', () => { const navLinks = document.getElementById('nav-links'); const dashboardTitle = document.getElementById('dashboard-title'); let tabs = []; if (user.role === 'student' || user.role === 'teacher') { dashboardTitle.textContent = user.role === 'student' ? "Student Hub" : "Teacher Hub"; appState.currentTab = 'my-classes'; tabs = [ { id: 'my-classes', label: 'My Classes' }, { id: 'team-mode', label: 'Team Mode' }, { id: 'billing', label: 'Billing' }, { id: 'profile', label: 'Profile' } ]; } else if (user.role === 'admin') { dashboardTitle.textContent = "Admin Panel"; appState.currentTab = 'admin-dashboard'; tabs = [ { id: 'admin-dashboard', label: 'Dashboard' }, { id: 'profile', label: 'My Profile' } ]; } navLinks.innerHTML = tabs.map(tab => `<button data-tab="${tab.id}" class="dashboard-tab text-left text-gray-300 hover:bg-gray-700/50 p-3 rounded-md transition-colors">${tab.label}</button>`).join(''); document.querySelectorAll('.dashboard-tab').forEach(tab => tab.addEventListener('click', () => switchTab(tab.dataset.tab))); document.getElementById('logout-btn').addEventListener('click', () => handleLogout(true)); setupNotificationBell(); switchTab(appState.currentTab); fetchBackgroundMusic(); }); }
        function switchTab(tab) { appState.currentTab = tab; appState.selectedClass = null; document.querySelectorAll('.dashboard-tab').forEach(t => t.classList.toggle('active-tab', t.dataset.tab === tab)); const contentContainer = document.getElementById('dashboard-content'); const setups = { 'my-classes': setupMyClassesTab, 'team-mode': setupTeamModeTab, 'profile': setupProfileTab, 'billing': setupBillingTab, 'admin-dashboard': setupAdminDashboardTab }; if (setups[tab]) setups[tab](contentContainer); }
        async function setupMyClassesTab(container) { renderSubTemplate(container, 'template-my-classes', async () => { const actionContainer = document.getElementById('class-action-container'), listContainer = document.getElementById('classes-list'); const actionTemplateId = `template-${appState.currentUser.role}-class-action`; renderSubTemplate(actionContainer, actionTemplateId, () => { if (appState.currentUser.role === 'student') document.getElementById('join-class-btn').addEventListener('click', handleJoinClass); else document.getElementById('create-class-btn').addEventListener('click', handleCreateClass); }); const result = await apiCall('/my_classes'); if (result.success && result.classes) { if (result.classes.length === 0) listContainer.innerHTML = `<p class="text-gray-400 text-center col-span-full">You haven't joined or created any classes yet.</p>`; else listContainer.innerHTML = result.classes.map(cls => `<div class="glassmorphism p-4 rounded-lg cursor-pointer hover:bg-gray-700/50 transition-colors" data-id="${cls.id}" data-name="${cls.name}"><div class="font-bold text-white text-lg">${escapeHtml(cls.name)}</div><div class="text-gray-400 text-sm">Teacher: ${escapeHtml(cls.teacher_name)}</div>${appState.currentUser.role === 'teacher' ? `<div class="text-sm mt-2">Code: <span class="font-mono text-cyan-400">${escapeHtml(cls.code)}</span></div>` : ''}</div>`).join(''); listContainer.querySelectorAll('div[data-id]').forEach(el => el.addEventListener('click', (e) => selectClass(e.currentTarget.dataset.id))); } }); }
        async function setupTeamModeTab(container) { renderSubTemplate(container, 'template-team-mode', async () => { renderSubTemplate(document.getElementById('team-action-container'), 'template-team-actions', () => { document.getElementById('join-team-btn').addEventListener('click', handleJoinTeam); document.getElementById('create-team-btn').addEventListener('click', handleCreateTeam); }); const listContainer = document.getElementById('teams-list'); const result = await apiCall('/teams'); if (result.success && result.teams) { if (result.teams.length === 0) { listContainer.innerHTML = `<p class="text-gray-400 text-center col-span-full">You are not part of any teams yet.</p>`; } else { listContainer.innerHTML = result.teams.map(team => `<div class="glassmorphism p-4 rounded-lg cursor-pointer hover:bg-gray-700/50 transition-colors" data-id="${team.id}"><div class="font-bold text-white text-lg">${escapeHtml(team.name)}</div><div class="text-gray-400 text-sm">Owner: ${escapeHtml(team.owner_name)}</div><div class="text-sm mt-2">Code: <span class="font-mono text-cyan-400">${escapeHtml(team.code)}</span></div><div class="text-sm text-gray-400">${escapeHtml(String(team.member_count))} members</div></div>`).join(''); listContainer.querySelectorAll('div[data-id]').forEach(el => el.addEventListener('click', e => selectTeam(e.currentTarget.dataset.id))); } } }); }
        async function selectTeam(teamId) { const result = await apiCall(`/teams/${teamId}`); if (!result.success) return; const team = result.team; let modalContent = `<h3 class="text-2xl font-bold text-white mb-2">${escapeHtml(team.name)}</h3><p class="text-gray-400 mb-4">Team Code: <span class="font-mono text-cyan-400">${escapeHtml(team.code)}</span></p><h4 class="text-lg font-semibold text-white mb-2">Members</h4><ul class="space-y-2">${team.members.map(m => `<li class="flex items-center gap-3 p-2 bg-gray-800/50 rounded-md"><img src="${escapeHtml(m.profile.avatar || `https://i.pravatar.cc/40?u=${m.id}`)}" class="w-8 h-8 rounded-full"><span>${escapeHtml(m.username)} ${m.id === team.owner_id ? '(Owner)' : ''}</span></li>`).join('')}</ul>`; showModal(modalContent); }
        async function handleJoinTeam() { const code = document.getElementById('team-code').value.trim().toUpperCase(); if (!code) return showToast('Please enter a team code.', 'error'); const result = await apiCall('/join_team', { method: 'POST', body: { code } }); if (result.success) { showToast(result.message, 'success'); setupTeamModeTab(document.getElementById('dashboard-content')); } }
        async function handleCreateTeam() { const name = document.getElementById('new-team-name').value.trim(); if (!name) return showToast('Please enter a team name.', 'error'); const result = await apiCall('/teams', { method: 'POST', body: { name } }); if (result.success) { showToast(`Team "${escapeHtml(result.team.name)}" created!`, 'success'); setupTeamModeTab(document.getElementById('dashboard-content')); } }
        function setupProfileTab(container) { renderSubTemplate(container, 'template-profile', () => { document.getElementById('bio').value = appState.currentUser.profile.bio || ''; document.getElementById('avatar').value = appState.currentUser.profile.avatar || ''; const themeSelect = document.createElement('select'); themeSelect.id = 'theme-select'; themeSelect.name = 'theme_preference'; themeSelect.className = 'w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600'; themeSelect.innerHTML = Object.keys(themes).map(themeName => `<option value="${themeName}">${themeName.charAt(0).toUpperCase() + themeName.slice(1)}</option>`).join(''); themeSelect.value = appState.currentUser.theme_preference || 'dark'; const themeControl = document.createElement('div'); themeControl.className = 'mb-4'; themeControl.innerHTML = '<label for="theme-select" class="block text-sm font-medium text-gray-300 mb-1">Theme</label>'; themeControl.appendChild(themeSelect); document.getElementById('profile-form').prepend(themeControl); document.getElementById('profile-form').addEventListener('submit', handleUpdateProfile); }); }
        async function handleUpdateProfile(e) { e.preventDefault(); const form = e.target; const body = Object.fromEntries(new FormData(form)); const result = await apiCall('/update_profile', { method: 'POST', body }); if (result.success) { appState.currentUser.profile = result.profile; appState.currentUser.theme_preference = body.theme_preference; applyTheme(body.theme_preference); showToast('Profile updated!', 'success'); } }
        function setupBillingTab(container) { renderSubTemplate(container, 'template-billing', () => { const content = document.getElementById('billing-content'); if (appState.currentUser.has_subscription) { content.innerHTML = `<p class="mb-4">You have an active subscription.</p><button id="manage-billing-btn" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Manage Billing</button>`; document.getElementById('manage-billing-btn').addEventListener('click', handleManageBilling); } else { content.innerHTML = `<p class="mb-4">Upgrade to a Pro plan for more features!</p><button id="upgrade-btn" data-price-id="${SITE_CONFIG.STRIPE_STUDENT_PRO_PRICE_ID}" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Upgrade to Pro</button>`; document.getElementById('upgrade-btn').addEventListener('click', handleUpgrade); } }); }
        async function setupAdminDashboardTab(container) { renderSubTemplate(container, 'template-admin-dashboard', async () => { const result = await apiCall('/admin/dashboard_data'); if (result.success) { document.getElementById('admin-stats').innerHTML = Object.entries(result.stats).map(([key, value]) => `<div class="glassmorphism p-4 rounded-lg"><p class="text-sm text-gray-400">${escapeHtml(key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()))}</p><p class="text-2xl font-bold">${escapeHtml(String(value))}</p></div>`).join(''); } document.querySelectorAll('.admin-view-tab').forEach(tab => tab.addEventListener('click', (e) => switchAdminView(e.currentTarget.dataset.tab))); switchAdminView('users'); }); }
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
        async function main() { const status = await apiCall('/status'); if (status.success && status.user) { appState.currentUser = status.user; applyTheme(status.user.theme_preference || 'dark'); setupDashboard(status.user, status.settings); } else { renderPage('template-welcome-anime', () => { document.getElementById('get-started-btn').addEventListener('click', setupRoleChoicePage); playAudio('welcome-audio'); }); } }
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
    return HTML_CONTENT

@app.route('/reset/<token>')
def reset_password_page(token):
    try:
        email = password_reset_serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
    except (SignatureExpired, BadTimeSignature):
        return render_template_string("<h1>Password reset link is expired or invalid.</h1><p>Please request a new one.</p>")
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
                const token = form.token.value;
                if (password !== confirm_password) {{
                    document.getElementById('message').textContent = 'Passwords do not match.';
                    return;
                }}
                const response = await fetch('/api/reset-password', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ token, password }})
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
    logging.error(f"Unhandled exception: {str(e)}", exc_info=True)
    return jsonify(error='An internal server error occurred.'), 500

@app.route('/api/signup', methods=['POST'])
def signup():
    """Register a new user."""
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
        new_user = User(
            username=data['username'],
            email=data['email'],
            password_hash=hashed_pw,
            role=data['account_type']
        )
        # The Profile is created automatically by the 'after_insert' event listener
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        return jsonify(success=True, user=new_user.to_dict())
        
    except IntegrityError:
        db.session.rollback()
        return jsonify(error='A database integrity error occurred. The username or email might already exist.'), 409
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error during signup: {str(e)}", exc_info=True)
        return jsonify(error='An unexpected error occurred during account creation.'), 500

@app.route('/api/login', methods=['POST'])
def login():
    """Authenticate and log in a user."""
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
            user.profile = Profile()
            db.session.commit()
            logging.info(f"Profile created on-demand for legacy user: {user.id}")
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error creating profile for user {user.id} on login: {str(e)}")
            
    login_user(user)
    return jsonify(success=True, user=user.to_dict())

# ... (rest of the API routes are unchanged and correct)
# ... (logout, status, request_password_reset, reset_password)
@app.route('/api/logout')
@login_required
def logout():
    """Log out the current user."""
    logout_user()
    return jsonify(success=True, message="You have been logged out.")

@app.route('/api/status')
def status():
    """Check the current user's authentication status."""
    if current_user.is_authenticated:
        return jsonify(success=True, user=current_user.to_dict(), settings={})
    return jsonify(success=False, user=None)

@app.route('/api/request-password-reset', methods=['POST'])
def request_password_reset():
    """Send a password reset email to a user."""
    data = request.json
    user = User.query.filter_by(email=data.get('email')).first()
    if user:
        try:
            token = password_reset_serializer.dumps(user.email, salt=app.config['SECURITY_PASSWORD_SALT'])
            reset_url = url_for('reset_password_page', token=token, _external=True)
            msg = Message('Password Reset Request for Myth AI', recipients=[user.email])
            msg.body = f'To reset your password, please click the following link: {reset_url}\n\nIf you did not request this, please ignore this email.'
            mail.send(msg)
        except Exception as e:
            logging.error(f"Failed to send password reset email: {str(e)}")
    return jsonify(success=True, message='If an account with that email exists, a password reset link has been sent.')

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    """Reset a user's password using a valid token."""
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
        logging.error(f"Error resetting password: {str(e)}")
        return jsonify(error='An unexpected error occurred while resetting the password.'), 500

# ==============================================================================
# --- 6. API ROUTES - CLASSES & CHAT ---
# ==============================================================================

def user_has_class_access(class_id, user):
    """Helper function to check if a user has access to a class."""
    if not class_id or not user:
        return False
    cls = Class.query.get(class_id)
    if not cls:
        return False
    is_teacher = user.id == cls.teacher_id
    is_student = cls.students.filter_by(id=user.id).first() is not None
    is_admin = user.role == 'admin'
    return is_teacher or is_student or is_admin

@app.route('/api/my_classes')
@login_required
def my_classes():
    """Get all classes for the current user."""
    if current_user.role == 'teacher':
        classes = current_user.taught_classes
    else:
        classes = current_user.enrolled_classes.all()
    
    class_list = [{
        'id': c.id, 
        'name': c.name, 
        'teacher_name': c.teacher.username, 
        'code': c.code
    } for c in classes]
    return jsonify(success=True, classes=class_list)

@app.route('/api/classes', methods=['POST'])
@teacher_required
def create_class():
    """Create a new class."""
    data = request.json
    if not data or 'name' not in data:
        return jsonify(error='Class name is required.'), 400
    
    try:
        code = secrets.token_hex(4).upper()
        while Class.query.filter_by(code=code).first():
            code = secrets.token_hex(4).upper()
            
        new_class = Class(name=data['name'], code=code, teacher_id=current_user.id)
        db.session.add(new_class)
        db.session.commit()
        return jsonify(success=True, class_={'id': new_class.id, 'name': new_class.name, 'code': new_class.code}), 201
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error creating class: {str(e)}")
        return jsonify(error='Failed to create the class.'), 500

@app.route('/api/join_class', methods=['POST'])
@login_required
def join_class():
    """Allow a student to join a class using a code."""
    data = request.json
    code = data.get('code', '').upper()
    if not code:
        return jsonify(error='Class code is required.'), 400
        
    cls = Class.query.filter_by(code=code).first()
    if not cls:
        return jsonify(error='Invalid class code.'), 404
        
    if cls.students.filter_by(id=current_user.id).first():
        return jsonify(error='You are already enrolled in this class.'), 400
        
    try:
        cls.students.append(current_user)
        db.session.commit()
        return jsonify(success=True, message=f'Successfully joined class: {cls.name}')
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error joining class: {str(e)}")
        return jsonify(error='An unexpected error occurred while joining the class.'), 500

@app.route('/api/classes/<class_id>')
@login_required
def get_class_details(class_id):
    """Get detailed information about a specific class."""
    if not user_has_class_access(class_id, current_user):
        return jsonify(error="You do not have permission to access this class."), 403
        
    cls = Class.query.options(db.joinedload(Class.students).subqueryload(User.profile)).get_or_404(class_id)
    
    class_data = {
        'id': cls.id,
        'name': cls.name,
        'students': [{
            'id': s.id, 
            'username': s.username, 
            'profile': {'bio': s.profile.bio or '', 'avatar': s.profile.avatar or ''} if s.profile else {'bio': '', 'avatar': ''}
        } for s in cls.students]
    }
    return jsonify(success=True, class_=class_data)

@app.route('/api/class_messages/<class_id>')
@login_required
def get_class_messages(class_id):
    """Get all chat messages for a specific class."""
    if not user_has_class_access(class_id, current_user):
        return jsonify(error="You do not have permission to view these messages."), 403
        
    messages = ChatMessage.query.filter_by(class_id=class_id).order_by(ChatMessage.timestamp.asc()).all()
    
    message_list = [{
        'id': m.id,
        'sender_id': m.sender_id,
        'sender_name': m.sender.username if m.sender else 'AI Assistant',
        'sender_avatar': m.sender.profile.avatar if m.sender and m.sender.profile else None,
        'content': m.content,
        'timestamp': m.timestamp.isoformat()
    } for m in messages]
    return jsonify(success=True, messages=message_list)

@app.route('/api/chat/send', methods=['POST'])
@login_required
def send_chat_and_get_ai_response():
    data = request.json
    class_id = data.get('class_id')
    prompt = data.get('prompt')

    if not class_id or not prompt:
        return jsonify(error='Missing class_id or prompt.'), 400
    if not user_has_class_access(class_id, current_user):
        return jsonify(error="Permission denied."), 403
    if not current_user.profile:
        try:
            current_user.profile = Profile()
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logging.error(f"Critical error: Failed to create profile on-the-fly for user {current_user.id}. Error: {str(e)}")
            return jsonify(error='Could not process request due to a profile error.'), 500

    try:
        user_msg = ChatMessage(class_id=class_id, sender_id=current_user.id, content=prompt)
        if any(q in prompt.lower() for q in ['who made you', 'who created you', 'who is your creator']):
            ai_response_text = "I was created by the collaborative efforts of DeVHossein."
        else:
            site_persona_setting = SiteSettings.query.get('ai_persona')
            persona = current_user.ai_persona or (site_persona_setting.value if site_persona_setting else "a helpful AI assistant")
            ai_response_text = f"As {persona}, I've received your message: '{prompt}'. I'm processing it now."
        ai_msg = ChatMessage(class_id=class_id, sender_id=None, content=ai_response_text)
        db.session.add_all([user_msg, ai_msg])
        db.session.commit()

        socketio.emit('new_message', {
            'id': user_msg.id, 'class_id': user_msg.class_id, 'sender_id': user_msg.sender_id,
            'sender_name': current_user.username, 'sender_avatar': current_user.profile.avatar if current_user.profile else None,
            'content': user_msg.content, 'timestamp': user_msg.timestamp.isoformat()
        }, room=f'class_{class_id}')
        socketio.emit('new_message', {
            'id': ai_msg.id, 'class_id': ai_msg.class_id, 'sender_id': None, 'sender_name': 'AI Assistant',
            'sender_avatar': None, 'content': ai_msg.content, 'timestamp': ai_msg.timestamp.isoformat()
        }, room=f'class_{class_id}')
        return jsonify(success=True)
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error in chat/AI response flow: {str(e)}", exc_info=True)
        return jsonify(error='An internal error occurred while processing your message.'), 500

# ==============================================================================
# --- 7. API ROUTES - TEAMS ---
# ==============================================================================
# ... (Team routes are unchanged)
@app.route('/api/teams')
@login_required
def get_my_teams():
    teams = current_user.teams.all()
    team_list = [{'id': t.id, 'name': t.name, 'code': t.code, 'owner_name': t.owner.username, 'member_count': t.members.count()} for t in teams]
    return jsonify(success=True, teams=team_list)

@app.route('/api/teams', methods=['POST'])
@login_required
def create_team():
    data = request.json
    if not data or not data.get('name'):
        return jsonify(error='Team name is required.'), 400
    try:
        code = secrets.token_hex(4).upper()
        while Team.query.filter_by(code=code).first():
            code = secrets.token_hex(4).upper()
        new_team = Team(name=data['name'], code=code, owner_id=current_user.id)
        new_team.members.append(current_user)
        db.session.add(new_team)
        db.session.commit()
        return jsonify(success=True, team={'id': new_team.id, 'name': new_team.name, 'code': new_team.code}), 201
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error creating team: {str(e)}")
        return jsonify(error='Failed to create the team.'), 500

@app.route('/api/join_team', methods=['POST'])
@login_required
def join_team():
    data = request.json
    code = data.get('code', '').upper()
    if not code:
        return jsonify(error='Team code is required.'), 400
    team = Team.query.filter_by(code=code).first()
    if not team:
        return jsonify(error='Invalid team code.'), 404
    if current_user in team.members:
        return jsonify(error='You are already a member of this team.'), 400
    try:
        team.members.append(current_user)
        db.session.commit()
        return jsonify(success=True, message=f'Successfully joined team: {team.name}')
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error joining team: {str(e)}")
        return jsonify(error='An unexpected error occurred while joining the team.'), 500

@app.route('/api/teams/<team_id>')
@login_required
def get_team_details(team_id):
    team = Team.query.options(db.joinedload(Team.members).subqueryload(User.profile)).get_or_404(team_id)
    if current_user not in team.members and current_user.role != 'admin':
        return jsonify(error="You do not have permission to access this team."), 403
    team_data = {
        'id': team.id, 'name': team.name, 'code': team.code, 'owner_id': team.owner_id,
        'members': [{'id': m.id, 'username': m.username, 'profile': {'bio': m.profile.bio or '', 'avatar': m.profile.avatar or ''} if m.profile else {}} for m in team.members]
    }
    return jsonify(success=True, team=team_data)

# ==============================================================================
# --- 8. API ROUTES - USER PROFILE & BILLING ---
# ==============================================================================
# ... (Profile and Billing routes are unchanged)
@app.route('/api/update_profile', methods=['POST'])
@login_required
def update_profile():
    data = request.json
    try:
        profile = current_user.profile
        if not profile:
            profile = Profile(user_id=current_user.id)
            db.session.add(profile)
        profile.bio = data.get('bio', profile.bio)
        profile.avatar = data.get('avatar', profile.avatar)
        current_user.theme_preference = data.get('theme_preference', current_user.theme_preference)
        db.session.commit()
        return jsonify(success=True, profile={'bio': profile.bio, 'avatar': profile.avatar})
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error updating profile for user {current_user.id}: {str(e)}")
        return jsonify(error='Could not update profile.'), 500

@app.route('/api/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    data = request.json
    price_id = data.get('price_id')
    if not price_id:
        return jsonify(error='Price ID is required.'), 400
    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'], line_items=[{'price': price_id, 'quantity': 1}],
            mode='subscription', success_url=f'{SITE_CONFIG["YOUR_DOMAIN"]}/?session_id={{CHECKOUT_SESSION_ID}}',
            cancel_url=SITE_CONFIG['YOUR_DOMAIN'], customer_email=current_user.email,
            client_reference_id=current_user.id
        )
        return jsonify(success=True, session_id=checkout_session.id)
    except Exception as e:
        logging.error(f"Stripe Checkout Session Error: {str(e)}")
        return jsonify(error=str(e)), 500

@app.route('/api/create-portal-session', methods=['POST'])
@login_required
def create_portal_session():
    if not current_user.stripe_customer_id:
        return jsonify(error='User does not have a Stripe customer ID.'), 400
    try:
        portal_session = stripe.billing_portal.Session.create(
            customer=current_user.stripe_customer_id, return_url=SITE_CONFIG['YOUR_DOMAIN']
        )
        return jsonify(success=True, url=portal_session.url)
    except Exception as e:
        logging.error(f"Stripe Portal Session Error: {str(e)}")
        return jsonify(error=str(e)), 500

@app.route('/stripe_webhooks', methods=['POST'])
def stripe_webhooks():
    return jsonify(status='success'), 200

# ==============================================================================
# --- 9. API ROUTES - NOTIFICATIONS ---
# ==============================================================================
# ... (Notification routes are unchanged)
@app.route('/api/notifications')
@login_required
def get_notifications():
    notifs = current_user.notifications.order_by(Notification.timestamp.desc()).all()
    return jsonify(success=True, notifications=[{'id': n.id, 'content': n.content, 'is_read': n.is_read, 'timestamp': n.timestamp.isoformat()} for n in notifs])

@app.route('/api/notifications/unread_count')
@login_required
def unread_notifications_count():
    count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    return jsonify(success=True, count=count)

@app.route('/api/notifications/mark_read', methods=['POST'])
@login_required
def mark_notifications_read():
    try:
        Notification.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
        db.session.commit()
        return jsonify(success=True)
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error marking notifications as read for user {current_user.id}: {str(e)}")
        return jsonify(error='Could not update notifications.'), 500

# ==============================================================================
# --- 10. API ROUTES - ADMIN PANEL ---
# ==============================================================================
# ... (Admin routes are unchanged)
@app.route('/api/admin/dashboard_data')
@admin_required
def admin_dashboard_data():
    stats = {
        'total_users': User.query.count(), 'total_classes': Class.query.count(),
        'total_teams': Team.query.count(), 'active_subscriptions': User.query.filter_by(has_subscription=True).count()
    }
    users = [u.to_dict() for u in User.query.all()]
    classes = [{'id': c.id, 'name': c.name, 'teacher_name': c.teacher.username, 'code': c.code, 'student_count': c.students.count()} for c in Class.query.all()]
    settings = {s.key: s.value for s in SiteSettings.query.all()}
    return jsonify(success=True, stats=stats, users=users, classes=classes, settings=settings)

@app.route('/api/admin/users/<user_id>', methods=['DELETE'])
@admin_required
def admin_delete_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        return jsonify(success=True, message=f'User {user.username} deleted.')
    except Exception as e:
        db.session.rollback()
        logging.error(f"Admin error deleting user {user_id}: {str(e)}")
        return jsonify(error='Could not delete user.'), 500

@app.route('/api/admin/classes/<class_id>', methods=['DELETE'])
@admin_required
def admin_delete_class(class_id):
    try:
        cls = Class.query.get_or_404(class_id)
        db.session.delete(cls)
        db.session.commit()
        return jsonify(success=True, message=f'Class {cls.name} deleted.')
    except Exception as e:
        db.session.rollback()
        logging.error(f"Admin error deleting class {class_id}: {str(e)}")
        return jsonify(error='Could not delete class.'), 500

@app.route('/api/admin/update_settings', methods=['POST'])
@admin_required
def admin_update_settings():
    data = request.json
    try:
        for key, value in data.items():
            if not isinstance(key, str) or not isinstance(value, str):
                continue
            setting = SiteSettings.query.get(key)
            if setting:
                setting.value = value
            else:
                setting = SiteSettings(key=key, value=value)
                db.session.add(setting)
        db.session.commit()
        return jsonify(success=True, message='Settings updated.')
    except Exception as e:
        db.session.rollback()
        logging.error(f"Admin error updating settings: {str(e)}")
        return jsonify(error='Could not update settings.'), 500

@app.route('/api/admin/toggle_maintenance', methods=['POST'])
@admin_required
def admin_toggle_maintenance():
    try:
        setting = SiteSettings.query.get('maintenance_mode')
        if setting and setting.value == 'true':
            setting.value = 'false'
            enabled = False
        else:
            if not setting:
                setting = SiteSettings(key='maintenance_mode', value='true')
                db.session.add(setting)
            else:
                setting.value = 'true'
            enabled = True
        db.session.commit()
        return jsonify(success=True, enabled=enabled)
    except Exception as e:
        db.session.rollback()
        logging.error(f"Admin error toggling maintenance mode: {str(e)}")
        return jsonify(error='Could not toggle maintenance mode.'), 500

@app.route('/api/admin/music', methods=['GET', 'POST'])
@admin_required
def admin_manage_music():
    if request.method == 'POST':
        data = request.json
        if not data or 'name' not in data or 'url' not in data:
            return jsonify(error='Missing name or URL for music track.'), 400
        try:
            music = BackgroundMusic(name=data['name'], url=data['url'], uploaded_by=current_user.id)
            db.session.add(music)
            db.session.commit()
            return jsonify(success=True, message='Music track added.'), 201
        except Exception as e:
            db.session.rollback()
            return jsonify(error='Failed to add music track.'), 500
    music_tracks = BackgroundMusic.query.all()
    return jsonify(success=True, music=[{'id': m.id, 'name': m.name, 'url': m.url} for m in music_tracks])

@app.route('/api/admin/music/<int:music_id>', methods=['DELETE'])
@admin_required
def admin_delete_music(music_id):
    try:
        music = BackgroundMusic.query.get_or_404(music_id)
        db.session.delete(music)
        db.session.commit()
        return jsonify(success=True, message='Music track deleted.')
    except Exception as e:
        db.session.rollback()
        return jsonify(error='Failed to delete music track.'), 500

# ==============================================================================
# --- 11. SOCKET.IO EVENTS ---
# ==============================================================================
# ... (Socket.IO events are unchanged)
@socketio.on('join')
def on_join(data):
    if current_user.is_authenticated:
        room = data.get('room')
        if room:
            join_room(room)

@socketio.on('leave')
def on_leave(data):
    if current_user.is_authenticated:
        room = data.get('room')
        if room:
            leave_room(room)

# ==============================================================================
# --- 12. APP INITIALIZATION & DATABASE SETUP ---
# ==============================================================================

# *** FIX: AUTOMATIC PROFILE CREATION ON USER INSERT ***
# This event listener is a robust way to ensure every user gets a profile.
@event.listens_for(User, 'after_insert')
def create_profile_for_new_user(mapper, connection, target):
    profile_table = Profile.__table__
    connection.execute(profile_table.insert().values(user_id=target.id))

# *** CRITICAL FIX FOR RENDER DEPLOYMENT ***
with app.app_context():
    db.create_all()
    logging.info("Database tables checked and created if they didn't exist.")

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

    if not SiteSettings.query.get('ai_persona'):
        try:
            ai_persona_setting = SiteSettings(key='ai_persona', value='a helpful AI assistant')
            db.session.add(ai_persona_setting)
            db.session.commit()
            logging.info("Default AI persona setting created.")
        except IntegrityError:
            db.session.rollback()
            logging.warning("Default AI persona setting already exists.")

if __name__ == '__main__':
    socketio.run(app, debug=True, port=50



