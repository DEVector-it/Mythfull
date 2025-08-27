# --- Imports ---
import os
import json
import logging
import time
import uuid
import secrets
import requests
import re
import random
import threading
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
from sqlalchemy.engine import Engine
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

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
app.config['WTF_CSRF_SECRET_KEY'] = os.environ.get('WTF_CSRF_SECRET_KEY', 'a-super-secret-csrf-key')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['CORS_HEADERS'] = 'Content-Type'
app.config['LIMITER_STORAGE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
app.config['LIMITER_HEADERS_ENABLED'] = True


# --- Security, CORS, CSRF & Rate Limiting ---
CORS(app, supports_credentials=True, origins="*")
csrf = CSRFProtect(app)
csp = {
    'default-src': [
        '\'self\'',
        'https://cdn.tailwindcss.com',
        'https://cdnjs.cloudflare.com',
        'https://js.stripe.com',
        'https://fonts.googleapis.com',
        'https://fonts.gstatic.com',
        'https://*.onrender.com' 
    ]
}
Talisman(app, content_security_policy=csp)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
)

# --- Site-wide Configuration Dictionary ---
SITE_CONFIG = {
    "STRIPE_SECRET_KEY": os.environ.get('STRIPE_SECRET_KEY'),
    "STRIPE_PUBLIC_KEY": os.environ.get('STRIPE_PUBLIC_KEY'),
    "STRIPE_STUDENT_PRICE_ID": os.environ.get('STRIPE_STUDENT_PRICE_ID'),
    "STRIPE_STUDENT_PRO_PRICE_ID": os.environ.get('STRIPE_STUDENT_PRO_PRICE_ID'),
    "YOUR_DOMAIN": os.environ.get('YOUR_DOMAIN', 'https://mythsg.onrender.com'),
    "SECRET_TEACHER_KEY": os.environ.get('SECRET_TEACHER_KEY', 'SUPER-SECRET-TEACHER-KEY'),
    "ADMIN_SECRET_KEY": os.environ.get('ADMIN_SECRET_KEY', 'NoobAdmin'),
    "ADMIN_DEFAULT_PASSWORD": os.environ.get('ADMIN_DEFAULT_PASSWORD', 'adminpassword'),
    "STRIPE_WEBHOOK_SECRET": os.environ.get('STRIPE_WEBHOOK_SECRET'),
    "GEMINI_API_KEYS": os.environ.get('GEMINI_API_KEYS', 'YOUR_SINGLE_API_KEY').split(','),
    "SUPPORT_EMAIL": os.environ.get('MAIL_SENDER')
}

# --- Trustworthy AI Personas ---
AI_PERSONAS = {
    'default': "a helpful and trustworthy AI assistant designed for learning.",
    'socratic': "a tutor who asks guiding questions, in the style of Socrates, to help you discover the answer yourself.",
    'collaborator': "a creative partner for brainstorming and exploring new ideas.",
    'fact-checker': "a meticulous assistant who verifies information and provides sources.",
    'concise': "an assistant that provides brief, to-the-point answers.",
    'pirate': "a swashbuckling AI that speaks in pirate lingo while teaching ye the ropes of knowledge, arrr!",
    'detective': "a sleuth-like AI that investigates concepts and uncovers truths like a master detective."
}


# --- Initialize Extensions with the App ---
stripe.api_key = SITE_CONFIG.get("STRIPE_SECRET_KEY")
password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
db = SQLAlchemy(app)
mail = Mail(app)

# --- Flask-Mail Configuration ---
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_SENDER')

@app.after_request
def set_csrf_cookie(response):
    response.set_cookie('csrf_token', generate_csrf())
    return response

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
    ai_persona = db.Column(db.String(50), nullable=True, default='default')
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


@event.listens_for(User, 'after_insert')
def create_profile_for_new_user(mapper, connection, target):
    """Create a profile for a new user automatically."""
    profile_table = Profile.__table__
    connection.execute(profile_table.insert().values(user_id=target.id))


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
HTML_CONTENT = r"""
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
        
        .shiny-button { 
            position: relative;
            overflow: hidden;
            transition: transform 0.2s ease, box-shadow 0.2s ease; 
            box-shadow: 0 0 5px rgba(0,0,0,0.5);
        }
        .shiny-button:hover { 
            transform: translateY(-2px); 
            box-shadow: 0 4px 15px hsla(var(--brand-hue), 80%, 50%, 0.4);
        }
        .shiny-button:disabled {
            cursor: not-allowed;
            opacity: 0.6;
        }
        .fade-in { animation: fadeIn 0.5s ease-out forwards; }
        .fade-out { animation: fadeOut 0.3s ease-in forwards; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes fadeOut { from { opacity: 1; } to { opacity: 0; } }

        .active-tab { background-color: var(--bg-light) !important; color: white !important; position:relative; }
        .active-tab::after { content: ''; position: absolute; bottom: 0; left: 10%; width: 80%; height: 2px; background: var(--glow-color); border-radius: 2px; }
        .modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); display: flex; align-items: center; justify-content: center; z-index: 1000; }
        .ai-message .chat-bubble { background-color: #2E1A47; border-color: #8B5CF6; }
        .user-message .chat-bubble { background-color: #1E40AF; border-color: #3B82F6; }
        
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
        
        .btn-loader {
            border: 2px solid #f3f3f3;
            border-top: 2px solid hsl(var(--brand-hue), 90%, 60%);
            border-radius: 50%;
            width: 1.25rem;
            height: 1.25rem;
            animation: spin 1s linear infinite;
        }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }

        /* --- RESPONSIVENESS: Mobile Navigation --- */
        #mobile-nav-toggle { display: none; }
        @media (max-width: 768px) {
            #mobile-nav-toggle { display: block; }
            #main-nav {
                transform: translateX(-100%);
                transition: transform 0.3s ease-in-out;
                position: fixed;
                height: 100%;
                z-index: 40;
            }
            #main-nav.open {
                transform: translateX(0);
            }
            #content-overlay {
                display: none;
                position: fixed;
                top: 0; left: 0; right: 0; bottom: 0;
                background-color: rgba(0,0,0,0.5);
                z-index: 30;
            }
            #content-overlay.active {
                display: block;
            }
        }
    </style>
</head>
<body class="text-gray-200 antialiased">
    <div id="app-container" class="relative h-screen w-screen overflow-hidden flex flex-col"></div>
    <div id="toast-container" class="fixed top-6 right-6 z-[100] flex flex-col gap-2"></div>
    <div id="modal-container"></div>
    <div class="fixed bottom-4 left-4 text-xs text-gray-500">
        &copy; <span id="current-year"></span> Myth AI | Made by Hossein
    </div>
    <audio id="background-music" loop autoplay></audio>
    
    <template id="template-full-screen-loader">
        <div class="full-screen-loader fade-in">
            <div class="loader-dots">
                <div class="dot1"></div><div class="dot2"></div><div class="dot3"></div>
            </div>
            <div class="waiting-text">Preparing your adventure...</div>
        </div>
    </template>

    <template id="template-role-choice">
        <div class="flex flex-col items-center justify-center h-full w-full p-4 fade-in welcome-bg">
            <div class="w-full max-w-md text-center">
                <div class="flex items-center justify-center gap-3 mb-4">
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
        <div class="flex h-full w-full bg-gray-800 fade-in relative md:static">
            <!-- RESPONSIVENESS: Main Navigation Sidebar -->
            <nav id="main-nav" class="w-64 bg-gray-900/70 backdrop-blur-sm p-6 flex flex-col gap-4 flex-shrink-0 border-r border-white/10 md:relative md:translate-x-0">
                <div class="flex items-center gap-3 mb-6">
                    <h2 class="text-2xl font-bold brand-gradient-text" id="dashboard-title">Portal</h2>
                </div>
                <div id="nav-links" class="flex flex-col gap-2"></div>
                <div class="mt-auto flex flex-col gap-4">
                    <div id="adsense-container" class="w-full h-48 bg-gray-700/50 rounded-lg flex items-center justify-center text-gray-500 text-sm">Ad Placeholder</div>
                    <div id="notification-bell-container" class="relative"></div>
                    <button id="logout-btn" class="bg-red-600/50 hover:bg-red-600 border border-red-500 text-white font-bold py-2 px-4 rounded-lg transition-colors">Logout</button>
                </div>
            </nav>
            <!-- RESPONSIVENESS: Content Overlay for Mobile Nav -->
            <div id="content-overlay"></div>
            <main class="flex-1 p-8 overflow-y-auto">
                <!-- RESPONSIVENESS: Mobile Nav Toggle Button -->
                <button id="mobile-nav-toggle" class="absolute top-6 left-6 z-50 text-white md:hidden">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16m-7 6h7"></path></svg>
                </button>
                <div id="dashboard-content" class="transition-opacity duration-300"></div>
            </main>
        </div>
    </template>
    
    <template id="template-auth-form"><div class="flex flex-col items-center justify-center h-full w-full p-4 fade-in welcome-bg"><div class="w-full max-w-md glassmorphism rounded-2xl p-8 shadow-2xl"><button id="back-to-roles" class="text-sm text-blue-400 hover:text-blue-300 mb-4">&larr; Back to Role Selection</button><h1 class="text-3xl font-bold text-center brand-gradient-text mb-2" id="auth-title">Portal Login</h1><p class="text-gray-400 text-center mb-6" id="auth-subtitle">Sign in to continue</p><form id="auth-form"><input type="hidden" id="account_type" name="account_type" value="student"><div id="email-field" class="hidden mb-4"><label for="email" class="block text-sm font-medium text-gray-300 mb-1">Email</label><input type="email" id="email" name="email" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500"></div><div class="mb-4"><label for="username" class="block text-sm font-medium text-gray-300 mb-1">Username</label><input type="text" id="username" name="username" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" required></div><div class="mb-4"><label for="password" class="block text-sm font-medium text-gray-300 mb-1">Password</label><input type="password" id="password" name="password" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" required></div><div id="teacher-key-field" class="hidden mb-4"><label for="teacher-secret-key" class="block text-sm font-medium text-gray-300 mb-1">Secret Teacher Key</label><input type="text" id="teacher-secret-key" name="secret_key" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="Required for teacher sign up"></div><div id="admin-key-field" class="hidden mb-4"><label for="admin-secret-key" class="block text-sm font-medium text-gray-300 mb-1">Secret Admin Key</label><input type="password" id="admin-secret-key" name="admin_secret_key" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="Required for admin login"></div><div class="flex justify-end mb-6"><button type="button" id="forgot-password-link" class="text-xs text-blue-400 hover:text-blue-300">Forgot Password?</button></div><button type="submit" id="auth-submit-btn" class="w-full brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg transition-opacity flex items-center justify-center h-12">Login</button><p id="auth-error" class="text-red-400 text-sm text-center h-4 mt-3"></p></form><div class="text-center mt-6"><button id="auth-toggle-btn" class="text-sm text-blue-400 hover:text-blue-300">Don't have an account? <span class="font-semibold">Sign Up</span></button></div></div></div></template>
    <template id="template-my-classes"><h3 class="text-3xl font-bold text-white mb-6">My Classes</h3><div id="class-action-container" class="mb-6"></div><div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6" id="classes-list"></div><div id="selected-class-view" class="mt-8 hidden"></div></template>
    <template id="template-team-mode"><h3 class="text-3xl font-bold text-white mb-6">Team Mode</h3><div id="team-action-container" class="mb-6"></div><div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6" id="teams-list"></div><div id="selected-team-view" class="mt-8 hidden"></div></template>
    <template id="template-student-class-action"><div class="glassmorphism p-4 rounded-lg"><h4 class="font-semibold text-lg mb-2 text-white">Join a New Class</h4><div class="flex items-center gap-2"><input type="text" id="class-code" placeholder="Enter class code" class="flex-grow p-3 bg-gray-700/50 rounded-lg border border-gray-600"><button id="join-class-btn" class="brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg flex items-center justify-center h-12 w-28">Join</button></div></div></template>
    <template id="template-teacher-class-action"><div class="glassmorphism p-4 rounded-lg"><h4 class="font-semibold text-lg mb-2 text-white">Create a New Class</h4><div class="flex items-center gap-2"><input type="text" id="new-class-name" name="name" placeholder="New class name" class="flex-grow p-3 bg-gray-700/50 rounded-lg border border-gray-600"><button id="create-class-btn" class="brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg flex items-center justify-center h-12 w-28">Create</button></div></div></template>
    <template id="template-team-actions"><div class="grid grid-cols-1 md:grid-cols-2 gap-4"><div class="glassmorphism p-4 rounded-lg"><h4 class="font-semibold text-lg mb-2 text-white">Join a Team</h4><div class="flex items-center gap-2"><input type="text" id="team-code" placeholder="Enter team code" class="flex-grow p-3 bg-gray-700/50 rounded-lg border border-gray-600"><button id="join-team-btn" class="brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg">Join</button></div></div><div class="glassmorphism p-4 rounded-lg"><h4 class="font-semibold text-lg mb-2 text-white">Create a New Team</h4><div class="flex items-center gap-2"><input type="text" id="new-team-name" placeholder="New team name" class="flex-grow p-3 bg-gray-700/50 rounded-lg border border-gray-600"><button id="create-team-btn" class="brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg">Create</button></div></div></div></template>
    <template id="template-selected-class-view"><div class="glassmorphism p-6 rounded-lg"><div class="flex justify-between items-start"><h4 class="text-2xl font-bold text-white mb-4">Class: <span id="selected-class-name"></span></h4><button id="back-to-classes-btn" class="text-sm text-blue-400 hover:text-blue-300">&larr; Back to All Classes</button></div><div class="flex border-b border-gray-600 mb-4 overflow-x-auto"><button class="py-2 px-4 text-gray-300 hover:text-white class-view-tab whitespace-nowrap" data-tab="chat">Chat</button><button class="py-2 px-4 text-gray-300 hover:text-white class-view-tab whitespace-nowrap" data-tab="assignments">Assignments</button><button class="py-2 px-4 text-gray-300 hover:text-white class-view-tab whitespace-nowrap" data-tab="quizzes">Quizzes</button><button class="py-2 px-4 text-gray-300 hover:text-white class-view-tab whitespace-nowrap" data-tab="students">Students</button></div><div id="class-view-content"></div></div></template>
    <template id="template-class-chat-view"><div id="chat-messages" class="bg-gray-900/50 p-4 rounded-lg h-96 overflow-y-auto mb-4 border border-gray-700 flex flex-col gap-4"></div><form id="chat-form" class="flex items-center gap-2"><input type="text" id="chat-input" placeholder="Ask the AI assistant for help..." class="flex-grow w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600"><button type="submit" id="send-chat-btn" class="brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg">Send</button></form></div></template>
    <template id="template-class-assignments-view"><div class="flex justify-between items-center mb-4"><h5 class="text-xl font-semibold text-white">Assignments</h5><div id="assignment-action-container"></div></div><div id="assignments-list" class="space-y-4"></div></template>
    <template id="template-class-quizzes-view"><div class="flex justify-between items-center mb-4"><h5 class="text-xl font-semibold text-white">Quizzes</h5><div id="quiz-action-container"></div></div><div id="quizzes-list" class="space-y-4"></div></template>
    <template id="template-class-students-view"><h5 class="text-xl font-semibold text-white mb-4">Enrolled Students</h5><ul id="class-students-list" class="space-y-2"></ul></template>
    <template id="template-profile"><h3 class="text-3xl font-bold text-white mb-6">Customize Profile</h3><form id="profile-form" class="glassmorphism p-6 rounded-lg max-w-lg"><div class="mb-4"><label for="bio" class="block text-sm font-medium text-gray-300 mb-1">Bio</label><textarea id="bio" name="bio" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" rows="4"></textarea></div><div class="mb-4"><label for="avatar" class="block text-sm font-medium text-gray-300 mb-1">Avatar URL</label><input type="url" id="avatar" name="avatar" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600"></div><button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Save Profile</button></form></template>
    <template id="template-ai-settings"><h3 class="text-3xl font-bold text-white mb-6">AI Persona Settings</h3><form id="ai-settings-form" class="glassmorphism p-6 rounded-lg max-w-lg"><div class="mb-4"><label for="ai-persona-select" class="block text-sm font-medium text-gray-300 mb-2">Choose your AI's personality</label><select id="ai-persona-select" name="ai_persona" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600"></select><p class="text-xs text-gray-400 mt-2" id="ai-persona-description">Select a persona to see its description.</p></div><button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Save AI Settings</button></form></template>
    <template id="template-theme-settings"><h3 class="text-3xl font-bold text-white mb-6">Theme Settings</h3><form id="theme-settings-form" class="glassmorphism p-6 rounded-lg max-w-lg"><div class="mb-4"><label for="theme-select" class="block text-sm font-medium text-gray-300 mb-2">Choose your theme</label><select id="theme-select" name="theme_preference" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600"></select></div><button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Save Theme</button></form></template>
    <template id="template-billing"><h3 class="text-3xl font-bold text-white mb-6">Billing & Plans</h3><div id="billing-content" class="glassmorphism p-6 rounded-lg"></div></template>
    <template id="template-admin-dashboard"><h3 class="text-3xl font-bold text-white mb-6">Admin Panel</h3><div id="admin-stats" class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8"></div><div class="flex border-b border-gray-600 mb-4 overflow-x-auto"><button class="py-2 px-4 text-gray-300 hover:text-white admin-view-tab whitespace-nowrap" data-tab="users">Users</button><button class="py-2 px-4 text-gray-300 hover:text-white admin-view-tab whitespace-nowrap" data-tab="classes">Classes</button><button class="py-2 px-4 text-gray-300 hover:text-white admin-view-tab whitespace-nowrap" data-tab="settings">Settings</button><button class="py-2 px-4 text-gray-300 hover:text-white admin-view-tab whitespace-nowrap" data-tab="music">Music</button></div><div id="admin-view-content"></div></main></div></template>
    <template id="template-admin-users-view"><div class="flex justify-between items-center mb-4"><h4 class="text-xl font-bold text-white">User Management</h4><button id="add-user-btn" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Add User</button></div><div class="overflow-x-auto glassmorphism p-4 rounded-lg"><table class="w-full text-left text-sm text-gray-300"><thead><tr class="border-b border-gray-600"><th class="p-3">Username</th><th class="p-3">Email</th><th class="p-3">Role</th><th class="p-3">Created At</th><th class="p-3">Actions</th></tr></thead><tbody id="admin-user-list" class="divide-y divide-gray-700/50"></tbody></table></div></template>
    <template id="template-admin-classes-view"><h4 class="text-xl font-bold text-white mb-4">Class Management</h4><div class="overflow-x-auto glassmorphism p-4 rounded-lg"><table class="w-full text-left text-sm text-gray-300"><thead><tr class="border-b border-gray-600"><th class="p-3">Name</th><th class="p-3">Teacher</th><th class="p-3">Code</th><th class="p-3">Students</th><th class="p-3">Actions</th></tr></thead><tbody id="admin-class-list" class="divide-y divide-gray-700/50"></tbody></table></div></template>
    <template id="template-admin-settings-view"><h4 class="text-xl font-bold text-white mb-4">Site Settings</h4><form id="admin-settings-form" class="glassmorphism p-6 rounded-lg max-w-lg"><div class="mb-4"><label for="setting-announcement" class="block text-sm font-medium text-gray-300 mb-1">Announcement Banner</label><input type="text" id="setting-announcement" name="announcement" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600"></div><div class="mb-4"><label for="setting-daily-message" class="block text-sm font-medium text-gray-300 mb-1">Message of the Day</label><input type="text" id="setting-daily-message" name="daily_message" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600"></div><div class="mb-4"><label for="ai-persona-input" class="block text-sm font-medium text-gray-300 mb-1">Default AI Persona (for new users)</label><select id="ai-persona-input" name="ai_persona" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600"></select></div><div class="mb-4"><label class="block text-sm font-medium text-gray-300 mb-1">Maintenance Mode</label><button type="button" id="maintenance-toggle-btn" class="bg-yellow-500 hover:bg-yellow-600 text-white font-bold py-2 px-4 rounded-lg">Toggle Maintenance Mode</button></div><button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Save Settings</button></form></template>
    <template id="template-admin-music-view"><h4 class="text-xl font-bold text-white mb-4">Background Music</h4><div class="flex items-center gap-2 mb-4"><input type="text" id="music-name" placeholder="Music Title" class="flex-grow p-3 bg-gray-700/50 rounded-lg border border-gray-600"><input type="url" id="music-url" placeholder="Music URL (MP3)" class="flex-grow p-3 bg-gray-700/50 rounded-lg border border-gray-600"><button id="add-music-btn" class="brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg">Add Music</button></div><ul id="music-list" class="space-y-2"></ul></template>
    <template id="template-modal"><div class="modal-overlay fade-in"><div class="glassmorphism rounded-2xl p-8 shadow-2xl w-full max-w-2xl modal-content relative"><button class="absolute top-4 right-4 text-gray-400 hover:text-white text-2xl leading-none">&times;</button><div class="modal-body"></div></div></div></template>
    <template id="template-privacy-policy"><h2 class="text-2xl font-bold text-white mb-4">Privacy Policy</h2><p class="text-gray-300">This is a placeholder for your privacy policy. You should replace this with your actual policy, detailing how you collect, use, and protect user data. Make sure to comply with relevant regulations like GDPR and CCPA.</p></template>
    <template id="template-plans"><h2 class="text-2xl font-bold text-white mb-4">Subscription Plans</h2><div class="grid md:grid-cols-2 gap-6"><div class="glassmorphism p-6 rounded-lg"><h3 class="text-xl font-bold text-cyan-400">Free Plan</h3><p class="text-gray-400">Basic access for all users.</p></div><div class="glassmorphism p-6 rounded-lg border-2 border-purple-500"><h3 class="text-xl font-bold text-purple-400">Pro Plan</h3><p class="text-gray-400">Unlock unlimited AI interactions and advanced features.</p><button class="mt-4 brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg" id="upgrade-from-modal-btn">Upgrade Now</button></div></div></template>
    <template id="template-contact-form"><h2 class="text-2xl font-bold text-white mb-4">Contact Us</h2><form id="contact-form"><div class="mb-4"><label for="contact-name" class="block text-sm">Name</label><input type="text" id="contact-name" name="name" class="w-full p-2 bg-gray-800 rounded" required></div><div class="mb-4"><label for="contact-email" class="block text-sm">Email</label><input type="email" id="contact-email" name="email" class="w-full p-2 bg-gray-800 rounded" required></div><div class="mb-4"><label for="contact-message" class="block text-sm">Message</label><textarea id="contact-message" name="message" class="w-full p-2 bg-gray-800 rounded" rows="5" required></textarea></div><button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Send Message</button></form></template>
    <template id="template-create-assignment-modal">
        <h3 class="text-2xl font-bold text-white mb-4">Create New Assignment</h3>
        <form id="create-assignment-form">
            <div class="mb-4">
                <label for="assignment-title" class="block text-sm font-medium text-gray-300 mb-1">Title</label>
                <input type="text" id="assignment-title" name="title" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" required>
            </div>
            <div class="mb-4">
                <label for="assignment-description" class="block text-sm font-medium text-gray-300 mb-1">Description</label>
                <textarea id="assignment-description" name="description" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" rows="5" required></textarea>
            </div>
            <div class="mb-4">
                <label for="assignment-due-date" class="block text-sm font-medium text-gray-300 mb-1">Due Date</label>
                <input type="date" id="assignment-due-date" name="due_date" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" required>
            </div>
            <button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Create Assignment</button>
        </form>
    </template>
    <template id="template-view-assignment-modal">
        <div class="flex justify-between items-start mb-4">
            <h3 class="text-2xl font-bold text-white" id="assignment-title-view"></h3>
            <button id="close-modal-btn" class="text-gray-400 hover:text-white text-2xl leading-none">&times;</button>
        </div>
        <p id="assignment-description-view" class="text-gray-300 mb-4"></p>
        <p class="text-sm text-gray-400 mb-6">Due: <span id="assignment-due-date-view"></span></p>
        <div id="assignment-submissions-section">
            <h4 class="text-xl font-semibold text-white mb-4">Submissions</h4>
            <div id="submissions-list" class="space-y-4"></div>
        </div>
    </template>
    <template id="template-create-quiz-modal">
        <h3 class="text-2xl font-bold text-white mb-4">Create New Quiz</h3>
        <form id="create-quiz-form">
            <div class="mb-4">
                <label for="quiz-title" class="block text-sm font-medium text-gray-300 mb-1">Title</label>
                <input type="text" id="quiz-title" name="title" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" required>
            </div>
            <div class="mb-4">
                <label for="quiz-description" class="block text-sm font-medium text-gray-300 mb-1">Description (Optional)</label>
                <textarea id="quiz-description" name="description" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" rows="3"></textarea>
            </div>
            <div class="mb-4">
                <label for="quiz-time-limit" class="block text-sm font-medium text-gray-300 mb-1">Time Limit (minutes)</label>
                <input type="number" id="quiz-time-limit" name="time_limit" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" value="30" min="1" required>
            </div>
            <div id="quiz-questions-container" class="space-y-4">
            </div>
            <button type="button" id="add-question-btn" class="mt-4 bg-gray-600/50 hover:bg-gray-600 text-white font-bold py-2 px-4 rounded-lg">Add Question</button>
            <button type="submit" class="mt-4 brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Create Quiz</button>
        </form>
    </template>
    <template id="template-quiz-question-field">
        <div class="glassmorphism p-4 rounded-lg relative">
            <button type="button" class="remove-question-btn absolute top-2 right-2 text-red-400 hover:text-red-300">&times;</button>
            <div class="mb-2">
                <label class="block text-sm font-medium text-gray-300 mb-1">Question</label>
                <input type="text" name="question_text" class="w-full p-2 bg-gray-700/50 rounded-lg border border-gray-600" required>
            </div>
            <div class="mb-2">
                <label class="block text-sm font-medium text-gray-300 mb-1">Correct Answer</label>
                <input type="text" name="correct_answer" class="w-full p-2 bg-gray-700/50 rounded-lg border border-gray-600" required>
            </div>
            <div class="space-y-2">
                <label class="block text-sm font-medium text-gray-300">Incorrect Answers</label>
                <input type="text" name="incorrect_answer_1" class="w-full p-2 bg-gray-700/50 rounded-lg border border-gray-600" required>
                <input type="text" name="incorrect_answer_2" class="w-full p-2 bg-gray-700/50 rounded-lg border border-gray-600" required>
                <input type="text" name="incorrect_answer_3" class="w-full p-2 bg-gray-700/50 rounded-lg border border-gray-600" required>
            </div>
        </div>
    </template>
    <template id="template-admin-create-user-modal">
        <h3 class="text-2xl font-bold text-white mb-4">Create New User</h3>
        <form id="admin-create-user-form">
            <div class="mb-4">
                <label for="new-username" class="block text-sm font-medium text-gray-300 mb-1">Username</label>
                <input type="text" id="new-username" name="username" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" required>
            </div>
            <div class="mb-4">
                <label for="new-email" class="block text-sm font-medium text-gray-300 mb-1">Email</label>
                <input type="email" id="new-email" name="email" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" required>
            </div>
            <div class="mb-4">
                <label for="new-password" class="block text-sm font-medium text-gray-300 mb-1">Password</label>
                <input type="password" id="new-password" name="password" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" required>
            </div>
            <div class="mb-4">
                <label for="new-role" class="block text-sm font-medium text-gray-300 mb-1">Role</label>
                <select id="new-role" name="role" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600">
                    <option value="student">Student</option>
                    <option value="teacher">Teacher</option>
                    <option value="admin">Admin</option>
                </select>
            </div>
            <button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Create User</button>
        </form>
    </template>
    
    <script>
    document.addEventListener('DOMContentLoaded', () => {
        const BASE_URL = 'https://mythsg.onrender.com';
        const SITE_CONFIG = {
            STRIPE_PUBLIC_KEY: '',
            STRIPE_STUDENT_PRO_PRICE_ID: 'price_YOUR_PRO_PRICE_ID'
        };
        
        const themes = {
            dark: { '--brand-hue': 220, '--bg-dark': '#0F172A', '--bg-med': '#1E293B', '--bg-light': '#334155', '--text-color': '#E2E8F0', '--text-secondary-color': '#94A3B8' },
            light: { '--brand-hue': 200, '--bg-dark': '#F1F5F9', '--bg-med': '#E2E8F0', '--bg-light': '#CBD5E1', '--text-color': '#1E293B', '--text-secondary-color': '#475569' },
            blue: { '--brand-hue': 210, '--bg-dark': '#0c1d3a', '--bg-med': '#1a2c4e', '--bg-light': '#2e4570', '--text-color': '#dbe8ff', '--text-secondary-color': '#a0b3d1' },
            purple: { '--brand-hue': 260, '--bg-dark': '#1e1b3b', '--bg-med': '#2d2852', '--bg-light': '#453f78', '--text-color': '#e6e3ff', '--text-secondary-color': '#b8b4d9' },
            neon: { '--brand-hue': 300, '--bg-dark': '#1a0033', '--bg-med': '#330066', '--bg-light': '#4d0099', '--text-color': '#ffccff', '--text-secondary-color': '#cc99ff' },
            sunset: { '--brand-hue': 30, '--bg-dark': '#331a00', '--bg-med': '#663300', '--bg-light': '#994d00', '--text-color': '#ffe6cc', '--text-secondary-color': '#ffb366' }
        };

        const appState = { currentUser: null, currentTab: 'my-classes', selectedClass: null, socket: null, stripe: null, quizTimer: null, isLoginView: true, selectedRole: null, aiPersonas: {} };
        const DOMElements = { appContainer: document.getElementById('app-container'), toastContainer: document.getElementById('toast-container'), modalContainer: document.getElementById('modal-container'), backgroundMusic: document.getElementById('background-music') };
        
        const aiAvatarSvg = 'data:image/svg+xml;base64,' + btoa(`<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="logoGradient" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" style="stop-color:hsl(var(--brand-hue), 90%, 60%);" /><stop offset="100%" style="stop-color:hsl(var(--brand-hue), 90%, 40%);" /></linearGradient></defs><circle cx="50" cy="50" r="45" fill="url(#logoGradient)"/><circle cx="28" cy="68" r="8" fill="white"/><circle cx="50" cy="32" r="8" fill="white"/><circle cx="72" cy="68" r="8" fill="white"/><path d="M31 61 L 47 40" stroke="white" stroke-width="5" stroke-linecap="round"/><path d="M53 40 L 69 61" stroke="white" stroke-width="5" stroke-linecap="round"/></svg>`);
        const thinkingIndicatorHtml = `
            <div id="thinking-indicator" class="ai-message flex items-center gap-3 justify-start fade-in">
                <img src="${aiAvatarSvg}" class="w-8 h-8 rounded-full">
                <div class="flex flex-col">
                    <span class="text-xs text-gray-400">Myth AI is thinking...</span>
                    <div class="chat-bubble p-3 rounded-lg border mt-1 max-w-md text-white">
                        <div class="loader-dots">
                            <div class="dot1 w-2 h-2"></div>
                            <div class="dot2 w-2 h-2"></div>
                            <div class="dot3 w-2 h-2"></div>
                        </div>
                    </div>
                </div>
            </div>
        `;

        document.getElementById('current-year').textContent = new Date().getFullYear();

        // --- Core Helper Functions ---
        function applyTheme(themeName) { const theme = themes[themeName]; if (theme) { for (const [key, value] of Object.entries(theme)) { document.documentElement.style.setProperty(key, value); } } }
        function showToast(message, type = 'info') { const colors = { info: 'bg-blue-600', success: 'bg-green-600', error: 'bg-red-600' }; const toast = document.createElement('div'); toast.className = `text-white text-sm py-2 px-4 rounded-lg shadow-lg fade-in ${colors[type]}`; toast.textContent = message; DOMElements.toastContainer.appendChild(toast); setTimeout(() => { toast.style.opacity = '0'; setTimeout(() => toast.remove(), 500); }, 3500); }
        function escapeHtml(text) { if (typeof text !== 'string') return ''; const map = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'}; return text.replace(/[&<>"']/g, m => map[m]); }
        
        function toggleButtonLoading(button, isLoading, originalContent = null) { if (!button) return; if (isLoading) { button.dataset.originalContent = button.innerHTML; button.innerHTML = '<div class="btn-loader mx-auto"></div>'; button.disabled = true; } else { button.innerHTML = originalContent || button.dataset.originalContent || 'Submit'; button.disabled = false; } }

        async function apiCall(endpoint, options = {}, showLoader = true) {
            let loader;
            if (showLoader) {
                loader = showFullScreenLoader('Processing...');
            }
            let response;
            try {
                const csrfToken = document.cookie.split('; ').find(row => row.startsWith('csrf_token='))?.split('=')[1];
                if (options.method && options.method.toLowerCase() !== 'get' && csrfToken) {
                    options.headers = {
                        'X-CSRFToken': csrfToken,
                        ...options.headers
                    };
                }
                if (options.body && typeof options.body === 'object') {
                    options.headers = { 'Content-Type': 'application/json', ...options.headers };
                    options.body = JSON.stringify(options.body);
                }
                response = await fetch(`${BASE_URL}/api${endpoint}`, { credentials: 'include', ...options });
                const contentType = response.headers.get("content-type");
                if (contentType && contentType.includes("application/json")) {
                    const data = await response.json();
                    if (!response.ok) {
                        if (response.status === 401 && endpoint !== '/status') handleLogout(false);
                        throw new Error(data.error || `Request failed with status ${response.status}`);
                    }
                    return { success: true, ...data };
                } else {
                    const text = await response.text();
                    throw new Error(`Server returned non-JSON response: ${text.substring(0, 100)}`);
                }
            } catch (error) {
                showToast(error.message, 'error');
                console.error("API Call Error:", error);
                return { success: false, error: error.message };
            } finally {
                if (loader) {
                    loader.remove();
                }
            }
        }
        
        function renderPage(templateId, setupFunction) { const template = document.getElementById(templateId); if (!template) return; const content = template.content.cloneNode(true); DOMElements.appContainer.innerHTML = ''; DOMElements.appContainer.appendChild(content); if (setupFunction) setupFunction(); }
        function renderSubTemplate(container, templateId, setupFunction) { const template = document.getElementById(templateId); if (!template) return; const content = template.content.cloneNode(true); container.innerHTML = ''; container.appendChild(content); if (setupFunction) setupFunction(); }
        function showModal(content, setupFunction, maxWidth = 'max-w-2xl') { const template = document.getElementById('template-modal').content.cloneNode(true); const modalBody = template.querySelector('.modal-body'); if(typeof content === 'string') { modalBody.innerHTML = content; } else { modalBody.innerHTML = ''; modalBody.appendChild(content); } template.querySelector('.modal-content').classList.replace('max-w-2xl', maxWidth); template.querySelector('button').addEventListener('click', hideModal); DOMElements.modalContainer.innerHTML = ''; DOMElements.modalContainer.appendChild(template); if(setupFunction) setupFunction(DOMElements.modalContainer); }
        function hideModal() { DOMElements.modalContainer.innerHTML = ''; }
        
        function showConfirmationModal(message, onConfirm) { const content = document.createElement('div'); content.innerHTML = `<h3 class="text-xl font-bold text-white mb-4">Are you sure?</h3><p class="text-gray-300 mb-6">${escapeHtml(message)}</p><div class="flex justify-end gap-4"><button id="confirm-cancel" class="bg-gray-600/50 hover:bg-gray-600 shiny-button text-white font-bold py-2 px-4 rounded-lg">Cancel</button><button id="confirm-ok" class="bg-red-600/80 hover:bg-red-600 shiny-button text-white font-bold py-2 px-4 rounded-lg">Confirm</button></div>`; showModal(content, (modal) => { modal.querySelector('#confirm-cancel').addEventListener('click', hideModal); modal.querySelector('#confirm-ok').addEventListener('click', () => { onConfirm(); hideModal(); }); }, 'max-w-md'); }

        function showFullScreenLoader(message = 'Loading...') {
            const existingLoader = DOMElements.appContainer.querySelector('.full-screen-loader');
            if (existingLoader) existingLoader.remove();
            const loaderTemplate = document.getElementById('template-full-screen-loader');
            const loaderElement = loaderTemplate.content.firstElementChild.cloneNode(true);
            loaderElement.querySelector('.waiting-text').textContent = message;
            DOMElements.appContainer.appendChild(loaderElement);
            return loaderElement;
        }
        function connectSocket() { if (appState.socket) appState.socket.disconnect(); appState.socket = io(BASE_URL); appState.socket.on('connect', () => { console.log('Socket connected!'); appState.socket.emit('join', { room: `user_${appState.currentUser.id}` }); }); appState.socket.on('new_message', (data) => { if (appState.selectedClass && data.class_id === appState.selectedClass.id) appendChatMessage(data); }); appState.socket.on('new_notification', (data) => { showToast(`Notification: ${data.content}`, 'info'); updateNotificationBell(true); }); }
        
        // --- Page Setup Functions ---
        function setupRoleChoicePage() { renderPage('template-role-choice', () => { document.querySelectorAll('.role-btn').forEach(btn => { btn.addEventListener('click', (e) => { appState.selectedRole = e.currentTarget.dataset.role; setupAuthPage(); }); }); }); }
        function setupAuthPage() { renderPage('template-auth-form', () => { updateAuthView(); document.getElementById('auth-form').addEventListener('submit', handleAuthSubmit); document.getElementById('auth-toggle-btn').addEventListener('click', () => { appState.isLoginView = !appState.isLoginView; updateAuthView(); }); document.getElementById('forgot-password-link').addEventListener('click', handleForgotPassword); document.getElementById('back-to-roles').addEventListener('click', setupRoleChoicePage); }); }
        function updateAuthView() { const title = document.getElementById('auth-title'); const subtitle = document.getElementById('auth-subtitle'); const submitBtn = document.getElementById('auth-submit-btn'); const toggleBtn = document.getElementById('auth-toggle-btn'); const emailField = document.getElementById('email-field'); const teacherKeyField = document.getElementById('teacher-key-field'); const adminKeyField = document.getElementById('admin-key-field'); const usernameInput = document.getElementById('username'); document.getElementById('account_type').value = appState.selectedRole; title.textContent = `${appState.selectedRole.charAt(0).toUpperCase() + appState.selectedRole.slice(1)} Portal`; adminKeyField.classList.add('hidden'); teacherKeyField.classList.add('hidden'); usernameInput.disabled = false; 
            if (appState.selectedRole === 'admin') {
                appState.isLoginView = true;
                toggleBtn.classList.add('hidden');
                adminKeyField.classList.remove('hidden');
                document.getElementById('admin-secret-key').required = true;
            } else {
                toggleBtn.classList.remove('hidden');
            }
            if (appState.isLoginView) { subtitle.textContent = 'Sign in to continue'; submitBtn.textContent = 'Login'; toggleBtn.innerHTML = "Don't have an account? <span class='font-semibold'>Sign Up</span>"; emailField.classList.add('hidden'); document.getElementById('email').required = false; } else { subtitle.textContent = 'Create your Account'; submitBtn.textContent = 'Sign Up'; toggleBtn.innerHTML = "Already have an account? <span class='font-semibold'>Login</span>"; emailField.classList.remove('hidden'); document.getElementById('email').required = true; if (appState.selectedRole === 'teacher') { teacherKeyField.classList.remove('hidden'); document.getElementById('teacher-secret-key').required = true; } } }
        
        async function handleAuthSubmit(e) { e.preventDefault(); const form = e.target; const button = form.querySelector('button[type="submit"]'); toggleButtonLoading(button, true); const endpoint = appState.isLoginView ? '/login' : '/signup'; const body = Object.fromEntries(new FormData(form)); const result = await apiCall(endpoint, { method: 'POST', body }); if (result.success) { handleLoginSuccess(result.user, result.settings); } else { document.getElementById('auth-error').textContent = result.error; toggleButtonLoading(button, false, appState.isLoginView ? 'Login' : 'Sign Up'); } }

        function handleLoginSuccess(user, settings) {
            appState.currentUser = user;
            appState.aiPersonas = settings.ai_personas || {};
            
            // SAVVY CHANGE: Apply global theme first, then user theme if no global is set
            if (settings.global_theme) {
                applyTheme(settings.global_theme);
            } else if (user.theme_preference) {
                applyTheme(user.theme_preference);
            }

            // SAVVY CHANGE: Apply global music if it exists
            if (settings.global_music_url) {
                playBackgroundMusic(settings.global_music_url);
            }

            showFullScreenLoader('Logging you in...');
            setupDashboard(user, settings);
        }

        async function setupDashboard(user, settings) { 
            if (!user) return setupRoleChoicePage();
            
            const stripeConfig = await apiCall('/stripe_config', {}, false);
            if (stripeConfig.success && stripeConfig.public_key) {
                SITE_CONFIG.STRIPE_PUBLIC_KEY = stripeConfig.public_key;
                if (!appState.stripe) {
                    appState.stripe = Stripe(SITE_CONFIG.STRIPE_PUBLIC_KEY);
                }
            } else {
                showToast("Could not load payment processor. Billing features may not work.", 'error');
            }

            connectSocket();
            renderPage('template-main-dashboard', () => { 
                const navLinks = document.getElementById('nav-links'); 
                const dashboardTitle = document.getElementById('dashboard-title'); 
                let tabs = []; 
                if (user.role === 'student' || user.role === 'teacher') { 
                    dashboardTitle.textContent = user.role === 'student' ? "Student Hub" : "Teacher Hub"; 
                    appState.currentTab = 'my-classes'; 
                    tabs = [ 
                        { id: 'my-classes', label: 'My Classes' }, 
                        { id: 'team-mode', label: 'Team Mode' }, 
                        { id: 'ai-settings', label: 'AI Settings' }, 
                        { id: 'theme-settings', label: 'Theme' }, 
                        { id: 'billing', label: 'Billing' }, 
                        { id: 'profile', label: 'Profile' } 
                    ]; 
                } else if (user.role === 'admin') { 
                    dashboardTitle.textContent = "Admin Panel"; 
                    appState.currentTab = 'admin-dashboard'; 
                    tabs = [ 
                        { id: 'admin-dashboard', label: 'Dashboard' }, 
                        { id: 'profile', label: 'My Profile' } 
                    ]; 
                } 
                navLinks.innerHTML = tabs.map(tab => `<button data-tab="${tab.id}" class="dashboard-tab text-left text-gray-300 hover:bg-gray-700/50 p-3 rounded-md transition-colors">${tab.label}</button>`).join(''); 
                document.querySelectorAll('.dashboard-tab').forEach(tab => tab.addEventListener('click', () => switchTab(tab.dataset.tab))); 
                document.getElementById('logout-btn').addEventListener('click', () => handleLogout(true)); 
                setupNotificationBell(); 
                setupMobileNav(); 
                switchTab(appState.currentTab); 
                if (!settings.global_music_url) { // Only fetch random if no global is set
                    fetchBackgroundMusic(); 
                }
            }); 
        }
        
        function switchTab(tab) { 
            appState.currentTab = tab; 
            appState.selectedClass = null; 
            document.querySelectorAll('.dashboard-tab').forEach(t => t.classList.toggle('active-tab', t.dataset.tab === tab)); 
            const contentContainer = document.getElementById('dashboard-content'); 
            const setups = { 
                'my-classes': setupMyClassesTab, 
                'team-mode': setupTeamModeTab, 
                'profile': setupProfileTab, 
                'billing': setupBillingTab, 
                'admin-dashboard': setupAdminDashboardTab, 
                'ai-settings': setupAiSettingsTab, 
                'theme-settings': setupThemeSettingsTab 
            }; 
            if (setups[tab]) { 
                contentContainer.classList.add('opacity-0'); 
                setTimeout(() => { 
                    setups[tab](contentContainer); 
                    contentContainer.classList.remove('opacity-0'); 
                }, 150); 
            } 
        }
        
        // --- Tab Content Functions ---
        async function setupMyClassesTab(container) { renderSubTemplate(container, 'template-my-classes', async () => { const actionContainer = document.getElementById('class-action-container'); const listContainer = document.getElementById('classes-list'); const actionTemplateId = `template-${appState.currentUser.role}-class-action`; renderSubTemplate(actionContainer, actionTemplateId, () => { if (appState.currentUser.role === 'student') document.getElementById('join-class-btn').addEventListener('click', handleJoinClass); else document.getElementById('create-class-btn').addEventListener('click', handleCreateClass); }); listContainer.addEventListener('click', (e) => { const classCard = e.target.closest('div[data-id]'); if (classCard) { selectClass(classCard.dataset.id); } }); const result = await apiCall('/my_classes', {}, false); if (result.success && result.classes) { if (result.classes.length === 0) listContainer.innerHTML = `<p class="text-gray-400 text-center col-span-full">You haven't joined or created any classes yet.</p>`; else listContainer.innerHTML = result.classes.map(createClassCardHTML).join(''); } }); }
        
        function createClassCardHTML(cls) { return `<div class="glassmorphism p-4 rounded-lg cursor-pointer hover:bg-gray-700/50 transition-colors fade-in" data-id="${cls.id}" data-name="${cls.name}"><div class="font-bold text-white text-lg">${escapeHtml(cls.name)}</div><div class="text-gray-400 text-sm">Teacher: ${escapeHtml(cls.teacher_name)}</div>${appState.currentUser.role === 'teacher' ? `<div class="text-sm mt-2">Code: <span class="font-mono text-cyan-400">${escapeHtml(cls.code)}</span></div>` : ''}</div>`; }
        
        async function handleJoinClass() { const codeInput = document.getElementById('class-code'); const button = document.getElementById('join-class-btn'); const code = codeInput.value.trim().toUpperCase(); if (!code) return showToast('Please enter a class code.', 'error'); toggleButtonLoading(button, true, 'Join'); const result = await apiCall('/join_class', { method: 'POST', body: { code } }, false); toggleButtonLoading(button, false, 'Join'); if (result.success) { showToast(result.message || 'Joined class!', 'success'); codeInput.value = ''; setupMyClassesTab(document.getElementById('dashboard-content')); } }

        async function handleCreateClass() { const nameInput = document.getElementById('new-class-name'); const button = document.getElementById('create-class-btn'); const name = nameInput.value.trim(); if (!name) return showToast('Please enter a class name.', 'error'); toggleButtonLoading(button, true, 'Create'); const result = await apiCall('/classes', { method: 'POST', body: { name } }, false); toggleButtonLoading(button, false, 'Create'); if (result.success) { showToast(`Class "${escapeHtml(result.class.name)}" created!`, 'success'); nameInput.value = ''; setupMyClassesTab(document.getElementById('dashboard-content')); } }
        
        function setupAiSettingsTab(container) {
            renderSubTemplate(container, 'template-ai-settings', () => {
                const select = document.getElementById('ai-persona-select');
                const description = document.getElementById('ai-persona-description');
                
                select.innerHTML = Object.entries(appState.aiPersonas).map(([key, value]) => {
                    const name = key.charAt(0).toUpperCase() + key.slice(1).replace('-', ' ');
                    return `<option value="${key}">${name}</option>`;
                }).join('');

                select.value = appState.currentUser.ai_persona || 'default';
                description.textContent = appState.aiPersonas[select.value] || '';

                select.addEventListener('change', () => {
                    description.textContent = appState.aiPersonas[select.value] || '';
                });

                document.getElementById('ai-settings-form').addEventListener('submit', handleUpdateAiSettings);
            });
        }

        async function handleUpdateAiSettings(e) {
            e.preventDefault();
            const form = e.target;
            const button = form.querySelector('button[type="submit"]');
            const body = Object.fromEntries(new FormData(form));
            
            toggleButtonLoading(button, true, 'Save AI Settings');
            const result = await apiCall('/update_profile', { method: 'POST', body }, false);
            toggleButtonLoading(button, false, 'Save AI Settings');

            if (result.success) {
                appState.currentUser = result.user;
                showToast('AI Persona updated!', 'success');
            }
        }
        
        function setupThemeSettingsTab(container) {
            renderSubTemplate(container, 'template-theme-settings', () => {
                const select = document.getElementById('theme-select');
                select.innerHTML = Object.keys(themes).map(themeName => `<option value="${themeName}">${themeName.charAt(0).toUpperCase() + themeName.slice(1)}</option>`).join('');
                select.value = appState.currentUser.theme_preference || 'dark';
                document.getElementById('theme-settings-form').addEventListener('submit', handleUpdateTheme);
            });
        }

        async function handleUpdateTheme(e) {
            e.preventDefault();
            const form = e.target;
            const button = form.querySelector('button[type="submit"]');
            const body = Object.fromEntries(new FormData(form));
            
            toggleButtonLoading(button, true, 'Save Theme');
            const result = await apiCall('/update_profile', { method: 'POST', body }, false);
            toggleButtonLoading(button, false, 'Save Theme');

            if (result.success) {
                appState.currentUser = result.user;
                applyTheme(body.theme_preference);
                showToast('Theme updated!', 'success');
            }
        }

        async function setupTeamModeTab(container) { renderSubTemplate(container, 'template-team-mode', async () => { renderSubTemplate(document.getElementById('team-action-container'), 'template-team-actions', () => { document.getElementById('join-team-btn').addEventListener('click', handleJoinTeam); document.getElementById('create-team-btn').addEventListener('click', handleCreateTeam); }); const listContainer = document.getElementById('teams-list'); const result = await apiCall('/teams', {}, false); if (result.success && result.teams) { if (result.teams.length === 0) { listContainer.innerHTML = `<p class="text-gray-400 text-center col-span-full">You are not part of any teams yet.</p>`; } else { listContainer.innerHTML = result.teams.map(team => `<div class="glassmorphism p-4 rounded-lg cursor-pointer hover:bg-gray-700/50 transition-colors" data-id="${team.id}"><div class="font-bold text-white text-lg">${escapeHtml(team.name)}</div><div class="text-gray-400 text-sm">Owner: ${escapeHtml(team.owner_name)}</div><div class="text-sm mt-2">Code: <span class="font-mono text-cyan-400">${escapeHtml(team.code)}</span></div><div class="text-sm text-gray-400">${escapeHtml(String(team.member_count))} members</div></div>`).join(''); listContainer.querySelectorAll('div[data-id]').forEach(el => el.addEventListener('click', e => selectTeam(e.currentTarget.dataset.id))); } } }); }
        async function selectTeam(teamId) { const result = await apiCall(`/teams/${teamId}`, {}, false); if (!result.success) return; const team = result.team; let modalContent = `<h3 class="text-2xl font-bold text-white mb-2">${escapeHtml(team.name)}</h3><p class="text-gray-400 mb-4">Team Code: <span class="font-mono text-cyan-400">${escapeHtml(team.code)}</span></p><h4 class="text-lg font-semibold text-white mb-2">Members</h4><ul class="space-y-2">${team.members.map(m => `<li class="flex items-center gap-3 p-2 bg-gray-800/50 rounded-md"><img src="${escapeHtml(m.profile.avatar || `https://i.pravatar.cc/40?u=${m.id}`)}" class="w-8 h-8 rounded-full"><span>${escapeHtml(m.username)} ${m.id === team.owner_id ? '(Owner)' : ''}</span></li>`).join('')}</ul>`; showModal(modalContent); }
        async function handleJoinTeam() { const code = document.getElementById('team-code').value.trim().toUpperCase(); if (!code) return showToast('Please enter a team code.', 'error'); const result = await apiCall('/join_team', { method: 'POST', body: { code } }, false); if (result.success) { showToast(result.message, 'success'); setupTeamModeTab(document.getElementById('dashboard-content')); } }
        async function handleCreateTeam() { const name = document.getElementById('new-team-name').value.trim(); if (!name) return showToast('Please enter a team name.', 'error'); const result = await apiCall('/teams', { method: 'POST', body: { name } }, false); if (result.success) { showToast(`Team "${escapeHtml(result.team.name)}" created!`, 'success'); setupTeamModeTab(document.getElementById('dashboard-content')); } }
        function setupProfileTab(container) { renderSubTemplate(container, 'template-profile', () => { document.getElementById('bio').value = appState.currentUser.profile.bio || ''; document.getElementById('avatar').value = appState.currentUser.profile.avatar || ''; document.getElementById('profile-form').addEventListener('submit', handleUpdateProfile); }); }
        async function handleUpdateProfile(e) { e.preventDefault(); const form = e.target; const body = Object.fromEntries(new FormData(form)); const result = await apiCall('/update_profile', { method: 'POST', body }, false); if (result.success) { appState.currentUser = result.user; showToast('Profile updated!', 'success'); } }
        function setupBillingTab(container) { renderSubTemplate(container, 'template-billing', () => { const content = document.getElementById('billing-content'); if (appState.currentUser.has_subscription) { content.innerHTML = `<p class="mb-4">You have an active subscription.</p><button id="manage-billing-btn" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Manage Billing</button>`; document.getElementById('manage-billing-btn').addEventListener('click', handleManageBilling); } else { content.innerHTML = `<p class="mb-4">Upgrade to a Pro plan for more features!</p><button id="upgrade-btn" data-price-id="${SITE_CONFIG.STRIPE_STUDENT_PRO_PRICE_ID}" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Upgrade to Pro</button>`; document.getElementById('upgrade-btn').addEventListener('click', handleUpgrade); } }); }
        async function setupAdminDashboardTab(container) { renderSubTemplate(container, 'template-admin-dashboard', async () => { const result = await apiCall('/admin/dashboard_data', {}, false); if (result.success) { document.getElementById('admin-stats').innerHTML = Object.entries(result.stats).map(([key, value]) => `<div class="glassmorphism p-4 rounded-lg"><p class="text-sm text-gray-400">${escapeHtml(key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()))}</p><p class="text-2xl font-bold">${escapeHtml(String(value))}</p></div>`).join(''); } document.querySelectorAll('.admin-view-tab').forEach(tab => tab.addEventListener('click', (e) => switchAdminView(e.currentTarget.dataset.tab))); switchAdminView('users'); }); }
        async function switchAdminView(view) { document.querySelectorAll('.admin-view-tab').forEach(t => t.classList.toggle('active-tab', t.dataset.tab === view)); const container = document.getElementById('admin-view-content'); if (view === 'users') { renderSubTemplate(container, 'template-admin-users-view', async () => { document.getElementById('add-user-btn').addEventListener('click', handleAdminCreateUser); const result = await apiCall('/admin/dashboard_data', {}, false); if(!result.success) return; const userList = document.getElementById('admin-user-list'); userList.innerHTML = result.users.map(u => `<tr><td class="p-3">${escapeHtml(u.username)}</td><td class="p-3">${escapeHtml(u.email)}</td><td class="p-3">${escapeHtml(u.role)}</td><td class="p-3">${new Date(u.created_at).toLocaleDateString()}</td><td class="p-3 space-x-2"><button class="text-blue-400 hover:text-blue-300" data-action="edit" data-id="${u.id}">Edit</button><button class="text-red-500 hover:text-red-400" data-action="delete" data-id="${u.id}">Delete</button></td></tr>`).join(''); userList.querySelectorAll('button').forEach(btn => btn.addEventListener('click', (e) => handleAdminUserAction(e.currentTarget.dataset.action, e.currentTarget.dataset.id))); }); } else if (view === 'classes') { renderSubTemplate(container, 'template-admin-classes-view', async () => { const result = await apiCall('/admin/dashboard_data', {}, false); if(!result.success) return; document.getElementById('admin-class-list').innerHTML = result.classes.map(c => `<tr><td class="p-3">${escapeHtml(c.name)}</td><td class="p-3">${escapeHtml(c.teacher_name)}</td><td class="p-3">${escapeHtml(c.code)}</td><td class="p-3">${escapeHtml(String(c.student_count))}</td><td class="p-3"><button class="text-red-500 hover:text-red-400" data-id="${c.id}">Delete</button></td></tr>`).join(''); document.getElementById('admin-class-list').querySelectorAll('button').forEach(btn => btn.addEventListener('click', (e) => handleAdminDeleteClass(e.currentTarget.dataset.id))); }); } else if (view === 'settings') { renderSubTemplate(container, 'template-admin-settings-view', async () => { const result = await apiCall('/admin/dashboard_data', {}, false); if(!result.success) return; document.getElementById('setting-announcement').value = result.settings.announcement || ''; document.getElementById('setting-daily-message').value = result.settings.daily_message || ''; const personaSelect = document.getElementById('ai-persona-input'); personaSelect.innerHTML = Object.keys(appState.aiPersonas).map(key => `<option value="${key}">${key.charAt(0).toUpperCase() + key.slice(1)}</option>`).join(''); personaSelect.value = result.settings.ai_persona || 'default'; document.getElementById('admin-settings-form').addEventListener('submit', handleAdminUpdateSettings); document.getElementById('maintenance-toggle-btn').addEventListener('click', handleToggleMaintenance); }); } else if (view === 'music') { renderSubTemplate(container, 'template-admin-music-view', async () => { const musicListContainer = document.getElementById('music-list'); const musicResult = await apiCall('/admin/music', {}, false); if (musicResult.success && musicResult.music) { musicListContainer.innerHTML = musicResult.music.map(m => `<li class="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg"><span>${escapeHtml(m.name)}</span><div class="space-x-2"><button class="text-green-400 hover:text-green-300 play-music-btn" data-url="${escapeHtml(m.url)}">Play</button><button class="text-red-500 hover:text-red-400 delete-music-btn" data-id="${m.id}">Delete</button></div></li>`).join(''); document.getElementById('add-music-btn').addEventListener('click', handleAddMusic); musicListContainer.querySelectorAll('.play-music-btn').forEach(btn => btn.addEventListener('click', (e) => playBackgroundMusic(e.currentTarget.dataset.url))); musicListContainer.querySelectorAll('.delete-music-btn').forEach(btn => btn.addEventListener('click', (e) => handleDeleteMusic(e.currentTarget.dataset.id))); } }); } }

        function handleAdminCreateUser() {
            showModal(document.getElementById('template-admin-create-user-modal').content.cloneNode(true), (modal) => {
                document.getElementById('admin-create-user-form').addEventListener('submit', async (e) => {
                    e.preventDefault();
                    const form = e.target;
                    const button = form.querySelector('button[type="submit"]');
                    const body = Object.fromEntries(new FormData(form));
                    toggleButtonLoading(button, true, 'Create User');
                    const result = await apiCall('/admin/users', { method: 'POST', body });
                    toggleButtonLoading(button, false, 'Create User');
                    if (result.success) {
                        showToast(`User "${escapeHtml(result.user.username)}" created!`, 'success');
                        hideModal();
                        switchAdminView('users');
                    } else {
                        showToast(result.error, 'error');
                    }
                });
            });
        }

        async function handleForgotPassword() { const email = prompt('Please enter your account email:'); if (email && /^\S+@\S+\.\S+$/.test(email)) { const result = await apiCall('/request-password-reset', { method: 'POST', body: { email } }); if(result.success) showToast(result.message || 'Request sent.', 'info'); } else if (email) showToast('Please enter a valid email.', 'error'); }
        async function handleLogout(doApiCall) { if (doApiCall) await apiCall('/logout', { method: 'POST' }); if (appState.socket) appState.socket.disconnect(); appState.currentUser = null; window.location.reload(); }
        async function selectClass(classId) { if (appState.selectedClass && appState.socket) appState.socket.emit('leave', { room: `class_${appState.selectedClass.id}` }); const result = await apiCall(`/classes/${classId}`, {}, false); if(!result.success) return; appState.selectedClass = result.class; appState.socket.emit('join', { room: `class_${classId}` }); document.getElementById('classes-list').classList.add('hidden'); document.getElementById('class-action-container').classList.add('hidden'); const viewContainer = document.getElementById('selected-class-view'); viewContainer.classList.remove('hidden'); renderSubTemplate(viewContainer, 'template-selected-class-view', () => { document.getElementById('selected-class-name').textContent = escapeHtml(appState.selectedClass.name); document.getElementById('back-to-classes-btn').addEventListener('click', () => { viewContainer.classList.add('hidden'); document.getElementById('classes-list').classList.remove('hidden'); document.getElementById('class-action-container').classList.remove('hidden'); }); document.querySelectorAll('.class-view-tab').forEach(tab => tab.addEventListener('click', (e) => switchClassView(e.currentTarget.dataset.tab))); switchClassView('chat'); }); }
        async function switchClassView(view) { 
            document.querySelectorAll('.class-view-tab').forEach(t => t.classList.toggle('active-tab', t.dataset.tab === view)); 
            const container = document.getElementById('class-view-content'); 
            if (view === 'chat') { 
                renderSubTemplate(container, 'template-class-chat-view', async () => { 
                    document.getElementById('chat-form').addEventListener('submit', handleSendChat); 
                    const result = await apiCall(`/class_messages/${appState.selectedClass.id}`, {}, false); 
                    if (result.success) { 
                        const messagesDiv = document.getElementById('chat-messages'); 
                        messagesDiv.innerHTML = ''; 
                        result.messages.forEach(m => appendChatMessage(m)); 
                    } 
                }); 
            } else if (view === 'assignments') { 
                renderSubTemplate(container, 'template-class-assignments-view', async () => { 
                    const list = document.getElementById('assignments-list'); 
                    const actionContainer = document.getElementById('assignment-action-container'); 
                    if(appState.currentUser.role === 'teacher') { 
                        actionContainer.innerHTML = `<button id="create-assignment-btn" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">New Assignment</button>`; 
                        document.getElementById('create-assignment-btn').addEventListener('click', handleCreateAssignment); 
                    } 
                    const result = await apiCall(`/classes/${appState.selectedClass.id}/assignments`, {}, false); 
                    if(result.success) { 
                        if(result.assignments.length === 0) list.innerHTML = `<p class="text-gray-400">No assignments posted yet.</p>`; 
                        else list.innerHTML = result.assignments.map(a => `<div class="p-4 bg-gray-800/50 rounded-lg cursor-pointer" data-id="${a.id}"><div class="flex justify-between items-center"><h6 class="font-bold text-white">${escapeHtml(a.title)}</h6><span class="text-sm text-gray-400">Due: ${new Date(a.due_date).toLocaleDateString()}</span></div>${appState.currentUser.role === 'student' ? (a.student_submission ? `<span class="text-xs text-green-400">Submitted</span>` : `<span class="text-xs text-yellow-400">Not Submitted</span>`) : `<span class="text-xs text-cyan-400">${escapeHtml(String(a.submission_count))} Submissions</span>`}</div>`).join(''); 
                        list.querySelectorAll('div[data-id]').forEach(el => el.addEventListener('click', e => viewAssignmentDetails(e.currentTarget.dataset.id))); 
                    } 
                }); 
            } else if (view === 'quizzes') { 
                renderSubTemplate(container, 'template-class-quizzes-view', async () => { 
                    const list = document.getElementById('quizzes-list'); 
                    const actionContainer = document.getElementById('quiz-action-container'); 
                    if(appState.currentUser.role === 'teacher') { 
                        actionContainer.innerHTML = `<button id="create-quiz-btn" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">New Quiz</button>`; 
                        document.getElementById('create-quiz-btn').addEventListener('click', handleCreateQuiz); 
                    } 
                    const result = await apiCall(`/classes/${appState.selectedClass.id}/quizzes`, {}, false); 
                    if(result.success) { 
                        if(result.quizzes.length === 0) list.innerHTML = `<p class="text-gray-400">No quizzes posted yet.</p>`; 
                        else list.innerHTML = result.quizzes.map(q => `<div class="p-4 bg-gray-800/50 rounded-lg cursor-pointer" data-id="${q.id}"><div class="flex justify-between items-center"><h6 class="font-bold text-white">${escapeHtml(q.title)}</h6><span class="text-sm text-gray-400">${escapeHtml(String(q.time_limit))} mins</span></div>${appState.currentUser.role === 'student' ? (q.student_attempt ? `<span class="text-xs text-green-400">Attempted - Score: ${escapeHtml(q.student_attempt.score.toFixed(2))}%</span>` : `<span class="text-xs text-yellow-400">Not Attempted</span>`) : ``}</div>`).join(''); 
                        list.querySelectorAll('div[data-id]').forEach(el => el.addEventListener('click', e => viewQuizDetails(e.currentTarget.dataset.id))); 
                    } 
                }); 
            } else if (view === 'students') { 
                renderSubTemplate(container, 'template-class-students-view', async () => { 
                    const result = await apiCall(`/classes/${appState.selectedClass.id}`, {}, false);
                    if (result.success) {
                        document.getElementById('class-students-list').innerHTML = result.class.students.map(s => `<li class="flex items-center gap-3 p-2 bg-gray-800/50 rounded-md"><img src="${escapeHtml(s.profile.avatar || `https://i.pravatar.cc/40?u=${s.id}`)}" class="w-8 h-8 rounded-full"><span>${escapeHtml(s.username)}</span></li>`).join(''); 
                    }
                }); 
            } 
        }
        
        async function handleSendChat(e) { 
            e.preventDefault(); 
            const input = document.getElementById('chat-input'); 
            const button = document.getElementById('send-chat-btn'); 
            const message = input.value.trim(); 
            if (!message) return; 

            const userMessage = { 
                sender_id: appState.currentUser.id, 
                sender_name: appState.currentUser.username, 
                content: message, 
                timestamp: new Date().toISOString() 
            };
            appendChatMessage(userMessage);
            input.value = '';
            
            const messagesDiv = document.getElementById('chat-messages');
            messagesDiv.insertAdjacentHTML('beforeend', thinkingIndicatorHtml);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;

            const result = await apiCall('/chat/send', { method: 'POST', body: { prompt: message, class_id: appState.selectedClass.id } }, false);
            
            if (!result.success) {
                const errorMsg = { 
                    id: 'error-' + Date.now(), 
                    class_id: appState.selectedClass.id, 
                    sender_id: null, 
                    sender_name: "System Error", 
                    content: result.error || "Could not send message.", 
                    timestamp: new Date().toISOString() 
                };
                const indicator = document.getElementById('thinking-indicator');
                if (indicator) indicator.remove();
                appendChatMessage(errorMsg);
            }
        }
        
        function appendChatMessage(message) { 
            const messagesDiv = document.getElementById('chat-messages'); 
            if (!messagesDiv) return; 

            if (!message.sender_id) {
                const indicator = messagesDiv.querySelector('#thinking-indicator');
                if (indicator) indicator.remove();
            }
            
            const isCurrentUser = message.sender_id === appState.currentUser.id; 
            const isAI = message.sender_id === null; 
            const msgWrapper = document.createElement('div'); 
            msgWrapper.className = `flex items-start gap-3 ${isCurrentUser ? 'user-message justify-end' : 'ai-message justify-start'} fade-in`; 
            const avatar = `<img src="${escapeHtml(message.sender_avatar || (isAI ? aiAvatarSvg : `https://i.pravatar.cc/40?u=${message.sender_id}`))}" class="w-8 h-8 rounded-full">`; 
            const bubble = `<div class="flex flex-col"><span class="text-xs text-gray-400 ${isCurrentUser ? 'text-right' : 'text-left'}">${escapeHtml(message.sender_name || (isAI ? 'AI Assistant' : 'User'))}</span><div class="chat-bubble p-3 rounded-lg border mt-1 max-w-md text-white">${escapeHtml(message.content)}</div><span class="text-xs text-gray-500 mt-1 ${isCurrentUser ? 'text-right' : 'text-left'}">${new Date(message.timestamp).toLocaleTimeString()}</span></div>`; 
            msgWrapper.innerHTML = isCurrentUser ? bubble + avatar : avatar + bubble; 
            messagesDiv.appendChild(msgWrapper); 
            messagesDiv.scrollTop = messagesDiv.scrollHeight; 
        }
        async function fetchBackgroundMusic() { const result = await apiCall('/admin/music', {}, false); if (result.success && result.music.length > 0) { const randomTrack = result.music[Math.floor(Math.random() * result.music.length)]; DOMElements.backgroundMusic.src = randomTrack.url; DOMElements.backgroundMusic.play().catch(e => console.error("Music playback failed:", e)); } }
        async function main() { const status = await apiCall('/status'); if (status.success && status.user) { handleLoginSuccess(status.user, status.settings); } else { setupRoleChoicePage(); } }
        function setupNotificationBell() { const container = document.getElementById('notification-bell-container'); container.innerHTML = `<button id="notification-bell" class="relative text-gray-400 hover:text-white"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6 6 0 10-12 0v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"></path></svg><span id="notification-dot" class="absolute top-0 right-0 w-2 h-2 bg-red-500 rounded-full hidden"></span></button>`; document.getElementById('notification-bell').addEventListener('click', handleNotifications); updateNotificationBell(); }
        async function updateNotificationBell(hasUnread = false) { const dot = document.getElementById('notification-dot'); if(!dot) return; if (hasUnread) { dot.classList.remove('hidden'); } else { const result = await apiCall('/notifications/unread_count', {}, false); if (result.success && result.count > 0) dot.classList.remove('hidden'); else dot.classList.add('hidden'); } }
        async function handleNotifications() { const result = await apiCall('/notifications', {}, false); if (!result.success) return; const modalContent = document.createElement('div'); modalContent.innerHTML = `<h3 class="text-xl font-bold text-white mb-4">Notifications</h3><ul class="space-y-2">${result.notifications.map(n => `<li class="p-3 bg-gray-800/50 rounded-lg ${n.is_read ? 'text-gray-400' : 'text-white'}">${escapeHtml(n.content)} <span class="text-xs text-gray-500">${new Date(n.timestamp).toLocaleString()}</span></li>`).join('') || '<p class="text-gray-400">No notifications.</p>'}</ul>`; showModal(modalContent); await apiCall('/notifications/mark_read', { method: 'POST' }, false); updateNotificationBell(); }
        async function handleUpgrade() { if (!appState.stripe) { showToast('Stripe.js not initialized. Please refresh.', 'error'); return; } const result = await apiCall('/create-checkout-session', { method: 'POST', body: { price_id: SITE_CONFIG.STRIPE_STUDENT_PRO_PRICE_ID } }); if (result.success && result.session_id) { appState.stripe.redirectToCheckout({ sessionId: result.session_id }); } }
        async function handleManageBilling() { const result = await apiCall('/create-portal-session', { method: 'POST' }); if (result.success && result.url) { window.location.href = result.url; } }
        
        function handleAdminUserAction(action, userId) { if (action === 'delete') { showConfirmationModal('This will permanently delete the user and all their data.', async () => { const result = await apiCall(`/admin/users/${userId}`, { method: 'DELETE' }, false); if (result.success) { showToast('User deleted.', 'success'); switchAdminView('users'); } }); } else if (action === 'edit') { showToast('Edit user is not yet implemented.', 'info'); } }
        function handleAdminDeleteClass(classId) { showConfirmationModal('This will permanently delete the class and all its data.', async () => { const result = await apiCall(`/admin/classes/${classId}`, { method: 'DELETE' }, false); if (result.success) { showToast('Class deleted.', 'success'); switchAdminView('classes'); } }); }
        async function handleAdminUpdateSettings(e) { e.preventDefault(); const form = e.target; const body = Object.fromEntries(new FormData(form)); const result = await apiCall('/admin/update_settings', { method: 'POST', body }, false); if (result.success) { showToast('Settings updated.', 'success'); } }
        async function handleToggleMaintenance() { const result = await apiCall('/admin/toggle_maintenance', { method: 'POST' }, false); if (result.success) showToast(`Maintenance mode ${result.enabled ? 'enabled' : 'disabled'}.`, 'success'); }
        async function handleAddMusic() { const name = document.getElementById('music-name').value; const url = document.getElementById('music-url').value; if (!name || !url) return showToast('Please provide a name and URL.', 'error'); const result = await apiCall('/admin/music', { method: 'POST', body: { name, url } }, false); if (result.success) { showToast('Music added.', 'success'); switchAdminView('music'); } }
        function handleDeleteMusic(musicId) { showConfirmationModal('Are you sure you want to delete this music track?', async () => { const result = await apiCall(`/admin/music/${musicId}`, { method: 'DELETE' }, false); if (result.success) { showToast('Music deleted.', 'success'); switchAdminView('music'); } }); }
        
        async function handleCreateAssignment() {
            showModal(document.getElementById('template-create-assignment-modal').content.cloneNode(true), (modal) => {
                document.getElementById('create-assignment-form').addEventListener('submit', async (e) => {
                    e.preventDefault();
                    const form = e.target;
                    const button = form.querySelector('button[type="submit"]');
                    const body = Object.fromEntries(new FormData(form));
                    body.class_id = appState.selectedClass.id;
                    toggleButtonLoading(button, true, 'Create Assignment');
                    const result = await apiCall(`/classes/${appState.selectedClass.id}/assignments`, { method: 'POST', body });
                    toggleButtonLoading(button, false, 'Create Assignment');
                    if (result.success) {
                        showToast(`Assignment "${escapeHtml(result.assignment.title)}" created.`, 'success');
                        hideModal();
                        switchClassView('assignments');
                    } else {
                        showToast(result.error, 'error');
                    }
                });
            });
        }

        async function viewAssignmentDetails(assignmentId) {
            const result = await apiCall(`/assignments/${assignmentId}`, {}, false);
            if (!result.success) return;
            const assignment = result.assignment;
            
            const modalTemplate = document.getElementById('template-view-assignment-modal').content.cloneNode(true);
            
            modalTemplate.querySelector('#assignment-title-view').textContent = assignment.title;
            modalTemplate.querySelector('#assignment-description-view').textContent = assignment.description;
            modalTemplate.querySelector('#assignment-due-date-view').textContent = new Date(assignment.due_date).toLocaleDateString();
            
            const submissionsSection = modalTemplate.querySelector('#assignment-submissions-section');
            let submissionsListHtml = '';
            if (appState.currentUser.role === 'student') {
                if (assignment.submission) {
                    submissionsListHtml = `
                        <h4 class="text-xl font-semibold text-white mb-4">Your Submission</h4>
                        <div class="bg-gray-800/50 p-4 rounded-lg">
                            <p class="text-gray-400">${escapeHtml(assignment.submission.content)}</p>
                            <p class="mt-2 text-sm text-green-400">Submitted on: ${new Date(assignment.submission.submitted_at).toLocaleString()}</p>
                            ${assignment.submission.grade !== null ? `<p class="mt-2 text-sm text-cyan-400">Grade: ${assignment.submission.grade}%</p>` : ''}
                            ${assignment.submission.feedback ? `<p class="mt-2 text-sm text-gray-300">Feedback: ${escapeHtml(assignment.submission.feedback)}</p>` : ''}
                        </div>
                    `;
                } else {
                    submissionsListHtml = `
                        <h4 class="text-xl font-semibold text-white mb-4">Your Submission</h4>
                        <form id="submit-assignment-form">
                            <textarea id="submission-content" name="content" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" rows="5" placeholder="Type your submission here..." required></textarea>
                            <button type="submit" class="mt-4 brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Submit Assignment</button>
                        </form>
                    `;
                }
            } else if (appState.currentUser.role === 'teacher' || appState.currentUser.role === 'admin') {
                submissionsListHtml = `
                    <h4 class="text-xl font-semibold text-white mb-4">Submissions (${assignment.submissions.length})</h4>
                    <div id="submissions-list" class="space-y-4">
                        ${assignment.submissions.length > 0 ? assignment.submissions.map(s => `
                            <div class="bg-gray-800/50 p-4 rounded-lg">
                                <p class="font-bold text-white">${escapeHtml(s.student_name)}</p>
                                <p class="text-gray-400 text-sm mt-1">${escapeHtml(s.content)}</p>
                                <form class="grade-submission-form mt-4" data-submission-id="${s.id}">
                                    <input type="number" name="grade" placeholder="Grade (0-100)" class="w-28 p-2 bg-gray-700/50 rounded-lg border border-gray-600 inline-block" min="0" max="100" value="${s.grade || ''}">
                                    <textarea name="feedback" placeholder="Feedback" class="flex-grow p-2 bg-gray-700/50 rounded-lg border border-gray-600 inline-block w-full mt-2">${s.feedback || ''}</textarea>
                                    <button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg mt-2">Save</button>
                                </form>
                            </div>
                        `).join('') : '<p class="text-gray-400">No submissions yet.</p>'}
                    </div>
                `;
            }
            
            submissionsSection.innerHTML = submissionsListHtml;

            showModal(modalTemplate, (modal) => {
                modal.querySelector('#close-modal-btn').addEventListener('click', hideModal);
                const form = modal.querySelector('#submit-assignment-form');
                if (form) {
                    form.addEventListener('submit', async (e) => {
                        e.preventDefault();
                        const subContent = form.querySelector('#submission-content').value;
                        const submissionResult = await apiCall(`/assignments/${assignmentId}/submit`, { method: 'POST', body: { content: subContent } });
                        if (submissionResult.success) {
                            showToast('Assignment submitted successfully!', 'success');
                            hideModal();
                            switchClassView('assignments');
                        } else {
                            showToast(submissionResult.error, 'error');
                        }
                    });
                }
                modal.querySelectorAll('.grade-submission-form').forEach(form => {
                    form.addEventListener('submit', async (e) => {
                        e.preventDefault();
                        const submissionId = form.dataset.submissionId;
                        const grade = form.querySelector('input[name="grade"]').value;
                        const feedback = form.querySelector('textarea[name="feedback"]').value;
                        const saveBtn = form.querySelector('button');
                        toggleButtonLoading(saveBtn, true, 'Save');
                        const result = await apiCall(`/submissions/${submissionId}/grade`, { method: 'POST', body: { grade, feedback } }, false);
                        toggleButtonLoading(saveBtn, false, 'Save');
                        if (result.success) {
                            showToast('Grade and feedback saved.', 'success');
                        } else {
                            showToast(result.error, 'error');
                        }
                    });
                });
            });
        }
        
        async function handleCreateQuiz() {
            showModal(document.getElementById('template-create-quiz-modal').content.cloneNode(true), (modal) => {
                const questionContainer = document.getElementById('quiz-questions-container');
                const addQuestionBtn = document.getElementById('add-question-btn');

                const addQuestion = () => {
                    const template = document.getElementById('template-quiz-question-field').content.cloneNode(true);
                    const newQuestionDiv = template.querySelector('div');
                    newQuestionDiv.querySelector('.remove-question-btn').addEventListener('click', () => newQuestionDiv.remove());
                    questionContainer.appendChild(template);
                };

                addQuestionBtn.addEventListener('click', addQuestion);
                document.getElementById('create-quiz-form').addEventListener('submit', async (e) => {
                    e.preventDefault();
                    const form = e.target;
                    const button = form.querySelector('button[type="submit"]');
                    const formData = new FormData(form);
                    const questions = [];
                    const questionFields = questionContainer.querySelectorAll('.glassmorphism');

                    questionFields.forEach(field => {
                        const questionText = field.querySelector('input[name="question_text"]').value;
                        const correctAnswer = field.querySelector('input[name="correct_answer"]').value;
                        const incorrectAnswers = [
                            field.querySelector('input[name="incorrect_answer_1"]').value,
                            field.querySelector('input[name="incorrect_answer_2"]').value,
                            field.querySelector('input[name="incorrect_answer_3"]').value
                        ];
                        questions.push({ text: questionText, choices: { correct: correctAnswer, incorrect: incorrectAnswers } });
                    });

                    const body = {
                        title: formData.get('title'),
                        description: formData.get('description'),
                        time_limit: parseInt(formData.get('time_limit'), 10),
                        questions: questions
                    };

                    toggleButtonLoading(button, true, 'Create Quiz');
                    const result = await apiCall(`/classes/${appState.selectedClass.id}/quizzes`, { method: 'POST', body });
                    toggleButtonLoading(button, false, 'Create Quiz');
                    if (result.success) {
                        showToast(`Quiz "${escapeHtml(result.quiz.title)}" created.`, 'success');
                        hideModal();
                        switchClassView('quizzes');
                    } else {
                        showToast(result.error, 'error');
                    }
                });
                addQuestion();
            });
        }

        async function viewQuizDetails(quizId) {
            const result = await apiCall(`/quizzes/${quizId}`, {}, false);
            if (!result.success) return;
            const quiz = result.quiz;
            let modalContentHtml = `
                <div class="flex justify-between items-start">
                    <div>
                        <h3 class="text-2xl font-bold text-white mb-2">${escapeHtml(quiz.title)}</h3>
                        <p class="text-gray-300 mb-2">${escapeHtml(quiz.description)}</p>
                        <p class="text-sm text-gray-400">Time Limit: ${quiz.time_limit} minutes</p>
                    </div>
                    <button id="close-modal-btn" class="text-gray-400 hover:text-white text-2xl leading-none">&times;</button>
                </div>
            `;
            if (appState.currentUser.role === 'student') {
                if (quiz.attempt) {
                    modalContentHtml += `
                        <div class="mt-6">
                            <h4 class="text-xl font-semibold text-white mb-2">Your Attempt</h4>
                            <div class="bg-gray-800/50 p-4 rounded-lg">
                                <p class="text-lg text-green-400">Score: ${quiz.attempt.score.toFixed(2)}%</p>
                                <p class="text-sm text-gray-400">Completed on: ${new Date(quiz.attempt.end_time).toLocaleString()}</p>
                            </div>
                        </div>
                    `;
                } else {
                    modalContentHtml += `
                        <div class="mt-6 flex justify-center">
                            <button id="start-quiz-btn" class="brand-gradient-bg shiny-button text-white font-bold py-3 px-6 rounded-lg">Start Quiz</button>
                        </div>
                    `;
                }
            } else if (appState.currentUser.role === 'teacher' || appState.currentUser.role === 'admin') {
                modalContentHtml += `
                    <h4 class="text-xl font-semibold text-white mb-4 mt-6">Attempts (${quiz.attempts.length})</h4>
                    <ul class="space-y-2">
                        ${quiz.attempts.length > 0 ? quiz.attempts.map(a => `
                            <li class="p-3 bg-gray-800/50 rounded-lg flex justify-between items-center">
                                <div>
                                    <p class="font-bold">${escapeHtml(a.student_name)}</p>
                                    <p class="text-sm text-gray-400">Score: ${a.score.toFixed(2)}%</p>
                                </div>
                                <span class="text-xs text-gray-500">${new Date(a.end_time).toLocaleString()}</span>
                            </li>
                        `).join('') : '<p class="text-gray-400">No attempts yet.</p>'}
                    </ul>
                `;
            }

            showModal(modalContentHtml, (modal) => {
                modal.querySelector('#close-modal-btn').addEventListener('click', hideModal);
                const startBtn = modal.querySelector('#start-quiz-btn');
                if (startBtn) {
                    startBtn.addEventListener('click', () => {
                        showToast('Quiz starting! This feature is not yet fully implemented.', 'info');
                    });
                }
            });
        }
        
        function setupMobileNav() {
            const toggleBtn = document.getElementById('mobile-nav-toggle');
            const nav = document.getElementById('main-nav');
            const overlay = document.getElementById('content-overlay');

            if (toggleBtn && nav && overlay) {
                toggleBtn.addEventListener('click', () => {
                    nav.classList.toggle('open');
                    overlay.classList.toggle('active');
                });
                overlay.addEventListener('click', () => {
                    nav.classList.remove('open');
                    overlay.classList.remove('active');
                });
            }
        }
        
        function playBackgroundMusic(url) {
            if (DOMElements.backgroundMusic) {
                if (url) {
                    DOMElements.backgroundMusic.src = url;
                    DOMElements.backgroundMusic.play().catch(e => console.error("Music playback failed:", e));
                } else {
                    DOMElements.backgroundMusic.pause();
                    DOMElements.backgroundMusic.src = "";
                }
            }
        }

        main();
    });
    </script>
</body>
</html>
"""

# ==============================================================================
# --- 5. API ROUTES ---
# ==============================================================================
@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role = data.get('account_type', 'student')
    secret_key = data.get('secret_key')

    if not all([username, email, password]):
        return jsonify({"error": "Missing required fields."}), 400

    if User.query.filter(or_(User.username == username, User.email == email)).first():
        return jsonify({"error": "Username or email already exists."}), 409
    
    if role == 'teacher' and secret_key != SITE_CONFIG['SECRET_TEACHER_KEY']:
        return jsonify({"error": "Invalid secret teacher key."}), 403

    new_user = User(
        username=username,
        email=email,
        password_hash=generate_password_hash(password),
        role=role
    )
    db.session.add(new_user)
    db.session.commit()
    login_user(new_user)
    
    settings = {setting.key: setting.value for setting in SiteSettings.query.all()}
    settings['ai_personas'] = AI_PERSONAS

    return jsonify({"success": True, "user": new_user.to_dict(), "settings": settings})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    admin_secret_key = data.get('admin_secret_key')
    
    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password_hash, password):
        if user.role == 'admin' and admin_secret_key != SITE_CONFIG['ADMIN_SECRET_KEY']:
             return jsonify({"error": "Invalid admin secret key."}), 403
        
        login_user(user)
        settings = {setting.key: setting.value for setting in SiteSettings.query.all()}
        settings['ai_personas'] = AI_PERSONAS
        return jsonify({"success": True, "user": user.to_dict(), "settings": settings})

    return jsonify({"error": "Invalid username or password."}), 401

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({"success": True})

@app.route('/api/status')
def status():
    if current_user.is_authenticated:
        settings = {setting.key: setting.value for setting in SiteSettings.query.all()}
        settings['ai_personas'] = AI_PERSONAS
        return jsonify({"logged_in": True, "user": current_user.to_dict(), "settings": settings})
    return jsonify({"logged_in": False})

# ... (Add all other API routes here, such as classes, assignments, admin, etc.)

# ==============================================================================
# --- 6. MAIN EXECUTION ---
# ==============================================================================
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    return render_template_string(HTML_CONTENT)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash(SITE_CONFIG['ADMIN_DEFAULT_PASSWORD']),
                role='admin'
            )
            db.session.add(admin)
            db.session.commit()
            logging.info("Admin user created.")
    socketio.run(app, debug=True, host='0.0.0.0', port=5001)

