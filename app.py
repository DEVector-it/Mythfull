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
import google.generativeai as genai

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
        'https://mythsg.onrender.com'
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
    "GEMINI_API_KEYS": os.environ.get('GEMINI_API_KEYS', '').split(','),
    "SUPPORT_EMAIL": os.environ.get('MAIL_SENDER')
}

# --- AI Configuration ---
GEMINI_API_KEYS = [key for key in SITE_CONFIG['GEMINI_API_KEYS'] if key]
if GEMINI_API_KEYS:
    genai.configure(api_key=random.choice(GEMINI_API_KEYS))

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

user_achievement_association = db.Table('user_achievement_association',
    db.Column('user_id', db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True),
    db.Column('achievement_id', db.Integer, db.ForeignKey('achievement.id', ondelete='CASCADE'), primary_key=True)
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
    achievements = db.relationship('Achievement', secondary=user_achievement_association, back_populates='users', lazy='dynamic')

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
    leaderboard_entries = db.relationship('Leaderboard', back_populates='class_obj', lazy=True, cascade="all, delete-orphan")

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

class Achievement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=False)
    icon = db.Column(db.String(100), nullable=False) # e.g., 'star', 'check', 'award'
    users = db.relationship('User', secondary=user_achievement_association, back_populates='achievements', lazy='dynamic')

class Leaderboard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    class_id = db.Column(db.String(36), db.ForeignKey('class.id', ondelete='CASCADE'), nullable=False)
    student_id = db.Column(db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    score = db.Column(db.Integer, default=0, nullable=False)
    student = db.relationship('User')
    class_obj = db.relationship('Class', back_populates='leaderboard_entries')


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
            #main-nav.open { transform: translateX(0); }
            #content-overlay {
                display: none;
                position: fixed;
                top: 0; left: 0; right: 0; bottom: 0;
                background-color: rgba(0,0,0,0.5);
                z-index: 30;
            }
            #content-overlay.active { display: block; }
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
    <audio id="background-music" loop></audio>
    
    <template id="template-full-screen-loader">
        <div class="full-screen-loader fade-in">
            <div class="loader-dots"><div class="dot1"></div><div class="dot2"></div><div class="dot3"></div></div>
            <div class="waiting-text">Preparing your adventure...</div>
        </div>
    </template>

    <template id="template-role-choice">
        <div class="flex flex-col items-center justify-center h-full w-full p-4 fade-in welcome-bg">
            <div class="w-full max-w-md text-center">
                <h1 class="text-5xl font-bold brand-gradient-text mb-4">Myth AI</h1>
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
            <nav id="main-nav" class="w-64 bg-gray-900/70 backdrop-blur-sm p-6 flex flex-col gap-4 flex-shrink-0 border-r border-white/10 md:relative md:translate-x-0">
                <h2 class="text-2xl font-bold brand-gradient-text mb-6" id="dashboard-title">Portal</h2>
                <div id="nav-links" class="flex flex-col gap-2"></div>
                <div class="mt-auto flex flex-col gap-4">
                    <div id="adsense-container" class="w-full h-48 bg-gray-700/50 rounded-lg flex items-center justify-center text-gray-500 text-sm">Ad Placeholder</div>
                    <div id="notification-bell-container" class="relative"></div>
                    <button id="logout-btn" class="bg-red-600/50 hover:bg-red-600 border border-red-500 text-white font-bold py-2 px-4 rounded-lg transition-colors">Logout</button>
                </div>
            </nav>
            <div id="content-overlay"></div>
            <main class="flex-1 p-8 overflow-y-auto">
                <button id="mobile-nav-toggle" class="absolute top-6 left-6 z-50 text-white md:hidden">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16m-7 6h7"></path></svg>
                </button>
                <div id="dashboard-content" class="transition-opacity duration-300"></div>
            </main>
        </div>
    </template>
    
    <template id="template-auth-form"><div class="flex flex-col items-center justify-center h-full w-full p-4 fade-in welcome-bg"><div class="w-full max-w-md glassmorphism rounded-2xl p-8 shadow-2xl"><button id="back-to-roles" class="text-sm text-blue-400 hover:text-blue-300 mb-4">&larr; Back to Role Selection</button><h1 class="text-3xl font-bold text-center brand-gradient-text mb-2" id="auth-title">Portal Login</h1><p class="text-gray-400 text-center mb-6" id="auth-subtitle">Sign in to continue</p><form id="auth-form"><input type="hidden" id="account_type" name="account_type" value="student"><div id="email-field" class="hidden mb-4"><label for="email" class="block text-sm font-medium text-gray-300 mb-1">Email</label><input type="email" id="email" name="email" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500"></div><div class="mb-4"><label for="username" class="block text-sm font-medium text-gray-300 mb-1">Username</label><input type="text" id="username" name="username" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" required></div><div class="mb-4"><label for="password" class="block text-sm font-medium text-gray-300 mb-1">Password</label><input type="password" id="password" name="password" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" required></div><div id="teacher-key-field" class="hidden mb-4"><label for="teacher-secret-key" class="block text-sm font-medium text-gray-300 mb-1">Secret Teacher Key</label><input type="text" id="teacher-secret-key" name="secret_key" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="Required for teacher sign up"></div><div id="admin-key-field" class="hidden mb-4"><label for="admin-secret-key" class="block text-sm font-medium text-gray-300 mb-1">Secret Admin Key</label><input type="password" id="admin-secret-key" name="admin_secret_key" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="Required for admin login"></div><div class="flex justify-end mb-6"><button type="button" id="forgot-password-link" class="text-xs text-blue-400 hover:text-blue-300">Forgot Password?</button></div><button type="submit" id="auth-submit-btn" class="w-full brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg transition-opacity flex items-center justify-center h-12">Login</button><p id="auth-error" class="text-red-400 text-sm text-center h-4 mt-3"></p></form><div class="text-center mt-6"><button id="auth-toggle-btn" class="text-sm text-blue-400 hover:text-blue-300">Don't have an account? <span class="font-semibold">Sign Up</span></button></div></div></div></template>
    <template id="template-my-classes"><h3 class="text-3xl font-bold text-white mb-6">My Classes</h3><div id="class-action-container" class="mb-6"></div><div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6" id="classes-list"></div><div id="selected-class-view" class="mt-8 hidden"></div></template>
    <template id="template-student-class-action"><div class="glassmorphism p-4 rounded-lg"><h4 class="font-semibold text-lg mb-2 text-white">Join a New Class</h4><div class="flex items-center gap-2"><input type="text" id="class-code" placeholder="Enter class code" class="flex-grow p-3 bg-gray-700/50 rounded-lg border border-gray-600"><button id="join-class-btn" class="brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg flex items-center justify-center h-12 w-28">Join</button></div></div></template>
    <template id="template-teacher-class-action"><div class="glassmorphism p-4 rounded-lg"><h4 class="font-semibold text-lg mb-2 text-white">Create a New Class</h4><div class="flex items-center gap-2"><input type="text" id="new-class-name" name="name" placeholder="New class name" class="flex-grow p-3 bg-gray-700/50 rounded-lg border border-gray-600"><button id="create-class-btn" class="brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg flex items-center justify-center h-12 w-28">Create</button></div></div></template>
    <template id="template-selected-class-view"><div class="glassmorphism p-6 rounded-lg"><div class="flex justify-between items-start"><h4 class="text-2xl font-bold text-white mb-4">Class: <span id="selected-class-name"></span></h4><button id="back-to-classes-btn" class="text-sm text-blue-400 hover:text-blue-300">&larr; Back to All Classes</button></div><div class="flex border-b border-gray-600 mb-4 overflow-x-auto"><button class="py-2 px-4 text-gray-300 hover:text-white class-view-tab whitespace-nowrap" data-tab="chat">Chat</button><button class="py-2 px-4 text-gray-300 hover:text-white class-view-tab whitespace-nowrap" data-tab="assignments">Assignments</button><button class="py-2 px-4 text-gray-300 hover:text-white class-view-tab whitespace-nowrap" data-tab="quizzes">Quizzes</button><button class="py-2 px-4 text-gray-300 hover:text-white class-view-tab whitespace-nowrap" data-tab="students">Students</button><button class="py-2 px-4 text-gray-300 hover:text-white class-view-tab whitespace-nowrap" data-tab="leaderboard">Leaderboard</button></div><div id="class-view-content"></div></div></template>
    <template id="template-class-chat-view"><div id="chat-messages" class="bg-gray-900/50 p-4 rounded-lg h-96 overflow-y-auto mb-4 border border-gray-700 flex flex-col gap-4"></div><form id="chat-form" class="flex items-center gap-2"><input type="text" id="chat-input" placeholder="Ask the AI assistant for help..." class="flex-grow w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600"><button type="submit" id="send-chat-btn" class="brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg">Send</button></form></div></template>
    <template id="template-class-assignments-view"><div class="flex justify-between items-center mb-4"><h5 class="text-xl font-semibold text-white">Assignments</h5><div id="assignment-action-container"></div></div><div id="assignments-list" class="space-y-4"></div></template>
    <template id="template-class-leaderboard-view"><h5 class="text-xl font-semibold text-white mb-4">Leaderboard</h5><div id="leaderboard-list" class="space-y-2"></div></template>
    <template id="template-achievements"><h3 class="text-3xl font-bold text-white mb-6">My Achievements</h3><div id="achievements-list" class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4"></div></template>
    <template id="template-modal"><div class="modal-overlay fade-in"><div class="glassmorphism rounded-2xl p-8 shadow-2xl w-full max-w-2xl modal-content relative"><button class="absolute top-4 right-4 text-gray-400 hover:text-white text-2xl leading-none">&times;</button><div class="modal-body"></div></div></div></template>
    
    <script>
    document.addEventListener('DOMContentLoaded', () => {
        const BASE_URL = 'https://mythsg.onrender.com';
        const themes = {
            '': { name: 'User Default' },
            dark: { name: 'Dark', styles: { '--brand-hue': 220, '--bg-dark': '#0F172A', '--bg-med': '#1E293B', '--bg-light': '#334155', '--text-color': '#E2E8F0', '--text-secondary-color': '#94A3B8' } },
            light: { name: 'Light', styles: { '--brand-hue': 200, '--bg-dark': '#F1F5F9', '--bg-med': '#E2E8F0', '--bg-light': '#CBD5E1', '--text-color': '#1E293B', '--text-secondary-color': '#475569' } },
        };
        const appState = { currentUser: null, currentTab: 'my-classes', selectedClass: null, socket: null, isLoginView: true, selectedRole: null, aiPersonas: {} };
        const DOMElements = { appContainer: document.getElementById('app-container'), toastContainer: document.getElementById('toast-container'), modalContainer: document.getElementById('modal-container'), backgroundMusic: document.getElementById('background-music') };
        
        document.getElementById('current-year').textContent = new Date().getFullYear();

        function applyTheme(themeName) { const theme = themes[themeName]; if (theme && theme.styles) { Object.entries(theme.styles).forEach(([key, value]) => document.documentElement.style.setProperty(key, value)); } }
        function showToast(message, type = 'info') { const colors = { info: 'bg-blue-600', success: 'bg-green-600', error: 'bg-red-600' }; const toast = document.createElement('div'); toast.className = `text-white text-sm py-2 px-4 rounded-lg shadow-lg fade-in ${colors[type]}`; toast.textContent = message; DOMElements.toastContainer.appendChild(toast); setTimeout(() => { toast.style.opacity = '0'; setTimeout(() => toast.remove(), 500); }, 3500); }
        function escapeHtml(text) { if (typeof text !== 'string') return ''; const map = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'}; return text.replace(/[&<>"']/g, m => map[m]); }
        function toggleButtonLoading(button, isLoading, originalContent = null) { if (!button) return; if (isLoading) { button.dataset.originalContent = button.innerHTML; button.innerHTML = '<div class="btn-loader mx-auto"></div>'; button.disabled = true; } else { button.innerHTML = originalContent || button.dataset.originalContent || 'Submit'; button.disabled = false; } }
        async function apiCall(endpoint, options = {}, showLoader = true) {
            let loader;
            if (showLoader) loader = showFullScreenLoader('Processing...');
            try {
                const csrfToken = document.cookie.split('; ').find(row => row.startsWith('csrf_token='))?.split('=')[1];
                options.headers = options.headers || {};
                if (options.method && options.method.toLowerCase() !== 'get' && csrfToken) options.headers['X-CSRFToken'] = csrfToken;
                if (options.body && typeof options.body === 'object') { options.headers['Content-Type'] = 'application/json'; options.body = JSON.stringify(options.body); }
                const response = await fetch(`${BASE_URL}/api${endpoint}`, { credentials: 'include', ...options });
                const data = await response.json();
                if (!response.ok) {
                    if (response.status === 401 && endpoint !== '/status') handleLogout(false);
                    throw new Error(data.error || `Request failed with status ${response.status}`);
                }
                return { success: true, ...data };
            } catch (error) { showToast(error.message, 'error'); console.error("API Call Error:", error); return { success: false, error: error.message }; }
            finally { if (loader) loader.remove(); }
        }
        function renderPage(templateId, setupFunction) { const template = document.getElementById(templateId); if (!template) return; const content = template.content.cloneNode(true); DOMElements.appContainer.innerHTML = ''; DOMElements.appContainer.appendChild(content); if (setupFunction) setupFunction(); }
        function renderSubTemplate(container, templateId, setupFunction) { const template = document.getElementById(templateId); if (!template) return; const content = template.content.cloneNode(true); container.innerHTML = ''; container.appendChild(content); if (setupFunction) setupFunction(); }
        function showModal(content, setupFunction) { const template = document.getElementById('template-modal').content.cloneNode(true); const modalBody = template.querySelector('.modal-body'); modalBody.innerHTML = content; template.querySelector('button').addEventListener('click', hideModal); DOMElements.modalContainer.innerHTML = ''; DOMElements.modalContainer.appendChild(template); if(setupFunction) setupFunction(); }
        function hideModal() { DOMElements.modalContainer.innerHTML = ''; }
        function showFullScreenLoader(message = 'Loading...') { const loader = document.getElementById('template-full-screen-loader').content.cloneNode(true); loader.querySelector('.waiting-text').textContent = message; DOMElements.appContainer.appendChild(loader); return DOMElements.appContainer.querySelector('.full-screen-loader'); }
        function connectSocket() { if (appState.socket) appState.socket.disconnect(); appState.socket = io(BASE_URL); appState.socket.on('connect', () => { if(appState.currentUser) appState.socket.emit('join', { room: `user_${appState.currentUser.id}` }); }); appState.socket.on('new_message', (data) => { if (appState.selectedClass && data.class_id === appState.selectedClass.id) appendChatMessage(data); }); appState.socket.on('leaderboard_update', (data) => { if(appState.selectedClass && data.class_id === appState.selectedClass.id && appState.currentTab === 'leaderboard') { setupLeaderboardTab(document.getElementById('class-view-content')); } });}
        
        function setupRoleChoicePage() { renderPage('template-role-choice', () => { document.querySelectorAll('.role-btn').forEach(btn => btn.addEventListener('click', (e) => { appState.selectedRole = e.currentTarget.dataset.role; setupAuthPage(); })); }); }
        function setupAuthPage() { renderPage('template-auth-form', () => { updateAuthView(); document.getElementById('auth-form').addEventListener('submit', handleAuthSubmit); document.getElementById('auth-toggle-btn').addEventListener('click', () => { appState.isLoginView = !appState.isLoginView; updateAuthView(); }); document.getElementById('back-to-roles').addEventListener('click', setupRoleChoicePage); }); }
        function updateAuthView() { const title = document.getElementById('auth-title'); const subtitle = document.getElementById('auth-subtitle'); const submitBtn = document.getElementById('auth-submit-btn'); const toggleBtn = document.getElementById('auth-toggle-btn'); const emailField = document.getElementById('email-field'); const teacherKeyField = document.getElementById('teacher-key-field'); const adminKeyField = document.getElementById('admin-key-field'); document.getElementById('account_type').value = appState.selectedRole; title.textContent = `${appState.selectedRole.charAt(0).toUpperCase() + appState.selectedRole.slice(1)} Portal`; adminKeyField.classList.add('hidden'); teacherKeyField.classList.add('hidden'); if (appState.selectedRole === 'admin') { appState.isLoginView = true; toggleBtn.classList.add('hidden'); adminKeyField.classList.remove('hidden'); } else { toggleBtn.classList.remove('hidden'); } if (appState.isLoginView) { subtitle.textContent = 'Sign in to continue'; submitBtn.textContent = 'Login'; toggleBtn.innerHTML = "Don't have an account? <span class='font-semibold'>Sign Up</span>"; emailField.classList.add('hidden'); } else { subtitle.textContent = 'Create your Account'; submitBtn.textContent = 'Sign Up'; toggleBtn.innerHTML = "Already have an account? <span class='font-semibold'>Login</span>"; emailField.classList.remove('hidden'); if (appState.selectedRole === 'teacher') teacherKeyField.classList.remove('hidden'); } }
        async function handleAuthSubmit(e) { e.preventDefault(); const form = e.target; const button = form.querySelector('button[type="submit"]'); toggleButtonLoading(button, true); const endpoint = appState.isLoginView ? '/login' : '/signup'; const body = Object.fromEntries(new FormData(form)); const result = await apiCall(endpoint, { method: 'POST', body }); if (result.success) handleLoginSuccess(result.user, result.settings); else { document.getElementById('auth-error').textContent = result.error; toggleButtonLoading(button, false, appState.isLoginView ? 'Login' : 'Sign Up'); } }
        function handleLoginSuccess(user, settings) { appState.currentUser = user; appState.aiPersonas = settings.ai_personas || {}; if (settings.global_theme) applyTheme(settings.global_theme); else if (user.theme_preference) applyTheme(user.theme_preference); playBackgroundMusic(settings.global_music_url || null); showFullScreenLoader('Logging you in...'); setupDashboard(); }
        function setupDashboard() { 
            connectSocket();
            renderPage('template-main-dashboard', () => { 
                const navLinks = document.getElementById('nav-links'); 
                const dashboardTitle = document.getElementById('dashboard-title'); 
                const user = appState.currentUser;
                let tabs = []; 
                if (user.role === 'student' || user.role === 'teacher') { 
                    dashboardTitle.textContent = user.role === 'student' ? "Student Hub" : "Teacher Hub"; 
                    appState.currentTab = 'my-classes'; 
                    tabs = [ { id: 'my-classes', label: 'My Classes' }, { id: 'achievements', label: 'Achievements' }, { id: 'ai-settings', label: 'AI Settings' }, { id: 'profile', label: 'Profile' } ]; 
                } else if (user.role === 'admin') { 
                    dashboardTitle.textContent = "Admin Panel"; 
                    appState.currentTab = 'admin-dashboard'; 
                    tabs = [ { id: 'admin-dashboard', label: 'Dashboard' }, { id: 'profile', label: 'My Profile' } ]; 
                } 
                navLinks.innerHTML = tabs.map(tab => `<button data-tab="${tab.id}" class="dashboard-tab text-left text-gray-300 hover:bg-gray-700/50 p-3 rounded-md transition-colors">${tab.label}</button>`).join(''); 
                document.querySelectorAll('.dashboard-tab').forEach(tab => tab.addEventListener('click', () => switchTab(tab.dataset.tab))); 
                document.getElementById('logout-btn').addEventListener('click', () => handleLogout(true)); 
                setupMobileNav();
                switchTab(appState.currentTab);
            }); 
        }
        function switchTab(tab) { appState.currentTab = tab; appState.selectedClass = null; document.querySelectorAll('.dashboard-tab').forEach(t => t.classList.toggle('active-tab', t.dataset.tab === tab)); const contentContainer = document.getElementById('dashboard-content'); const setups = { 'my-classes': setupMyClassesTab, 'achievements': setupAchievementsTab, 'admin-dashboard': setupAdminDashboardTab }; contentContainer.classList.add('opacity-0'); setTimeout(() => { if (setups[tab]) setups[tab](contentContainer); contentContainer.classList.remove('opacity-0'); }, 150); }
        async function setupMyClassesTab(container) { renderSubTemplate(container, 'template-my-classes', async () => { const actionContainer = document.getElementById('class-action-container'); const listContainer = document.getElementById('classes-list'); renderSubTemplate(actionContainer, `template-${appState.currentUser.role}-class-action`, () => { if (appState.currentUser.role === 'student') document.getElementById('join-class-btn').addEventListener('click', handleJoinClass); else document.getElementById('create-class-btn').addEventListener('click', handleCreateClass); }); listContainer.addEventListener('click', (e) => { const classCard = e.target.closest('div[data-id]'); if (classCard) selectClass(classCard.dataset.id); }); const result = await apiCall('/my_classes', {}, false); if (result.success) listContainer.innerHTML = result.classes.length === 0 ? `<p class="text-gray-400 text-center col-span-full">No classes yet.</p>` : result.classes.map(c => `<div class="glassmorphism p-4 rounded-lg cursor-pointer hover:bg-gray-700/50" data-id="${c.id}"><div class="font-bold text-white">${escapeHtml(c.name)}</div><div class="text-sm text-gray-400">Code: <span class="font-mono text-cyan-400">${escapeHtml(c.code)}</span></div></div>`).join(''); }); }
        async function handleJoinClass() { const codeInput = document.getElementById('class-code'); const button = document.getElementById('join-class-btn'); const code = codeInput.value.trim().toUpperCase(); if (!code) return; toggleButtonLoading(button, true); const result = await apiCall('/join_class', { method: 'POST', body: { code } }, false); if (result.success) { showToast(result.message, 'success'); setupMyClassesTab(document.getElementById('dashboard-content')); } toggleButtonLoading(button, false, 'Join'); }
        async function handleCreateClass() { const nameInput = document.getElementById('new-class-name'); const button = document.getElementById('create-class-btn'); const name = nameInput.value.trim(); if (!name) return; toggleButtonLoading(button, true); const result = await apiCall('/classes', { method: 'POST', body: { name } }, false); if (result.success) { showToast(`Class created!`, 'success'); setupMyClassesTab(document.getElementById('dashboard-content')); } toggleButtonLoading(button, false, 'Create'); }
        async function selectClass(classId) { if (appState.selectedClass && appState.socket) appState.socket.emit('leave', { room: `class_${appState.selectedClass.id}` }); const result = await apiCall(`/classes/${classId}`, {}, false); if(!result.success) return; appState.selectedClass = result.class; appState.socket.emit('join', { room: `class_${classId}` }); document.getElementById('classes-list').classList.add('hidden'); document.getElementById('class-action-container').classList.add('hidden'); const viewContainer = document.getElementById('selected-class-view'); viewContainer.classList.remove('hidden'); renderSubTemplate(viewContainer, 'template-selected-class-view', () => { document.getElementById('selected-class-name').textContent = escapeHtml(appState.selectedClass.name); document.getElementById('back-to-classes-btn').addEventListener('click', () => { viewContainer.classList.add('hidden'); document.getElementById('classes-list').classList.remove('hidden'); document.getElementById('class-action-container').classList.remove('hidden'); }); document.querySelectorAll('.class-view-tab').forEach(tab => tab.addEventListener('click', (e) => switchClassView(e.currentTarget.dataset.tab))); switchClassView('chat'); }); }
        async function switchClassView(view) { document.querySelectorAll('.class-view-tab').forEach(t => t.classList.toggle('active-tab', t.dataset.tab === view)); const container = document.getElementById('class-view-content'); const classId = appState.selectedClass.id; if (view === 'chat') { renderSubTemplate(container, 'template-class-chat-view', async () => { document.getElementById('chat-form').addEventListener('submit', handleSendChat); const result = await apiCall(`/class_messages/${classId}`, {}, false); if (result.success) { const messagesDiv = document.getElementById('chat-messages'); result.messages.forEach(m => appendChatMessage(m)); } }); } else if (view === 'assignments') { renderSubTemplate(container, 'template-class-assignments-view', async () => { if(appState.currentUser.role === 'teacher') { document.getElementById('assignment-action-container').innerHTML = `<button id="create-assignment-btn" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">New Assignment</button>`; document.getElementById('create-assignment-btn').addEventListener('click', handleCreateAssignment); } const result = await apiCall(`/classes/${classId}/assignments`, {}, false); if(result.success) { document.getElementById('assignments-list').innerHTML = result.assignments.map(a => `<div class="p-4 bg-gray-800/50 rounded-lg"><h6 class="font-bold text-white">${escapeHtml(a.title)}</h6><span class="text-sm text-gray-400">Due: ${new Date(a.due_date).toLocaleDateString()}</span></div>`).join(''); } }); } else if (view === 'leaderboard') { setupLeaderboardTab(container); } }
        async function handleSendChat(e) { e.preventDefault(); const input = document.getElementById('chat-input'); const message = input.value.trim(); if (!message) return; input.value = ''; await apiCall('/chat/send', { method: 'POST', body: { prompt: message, class_id: appState.selectedClass.id } }, false); }
        function appendChatMessage(message) { const messagesDiv = document.getElementById('chat-messages'); if (!messagesDiv) return; const isCurrentUser = message.sender_id === appState.currentUser.id; const bubble = `<div class="chat-bubble p-3 rounded-lg border max-w-md text-white">${escapeHtml(message.content)}</div>`; messagesDiv.insertAdjacentHTML('beforeend', `<div class="flex items-start gap-3 ${isCurrentUser ? 'justify-end' : 'justify-start'}">${bubble}</div>`); messagesDiv.scrollTop = messagesDiv.scrollHeight; }
        async function setupLeaderboardTab(container) { renderSubTemplate(container, 'template-class-leaderboard-view', async () => { const result = await apiCall(`/classes/${appState.selectedClass.id}/leaderboard`, {}, false); if(result.success) { document.getElementById('leaderboard-list').innerHTML = result.leaderboard.map((entry, index) => `<div class="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg"><div><span class="font-bold text-lg mr-4">${index + 1}.</span><span>${escapeHtml(entry.student_name)}</span></div><span class="font-semibold text-cyan-400">${entry.score} pts</span></div>`).join(''); } }); }
        async function setupAchievementsTab(container) { renderSubTemplate(container, 'template-achievements', async () => { const result = await apiCall('/achievements', {}, false); if(result.success) { document.getElementById('achievements-list').innerHTML = result.achievements.map(ach => `<div class="glassmorphism p-4 rounded-lg text-center"><div class="text-4xl mb-2">${ach.icon}</div><h4 class="font-bold text-white">${escapeHtml(ach.name)}</h4><p class="text-sm text-gray-400">${escapeHtml(ach.description)}</p></div>`).join(''); } }); }
        async function handleLogout(doApiCall) { if (doApiCall) await apiCall('/logout', { method: 'POST' }); if (appState.socket) appState.socket.disconnect(); window.location.reload(); }
        function setupMobileNav() { const toggleBtn = document.getElementById('mobile-nav-toggle'); const nav = document.getElementById('main-nav'); const overlay = document.getElementById('content-overlay'); if (toggleBtn && nav && overlay) { toggleBtn.addEventListener('click', () => { nav.classList.toggle('open'); overlay.classList.toggle('active'); }); overlay.addEventListener('click', () => { nav.classList.remove('open'); overlay.classList.remove('active'); }); } }
        function playBackgroundMusic(url) { if (DOMElements.backgroundMusic) { DOMElements.backgroundMusic.src = url || ''; if(url) DOMElements.backgroundMusic.play().catch(console.error); else DOMElements.backgroundMusic.pause(); } }
        async function main() { const status = await apiCall('/status'); if (status.success && status.user) handleLoginSuccess(status.user, status.settings); else setupRoleChoicePage(); }
        main();
    });
    </script>
</body>
</html>
"""

# ==============================================================================
# --- 5. API ROUTES ---
# ==============================================================================
def get_user_settings():
    settings = {s.key: s.value for s in SiteSettings.query.all()}
    settings['ai_personas'] = AI_PERSONAS
    return settings

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username, email, password = data.get('username'), data.get('email'), data.get('password')
    role, secret_key = data.get('account_type', 'student'), data.get('secret_key')
    if not all([username, email, password]): return jsonify({"error": "Missing fields."}), 400
    if User.query.filter(or_(User.username == username, User.email == email)).first(): return jsonify({"error": "User already exists."}), 409
    if role == 'teacher' and secret_key != SITE_CONFIG['SECRET_TEACHER_KEY']: return jsonify({"error": "Invalid teacher key."}), 403
    new_user = User(username=username, email=email, password_hash=generate_password_hash(password), role=role)
    db.session.add(new_user)
    db.session.commit()
    login_user(new_user)
    return jsonify({"success": True, "user": new_user.to_dict(), "settings": get_user_settings()})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data.get('username')).first()
    if user and check_password_hash(user.password_hash, data.get('password')):
        if user.role == 'admin' and data.get('admin_secret_key') != SITE_CONFIG['ADMIN_SECRET_KEY']: return jsonify({"error": "Invalid admin key."}), 403
        login_user(user)
        return jsonify({"success": True, "user": user.to_dict(), "settings": get_user_settings()})
    return jsonify({"error": "Invalid credentials."}), 401

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({"success": True})

@app.route('/api/status')
def status():
    settings = get_user_settings()
    if current_user.is_authenticated:
        return jsonify({"logged_in": True, "user": current_user.to_dict(), "settings": settings})
    return jsonify({"logged_in": False, "settings": settings})

@app.route('/api/my_classes', methods=['GET'])
@login_required
def my_classes():
    classes = current_user.taught_classes if current_user.role == 'teacher' else current_user.enrolled_classes.all()
    return jsonify({"success": True, "classes": [{"id": c.id, "name": c.name, "code": c.code, "teacher_name": c.teacher.username} for c in classes]})

@app.route('/api/classes', methods=['POST'])
@teacher_required
def create_class():
    name = request.json.get('name')
    if not name: return jsonify({"error": "Class name required."}), 400
    new_class = Class(name=name, teacher_id=current_user.id, code=''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789') for _ in range(6)))
    db.session.add(new_class)
    db.session.commit()
    return jsonify({"success": True, "class": {"id": new_class.id, "name": new_class.name, "code": new_class.code, "teacher_name": current_user.username}}), 201

@app.route('/api/join_class', methods=['POST'])
@login_required
def join_class():
    code = request.json.get('code')
    target_class = Class.query.filter_by(code=code).first()
    if not target_class: return jsonify({"error": "Invalid class code."}), 404
    if target_class in current_user.enrolled_classes: return jsonify({"error": "Already in this class."}), 409
    current_user.enrolled_classes.append(target_class)
    db.session.commit()
    return jsonify({"success": True, "message": f"Joined {target_class.name}."})

@app.route('/api/classes/<string:class_id>')
@login_required
def get_class(class_id):
    target_class = Class.query.get_or_404(class_id)
    if not (target_class.teacher_id == current_user.id or target_class in current_user.enrolled_classes or current_user.role == 'admin'):
        return jsonify({"error": "Not authorized."}), 403
    return jsonify({"success": True, "class": {"id": target_class.id, "name": target_class.name, "students": [s.to_dict() for s in target_class.students]}})

@app.route('/api/classes/<string:class_id>/assignments', methods=['GET'])
@login_required
def get_assignments(class_id):
    assignments = Assignment.query.filter_by(class_id=class_id).order_by(Assignment.due_date.desc()).all()
    return jsonify({"success": True, "assignments": [{"id": a.id, "title": a.title, "due_date": a.due_date.isoformat()} for a in assignments]})

@app.route('/api/class_messages/<string:class_id>')
@login_required
def get_class_messages(class_id):
    messages = ChatMessage.query.filter_by(class_id=class_id).order_by(ChatMessage.timestamp.asc()).all()
    return jsonify({"success": True, "messages": [{"sender_id": m.sender_id, "content": m.content} for m in messages]})

@app.route('/api/chat/send', methods=['POST'])
@login_required
def send_chat_message():
    data = request.get_json()
    prompt = data['prompt']
    class_id = data['class_id']
    
    user_message = ChatMessage(class_id=class_id, sender_id=current_user.id, content=prompt)
    db.session.add(user_message)
    db.session.commit()
    socketio.emit('new_message', {"sender_id": current_user.id, "content": prompt, "class_id": class_id}, room=f"class_{class_id}")

    if GEMINI_API_KEYS:
        try:
            model = genai.GenerativeModel('gemini-pro')
            response = model.generate_content(prompt)
            ai_response_content = response.text
        except Exception as e:
            ai_response_content = f"Error communicating with AI: {e}"
    else:
        ai_response_content = "AI is not configured."

    ai_message = ChatMessage(class_id=class_id, sender_id=None, content=ai_response_content)
    db.session.add(ai_message)
    db.session.commit()
    socketio.emit('new_message', {"sender_id": None, "content": ai_response_content, "class_id": class
