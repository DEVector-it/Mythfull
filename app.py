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
from sqlalchemy.engine import Engine
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

# ==============================================================================
# --- 1. INITIAL CONFIGURATION & SETUP ---
# ==============================================================================
load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

# Allow all origins for CORS
CORS(app, supports_credentials=True, origins="*")
Talisman(app, content_security_policy=None) # Add Talisman for security headers

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-fallback-secret-key-for-development')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get('SECURITY_PASSWORD_SALT', 'a-fallback-salt')

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

stripe.api_key = SITE_CONFIG.get("STRIPE_SECRET_KEY")
password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*") # Allow all origins for SocketIO
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_SENDER')
mail = Mail(app)

# Add this teardown function to ensure the session is always cleaned up.
@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

# ==============================================================================
# --- 2. DATABASE MODELS ---
# ==============================================================================
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite'):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

student_class_association = db.Table('student_class_association',
    db.Column('user_id', db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True),
    db.Column('class_id', db.String(36), db.ForeignKey('class.id', ondelete='CASCADE'), primary_key=True)
)

team_member_association = db.Table('team_member_association',
    db.Column('user_id', db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True),
    db.Column('team_id', db.String(36), db.ForeignKey('team.id', ondelete='CASCADE'), primary_key=True)
)

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
    
    # Relationships
    profile = db.relationship('Profile', back_populates='user', uselist=False, cascade="all, delete-orphan")
    taught_classes = db.relationship('Class', back_populates='teacher', lazy=True, foreign_keys='Class.teacher_id', cascade="all, delete-orphan")
    enrolled_classes = db.relationship('Class', secondary=student_class_association, back_populates='students', lazy='dynamic')
    teams = db.relationship('Team', secondary=team_member_association, back_populates='members', lazy='dynamic')
    submissions = db.relationship('Submission', back_populates='student', lazy=True, cascade="all, delete-orphan")
    quiz_attempts = db.relationship('QuizAttempt', back_populates='student', lazy=True, cascade="all, delete-orphan")
    notifications = db.relationship('Notification', back_populates='user', lazy=True, cascade="all, delete-orphan")
    def __repr__(self):
        return f'<User {self.username}>'

    def to_dict(self):
        profile_data = {
            'bio': '',
            'avatar': ''
        }
        if self.profile:
            profile_data['bio'] = self.profile.bio or ''
            profile_data['avatar'] = self.profile.avatar or ''

        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'created_at': self.created_at.isoformat(),
            'has_subscription': self.has_subscription,
            'profile': profile_data,
            'ai_persona': self.ai_persona,
            'theme_preference': self.theme_preference
        }

class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    bio = db.Column(db.Text, nullable=True)
    avatar = db.Column(db.String(500), nullable=True)
    user = db.relationship('User', back_populates='profile')
    def __repr__(self):
        return f'<Profile {self.user_id}>'

class Team(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(8), unique=True, nullable=False, index=True)
    owner_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False, index=True)
    owner = db.relationship('User', foreign_keys=[owner_id])
    members = db.relationship('User', secondary=team_member_association, back_populates='teams', lazy='dynamic')
    def __repr__(self):
        return f'<Team {self.name}>'

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
    def __repr__(self):
        return f'<Class {self.name}>'

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    class_id = db.Column(db.String(36), db.ForeignKey('class.id', ondelete='CASCADE'), nullable=False)
    sender_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=True) # Null for AI
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    class_obj = db.relationship('Class', back_populates='messages')
    sender = db.relationship('User')
    def __repr__(self):
        return f'<Message from {self.sender_id}>'

class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    class_id = db.Column(db.String(36), db.ForeignKey('class.id', ondelete='CASCADE'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    due_date = db.Column(db.DateTime, nullable=False)
    class_obj = db.relationship('Class', back_populates='assignments')
    submissions = db.relationship('Submission', back_populates='assignment', lazy='dynamic', cascade="all, delete-orphan")
    def __repr__(self):
        return f'<Assignment {self.title}>'

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
    def __repr__(self):
        return f'<Submission {self.id}>'

class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    class_id = db.Column(db.String(36), db.ForeignKey('class.id', ondelete='CASCADE'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    time_limit = db.Column(db.Integer, nullable=False) # In minutes
    class_obj = db.relationship('Class', back_populates='quizzes')
    questions = db.relationship('Question', back_populates='quiz', lazy=True, cascade="all, delete-orphan")
    attempts = db.relationship('QuizAttempt', back_populates='quiz', lazy='dynamic', cascade="all, delete-orphan")
    def __repr__(self):
        return f'<Quiz {self.title}>'

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id', ondelete='CASCADE'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    question_type = db.Column(db.String(50), nullable=False, default='multiple_choice')
    quiz = db.relationship('Quiz', back_populates='questions')
    choices = db.Column(db.JSON, nullable=False) # Store choices as JSON array of objects e.g. [{"id": "...", "text": "...", "is_correct": true/false}]
    def __repr__(self):
        return f'<Question {self.id}>'

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
    def __repr__(self):
        return f'<QuizAttempt {self.id}>'

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', back_populates='notifications')
    def __repr__(self):
        return f'<Notification {self.id}>'

class SiteSettings(db.Model):
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.String(500))
    def __repr__(self):
        return f'<SiteSettings {self.key}>'

# ==============================================================================
# --- 3. USER & SESSION MANAGEMENT ---
# ==============================================================================
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.unauthorized_handler
def unauthorized():
    return jsonify({"error": "Login required.", "logged_in": False}), 401

@login_manager.user_loader
def load_user(user_id): return User.query.get(user_id)

def role_required(role_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated: return jsonify({"error": "Login required."}), 401
            if current_user.role != role_name and current_user.role != 'admin': return jsonify({"error": f"{role_name.capitalize()} access required."}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

admin_required = role_required('admin')
teacher_required = role_required('teacher')

# ==============================================================================
# --- 4. FRONTEND CONTENT ---
# ==============================================================================
HTML_CONTENT = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="google-site-verification" content="YOUR_GOOGLE_VERIFICATION_CODE" />
    <title>Myth AI Portal</title>
    <script src="https://cdn.tailwindcss.com"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script><script src="https://js.stripe.com/v3/"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --brand-hue: 220;
            --bg-dark: #0F172A;
            --bg-med: #1E293B;
            --bg-light: #334155;
            --glow-color: hsl(var(--brand-hue), 100%, 70%);
            --text-color: #E2E8F0;
            --text-secondary-color: #94A3B8;
        }
        body { background-color: var(--bg-dark); font-family: 'Inter', sans-serif; color: var(--text-color); }
        .theme-light {
            --bg-dark: #F1F5F9;
            --bg-med: #E2E8F0;
            --bg-light: #CBD5E1;
            --glow-color: hsl(200, 90%, 50%);
            --text-color: #1E293B;
            --text-secondary-color: #475569;
        }
        .glassmorphism { background: rgba(31, 41, 55, 0.5); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.1); }
        .brand-gradient-text { background-image: linear-gradient(120deg, hsl(var(--brand-hue), 90%, 60%), hsl(260, 90%, 65%)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .brand-gradient-bg { background-image: linear-gradient(120deg, hsl(var(--brand-hue), 90%, 55%), hsl(260, 90%, 60%)); }
        .shiny-button { transition: all 0.3s ease; box-shadow: 0 0 5px rgba(0,0,0,0.5), 0 0 10px var(--glow-color, #fff) inset; }
        .shiny-button:hover { transform: translateY(-2px); box-shadow: 0 4px 15px hsla(var(--brand-hue), 80%, 50%, 0.4), 0 0 5px var(--glow-color, #fff) inset; }
        .fade-in { animation: fadeIn 0.5s ease-out forwards; } @keyframes fadeIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
        .active-tab { background-color: var(--bg-light) !important; color: white !important; position:relative; }
        .active-tab::after { content: ''; position: absolute; bottom: 0; left: 10%; width: 80%; height: 2px; background: var(--glow-color); border-radius: 2px; }
        .modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); display: flex; align-items: center; justify-content: center; z-index: 1000; }
        .modal-content { max-height: 90vh; overflow-y: auto; } .loader { border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .ai-message .chat-bubble { background-color: #2E1A47; border-color: #8B5CF6; }
        .user-message .chat-bubble { background-color: #1E40AF; border-color: #3B82F6; }
        .full-screen-loader {
            position: fixed; top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0,0,0,0.8);
            display: flex; align-items: center; justify-content: center;
            flex-direction: column;
            z-index: 1001;
            transition: opacity 0.3s ease;
        }
        .full-screen-loader .waiting-text { margin-top: 1rem; font-size: 1.5rem; animation: pulse 1.5s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
    </style>
</head>
<body class="text-gray-200 antialiased">
    <div id="app-container" class="relative h-screen w-screen overflow-hidden flex flex-col"></div>
    <div id="toast-container" class="fixed top-6 right-6 z-[100] flex flex-col gap-2"></div>
    <div id="modal-container"></div>
    <div class="fixed bottom-4 left-4 text-xs text-gray-500">
        &copy; <span id="current-year"></span> Made by DeVector and Hossein
    </div>
    <template id="template-welcome-anime">
        <div class="flex flex-col items-center justify-center h-full w-full bg-cover bg-center p-4 fade-in" style="background-image: url('https://placehold.co/1920x1080/0F172A/FFFFFF?text=Anime+Background');">
            <div class="glassmorphism p-8 rounded-xl text-center">
                <img src="https://placehold.co/150x150/FFFFFF/000000?text=Myth+AI" alt="Myth AI Logo" class="mx-auto mb-4 rounded-full shadow-lg">
                <h1 class="text-4xl font-bold text-white mb-4">Welcome to Myth AI!</h1>
                <p class="text-gray-300 mb-6">Your journey into AI-powered learning begins now.</p>
                <button id="get-started-btn" class="brand-gradient-bg shiny-button text-white font-bold py-3 px-6 rounded-lg">Get Started</button>
            </div>
        </div>
        <audio id="welcome-audio" src="https://www.soundhelix.com/examples/mp3/SoundHelix-Song-1.mp3" preload="auto"></audio>
    </template>
    
    <template id="template-full-screen-loader">
        <div class="full-screen-loader fade-in">
            <div class="loader"></div>
            <div class="waiting-text">Preparing your adventure...</div>
        </div>
    </template>

    <template id="template-maintenance">
        <div class="flex flex-col items-center justify-center h-full w-full bg-gray-900 p-4 text-center">
            <svg class="w-16 h-16 text-yellow-400 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
            <h1 class="text-4xl font-bold text-white mb-2">Under Maintenance</h1>
            <p class="text-gray-400 mb-8">We're currently performing scheduled maintenance. Please check back soon.</p>
            <button id="admin-login-btn" class="text-blue-400 hover:text-blue-300">Admin Login</button>
        </div>
    </template>

    <template id="template-role-choice">
        <div class="flex flex-col items-center justify-center h-full w-full bg-gray-900 p-4 fade-in" style="background-image: radial-gradient(circle at top right, hsla(var(--brand-hue), 40%, 20%, 0.5), transparent 50%), radial-gradient(circle at bottom left, hsla(260, 40%, 20%, 0.5), transparent 50%);">
            <div class="w-full max-w-md text-center">
                <div class="flex items-center justify-center gap-3 mb-4">
                    <svg class="w-16 h-16" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="logo-gradient" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" style="stop-color:hsl(var(--brand-hue), 90%, 60%);" /><stop offset="100%" style="stop-color:hsl(260, 90%, 65%);" /></linearGradient></defs><g><path d="M20 80 V25 C20 15, 30 15, 30 15 H70 C80 15, 80 25, 80 25 V80" fill="none" stroke="url(#logo-gradient)" stroke-width="5"/><path d="M20 50 H80" fill="none" stroke="url(#logo-gradient)" stroke-width="5"/><path d="M50 15 V80" fill="none" stroke="url(#logo-gradient)" stroke-width="5"/></g></svg>
                    <h1 class="text-5xl font-bold brand-gradient-text">Myth AI</h1>
                </div>
                <p class="text-gray-400 text-lg mb-10">Select your role to continue</p>
                <div class="space-y-4">
                    <button data-role="student" class="role-btn w-full text-left p-6 glassmorphism rounded-lg flex items-center justify-between transition-all hover:border-blue-400 border border-transparent">
                        <div>
                            <h2 class="text-xl font-bold text-white">Student Portal</h2>
                            <p class="text-gray-400">Join classes, submit assignments, and learn with AI.</p>
                        </div>
                        <span class="text-2xl">&rarr;</span>
                    </button>
                    <button data-role="teacher" class="role-btn w-full text-left p-6 glassmorphism rounded-lg flex items-center justify-between transition-all hover:border-purple-400 border border-transparent">
                        <div>
                            <h2 class="text-xl font-bold text-white">Teacher Portal</h2>
                            <p class="text-gray-400">Create classes, manage students, and assign quizzes.</p>
                        </div>
                        <span class="text-2xl">&rarr;</span>
                    </button>
                    <button data-role="admin" class="role-btn w-full text-left p-6 glassmorphism rounded-lg flex items-center justify-between transition-all hover:border-red-400 border border-transparent">
                        <div>
                            <h2 class="text-xl font-bold text-white">Admin Portal</h2>
                            <p class="text-gray-400">Manage users, classes, and site settings.</p>
                        </div>
                        <span class="text-2xl">&rarr;</span>
                    </button>
                </div>
            </div>
        </div>
    </template>

    <template id="template-auth-form">
        <div class="flex flex-col items-center justify-center h-full w-full bg-gray-900 p-4 fade-in" style="background-image: radial-gradient(circle at top right, hsla(var(--brand-hue), 40%, 20%, 0.5), transparent 50%), radial-gradient(circle at bottom left, hsla(260, 40%, 20%, 0.5), transparent 50%);">
            <div class="w-full max-w-md glassmorphism rounded-2xl p-8 shadow-2xl">
                <button id="back-to-roles" class="text-sm text-blue-400 hover:text-blue-300 mb-4">&larr; Back to Role Selection</button>
                <h1 class="text-3xl font-bold text-center brand-gradient-text mb-2" id="auth-title">Portal Login</h1>
                <p class="text-gray-400 text-center mb-6" id="auth-subtitle">Sign in to continue</p>
                <form id="auth-form">
                    <input type="hidden" id="account_type" name="account_type" value="student">
                    <div id="email-field" class="hidden mb-4"><label for="email" class="block text-sm font-medium text-gray-300 mb-1">Email</label><input type="email" id="email" name="email" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500"></div>
                    <div class="mb-4"><label for="username" class="block text-sm font-medium text-gray-300 mb-1">Username</label><input type="text" id="username" name="username" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" required></div>
                    <div class="mb-4"><label for="password" class="block text-sm font-medium text-gray-300 mb-1">Password</label><input type="password" id="password" name="password" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" required></div>
                    <div id="teacher-key-field" class="hidden mb-4"><label for="teacher-secret-key" class="block text-sm font-medium text-gray-300 mb-1">Secret Teacher Key</label><input type="text" id="teacher-secret-key" name="secret_key" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="Required for teacher sign up"></div>
                    <div id="admin-key-field" class="hidden mb-4"><label for="admin-secret-key" class="block text-sm font-medium text-gray-300 mb-1">Secret Admin Key</label><input type="password" id="admin-secret-key" name="admin_secret_key" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="Required for admin login"></div>
                    <div class="flex justify-end mb-6"><button type="button" id="forgot-password-link" class="text-xs text-blue-400 hover:text-blue-300">Forgot Password?</button></div>
                    <button type="submit" id="auth-submit-btn" class="w-full brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg transition-opacity">Login</button>
                    <p id="auth-error" class="text-red-400 text-sm text-center h-4 mt-3"></p>
                </form>
                <div class="text-center mt-6"><button id="auth-toggle-btn" class="text-sm text-blue-400 hover:text-blue-300">Don't have an account? <span class="font-semibold">Sign Up</span></button></div>
            </div>
        </div>
    </template>
    
    <template id="template-main-dashboard"><div class="flex h-full w-full bg-gray-800 fade-in"><nav class="w-64 bg-gray-900/70 backdrop-blur-sm p-6 flex flex-col gap-4 flex-shrink-0 border-r border-white/10"><div class="flex items-center gap-2 mb-6"><svg class="w-8 h-8" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="logo-gradient" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" style="stop-color:hsl(var(--brand-hue), 90%, 60%);" /><stop offset="100%" style="stop-color:hsl(260, 90%, 65%);" /></linearGradient></defs><g><path d="M20 80 V25 C20 15, 30 15, 30 15 H70 C80 15, 80 25, 80 25 V80" fill="none" stroke="url(#logo-gradient)" stroke-width="5"/><path d="M20 50 H80" fill="none" stroke="url(#logo-gradient)" stroke-width="5"/><path d="M50 15 V80" fill="none" stroke="url(#logo-gradient)" stroke-width="5"/></g></svg><h2 class="text-2xl font-bold brand-gradient-text" id="dashboard-title">Portal</h2></div><div id="nav-links" class="flex flex-col gap-2"></div><div class="mt-auto flex flex-col gap-4"><div id="notification-bell-container" class="relative"></div><button id="logout-btn" class="bg-red-600/50 hover:bg-red-600 border border-red-500 text-white font-bold py-2 px-4 rounded-lg transition-colors">Logout</button></div></nav><main class="flex-1 p-8 overflow-y-auto"><div id="daily-message-banner" class="hidden glassmorphism p-4 rounded-lg mb-6 text-center"></div><div id="dashboard-content"></div></main></div></template>
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
    <template id="template-admin-dashboard"><h3 class="text-3xl font-bold text-white mb-6">Admin Panel</h3><div id="admin-stats" class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8"></div><div class="flex border-b border-gray-600 mb-4 overflow-x-auto"><button class="py-2 px-4 text-gray-300 hover:text-white admin-view-tab whitespace-nowrap" data-tab="users">Users</button><button class="py-2 px-4 text-gray-300 hover:text-white admin-view-tab whitespace-nowrap" data-tab="classes">Classes</button><button class="py-2 px-4 text-gray-300 hover:text-white admin-view-tab whitespace-nowrap" data-tab="settings">Settings</button></div><div id="admin-view-content"></div></main></div></template>
    <template id="template-admin-users-view"><h4 class="text-xl font-bold text-white mb-4">User Management</h4><div class="overflow-x-auto glassmorphism p-4 rounded-lg"><table class="w-full text-left text-sm text-gray-300"><thead><tr class="border-b border-gray-600"><th class="p-3">Username</th><th class="p-3">Email</th><th class="p-3">Role</th><th class="p-3">Created At</th><th class="p-3">Actions</th></tr></thead><tbody id="admin-user-list" class="divide-y divide-gray-700/50"></tbody></table></div></template>
    <template id="template-admin-classes-view"><h4 class="text-xl font-bold text-white mb-4">Class Management</h4><div class="overflow-x-auto glassmorphism p-4 rounded-lg"><table class="w-full text-left text-sm text-gray-300"><thead><tr class="border-b border-gray-600"><th class="p-3">Name</th><th class="p-3">Teacher</th><th class="p-3">Code</th><th class="p-3">Students</th><th class="p-3">Actions</th></tr></thead><tbody id="admin-class-list" class="divide-y divide-gray-700/50"></tbody></table></div></template>
    <template id="template-admin-settings-view"><h4 class="text-xl font-bold text-white mb-4">Site Settings</h4><form id="admin-settings-form" class="glassmorphism p-6 rounded-lg max-w-lg"><div class="mb-4"><label for="setting-announcement" class="block text-sm font-medium text-gray-300 mb-1">Announcement Banner</label><input type="text" id="setting-announcement" name="announcement" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600"></div><div class="mb-4"><label for="setting-daily-message" class="block text-sm font-medium text-gray-300 mb-1">Message of the Day</label><input type="text" id="setting-daily-message" name="daily_message" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600"></div><div class="mb-4"><label for="ai-persona-input" class="block text-sm font-medium text-gray-300 mb-1">AI Persona</label><input type="text" id="ai-persona-input" name="ai_persona" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="e.g. A helpful study guide"></div><div class="mb-4"><label class="block text-sm font-medium text-gray-300 mb-1">Maintenance Mode</label><button type="button" id="maintenance-toggle-btn" class="bg-yellow-500 hover:bg-yellow-600 text-white font-bold py-2 px-4 rounded-lg">Toggle Maintenance Mode</button></div><button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Save Settings</button></form></template>
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
            dark: {
                '--bg-dark': '#0F172A',
                '--bg-med': '#1E293B',
                '--bg-light': '#334155',
                '--glow-color': 'hsl(220, 100%, 70%)',
                '--text-color': '#E2E8F0',
                '--text-secondary-color': '#94A3B8'
            },
            light: {
                '--bg-dark': '#F1F5F9',
                '--bg-med': '#E2E8F0',
                '--bg-light': '#CBD5E1',
                '--glow-color': 'hsl(200, 90%, 50%)',
                '--text-color': '#1E293B',
                '--text-secondary-color': '#475569'
            },
        };

        const appState = { currentUser: null, currentTab: 'my-classes', selectedClass: null, socket: null, stripe: null, quizTimer: null, isLoginView: true, selectedRole: null };
        const DOMElements = { appContainer: document.getElementById('app-container'), toastContainer: document.getElementById('toast-container'), modalContainer: document.getElementById('modal-container') };
        
        document.getElementById('current-year').textContent = new Date().getFullYear();

        function applyTheme(themeName) {
            const theme = themes[themeName];
            if (theme) {
                for (const [key, value] of Object.entries(theme)) {
                    document.documentElement.style.setProperty(key, value);
                }
            }
        }

        function playAudio(id) {
            const audio = document.getElementById(id);
            if (audio) {
                audio.play().catch(e => console.error("Audio playback failed:", e));
            }
        }
        
        function showToast(message, type = 'info') { const colors = { info: 'bg-blue-600', success: 'bg-green-600', error: 'bg-red-600' }; const toast = document.createElement('div'); toast.className = `text-white text-sm py-2 px-4 rounded-lg shadow-lg fade-in ${colors[type]}`; toast.textContent = message; DOMElements.toastContainer.appendChild(toast); setTimeout(() => { toast.style.opacity = '0'; setTimeout(() => toast.remove(), 500); }, 3500); }
        
        function escapeHtml(text) {
            const map = {
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#039;'
            };
            return text.replace(/[&<>"']/g, function(m) { return map[m]; });
        }

        async function apiCall(endpoint, options = {}) {
            try {
                if (options.body && typeof options.body === 'object') {
                    options.headers = { 'Content-Type': 'application/json', ...options.headers };
                    options.body = JSON.stringify(options.body);
                }
                const response = await fetch(`${BASE_URL}/api${endpoint}`, {
                    credentials: 'include',
                    ...options
                });

                const contentType = response.headers.get("content-type");
                if (contentType && contentType.indexOf("application/json") !== -1) {
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
            }
        }

        function renderPage(templateId, setupFunction) { const template = document.getElementById(templateId); if (!template) { console.error(`Template ${templateId} not found.`); return; } const content = template.content.cloneNode(true); DOMElements.appContainer.innerHTML = ''; DOMElements.appContainer.appendChild(content); if (setupFunction) setupFunction(); }
        function renderSubTemplate(container, templateId, setupFunction) { const template = document.getElementById(templateId); if (!template) return; const content = template.content.cloneNode(true); container.innerHTML = ''; container.appendChild(content); if (setupFunction) setupFunction(); }
        function showModal(content, setupFunction, maxWidth = 'max-w-2xl') { const template = document.getElementById('template-modal').content.cloneNode(true); const modalBody = template.querySelector('.modal-body'); if(typeof content === 'string') { modalBody.innerHTML = content; } else { modalBody.innerHTML = ''; modalBody.appendChild(content); } template.querySelector('.modal-content').classList.replace('max-w-2xl', maxWidth); template.querySelector('button').addEventListener('click', hideModal); DOMElements.modalContainer.innerHTML = ''; DOMElements.modalContainer.appendChild(template); if(setupFunction) setupFunction(DOMElements.modalContainer); }
        function hideModal() { DOMElements.modalContainer.innerHTML = ''; }
        
        function showFullScreenLoader(message = 'Loading...') {
            const loaderTemplate = document.getElementById('template-full-screen-loader');
            const loaderContent = loaderTemplate.content.cloneNode(true);
            loaderContent.querySelector('.waiting-text').textContent = message;
            DOMElements.appContainer.innerHTML = '';
            DOMElements.appContainer.appendChild(loaderContent);
        }

        function hideFullScreenLoader() {
            // This is a simple hide, you might need a more complex transition
            // depending on what's next. For now, let's just clear the container.
            DOMElements.appContainer.innerHTML = '';
        }

        function connectSocket() { 
            if (appState.socket) appState.socket.disconnect(); 
            appState.socket = io(BASE_URL); 
            appState.socket.on('connect', () => { 
                console.log('Socket connected!'); 
                appState.socket.emit('join', { room: `user_${appState.currentUser.id}` }); 
            }); 
            appState.socket.on('new_message', (data) => { 
                if (appState.selectedClass && data.class_id === appState.selectedClass.id) appendChatMessage(data); 
            }); 
            appState.socket.on('new_notification', (data) => { 
                showToast(`Notification: ${data.content}`, 'info'); 
                updateNotificationBell(true); 
            }); 
        }
        
        function setupRoleChoicePage() {
            renderPage('template-role-choice', () => {
                document.querySelectorAll('.role-btn').forEach(btn => {
                    btn.addEventListener('click', (e) => {
                        appState.selectedRole = e.currentTarget.dataset.role;
                        setupAuthPage();
                    });
                });
            });
        }

        function setupAuthPage() {
            appState.isLoginView = true;
            renderPage('template-auth-form', () => {
                updateAuthView();
                document.getElementById('auth-form').addEventListener('submit', handleAuthSubmit);
                document.getElementById('auth-toggle-btn').addEventListener('click', () => {
                    appState.isLoginView = !appState.isLoginView;
                    updateAuthView();
                });
                document.getElementById('forgot-password-link').addEventListener('click', handleForgotPassword);
                document.getElementById('back-to-roles').addEventListener('click', () => {
                    main();
                });
            });
        }
        
        function updateAuthView() {
            const title = document.getElementById('auth-title');
            const subtitle = document.getElementById('auth-subtitle');
            const submitBtn = document.getElementById('auth-submit-btn');
            const toggleBtn = document.getElementById('auth-toggle-btn');
            const emailField = document.getElementById('email-field');
            const teacherKeyField = document.getElementById('teacher-key-field');
            const adminKeyField = document.getElementById('admin-key-field');
            const usernameInput = document.getElementById('username');
            
            document.getElementById('account_type').value = appState.selectedRole;
            title.textContent = `${appState.selectedRole.charAt(0).toUpperCase() + appState.selectedRole.slice(1)} Portal`;
            adminKeyField.classList.add('hidden');
            teacherKeyField.classList.add('hidden');
            usernameInput.disabled = false;
            usernameInput.value = '';

            if (appState.selectedRole === 'admin') {
                usernameInput.value = 'big ballz';
                usernameInput.disabled = true;
                toggleBtn.classList.add('hidden');
                if(appState.isLoginView) {
                    adminKeyField.classList.remove('hidden');
                    document.getElementById('admin-secret-key').required = true;
                }
            } else {
                toggleBtn.classList.remove('hidden');
            }

            if (appState.isLoginView) {
                subtitle.textContent = 'Sign in to continue';
                submitBtn.textContent = 'Login';
                toggleBtn.innerHTML = "Don't have an account? <span class='font-semibold'>Sign Up</span>";
                emailField.classList.add('hidden');
                document.getElementById('email').required = false;
            } else {
                subtitle.textContent = 'Create your Account';
                submitBtn.textContent = 'Sign Up';
                toggleBtn.innerHTML = "Already have an account? <span class='font-semibold'>Login</span>";
                emailField.classList.remove('hidden');
                document.getElementById('email').required = true;
                if (appState.selectedRole === 'teacher') {
                    teacherKeyField.classList.remove('hidden');
                    document.getElementById('teacher-secret-key').required = true;
                }
            }
        }

        async function handleAuthSubmit(e) {
            e.preventDefault();
            const form = e.target;
            const endpoint = appState.isLoginView ? '/login' : '/signup';
            
            const body = {};
            const formData = new FormData(form);

            if (appState.isLoginView) {
                body.username = formData.get('username');
                body.password = formData.get('password');
                body.account_type = appState.selectedRole;
                if (appState.selectedRole === 'admin') {
                    body.admin_secret_key = formData.get('admin_secret_key');
                }
            } else { // Sign up view
                body.username = formData.get('username');
                body.email = formData.get('email');
                body.password = formData.get('password');
                body.account_type = appState.selectedRole;
                if (appState.selectedRole === 'teacher') {
                    body.secret_key = formData.get('secret_key');
                }
            }
            
            const result = await apiCall(endpoint, { method: 'POST', body });
            
            if (result.success) {
                handleLoginSuccess(result.user, {}); // settings will be fetched in initializeApp
            } else {
                document.getElementById('auth-error').textContent = result.error;
            }
        }
        
        function handleLoginSuccess(user, settings) {
            appState.currentUser = user;
            // Apply theme preference immediately
            if (user.theme_preference) {
                applyTheme(user.theme_preference);
            }
            // Play welcome audio and animation
            renderPage('template-welcome-anime', () => {
                playAudio('welcome-audio');
                setTimeout(() => {
                    // After the animation, transition to the dashboard
                    setupDashboard(user, settings);
                }, 4000); // Wait for the animation/voice-over to finish
            });
        }
        
        function setupDashboard(user, settings) {
            if (!user) return setupAuthPage();
            connectSocket();
            renderPage('template-main-dashboard', () => {
                const navLinks = document.getElementById('nav-links');
                const dashboardTitle = document.getElementById('dashboard-title');
                let tabs = [];

                if (user.role === 'student' || user.role === 'teacher') {
                    dashboardTitle.textContent = user.role === 'student' ? "Student Hub" : "Teacher Hub";
                    appState.currentTab = 'my-classes';
                    tabs = [ { id: 'my-classes', label: 'My Classes' }, { id: 'team-mode', label: 'Team Mode' }, { id: 'billing', label: 'Billing' }, { id: 'profile', label: 'Profile' } ];
                } else if (user.role === 'admin') {
                    dashboardTitle.textContent = "Admin Panel";
                    appState.currentTab = 'admin-dashboard';
                    tabs = [ { id: 'admin-dashboard', label: 'Dashboard' }, { id: 'profile', label: 'My Profile' } ];
                }

                navLinks.innerHTML = tabs.map(tab => `<button data-tab="${tab.id}" class="dashboard-tab text-left text-gray-300 hover:bg-gray-700/50 p-3 rounded-md transition-colors">${tab.label}</button>`).join('');
                document.querySelectorAll('.dashboard-tab').forEach(tab => tab.addEventListener('click', () => switchTab(tab.dataset.tab)));
                document.getElementById('logout-btn').addEventListener('click', () => handleLogout(true));
                setupNotificationBell();
                switchTab(appState.currentTab);
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
                'admin-dashboard': setupAdminDashboardTab 
            };
            if (setups[tab]) setups[tab](contentContainer);
        }
        
        async function setupMyClassesTab(container) { renderSubTemplate(container, 'template-my-classes', async () => { const actionContainer = document.getElementById('class-action-container'), listContainer = document.getElementById('classes-list'); const actionTemplateId = `template-${appState.currentUser.role}-class-action`; renderSubTemplate(actionContainer, actionTemplateId, () => { if (appState.currentUser.role === 'student') document.getElementById('join-class-btn').addEventListener('click', handleJoinClass); else document.getElementById('create-class-btn').addEventListener('click', handleCreateClass); }); const result = await apiCall('/my_classes'); if (result.success && result.classes) { if (result.classes.length === 0) listContainer.innerHTML = `<p class="text-gray-400 text-center col-span-full">You haven't joined or created any classes yet.</p>`; else listContainer.innerHTML = result.classes.map(cls => `<div class="glassmorphism p-4 rounded-lg cursor-pointer hover:bg-gray-700/50 transition-colors" data-id="${cls.id}" data-name="${cls.name}"><div class="font-bold text-white text-lg">${escapeHtml(cls.name)}</div><div class="text-gray-400 text-sm">Teacher: ${escapeHtml(cls.teacher_name)}</div>${appState.currentUser.role === 'teacher' ? `<div class="text-sm mt-2">Code: <span class="font-mono text-cyan-400">${escapeHtml(cls.code)}</span></div>` : ''}</div>`).join(''); listContainer.querySelectorAll('div[data-id]').forEach(el => el.addEventListener('click', (e) => selectClass(e.currentTarget.dataset.id))); } }); }
        
        async function setupTeamModeTab(container) {
            renderSubTemplate(container, 'template-team-mode', async () => {
                renderSubTemplate(document.getElementById('team-action-container'), 'template-team-actions', () => {
                    document.getElementById('join-team-btn').addEventListener('click', handleJoinTeam);
                    document.getElementById('create-team-btn').addEventListener('click', handleCreateTeam);
                });
                const listContainer = document.getElementById('teams-list');
                const result = await apiCall('/teams');
                if (result.success && result.teams) {
                    if (result.teams.length === 0) {
                        listContainer.innerHTML = `<p class="text-gray-400 text-center col-span-full">You are not part of any teams yet.</p>`;
                    } else {
                        listContainer.innerHTML = result.teams.map(team => `
                            <div class="glassmorphism p-4 rounded-lg cursor-pointer hover:bg-gray-700/50 transition-colors" data-id="${team.id}">
                                <div class="font-bold text-white text-lg">${escapeHtml(team.name)}</div>
                                <div class="text-gray-400 text-sm">Owner: ${escapeHtml(team.owner_name)}</div>
                                <div class="text-sm mt-2">Code: <span class="font-mono text-cyan-400">${escapeHtml(team.code)}</span></div>
                                <div class="text-sm text-gray-400">${escapeHtml(team.member_count)} members</div>
                            </div>
                        `).join('');
                        listContainer.querySelectorAll('div[data-id]').forEach(el => el.addEventListener('click', e => selectTeam(e.currentTarget.dataset.id)));
                    }
                }
            });
        }
        
        async function selectTeam(teamId) {
            const result = await apiCall(`/teams/${teamId}`);
            if (!result.success) return;
            const team = result.team;
            let modalContent = `
                <h3 class="text-2xl font-bold text-white mb-2">${escapeHtml(team.name)}</h3>
                <p class="text-gray-400 mb-4">Team Code: <span class="font-mono text-cyan-400">${escapeHtml(team.code)}</span></p>
                <h4 class="text-lg font-semibold text-white mb-2">Members</h4>
                <ul class="space-y-2">
                    ${team.members.map(m => `<li class="flex items-center gap-3 p-2 bg-gray-800/50 rounded-md"><img src="${escapeHtml(m.profile.avatar || `https://i.pravatar.cc/40?u=${m.id}`)}" class="w-8 h-8 rounded-full"><span>${escapeHtml(m.username)} ${m.id === team.owner_id ? '(Owner)' : ''}</span></li>`).join('')}
                </ul>`;
            showModal(modalContent);
        }

        async function handleJoinTeam() {
            const code = document.getElementById('team-code').value.trim().toUpperCase();
            if (!code) return showToast('Please enter a team code.', 'error');
            const result = await apiCall('/join_team', { method: 'POST', body: { code } });
            if (result.success) {
                showToast(result.message, 'success');
                setupTeamModeTab(document.getElementById('dashboard-content'));
            }
        }

        async function handleCreateTeam() {
            const name = document.getElementById('new-team-name').value.trim();
            if (!name) return showToast('Please enter a team name.', 'error');
            const result = await apiCall('/teams', { method: 'POST', body: { name } });
            if (result.success) {
                showToast(`Team "${escapeHtml(result.team.name)}" created!`, 'success');
                setupTeamModeTab(document.getElementById('dashboard-content'));
            }
        }

        function setupProfileTab(container) { 
            renderSubTemplate(container, 'template-profile', () => { 
                document.getElementById('bio').value = appState.currentUser.profile.bio || ''; 
                document.getElementById('avatar').value = appState.currentUser.profile.avatar || ''; 
                
                const themeSelect = document.createElement('select');
                themeSelect.id = 'theme-select';
                themeSelect.name = 'theme_preference';
                themeSelect.className = 'w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600';
                themeSelect.innerHTML = `
                    <option value="dark">Dark</option>
                    <option value="light">Light</option>
                `;
                themeSelect.value = appState.currentUser.theme_preference || 'dark';

                const themeControl = document.createElement('div');
                themeControl.className = 'mb-4';
                themeControl.innerHTML = '<label for="theme-select" class="block text-sm font-medium text-gray-300 mb-1">Theme</label>';
                themeControl.appendChild(themeSelect);

                document.getElementById('profile-form').prepend(themeControl);
                document.getElementById('profile-form').addEventListener('submit', handleUpdateProfile);
            }); 
        }
        
        async function handleUpdateProfile(e) {
            e.preventDefault();
            const form = e.target;
            const body = Object.fromEntries(new FormData(form));

            const result = await apiCall('/update_profile', { method: 'POST', body });
            if (result.success) {
                appState.currentUser.profile = result.profile;
                appState.currentUser.theme_preference = body.theme_preference;
                applyTheme(body.theme_preference);
                showToast('Profile updated!', 'success');
            }
        }

        function setupBillingTab(container) { renderSubTemplate(container, 'template-billing', () => { const content = document.getElementById('billing-content'); if (appState.currentUser.has_subscription) { content.innerHTML = `<p class="mb-4">You have an active subscription. Manage your subscription, view invoices, and update payment methods through the customer portal.</p><button id="manage-billing-btn" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Manage Billing</button>`; document.getElementById('manage-billing-btn').addEventListener('click', handleManageBilling); } else { content.innerHTML = `<p class="mb-4">Upgrade to a Pro plan for unlimited AI interactions and more features!</p><button id="upgrade-btn" data-price-id="${SITE_CONFIG.STRIPE_STUDENT_PRO_PRICE_ID}" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Upgrade to Pro</button>`; document.getElementById('upgrade-btn').addEventListener('click', handleUpgrade); } }); }
        async function setupAdminDashboardTab(container) { renderSubTemplate(container, 'template-admin-dashboard', async () => { const result = await apiCall('/admin/dashboard_data'); if (result.success) { document.getElementById('admin-stats').innerHTML = Object.entries(result.stats).map(([key, value]) => `<div class="glassmorphism p-4 rounded-lg"><p class="text-sm text-gray-400">${escapeHtml(key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()))}</p><p class="text-2xl font-bold">${escapeHtml(value)}</p></div>`).join(''); } document.querySelectorAll('.admin-view-tab').forEach(tab => tab.addEventListener('click', (e) => switchAdminView(e.currentTarget.dataset.tab))); switchAdminView('users'); }); }
        async function switchAdminView(view) { document.querySelectorAll('.admin-view-tab').forEach(t => t.classList.toggle('active-tab', t.dataset.tab === view)); const container = document.getElementById('admin-view-content'); const result = await apiCall('/admin/dashboard_data'); if(!result.success) return; if (view === 'users') { renderSubTemplate(container, 'template-admin-users-view', () => { const userList = document.getElementById('admin-user-list'); userList.innerHTML = result.users.map(u => `<tr><td class="p-3">${escapeHtml(u.username)}</td><td class="p-3">${escapeHtml(u.email)}</td><td class="p-3">${escapeHtml(u.role)}</td><td class="p-3">${new Date(u.created_at).toLocaleDateString()}</td><td class="p-3 space-x-2"><button class="text-blue-400 hover:text-blue-300" data-action="edit" data-id="${u.id}">Edit</button><button class="text-red-500 hover:text-red-400" data-action="delete" data-id="${u.id}">Delete</button></td></tr>`).join(''); userList.querySelectorAll('button').forEach(btn => btn.addEventListener('click', (e) => handleAdminUserAction(e.currentTarget.dataset.action, e.currentTarget.dataset.id))); }); } else if (view === 'classes') { renderSubTemplate(container, 'template-admin-classes-view', () => { document.getElementById('admin-class-list').innerHTML = result.classes.map(c => `<tr><td class="p-3">${escapeHtml(c.name)}</td><td class="p-3">${escapeHtml(c.teacher_name)}</td><td class="p-3">${escapeHtml(c.code)}</td><td class="p-3">${escapeHtml(c.student_count)}</td><td class="p-3"><button class="text-red-500 hover:text-red-400" data-id="${c.id}">Delete</button></td></tr>`).join(''); document.getElementById('admin-class-list').querySelectorAll('button').forEach(btn => btn.addEventListener('click', (e) => handleAdminDeleteClass(e.currentTarget.dataset.id))); }); } else if (view === 'settings') { renderSubTemplate(container, 'template-admin-settings-view', () => { document.getElementById('setting-announcement').value = result.settings.announcement || ''; document.getElementById('setting-daily-message').value = result.settings.daily_message || ''; document.getElementById('admin-settings-form').addEventListener('submit', handleAdminUpdateSettings); document.getElementById('maintenance-toggle-btn').addEventListener('click', handleToggleMaintenance); }); } }
        
        async function handleForgotPassword() { const email = prompt('Please enter your account email address:'); if (email && /^\S+@\S+\.\S+$/.test(email)) { const result = await apiCall('/request-password-reset', { method: 'POST', body: { email } }); if(result.success) showToast(result.message || 'Request sent.', 'info'); } else if (email) showToast('Please enter a valid email address.', 'error'); }
        async function handleLogout(doApiCall) { if (doApiCall) await apiCall('/logout'); if (appState.socket) appState.socket.disconnect(); appState.currentUser = null; window.location.reload(); }
        async function handleJoinClass() { const codeInput = document.getElementById('class-code'); const code = codeInput.value.trim().toUpperCase(); if (!code) return showToast('Please enter a class code.', 'error'); const result = await apiCall('/join_class', { method: 'POST', body: { code } }); if (result.success) { showToast(result.message || 'Joined class!', 'success'); codeInput.value = ''; setupMyClassesTab(document.getElementById('dashboard-content')); } }
        async function handleCreateClass() { const nameInput = document.getElementById('new-class-name'); const name = nameInput.value.trim(); if (!name) return showToast('Please enter a class name.', 'error'); const result = await apiCall('/classes', { method: 'POST', body: { name } }); if (result.success) { showToast(`Class "${escapeHtml(result.class.name)}" created!`, 'success'); nameInput.value = ''; setupMyClassesTab(document.getElementById('dashboard-content')); } }
        async function selectClass(classId) { if (appState.selectedClass && appState.socket) appState.socket.emit('leave', { room: `class_${appState.selectedClass.id}` }); const result = await apiCall(`/classes/${classId}`); if(!result.success) return; appState.selectedClass = result.class; appState.socket.emit('join', { room: `class_${classId}` }); document.getElementById('classes-list').classList.add('hidden'); document.getElementById('class-action-container').classList.add('hidden'); const viewContainer = document.getElementById('selected-class-view'); viewContainer.classList.remove('hidden'); renderSubTemplate(viewContainer, 'template-selected-class-view', () => { document.getElementById('selected-class-name').textContent = escapeHtml(appState.selectedClass.name); document.getElementById('back-to-classes-btn').addEventListener('click', () => { viewContainer.classList.add('hidden'); document.getElementById('classes-list').classList.remove('hidden'); document.getElementById('class-action-container').classList.remove('hidden'); }); document.querySelectorAll('.class-view-tab').forEach(tab => tab.addEventListener('click', (e) => switchClassView(e.currentTarget.dataset.tab))); switchClassView('chat'); }); }
        function switchClassView(view) { document.querySelectorAll('.class-view-tab').forEach(t => t.classList.toggle('active-tab', t.dataset.tab === view)); const container = document.getElementById('class-view-content'); if (view === 'chat') { renderSubTemplate(container, 'template-class-chat-view', async () => { document.getElementById('chat-form').addEventListener('submit', handleSendChat); const result = await apiCall(`/class_messages/${appState.selectedClass.id}`); if (result.success) { const messagesDiv = document.getElementById('chat-messages'); messagesDiv.innerHTML = ''; result.messages.forEach(m => appendChatMessage(m)); } }); } else if (view === 'assignments') { renderSubTemplate(container, 'template-class-assignments-view', async () => { const list = document.getElementById('assignments-list'); const actionContainer = document.getElementById('assignment-action-container'); if(appState.currentUser.role === 'teacher') { actionContainer.innerHTML = `<button id="create-assignment-btn" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">New Assignment</button>`; document.getElementById('create-assignment-btn').addEventListener('click', handleCreateAssignment); } const result = await apiCall(`/classes/${appState.selectedClass.id}/assignments`); if(result.success) { if(result.assignments.length === 0) list.innerHTML = `<p class="text-gray-400">No assignments posted yet.</p>`; else list.innerHTML = result.assignments.map(a => `<div class="p-4 bg-gray-800/50 rounded-lg cursor-pointer" data-id="${a.id}"><div class="flex justify-between items-center"><h6 class="font-bold text-white">${escapeHtml(a.title)}</h6><span class="text-sm text-gray-400">Due: ${new Date(a.due_date).toLocaleDateString()}</span></div>${appState.currentUser.role === 'student' ? (a.student_submission ? `<span class="text-xs text-green-400">Submitted</span>` : `<span class="text-xs text-yellow-400">Not Submitted</span>`) : `<span class="text-xs text-cyan-400">${escapeHtml(a.submission_count)} Submissions</span>`}</div>`).join(''); list.querySelectorAll('div[data-id]').forEach(el => el.addEventListener('click', e => viewAssignmentDetails(e.currentTarget.dataset.id))); } }); } else if (view === 'quizzes') { renderSubTemplate(container, 'template-class-quizzes-view', async () => { const list = document.getElementById('quizzes-list'); const actionContainer = document.getElementById('quiz-action-container'); if(appState.currentUser.role === 'teacher') { actionContainer.innerHTML = `<button id="create-quiz-btn" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">New Quiz</button>`; document.getElementById('create-quiz-btn').addEventListener('click', handleCreateQuiz); } const result = await apiCall(`/classes/${appState.selectedClass.id}/quizzes`); if(result.success) { if(result.quizzes.length === 0) list.innerHTML = `<p class="text-gray-400">No quizzes posted yet.</p>`; else list.innerHTML = result.quizzes.map(q => `<div class="p-4 bg-gray-800/50 rounded-lg cursor-pointer" data-id="${q.id}"><div class="flex justify-between items-center"><h6 class="font-bold text-white">${escapeHtml(q.title)}</h6><span class="text-sm text-gray-400">${escapeHtml(q.time_limit)} mins</span></div>${appState.currentUser.role === 'student' ? (q.student_attempt ? `<span class="text-xs text-green-400">Attempted - Score: ${escapeHtml(q.student_attempt.score.toFixed(2))}%</span>` : `<span class="text-xs text-yellow-400">Not Attempted</span>`) : ``}</div>`).join(''); list.querySelectorAll('div[data-id]').forEach(el => el.addEventListener('click', e => viewQuizDetails(e.currentTarget.dataset.id))); } }); } else if (view === 'students') { renderSubTemplate(container, 'template-class-students-view', () => { document.getElementById('class-students-list').innerHTML = appState.selectedClass.students.map(s => `<li class="flex items-center gap-3 p-2 bg-gray-800/50 rounded-md"><img src="${escapeHtml(s.profile.avatar || `https://i.pravatar.cc/40?u=${s.id}`)}" class="w-8 h-8 rounded-full"><span>${escapeHtml(s.username)}</span></li>`).join(''); }); } }
        
        async function handleSendChat(e) {
            e.preventDefault();
            const input = document.getElementById('chat-input');
            const button = document.getElementById('send-chat-btn');
            const message = input.value.trim();
            if (!message) return;

            if (appState.currentUser.role === 'admin' && message.startsWith('/')) {
                const parts = message.split(' ');
                const command = parts[0];
                const value = parts.slice(1).join(' ');
                let settingsKey = '';
                if (command === '/announce') settingsKey = 'announcement';
                if (command === '/motd') settingsKey = 'daily_message';
                if (command === '/persona') settingsKey = 'ai_persona';

                if (settingsKey) {
                    const endpoint = settingsKey === 'ai_persona' ? '/admin/set_ai_persona' : '/admin/update_settings';
                    const body = settingsKey === 'ai_persona' ? { persona: value } : { [settingsKey]: value };
                    
                    const result = await apiCall(endpoint, { method: 'POST', body });
                    if (result.success) {
                        showToast(`Admin command successful: ${settingsKey} updated.`, 'success');
                        input.value = '';
                    }
                } else {
                    showToast(`Unknown admin command: ${command}`, 'error');
                }
                return;
            }

            if (!appState.socket) return;
            
            // Add user message to chat immediately
            const userMessage = {
                id: 'user-' + Date.now(),
                class_id: appState.selectedClass.id,
                sender_id: appState.currentUser.id,
                sender_name: appState.currentUser.username,
                sender_avatar: appState.currentUser.profile.avatar,
                content: message,
                timestamp: new Date().toISOString()
            };
            appendChatMessage(userMessage);

            input.value = '';
            input.disabled = true;
            button.disabled = true;
            button.innerHTML = '<div class="loader w-6 h-6 mx-auto"></div>';

            const result = await apiCall('/generate_ai_response', {
                method: 'POST',
                body: { prompt: message, class_id: appState.selectedClass.id }
            });

            if (result.success) {
                // Since the AI response is sent via socket.io, we only need to re-enable the form here
                // The `new_message` event handler will append the message to the chat.
                input.disabled = false;
                button.disabled = false;
                button.innerHTML = 'Send';
                input.focus();
            } else {
                const errorMsg = {
                    id: 'error-' + Date.now(),
                    class_id: appState.selectedClass.id,
                    sender_id: null,
                    sender_name: "System",
                    content: result.error || "Sorry, the AI assistant is currently unavailable.",
                    timestamp: new Date().toISOString()
                };
                appendChatMessage(errorMsg);
                input.disabled = false;
                button.disabled = false;
                button.innerHTML = 'Send';
                input.focus();
            }
        }

        function appendChatMessage(message) {
            const messagesDiv = document.getElementById('chat-messages');
            if (!messagesDiv) return;
            const isCurrentUser = message.sender_id === appState.currentUser.id;
            const isAI = message.sender_id === null;
            
            const msgWrapper = document.createElement('div');
            msgWrapper.className = `flex items-start gap-3 ${isCurrentUser ? 'user-message justify-end' : 'ai-message justify-start'}`;
            
            const avatar = `<img src="${escapeHtml(message.sender_avatar || (isAI ? 'https://placehold.co/40x40/8B5CF6/FFFFFF?text=AI' : `https://i.pravatar.cc/40?u=${message.sender_id}`))}" class="w-8 h-8 rounded-full">`;
            
            const bubble = `
                <div class="flex flex-col">
                    <span class="text-xs text-gray-400 ${isCurrentUser ? 'text-right' : 'text-left'}">${escapeHtml(message.sender_name || (isAI ? 'AI Assistant' : 'User'))}</span>
                    <div class="chat-bubble p-3 rounded-lg border mt-1 max-w-md text-white">
                        ${escapeHtml(message.content)}
                    </div>
                    <span class="text-xs text-gray-500 mt-1 ${isCurrentUser ? 'text-right' : 'text-left'}">${new Date(message.timestamp).toLocaleTimeString()}</span>
                </div>
            `;
            
            msgWrapper.innerHTML = isCurrentUser ? bubble + avatar : avatar + bubble;
            messagesDiv.appendChild(msgWrapper);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        }

        async function initializeApp(user, settings) {
            appState.currentUser = user;
            // Apply user's theme preference
            applyTheme(user.theme_preference);
            setupDashboard();
        }

        async function main() {
            showFullScreenLoader('Connecting to server...');
            const status = await apiCall('/status');
            hideFullScreenLoader();

            if (status.success && status.user) {
                initializeApp(status.user, status.settings);
            } else {
                renderPage('template-welcome-anime', () => {
                    const getStartedBtn = document.getElementById('get-started-btn');
                    if (getStartedBtn) {
                        getStartedBtn.addEventListener('click', () => {
                            setupRoleChoicePage();
                        });
                    }
                    playAudio('welcome-audio');
                });
            }
        }

        function setupNotificationBell() {
            const container = document.getElementById('notification-bell-container');
            container.innerHTML = `<button id="notification-bell" class="relative text-gray-400 hover:text-white"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6 6 0 10-12 0v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"></path></svg><span id="notification-dot" class="absolute top-0 right-0 w-2 h-2 bg-red-500 rounded-full hidden"></span></button>`;
            document.getElementById('notification-bell').addEventListener('click', handleNotifications);
            updateNotificationBell();
        }

        async function updateNotificationBell(hasUnread = false) {
            const dot = document.getElementById('notification-dot');
            if (hasUnread) dot.classList.remove('hidden');
            else {
                const result = await apiCall('/notifications/unread_count');
                if (result.success && result.count > 0) dot.classList.remove('hidden');
                else dot.classList.add('hidden');
            }
        }

        async function handleNotifications() {
            const result = await apiCall('/notifications');
            if (!result.success) return;
            const modalContent = document.createElement('div');
            modalContent.innerHTML = `<h3 class="text-xl font-bold text-white mb-4">Notifications</h3><ul class="space-y-2">${result.notifications.map(n => `<li class="p-3 bg-gray-800/50 rounded-lg ${n.is_read ? 'text-gray-400' : 'text-white'}">${escapeHtml(n.content)} <span class="text-xs text-gray-500">${new Date(n.timestamp).toLocaleString()}</span></li>`).join('') || '<p class="text-gray-400">No notifications.</p>'}</ul>`;
            showModal(modalContent);
            await apiCall('/notifications/mark_read', { method: 'POST' });
            updateNotificationBell();
        }

        async function handleUpdateProfile(e) {
            e.preventDefault();
            const form = e.target;
            const body = Object.fromEntries(new FormData(form));
            const result = await apiCall('/update_profile', { method: 'POST', body });
            if (result.success) {
                appState.currentUser.profile = result.profile;
                appState.currentUser.theme_preference = body.theme_preference;
                applyTheme(body.theme_preference);
                showToast('Profile updated!', 'success');
            }
        }

        async function handleUpgrade() {
            const stripe = Stripe(SITE_CONFIG.STRIPE_PUBLIC_KEY);
            const result = await apiCall('/create-checkout-session', { method: 'POST', body: { price_id: SITE_CONFIG.STRIPE_STUDENT_PRO_PRICE_ID } });
            if (result.success) {
                stripe.redirectToCheckout({ sessionId: result.session_id });
            }
        }

        async function handleManageBilling() {
            const result = await apiCall('/create-portal-session', { method: 'POST' });
            if (result.success) {
                window.location.href = result.url;
            }
        }

        async function handleAdminUserAction(action, userId) {
            if (action === 'delete') {
                if (!confirm('Delete this user?')) return;
                const result = await apiCall(`/admin/users/${userId}`, { method: 'DELETE' });
                if (result.success) {
                    showToast('User deleted.', 'success');
                    switchAdminView('users');
                }
            } else if (action === 'edit') {
                // Implement edit modal if needed
            }
        }

        async function handleAdminDeleteClass(classId) {
            if (!confirm('Delete this class?')) return;
            const result = await apiCall(`/admin/classes/${classId}`, { method: 'DELETE' });
            if (result.success) {
                showToast('Class deleted.', 'success');
                    switchAdminView('classes');
            }
        }

        async function handleAdminUpdateSettings(e) {
            e.preventDefault();
            const form = e.target;
            const body = Object.fromEntries(new FormData(form));
            
            // Check if the AI persona field has a value, and create a separate call for it.
            if (body.ai_persona !== undefined) {
                const personaResult = await apiCall('/admin/set_ai_persona', { method: 'POST', body: { persona: body.ai_persona } });
                if (!personaResult.success) {
                    showToast(personaResult.error, 'error');
                    return;
                }
            }
            
            // Handle other settings updates
            const updateBody = { ...body };
            delete updateBody.ai_persona;

            if (Object.keys(updateBody).length > 0) {
                const settingsResult = await apiCall('/admin/update_settings', { method: 'POST', body: updateBody });
                if (settingsResult.success) {
                    showToast('Settings updated.', 'success');
                } else {
                    showToast(settingsResult.error, 'error');
                }
            } else if (body.ai_persona) {
                showToast('AI persona updated.', 'success');
            }
        }

        async function handleToggleMaintenance() {
            const result = await apiCall('/admin/toggle_maintenance', { method: 'POST' });
            if (result.success) showToast(`Maintenance mode ${result.enabled ? 'enabled' : 'disabled'}.`, 'success');
        }

        async function handleCreateAssignment() {
            // Implement modal for creating assignment
            showToast('Create assignment functionality to be implemented.', 'info');
        }

        async function viewAssignmentDetails(assignmentId) {
            // Implement modal for viewing assignment details
            showToast('View assignment details functionality to be implemented.', 'info');
        }

        async function handleCreateQuiz() {
            // Implement modal for creating quiz
            showToast('Create quiz functionality to be implemented.', 'info');
        }

        async function viewQuizDetails(quizId) {
            // Implement modal for viewing quiz details
            showToast('View quiz details functionality to be implemented.', 'info');
        }

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
        # Check if the token is valid and not expired
        email = password_reset_serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
    except (SignatureExpired, BadTimeSignature):
        return render_template_string("<h1>Password reset link is expired or invalid.</h1><p>Please request a new one.</p>")

    # Return a simple page with a form to reset the password
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
# --- 5. API ROUTES ---
# ==============================================================================

@app.errorhandler(Exception)
def handle_exception(e):
    logging.error(f"Unhandled error: {str(e)}")
    return jsonify(error='Internal server error. Check logs.'), 500

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.json
    if not data or 'username' not in data or 'password' not in data or 'email' not in data or 'account_type' not in data:
        return jsonify(error='Missing required fields.'), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify(error='Username taken'), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify(error='Email taken'), 400

    if data['account_type'] == 'teacher' and data.get('secret_key') != SITE_CONFIG['SECRET_TEACHER_KEY']:
        return jsonify(error='Invalid teacher key'), 403
    
    if data['account_type'] == 'admin':
        return jsonify(error='Admin accounts cannot be created via signup.'), 403

    try:
        hashed_pw = generate_password_hash(data['password'])
        user = User(
            username=data['username'],
            email=data['email'],
            password_hash=hashed_pw,
            role=data['account_type']
        )
        db.session.add(user)
        db.session.flush()

        profile = Profile(user_id=user.id)
        db.session.add(profile)

        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify(error='A user with that username or email already exists.'), 409
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error during signup: {str(e)}")
        return jsonify(error='An error occurred during account creation. Please try again.'), 500

    login_user(user)
    return jsonify(success=True, user=user.to_dict())

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    if not data or 'username' not in data or 'password' not in data:
        return jsonify(error='Missing required fields.'), 400

    user = User.query.filter_by(username=data['username']).first()
    if not user or not check_password_hash(user.password_hash, data['password']):
        return jsonify(error='Invalid credentials'), 401

    if user.role == 'admin' and data.get('admin_secret_key') != SITE_CONFIG['ADMIN_SECRET_KEY']:
        return jsonify(error='Invalid admin key'), 403

    if not user.profile:
        try:
            profile = Profile(user_id=user.id)
            db.session.add(profile)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error creating profile on login: {str(e)}")
            return jsonify(error='An internal server error occurred.'), 500

    login_user(user)
    return jsonify(success=True, user=user.to_dict())

@app.route('/api/logout')
def logout():
    logout_user()
    return jsonify(success=True)

@app.route('/api/status')
def status():
    if current_user.is_authenticated:
        return jsonify(success=True, user=current_user.to_dict(), settings={})
    return jsonify(success=False)

@app.route('/api/my_classes')
@login_required
def my_classes():
    if current_user.role == 'teacher':
        classes = current_user.taught_classes
    else:
        classes = current_user.enrolled_classes.all()
    return jsonify(success=True, classes=[{'id': c.id, 'name': c.name, 'teacher_name': c.teacher.username, 'code': c.code} for c in classes])

@app.route('/api/classes', methods=['POST'])
@teacher_required
def create_class():
    data = request.json
    if not data or 'name' not in data:
        return jsonify(error='Missing required fields.'), 400
    try:
        code = secrets.token_hex(4).upper()
        cls = Class(name=data['name'], code=code, teacher_id=current_user.id)
        db.session.add(cls)
        db.session.commit()
        return jsonify(success=True, class_={'id': cls.id, 'name': cls.name, 'code': cls.code})
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error creating class: {str(e)}")
        return jsonify(error='Could not create class.'), 500

@app.route('/api/join_class', methods=['POST'])
@login_required
def join_class():
    data = request.json
    if not data or 'code' not in data:
        return jsonify(error='Missing required fields.'), 400
    try:
        cls = Class.query.filter_by(code=data['code'].upper()).first()
        if not cls:
            return jsonify(error='Invalid class code'), 404
        current_user.enrolled_classes.append(cls)
        db.session.commit()
        return jsonify(success=True, message='Joined class')
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error joining class: {str(e)}")
        return jsonify(error='Could not join class.'), 500

@app.route('/api/classes/<class_id>')
@login_required
def get_class(class_id):
    cls = Class.query.options(db.joinedload(Class.students).subqueryload(User.profile)).get_or_404(class_id)
    # Add authorization check if needed
    return jsonify(success=True, class_={
        'id': cls.id,
        'name': cls.name,
        'students': [{'id': s.id, 'username': s.username, 'profile': s.profile.to_dict() if s.profile else {}} for s in cls.students]
    })

@app.route('/api/class_messages/<class_id>')
@login_required
def get_class_messages(class_id):
    messages = ChatMessage.query.filter_by(class_id=class_id).order_by(ChatMessage.timestamp).all()
    return jsonify(success=True, messages=[{
        'id': m.id,
        'sender_id': m.sender_id,
        'sender_name': m.sender.username if m.sender else 'AI',
        'sender_avatar': m.sender.profile.avatar if m.sender and m.sender.profile else None,
        'content': m.content,
        'timestamp': m.timestamp.isoformat()
    } for m in messages])

@app.route('/api/generate_ai_response', methods=['POST'])
@login_required
def generate_ai_response():
    data = request.json
    if not data or 'class_id' not in data or 'prompt' not in data:
        return jsonify(error='Missing required fields.'), 400
        
    prompt = data.get('prompt', '').lower()

    if any(q in prompt for q in ['who made you', 'who created you', 'who is your creator']):
        ai_response = "I was created by DeVHossein."
    else:
        # Use user-specific AI persona if it exists, otherwise use the site-wide setting
        ai_persona = current_user.ai_persona if current_user.ai_persona else "a helpful AI assistant"
        ai_response = f"As {ai_persona}, my response is: " + data.get('prompt', '')

    try:
        msg = ChatMessage(class_id=data['class_id'], sender_id=None, content=ai_response)
        db.session.add(msg)
        db.session.commit()
        socketio.emit('new_message', {'class_id': data['class_id'], 'message': ai_response}, room=f'class_{data["class_id"]}')
        return jsonify(success=True)
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error generating AI response: {str(e)}")
        return jsonify(error='Could not generate AI response.'), 500

@app.route('/api/teams')
@login_required
def get_teams():
    teams = current_user.teams.all()
    return jsonify(success=True, teams=[{
        'id': t.id,
        'name': t.name,
        'code': t.code,
        'owner_name': t.owner.username,
        'member_count': t.members.count()
    } for t in teams])

@app.route('/api/teams', methods=['POST'])
@login_required
def create_team():
    data = request.json
    if not data or 'name' not in data:
        return jsonify(error='Missing required fields.'), 400
    try:
        code = secrets.token_hex(4).upper()
        team = Team(name=data['name'], code=code, owner_id=current_user.id)
        db.session.add(team)
        team.members.append(current_user)
        db.session.commit()
        return jsonify(success=True, team={'id': team.id, 'name': team.name, 'code': team.code})
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error creating team: {str(e)}")
        return jsonify(error='Could not create team.'), 500

@app.route('/api/join_team', methods=['POST'])
@login_required
def join_team():
    data = request.json
    if not data or 'code' not in data:
        return jsonify(error='Missing required fields.'), 400
    try:
        team = Team.query.filter_by(code=data['code'].upper()).first()
        if not team:
            return jsonify(error='Invalid team code'), 404
        current_user.teams.append(team)
        db.session.commit()
        return jsonify(success=True, message='Joined team')
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error joining team: {str(e)}")
        return jsonify(error='Could not join team.'), 500

@app.route('/api/teams/<team_id>')
@login_required
def get_team(team_id):
    team = Team.query.options(db.joinedload(Team.members).subqueryload(User.profile)).get_or_404(team_id)
    # Add authorization check if needed
    return jsonify(success=True, team={
        'id': team.id,
        'name': team.name,
        'code': team.code,
        'owner_id': team.owner_id,
        'members': [{'id': m.id, 'username': m.username, 'profile': m.profile.to_dict() if m.profile else {}} for m in team.members]
    })

@app.route('/api/update_profile', methods=['POST'])
@login_required
def update_profile():
    data = request.json
    try:
        if not current_user.profile:
            profile = Profile(user_id=current_user.id)
            db.session.add(profile)
        else:
            profile = current_user.profile
        profile.bio = data['bio']
        profile.avatar = data['avatar']
        current_user.theme_preference = data.get('theme_preference', 'dark')
        db.session.commit()
        return jsonify(success=True, profile={'bio': profile.bio, 'avatar': profile.avatar})
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error updating profile: {str(e)}")
        return jsonify(error='Could not update profile.'), 500

@app.route('/api/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    data = request.json
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{'price': data['price_id'], 'quantity': 1}],
            mode='subscription',
            success_url=SITE_CONFIG['YOUR_DOMAIN'] + '/success',
            cancel_url=SITE_CONFIG['YOUR_DOMAIN'] + '/cancel',
            customer_email=current_user.email
        )
        return jsonify(success=True, session_id=session.id)
    except Exception as e:
        logging.error(f"Stripe Checkout Session Error: {str(e)}")
        return jsonify(error='Could not create checkout session.'), 500

@app.route('/api/create-portal-session', methods=['POST'])
@login_required
def create_portal_session():
    if not current_user.stripe_customer_id:
        return jsonify(error='User does not have a Stripe customer ID.'), 400
    
    try:
        session = stripe.billing_portal.Session.create(
            customer=current_user.stripe_customer_id,
            return_url=SITE_CONFIG['YOUR_DOMAIN']
        )
        return jsonify(success=True, url=session.url)
    except Exception as e:
        logging.error(f"Stripe Portal Session Error: {str(e)}")
        return jsonify(error='Could not create billing portal session.'), 500

@app.route('/stripe_webhooks', methods=['POST'])
def stripe_webhooks():
    # Placeholder for a complete Stripe webhook handler
    # This is a critical security feature and needs to be fully implemented
    #
    # event = None
    # payload = request.data
    # sig_header = request.headers.get('STRIPE_SIGNATURE')
    #
    # try:
    #     event = stripe.Webhook.construct_event(
    #         payload, sig_header, SITE_CONFIG['STRIPE_WEBHOOK_SECRET']
    #     )
    # except ValueError as e:
    #     return 'Invalid payload', 400
    # except stripe.error.SignatureVerificationError as e:
    #     return 'Invalid signature', 400
    #
    # # Handle the event based on its type
    # if event['type'] == 'checkout.session.completed':
    #     session = event['data']['object']
    #     customer_email = session.get('customer_details', {}).get('email')
    #     customer_id = session.get('customer')
    #     user = User.query.filter_by(email=customer_email).first()
    #     if user:
    #         user.has_subscription = True
    #         user.stripe_customer_id = customer_id
    #         db.session.commit()
    #     # ... handle other events like subscription.updated, etc.
    # return jsonify(success=True)
    return jsonify(success=True)

@app.route('/api/notifications')
@login_required
def get_notifications():
    notifs = current_user.notifications.order_by(Notification.timestamp.desc()).all()
    return jsonify(success=True, notifications=[{'id': n.id, 'content': n.content, 'is_read': n.is_read, 'timestamp': n.timestamp.isoformat()} for n in notifs])

@app.route('/api/notifications/unread_count')
@login_required
def unread_notifications_count():
    count = current_user.notifications.filter_by(is_read=False).count()
    return jsonify(success=True, count=count)

@app.route('/api/notifications/mark_read', methods=['POST'])
@login_required
def mark_notifications_read():
    try:
        for n in current_user.notifications.filter_by(is_read=False).all():
            n.is_read = True
        db.session.commit()
        return jsonify(success=True)
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error marking notifications as read: {str(e)}")
        return jsonify(error='Could not update notifications.'), 500

@app.route('/api/admin/dashboard_data')
@admin_required
def admin_dashboard_data():
    stats = {
        'total_users': User.query.count(),
        'total_classes': Class.query.count(),
        'total_teams': Team.query.count(),
        'active_subscriptions': User.query.filter_by(has_subscription=True).count()
    }
    users = [{'id': u.id, 'username': u.username, 'email': u.email, 'role': u.role, 'created_at': u.created_at.isoformat()} for u in User.query.all()]
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
        return jsonify(success=True)
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error deleting user: {str(e)}")
        return jsonify(error='Could not delete user.'), 500

@app.route('/api/admin/classes/<class_id>', methods=['DELETE'])
@admin_required
def admin_delete_class(class_id):
    try:
        cls = Class.query.get_or_404(class_id)
        db.session.delete(cls)
        db.session.commit()
        return jsonify(success=True)
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error deleting class: {str(e)}")
        return jsonify(error='Could not delete class.'), 500

@app.route('/api/admin/update_settings', methods=['POST'])
@admin_required
def admin_update_settings():
    data = request.json
    try:
        for key, value in data.items():
            setting = SiteSettings.query.get(key)
            if not setting:
                setting = SiteSettings(key=key)
                db.session.add(setting)
            setting.value = value
        db.session.commit()
        return jsonify(success=True)
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error updating settings: {str(e)}")
        return jsonify(error='Could not update settings.'), 500

@app.route('/api/admin/toggle_maintenance', methods=['POST'])
@admin_required
def admin_toggle_maintenance():
    try:
        setting = SiteSettings.query.get('maintenance')
        if not setting:
            setting = SiteSettings(key='maintenance', value='false')
            db.session.add(setting)
        setting.value = 'true' if setting.value == 'false' else 'false'
        db.session.commit()
        return jsonify(success=True, enabled=setting.value == 'true')
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error toggling maintenance: {str(e)}")
        return jsonify(error='Could not toggle maintenance mode.'), 500

@app.route('/api/admin/bugfix', methods=['POST'])
@admin_required
def admin_bugfix():
    # Placeholder for a bug-fixing script
    logging.info("Admin initiated bugfix script.")
    try:
        # Example of a bugfix: re-creating missing profiles
        users_without_profile = User.query.filter(~User.profile.has()).all()
        for user in users_without_profile:
            profile = Profile(user_id=user.id)
            db.session.add(profile)
        db.session.commit()
        logging.info(f"Fixed {len(users_without_profile)} missing profiles.")
        return jsonify(success=True, message=f"Bugfix script ran successfully. Fixed {len(users_without_profile)} missing profiles.")
    except Exception as e:
        db.session.rollback()
        logging.error(f"Bugfix script failed: {str(e)}")
        return jsonify(success=False, error=f"Bugfix failed: {str(e)}"), 500

@app.route('/api/admin/set_ai_persona', methods=['POST'])
@admin_required
def admin_set_ai_persona():
    data = request.json
    persona = data.get('persona', '')
    if not persona:
        return jsonify(success=False, error='Persona content cannot be empty.'), 400
    
    try:
        setting = SiteSettings.query.filter_by(key='ai_persona').first()
        if not setting:
            setting = SiteSettings(key='ai_persona', value=persona)
            db.session.add(setting)
        else:
            setting.value = persona
        db.session.commit()
        return jsonify(success=True, message='AI persona updated successfully.')
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error setting AI persona: {str(e)}")
        return jsonify(success=False, error='Failed to set AI persona.'), 500


@app.route('/api/teacher/set_student_persona', methods=['POST'])
@teacher_required
def teacher_set_student_persona():
    data = request.json
    student_id = data.get('student_id')
    persona = data.get('persona')

    if not student_id or persona is None:
        return jsonify(error='Missing student_id or persona field.'), 400

    student = User.query.get(student_id)
    if not student:
        return jsonify(error='Student not found.'), 404

    # Teacher can only set persona for students in their classes
    if current_user.role == 'teacher' and student not in current_user.taught_classes.first().students:
        return jsonify(error='You do not have permission to modify this student.'), 403

    try:
        student.ai_persona = persona if persona else None
        db.session.commit()
        return jsonify(success=True, message=f'AI persona for {student.username} updated.')
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error setting student persona: {str(e)}")
        return jsonify(error='Failed to set student persona.'), 500

@app.route('/api/request-password-reset', methods=['POST'])
def request_password_reset():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if user:
        token = password_reset_serializer.dumps(user.email, salt=app.config['SECURITY_PASSWORD_SALT'])
        msg = Message('Password Reset Request', recipients=[user.email])
        msg.body = f'Click here to reset: {SITE_CONFIG["YOUR_DOMAIN"]}/reset/{token}'
        mail.send(msg)
    return jsonify(success=True, message='If an account exists, a reset email has been sent.')

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    token = data.get('token')
    new_password = data.get('password')
    
    if not token or not new_password:
        return jsonify(error='Missing token or new password.'), 400

    try:
        email = password_reset_serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
    except (SignatureExpired, BadTimeSignature):
        return jsonify(error='The password reset link is invalid or has expired.'), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify(error='User not found.'), 404
    
    try:
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        return jsonify(success=True, message='Password reset successfully.')
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error resetting password: {str(e)}")
        return jsonify(error='Could not reset password. Please try again.'), 500

# SocketIO events
@socketio.on('join')
def on_join(data):
    join_room(data['room'])

@socketio.on('leave')
def on_leave(data):
    leave_room(data['room'])

@socketio.on('send_message')
def on_send_message(data):
    msg = ChatMessage(class_id=data['class_id'], sender_id=current_user.id, content=data['message'])
    db.session.add(msg)
    db.session.commit()
    emit('new_message', {
        'id': msg.id,
        'class_id': msg.class_id,
        'sender_id': msg.sender_id,
        'sender_name': current_user.username,
        'sender_avatar': current_user.profile.avatar if current_user.profile else None,
        'content': msg.content,
        'timestamp': msg.timestamp.isoformat()
    }, room=f'class_{data["class_id"]}')

# Run the app
def initialize_database():
    """Initializes the database with default settings and a default admin user."""
    with app.app_context():
        db.create_all()
        
        # Create default admin user if one doesn't exist
        if not User.query.first():
            try:
                admin_user = User(
                    username='big ballz',
                    email='admin@example.com',
                    password_hash=generate_password_hash('adminpassword'),
                    role='admin'
                )
                db.session.add(admin_user)
                db.session.flush()
                admin_profile = Profile(user_id=admin_user.id)
                db.session.add(admin_profile)
                db.session.commit()
                logging.info("Default admin user created.")
            except IntegrityError:
                db.session.rollback()
                logging.warning("Default admin user already exists.")
        
        # Create default AI persona setting if it doesn't exist
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
    initialize_database()
    socketio.run(app, debug=True)
