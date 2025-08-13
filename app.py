# --- Imports ---
import os
import json
import logging
import time
import uuid
import secrets
import requests
from flask import Flask, Response, request, session, jsonify, redirect, url_for
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
from sqlalchemy import event, or_, func
from sqlalchemy.engine import Engine
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS

# ==============================================================================
# --- 1. INITIAL CONFIGURATION & SETUP ---
# ==============================================================================
load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)


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
    "SECRET_TEACHER_KEY": os.environ.get('SECRET_TEACHER_KEY'),
    "ADMIN_SECRET_KEY": os.environ.get('ADMIN_SECRET_KEY'),
    "STRIPE_WEBHOOK_SECRET": os.environ.get('STRIPE_WEBHOOK_SECRET'),
    "GEMINI_API_KEY": os.environ.get('GEMINI_API_KEY'),
    "SUPPORT_EMAIL": os.environ.get('SUPPORT_EMAIL')
}

stripe.api_key = SITE_CONFIG.get("STRIPE_SECRET_KEY")
password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_SENDER')
mail = Mail(app)

# ==============================================================================
# --- DATABASE MODELS ---
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
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True)
    role = db.Column(db.String(20), nullable=False, default='student')
    taught_classes = db.relationship('Class', back_populates='teacher', lazy=True, foreign_keys='Class.teacher_id', cascade="all, delete-orphan")
    enrolled_classes = db.relationship('Class', secondary=student_class_association, back_populates='students', lazy='dynamic')
    teams = db.relationship('Team', secondary=team_member_association, back_populates='members', lazy='dynamic')

class Team(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(8), unique=True, nullable=False)
    owner_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    owner = db.relationship('User', foreign_keys=[owner_id])
    members = db.relationship('User', secondary=team_member_association, back_populates='teams', lazy='dynamic')

class Class(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(8), unique=True, nullable=False)
    teacher_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    teacher = db.relationship('User', back_populates='taught_classes', foreign_keys=[teacher_id])
    students = db.relationship('User', secondary=student_class_association, back_populates='enrolled_classes', lazy='dynamic')

class SiteSettings(db.Model):
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.String(500))

# ==============================================================================
# --- USER & SESSION MANAGEMENT ---
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

# ==============================================================================
# --- FRONTEND CONTENT ---
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
        :root { --brand-hue: 220; --bg-dark: #0F172A; --bg-med: #1E293B; --bg-light: #334155; --glow-color: hsl(var(--brand-hue), 100%, 70%); }
        body { background-color: var(--bg-dark); font-family: 'Inter', sans-serif; }
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
    </style>
</head>
<body class="text-gray-200 antialiased">
    <div id="app-container" class="relative h-screen w-screen overflow-hidden flex flex-col"></div>
    <div id="toast-container" class="fixed top-6 right-6 z-[100] flex flex-col gap-2"></div>
    <div id="modal-container"></div>
    <!-- TEMPLATES START -->
    <template id="template-welcome-anime">
        <div class="flex flex-col items-center justify-center h-full w-full bg-cover bg-center p-4 fade-in" style="background-image: url('https://placehold.co/1920x1080/0F172A/FFFFFF?text=Anime+Background');">
            <div class="glassmorphism p-8 rounded-xl text-center">
                <h1 class="text-4xl font-bold text-white mb-4">Welcome to Myth AI!</h1>
                <p class="text-gray-300 mb-6">Your journey into AI-powered learning begins now.</p>
                <button id="get-started-btn" class="brand-gradient-bg shiny-button text-white font-bold py-3 px-6 rounded-lg">Get Started</button>
            </div>
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
                    <svg class="w-16 h-16" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><g><path d="M20 80 V25 C20 15, 30 15, 30 15 H70 C80 15, 80 25, 80 25 V80" fill="none" stroke="url(#logo-gradient)" stroke-width="5"/><path d="M20 50 H80" fill="none" stroke="url(#logo-gradient)" stroke-width="5"/><path d="M50 15 V80" fill="none" stroke="url(#logo-gradient)" stroke-width="5"/></g></svg>
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
    
    <template id="template-main-dashboard"><div class="flex h-full w-full bg-gray-800 fade-in"><nav class="w-64 bg-gray-900/70 backdrop-blur-sm p-6 flex flex-col gap-4 flex-shrink-0 border-r border-white/10"><div class="flex items-center gap-2 mb-6"><svg class="w-8 h-8" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><g><path d="M20 80 V25 C20 15, 30 15, 30 15 H70 C80 15, 80 25, 80 25 V80" fill="none" stroke="url(#logo-gradient)" stroke-width="5"/><path d="M20 50 H80" fill="none" stroke="url(#logo-gradient)" stroke-width="5"/><path d="M50 15 V80" fill="none" stroke="url(#logo-gradient)" stroke-width="5"/></g></svg><h2 class="text-2xl font-bold brand-gradient-text" id="dashboard-title">Portal</h2></div><div id="nav-links" class="flex flex-col gap-2"></div><div class="mt-auto flex flex-col gap-4"><div id="notification-bell-container" class="relative"></div><button id="logout-btn" class="bg-red-600/50 hover:bg-red-600 border border-red-500 text-white font-bold py-2 px-4 rounded-lg transition-colors">Logout</button></div></nav><main class="flex-1 p-8 overflow-y-auto"><div id="daily-message-banner" class="hidden glassmorphism p-4 rounded-lg mb-6 text-center"></div><div id="dashboard-content"></div></main></div></template>
    <template id="template-my-classes"><h3 class="text-3xl font-bold text-white mb-6">My Classes</h3><div id="class-action-container" class="mb-6"></div><div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6" id="classes-list"></div><div id="selected-class-view" class="mt-8 hidden"></div></template>
    <template id="template-team-mode"><h3 class="text-3xl font-bold text-white mb-6">Team Mode</h3><div id="team-action-container" class="mb-6"></div><div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6" id="teams-list"></div><div id="selected-team-view" class="mt-8 hidden"></div></template>
    <template id="template-student-class-action"><div class="glassmorphism p-4 rounded-lg"><h4 class="font-semibold text-lg mb-2 text-white">Join a New Class</h4><div class="flex items-center gap-2"><input type="text" id="class-code" placeholder="Enter class code" class="flex-grow p-3 bg-gray-700/50 rounded-lg border border-gray-600"><button id="join-class-btn" class="brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg">Join</button></div></div></template>
    <template id="template-teacher-class-action"><div class="glassmorphism p-4 rounded-lg"><h4 class="font-semibold text-lg mb-2 text-white">Create a New Class</h4><div class="flex items-center gap-2"><input type="text" id="new-class-name" placeholder="New class name" class="flex-grow p-3 bg-gray-700/50 rounded-lg border border-gray-600"><button id="create-class-btn" class="brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg">Create</button></div></div></template>
    <template id="template-team-actions"><div class="grid grid-cols-1 md:grid-cols-2 gap-4"><div class="glassmorphism p-4 rounded-lg"><h4 class="font-semibold text-lg mb-2 text-white">Join a Team</h4><div class="flex items-center gap-2"><input type="text" id="team-code" placeholder="Enter team code" class="flex-grow p-3 bg-gray-700/50 rounded-lg border border-gray-600"><button id="join-team-btn" class="brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg">Join</button></div></div><div class="glassmorphism p-4 rounded-lg"><h4 class="font-semibold text-lg mb-2 text-white">Create a New Team</h4><div class="flex items-center gap-2"><input type="text" id="new-team-name" placeholder="New team name" class="flex-grow p-3 bg-gray-700/50 rounded-lg border border-gray-600"><button id="create-team-btn" class="brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg">Create</button></div></div></div></template>
    <template id="template-selected-class-view"><div class="glassmorphism p-6 rounded-lg"><div class="flex justify-between items-start"><h4 class="text-2xl font-bold text-white mb-4">Class: <span id="selected-class-name"></span></h4><button id="back-to-classes-btn" class="text-sm text-blue-400 hover:text-blue-300">&larr; Back to All Classes</button></div><div class="flex border-b border-gray-600 mb-4 overflow-x-auto"><button class="py-2 px-4 text-gray-300 hover:text-white class-view-tab whitespace-nowrap" data-tab="chat">Chat</button><button class="py-2 px-4 text-gray-300 hover:text-white class-view-tab whitespace-nowrap" data-tab="assignments">Assignments</button><button class="py-2 px-4 text-gray-300 hover:text-white class-view-tab whitespace-nowrap" data-tab="quizzes">Quizzes</button><button class="py-2 px-4 text-gray-300 hover:text-white class-view-tab whitespace-nowrap" data-tab="students">Students</button></div><div id="class-view-content"></div></div></template>
    <template id="template-class-chat-view"><div id="chat-messages" class="bg-gray-900/50 p-4 rounded-lg h-96 overflow-y-auto mb-4 border border-gray-700 flex flex-col gap-4"></div><form id="chat-form" class="flex items-center gap-2"><input type="text" id="chat-input" placeholder="Ask the AI assistant or type an admin command..." class="flex-grow w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600"><button type="submit" id="send-chat-btn" class="brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg">Send</button></form></template>
    <template id="template-class-assignments-view"><div class="flex justify-between items-center mb-4"><h5 class="text-xl font-semibold text-white">Assignments</h5><div id="assignment-action-container"></div></div><div id="assignments-list" class="space-y-4"></div></template>
    <template id="template-class-quizzes-view"><div class="flex justify-between items-center mb-4"><h5 class="text-xl font-semibold text-white">Quizzes</h5><div id="quiz-action-container"></div></div><div id="quizzes-list" class="space-y-4"></div></template>
    <template id="template-class-students-view"><h5 class="text-xl font-semibold text-white mb-4">Enrolled Students</h5><ul id="class-students-list" class="space-y-2"></ul></template>
    <template id="template-profile"><h3 class="text-3xl font-bold text-white mb-6">Customize Profile</h3><form id="profile-form" class="glassmorphism p-6 rounded-lg max-w-lg"><div class="mb-4"><label for="bio" class="block text-sm font-medium text-gray-300 mb-1">Bio</label><textarea id="bio" name="bio" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" rows="4"></textarea></div><div class="mb-4"><label for="avatar" class="block text-sm font-medium text-gray-300 mb-1">Avatar URL</label><input type="url" id="avatar" name="avatar" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600"></div><button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Save Profile</button></form></template>
    <template id="template-billing"><h3 class="text-3xl font-bold text-white mb-6">Billing & Plans</h3><div id="billing-content" class="glassmorphism p-6 rounded-lg"></div></template>
    <template id="template-admin-dashboard"><h3 class="text-3xl font-bold text-white mb-6">Admin Panel</h3><div id="admin-stats" class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8"></div><div class="flex border-b border-gray-600 mb-4 overflow-x-auto"><button class="py-2 px-4 text-gray-300 hover:text-white admin-view-tab whitespace-nowrap" data-tab="users">Users</button><button class="py-2 px-4 text-gray-300 hover:text-white admin-view-tab whitespace-nowrap" data-tab="classes">Classes</button><button class="py-2 px-4 text-gray-300 hover:text-white admin-view-tab whitespace-nowrap" data-tab="settings">Settings</button></div><div id="admin-view-content"></div></template>
    <template id="template-admin-users-view"><h4 class="text-xl font-bold text-white mb-4">User Management</h4><div class="overflow-x-auto glassmorphism p-4 rounded-lg"><table class="w-full text-left text-sm text-gray-300"><thead><tr class="border-b border-gray-600"><th class="p-3">Username</th><th class="p-3">Email</th><th class="p-3">Role</th><th class="p-3">Created At</th><th class="p-3">Actions</th></tr></thead><tbody id="admin-user-list" class="divide-y divide-gray-700/50"></tbody></table></div></template>
    <template id="template-admin-classes-view"><h4 class="text-xl font-bold text-white mb-4">Class Management</h4><div class="overflow-x-auto glassmorphism p-4 rounded-lg"><table class="w-full text-left text-sm text-gray-300"><thead><tr class="border-b border-gray-600"><th class="p-3">Name</th><th class="p-3">Teacher</th><th class="p-3">Code</th><th class="p-3">Students</th><th class="p-3">Actions</th></tr></thead><tbody id="admin-class-list" class="divide-y divide-gray-700/50"></tbody></table></div></template>
    <template id="template-admin-settings-view"><h4 class="text-xl font-bold text-white mb-4">Site Settings</h4><form id="admin-settings-form" class="glassmorphism p-6 rounded-lg max-w-lg"><div class="mb-4"><label for="setting-announcement" class="block text-sm font-medium text-gray-300 mb-1">Announcement Banner</label><input type="text" id="setting-announcement" name="announcement" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600"></div><div class="mb-4"><label for="setting-daily-message" class="block text-sm font-medium text-gray-300 mb-1">Message of the Day</label><input type="text" id="setting-daily-message" name="daily_message" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600"></div><div class="mb-4"><label class="block text-sm font-medium text-gray-300 mb-1">Maintenance Mode</label><button type="button" id="maintenance-toggle-btn" class="bg-yellow-500 hover:bg-yellow-600 text-white font-bold py-2 px-4 rounded-lg">Toggle Maintenance Mode</button></div><button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Save Settings</button></form></template>
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

        const appState = { currentUser: null, currentTab: 'my-classes', selectedClass: null, socket: null, stripe: null, quizTimer: null, isLoginView: true, selectedRole: null };
        const DOMElements = { appContainer: document.getElementById('app-container'), toastContainer: document.getElementById('toast-container'), modalContainer: document.getElementById('modal-container') };
        
        function showToast(message, type = 'info') { const colors = { info: 'bg-blue-600', success: 'bg-green-600', error: 'bg-red-600' }; const toast = document.createElement('div'); toast.className = `text-white text-sm py-2 px-4 rounded-lg shadow-lg fade-in ${colors[type]}`; toast.textContent = message; DOMElements.toastContainer.appendChild(toast); setTimeout(() => { toast.style.opacity = '0'; setTimeout(() => toast.remove(), 500); }, 3500); }
        
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
                const data = await response.json(); 
                if (!response.ok) { 
                    if (response.status === 401) handleLogout(false); 
                    throw new Error(data.error || `Request failed with status ${response.status}`); 
                } 
                return { success: true, ...data }; 
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
            
            title.textContent = `${appState.selectedRole.charAt(0).toUpperCase() + appState.selectedRole.slice(1)} Portal`;
            adminKeyField.classList.add('hidden');
            teacherKeyField.classList.add('hidden');
            usernameInput.value = '';
            usernameInput.disabled = false;

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
            const endpoint = appState.isLoginView ? '/login' : '/signup';
            let body = Object.fromEntries(new FormData(e.target));
            
            if (appState.selectedRole === 'admin') {
                body.username = 'big ballz';
            }
            if (!appState.isLoginView) {
                body.account_type = appState.selectedRole;
            }
            
            const result = await apiCall(endpoint, { method: 'POST', body });
            
            if (result.success) {
                if (result.user.role === appState.selectedRole || (appState.selectedRole !== 'admin')) {
                     initializeApp(result.user, {});
                } else {
                    document.getElementById('auth-error').textContent = `Authentication failed. Please check your credentials and role.`;
                    handleLogout(true);
                }
            } else {
                document.getElementById('auth-error').textContent = result.error;
            }
        }
        
        function setupDashboard() {
            const user = appState.currentUser;
            if (!user) return setupAuthPage();
            connectSocket();
            renderPage('template-main-dashboard', () => {
                const navLinks = document.getElementById('nav-links');
                const dashboardTitle = document.getElementById('dashboard-title');
                let tabs = [];

                if (user.role === 'student') {
                    dashboardTitle.textContent = "Student Hub";
                    appState.currentTab = 'my-classes';
                    tabs = [ { id: 'my-classes', label: 'My Classes' }, { id: 'team-mode', label: 'Team Mode' }, { id: 'billing', label: 'Billing' }, { id: 'profile', label: 'Profile' } ];
                } else if (user.role === 'teacher') {
                    dashboardTitle.textContent = "Teacher Hub";
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
        
        async function setupMyClassesTab(container) { renderSubTemplate(container, 'template-my-classes', async () => { const actionContainer = document.getElementById('class-action-container'), listContainer = document.getElementById('classes-list'); const actionTemplateId = `template-${appState.currentUser.role}-class-action`; renderSubTemplate(actionContainer, actionTemplateId, () => { if (appState.currentUser.role === 'student') document.getElementById('join-class-btn').addEventListener('click', handleJoinClass); else document.getElementById('create-class-btn').addEventListener('click', handleCreateClass); }); const result = await apiCall('/my_classes'); if (result.success && result.classes) { if (result.classes.length === 0) listContainer.innerHTML = `<p class="text-gray-400 text-center col-span-full">You haven't joined or created any classes yet.</p>`; else listContainer.innerHTML = result.classes.map(cls => `<div class="glassmorphism p-4 rounded-lg cursor-pointer hover:bg-gray-700/50 transition-colors" data-id="${cls.id}" data-name="${cls.name}"><div class="font-bold text-white text-lg">${cls.name}</div><div class="text-gray-400 text-sm">Teacher: ${cls.teacher_name}</div>${appState.currentUser.role === 'teacher' ? `<div class="text-sm mt-2">Code: <span class="font-mono text-cyan-400">${cls.code}</span></div>` : ''}</div>`).join(''); listContainer.querySelectorAll('div[data-id]').forEach(el => el.addEventListener('click', (e) => selectClass(e.currentTarget.dataset.id))); } }); }
        
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
                                <div class="font-bold text-white text-lg">${team.name}</div>
                                <div class="text-gray-400 text-sm">Owner: ${team.owner_name}</div>
                                <div class="text-sm mt-2">Code: <span class="font-mono text-cyan-400">${team.code}</span></div>
                                <div class="text-sm text-gray-400">${team.member_count} members</div>
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
                <h3 class="text-2xl font-bold text-white mb-2">${team.name}</h3>
                <p class="text-gray-400 mb-4">Team Code: <span class="font-mono text-cyan-400">${team.code}</span></p>
                <h4 class="text-lg font-semibold text-white mb-2">Members</h4>
                <ul class="space-y-2">
                    ${team.members.map(m => `<li class="flex items-center gap-3 p-2 bg-gray-800/50 rounded-md"><img src="${m.profile.avatar || `https://i.pravatar.cc/40?u=${m.id}`}" class="w-8 h-8 rounded-full"><span>${m.username} ${m.id === team.owner_id ? '(Owner)' : ''}</span></li>`).join('')}
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
                showToast(`Team "${result.team.name}" created!`, 'success');
                setupTeamModeTab(document.getElementById('dashboard-content'));
            }
        }

        function setupProfileTab(container) { renderSubTemplate(container, 'template-profile', () => { document.getElementById('bio').value = appState.currentUser.profile.bio || ''; document.getElementById('avatar').value = appState.currentUser.profile.avatar || ''; document.getElementById('profile-form').addEventListener('submit', handleUpdateProfile); }); }
        function setupBillingTab(container) { renderSubTemplate(container, 'template-billing', () => { const content = document.getElementById('billing-content'); if (appState.currentUser.has_subscription) { content.innerHTML = `<p class="mb-4">You have an active subscription. Manage your subscription, view invoices, and update payment methods through the customer portal.</p><button id="manage-billing-btn" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Manage Billing</button>`; document.getElementById('manage-billing-btn').addEventListener('click', handleManageBilling); } else { content.innerHTML = `<p class="mb-4">Upgrade to a Pro plan for unlimited AI interactions and more features!</p><button id="upgrade-btn" data-price-id="${SITE_CONFIG.STRIPE_STUDENT_PRO_PRICE_ID}" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Upgrade to Pro</button>`; document.getElementById('upgrade-btn').addEventListener('click', handleUpgrade); } }); }
        async function setupAdminDashboardTab(container) { renderSubTemplate(container, 'template-admin-dashboard', async () => { const result = await apiCall('/admin/dashboard_data'); if (result.success) { document.getElementById('admin-stats').innerHTML = Object.entries(result.stats).map(([key, value]) => `<div class="glassmorphism p-4 rounded-lg"><p class="text-sm text-gray-400">${key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</p><p class="text-2xl font-bold">${value}</p></div>`).join(''); } document.querySelectorAll('.admin-view-tab').forEach(tab => tab.addEventListener('click', (e) => switchAdminView(e.currentTarget.dataset.tab))); switchAdminView('users'); }); }
        async function switchAdminView(view) { document.querySelectorAll('.admin-view-tab').forEach(t => t.classList.toggle('active-tab', t.dataset.tab === view)); const container = document.getElementById('admin-view-content'); const result = await apiCall('/admin/dashboard_data'); if(!result.success) return; if (view === 'users') { renderSubTemplate(container, 'template-admin-users-view', () => { const userList = document.getElementById('admin-user-list'); userList.innerHTML = result.users.map(u => `<tr><td class="p-3">${u.username}</td><td class="p-3">${u.email}</td><td class="p-3">${u.role}</td><td class="p-3">${new Date(u.created_at).toLocaleDateString()}</td><td class="p-3 space-x-2"><button class="text-blue-400 hover:text-blue-300" data-action="edit" data-id="${u.id}">Edit</button><button class="text-red-500 hover:text-red-400" data-action="delete" data-id="${u.id}">Delete</button></td></tr>`).join(''); userList.querySelectorAll('button').forEach(btn => btn.addEventListener('click', (e) => handleAdminUserAction(e.currentTarget.dataset.action, e.currentTarget.dataset.id))); }); } else if (view === 'classes') { renderSubTemplate(container, 'template-admin-classes-view', () => { document.getElementById('admin-class-list').innerHTML = result.classes.map(c => `<tr><td class="p-3">${c.name}</td><td class="p-3">${c.teacher_name}</td><td class="p-3">${c.code}</td><td class="p-3">${c.student_count}</td><td class="p-3"><button class="text-red-500 hover:text-red-400" data-id="${c.id}">Delete</button></td></tr>`).join(''); document.getElementById('admin-class-list').querySelectorAll('button').forEach(btn => btn.addEventListener('click', (e) => handleAdminDeleteClass(e.currentTarget.dataset.id))); }); } else if (view === 'settings') { renderSubTemplate(container, 'template-admin-settings-view', () => { document.getElementById('setting-announcement').value = result.settings.announcement || ''; document.getElementById('setting-daily-message').value = result.settings.daily_message || ''; document.getElementById('admin-settings-form').addEventListener('submit', handleAdminUpdateSettings); document.getElementById('maintenance-toggle-btn').addEventListener('click', handleToggleMaintenance); }); } }
        
        async function handleForgotPassword() { const email = prompt('Please enter your account email address:'); if (email && /^\\S+@\\S+\\.\\S+$/.test(email)) { const result = await apiCall('/request-password-reset', { method: 'POST', body: { email } }); if(result.success) showToast(result.message || 'Request sent.', 'info'); } else if (email) showToast('Please enter a valid email address.', 'error'); }
        async function handleLogout(doApiCall) { if (doApiCall) await apiCall('/logout'); if (appState.socket) appState.socket.disconnect(); appState.currentUser = null; window.location.reload(); }
        async function handleJoinClass() { const codeInput = document.getElementById('class-code'); const code = codeInput.value.trim().toUpperCase(); if (!code) return showToast('Please enter a class code.', 'error'); const result = await apiCall('/join_class', { method: 'POST', body: { code } }); if (result.success) { showToast(result.message || 'Joined class!', 'success'); codeInput.value = ''; setupMyClassesTab(document.getElementById('dashboard-content')); } }
        async function handleCreateClass() { const nameInput = document.getElementById('new-class-name'); const name = nameInput.value.trim(); if (!name) return showToast('Please enter a class name.', 'error'); const result = await apiCall('/classes', { method: 'POST', body: { name } }); if (result.success) { showToast(`Class "${result.class.name}" created!`, 'success'); nameInput.value = ''; setupMyClassesTab(document.getElementById('dashboard-content')); } }
        async function selectClass(classId) { if (appState.selectedClass && appState.socket) appState.socket.emit('leave', { room: `class_${appState.selectedClass.id}` }); const result = await apiCall(`/classes/${classId}`); if(!result.success) return; appState.selectedClass = result.class; appState.socket.emit('join', { room: `class_${classId}` }); document.getElementById('classes-list').classList.add('hidden'); document.getElementById('class-action-container').classList.add('hidden'); const viewContainer = document.getElementById('selected-class-view'); viewContainer.classList.remove('hidden'); renderSubTemplate(viewContainer, 'template-selected-class-view', () => { document.getElementById('selected-class-name').textContent = appState.selectedClass.name; document.getElementById('back-to-classes-btn').addEventListener('click', () => { viewContainer.classList.add('hidden'); document.getElementById('classes-list').classList.remove('hidden'); document.getElementById('class-action-container').classList.remove('hidden'); }); document.querySelectorAll('.class-view-tab').forEach(tab => tab.addEventListener('click', (e) => switchClassView(e.currentTarget.dataset.tab))); switchClassView('chat'); }); }
        function switchClassView(view) { document.querySelectorAll('.class-view-tab').forEach(t => t.classList.toggle('active-tab', t.dataset.tab === view)); const container = document.getElementById('class-view-content'); if (view === 'chat') { renderSubTemplate(container, 'template-class-chat-view', async () => { document.getElementById('chat-form').addEventListener('submit', handleSendChat); const result = await apiCall(`/class_messages/${appState.selectedClass.id}`); if (result.success) { const messagesDiv = document.getElementById('chat-messages'); messagesDiv.innerHTML = ''; result.messages.forEach(m => appendChatMessage(m)); } }); } else if (view === 'assignments') { renderSubTemplate(container, 'template-class-assignments-view', async () => { const list = document.getElementById('assignments-list'); const actionContainer = document.getElementById('assignment-action-container'); if(appState.currentUser.role === 'teacher') { actionContainer.innerHTML = `<button id="create-assignment-btn" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">New Assignment</button>`; document.getElementById('create-assignment-btn').addEventListener('click', handleCreateAssignment); } const result = await apiCall(`/classes/${appState.selectedClass.id}/assignments`); if(result.success) { if(result.assignments.length === 0) list.innerHTML = `<p class="text-gray-400">No assignments posted yet.</p>`; else list.innerHTML = result.assignments.map(a => `<div class="p-4 bg-gray-800/50 rounded-lg cursor-pointer" data-id="${a.id}"><div class="flex justify-between items-center"><h6 class="font-bold text-white">${a.title}</h6><span class="text-sm text-gray-400">Due: ${new Date(a.due_date).toLocaleDateString()}</span></div>${appState.currentUser.role === 'student' ? (a.student_submission ? `<span class="text-xs text-green-400">Submitted</span>` : `<span class="text-xs text-yellow-400">Not Submitted</span>`) : `<span class="text-xs text-cyan-400">${a.submission_count} Submissions</span>`}</div>`).join(''); list.querySelectorAll('div[data-id]').forEach(el => el.addEventListener('click', e => viewAssignmentDetails(e.currentTarget.dataset.id))); } }); } else if (view === 'quizzes') { renderSubTemplate(container, 'template-class-quizzes-view', async () => { const list = document.getElementById('quizzes-list'); const actionContainer = document.getElementById('quiz-action-container'); if(appState.currentUser.role === 'teacher') { actionContainer.innerHTML = `<button id="create-quiz-btn" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">New Quiz</button>`; document.getElementById('create-quiz-btn').addEventListener('click', handleCreateQuiz); } const result = await apiCall(`/classes/${appState.selectedClass.id}/quizzes`); if(result.success) { if(result.quizzes.length === 0) list.innerHTML = `<p class="text-gray-400">No quizzes posted yet.</p>`; else list.innerHTML = result.quizzes.map(q => `<div class="p-4 bg-gray-800/50 rounded-lg cursor-pointer" data-id="${q.id}"><div class="flex justify-between items-center"><h6 class="font-bold text-white">${q.title}</h6><span class="text-sm text-gray-400">${q.time_limit} mins</span></div>${appState.currentUser.role === 'student' ? (q.student_attempt ? `<span class="text-xs text-green-400">Attempted - Score: ${q.student_attempt.score.toFixed(2)}%</span>` : `<span class="text-xs text-yellow-400">Not Attempted</span>`) : ``}</div>`).join(''); list.querySelectorAll('div[data-id]').forEach(el => el.addEventListener('click', e => viewQuizDetails(e.currentTarget.dataset.id))); } }); } else if (view === 'students') { renderSubTemplate(container, 'template-class-students-view', () => { document.getElementById('class-students-list').innerHTML = appState.selectedClass.students.map(s => `<li class="flex items-center gap-3 p-2 bg-gray-800/50 rounded-md"><img src="${s.profile.avatar || `https://i.pravatar.cc/40?u=${s.id}`}" class="w-8 h-8 rounded-full"><span>${s.username}</span></li>`).join(''); }); } }
        
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

                if (settingsKey) {
                    const result = await apiCall('/admin/update_settings', { method: 'POST', body: { [settingsKey]: value } });
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
            appState.socket.emit('send_message', { class_id: appState.selectedClass.id, message: message });
            
            input.value = '';
            input.disabled = true;
            button.disabled = true;
            button.innerHTML = '<div class="loader w-6 h-6 mx-auto"></div>';

            const result = await apiCall('/generate_ai_response', {
                method: 'POST',
                body: { prompt: message, class_id: appState.selectedClass.id }
            });

            if (!result.success) {
                const errorMsg = {
                    id: 'error-' + Date.now(),
                    class_id: appState.selectedClass.id,
                    sender_id: null,
                    sender_name: "System",
                    content: "Sorry, the AI assistant is currently unavailable.",
                    timestamp: new Date().toISOString()
                };
                appendChatMessage(errorMsg);
            }
            
            input.disabled = false;
            button.disabled = false;
            button.innerHTML = 'Send';
            input.focus();
        }

        function appendChatMessage(message) {
            const messagesDiv = document.getElementById('chat-messages');
            if (!messagesDiv) return;
            const isCurrentUser = message.sender_id === appState.currentUser.id;
            const isAI = message.sender_id === null;
            
            const msgWrapper = document.createElement('div');
            msgWrapper.className = `flex items-start gap-3 ${isCurrentUser ? 'user-message justify-end' : 'ai-message justify-start'}`;
            
            const avatar = `<img src="${message.sender_avatar || (isAI ? 'https://placehold.co/40x40/8B5CF6/FFFFFF?text=AI' : `https://i.pravatar.cc/40?u=${message.sender_id}`)}" class="w-8 h-8 rounded-full">`;
            
            const bubble = `
                <div class="flex flex-col">
                    <span class="text-xs text-gray-400 ${isCurrentUser ? 'text-right' : 'text-left'} mb-1">${message.sender_name}</span>
                    <div class="chat-bubble p-3 rounded-lg border max-w-md">
                        <p class="text-white">${message.content}</p>
                    </div>
                </div>
            `;
            
            msgWrapper.innerHTML = isCurrentUser ? bubble + avatar : avatar + bubble;
            
            messagesDiv.appendChild(msgWrapper);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        }

        async function handleUpdateProfile(e) { e.preventDefault(); const result = await apiCall('/profile', { method: 'PUT', body: Object.fromEntries(new FormData(e.target)) }); if (result.success) { appState.currentUser.profile = result.profile; showToast('Profile updated!', 'success'); } }
        async function handleUpgrade(e) { const priceId = e.target.dataset.priceId; const result = await apiCall('/create-checkout-session', { method: 'POST', body: { price_id: priceId } }); if (result.success && result.sessionId) { const stripe = Stripe(appState.stripePublicKey); stripe.redirectToCheckout({ sessionId: result.sessionId }); } }
        async function handleManageBilling() { const result = await apiCall('/create-customer-portal-session', { method: 'POST' }); if (result.success && result.url) window.location.href = result.url; }
        function handleCreateAssignment() { const content = `<h3 class="text-2xl font-bold text-white mb-4">New Assignment</h3><form id="new-assignment-form"><div class="mb-4"><label class="block text-sm">Title</label><input type="text" name="title" class="w-full p-2 bg-gray-800 rounded" required></div><div class="mb-4"><label class="block text-sm">Description</label><textarea name="description" class="w-full p-2 bg-gray-800 rounded" rows="5" required></textarea></div><div class="mb-4"><label class="block text-sm">Due Date</label><input type="datetime-local" name="due_date" class="w-full p-2 bg-gray-800 rounded" required></div><button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Create</button></form>`; showModal(content, (modal) => { modal.querySelector('#new-assignment-form').addEventListener('submit', async (e) => { e.preventDefault(); const formData = Object.fromEntries(new FormData(e.target)); const result = await apiCall(`/classes/${appState.selectedClass.id}/assignments`, { method: 'POST', body: formData }); if (result.success) { hideModal(); showToast('Assignment created!', 'success'); switchClassView('assignments'); } }); }); }
        async function viewAssignmentDetails(assignmentId) { const result = await apiCall(`/assignments/${assignmentId}`); if(!result.success) return; const assignment = result.assignment; let modalContent = `<h3 class="text-2xl font-bold text-white mb-2">${assignment.title}</h3><p class="text-gray-400 mb-4">${assignment.description}</p><p class="text-sm text-gray-500 mb-6">Due: ${new Date(assignment.due_date).toLocaleString()}</p>`; if(appState.currentUser.role === 'teacher') { modalContent += `<h4 class="text-lg font-semibold text-white mb-2">Submissions</h4>`; if(assignment.submissions.length === 0) modalContent += `<p class="text-gray-400">No submissions yet.</p>`; else modalContent += assignment.submissions.map(s => `<div class="p-2 bg-gray-800 rounded mb-2"><strong>${s.student_name}:</strong> ${s.content.substring(0, 50)}... Grade: ${s.grade || 'Not graded'}</div>`).join(''); } else { if(assignment.my_submission) { modalContent += `<h4 class="text-lg font-semibold text-white mb-2">Your Submission</h4><div class="p-4 bg-gray-800 rounded"><p class="whitespace-pre-wrap">${assignment.my_submission.content}</p><hr class="my-2 border-gray-600"><p><strong>Grade:</strong> ${assignment.my_submission.grade || 'Not graded'}</p><p><strong>Feedback:</strong> ${assignment.my_submission.feedback || 'No feedback yet.'}</p></div>`; } else { modalContent += `<h4 class="text-lg font-semibold text-white mb-2">Submit Your Work</h4><form id="submit-assignment-form"><textarea name="content" class="w-full p-2 bg-gray-800 rounded" rows="8" required></textarea><button type="submit" class="mt-4 brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Submit</button></form>`; } } showModal(modalContent, modal => { if(modal.querySelector('#submit-assignment-form')) { modal.querySelector('#submit-assignment-form').addEventListener('submit', async e => { e.preventDefault(); const result = await apiCall(`/assignments/${assignmentId}/submissions`, { method: 'POST', body: Object.fromEntries(new FormData(e.target)) }); if(result.success) { hideModal(); showToast('Assignment submitted!', 'success'); switchClassView('assignments'); } }); } }); }
        function handleCreateQuiz() { let questionCounter = 0; const content = `<h3 class="text-2xl font-bold text-white mb-4">New Quiz</h3><form id="new-quiz-form"><div class="mb-4"><label class="block text-sm">Title</label><input type="text" name="title" class="w-full p-2 bg-gray-800 rounded" required></div><div class="mb-4"><label class="block text-sm">Description</label><textarea name="description" class="w-full p-2 bg-gray-800 rounded" rows="3"></textarea></div><div class="mb-4"><label class="block text-sm">Time Limit (minutes)</label><input type="number" name="time_limit" class="w-full p-2 bg-gray-800 rounded" required min="1"></div><hr class="my-4 border-gray-600"><div id="questions-container"></div><button type="button" id="add-question-btn" class="text-sm text-blue-400 hover:text-blue-300">+ Add Question</button><hr class="my-4 border-gray-600"><button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Create Quiz</button></form>`; showModal(content, modal => { const addQuestion = () => { const qId = questionCounter++; const qContainer = document.createElement('div'); qContainer.className = 'p-4 border border-gray-700 rounded-lg mb-4'; qContainer.innerHTML = `<div class="flex justify-between items-center mb-2"><label class="block text-sm">Question ${qId + 1}</label><button type="button" class="text-red-500 text-xs remove-question-btn">Remove</button></div><textarea name="q-text-${qId}" class="w-full p-2 bg-gray-700 rounded" required></textarea><div class="mt-2"><label class="block text-sm">Type</label><select name="q-type-${qId}" class="w-full p-2 bg-gray-700 rounded q-type-select"><option value="multiple_choice">Multiple Choice</option></select></div><div class="choices-container mt-2"></div>`; document.getElementById('questions-container').appendChild(qContainer); qContainer.querySelector('.remove-question-btn').addEventListener('click', () => qContainer.remove()); qContainer.querySelector('.q-type-select').dispatchEvent(new Event('change')); }; modal.querySelector('#add-question-btn').addEventListener('click', addQuestion); modal.querySelector('#questions-container').addEventListener('change', e => { if(e.target.classList.contains('q-type-select')) { const choicesContainer = e.target.closest('.p-4').querySelector('.choices-container'); const qId = e.target.name.split('-')[2]; choicesContainer.innerHTML = `<div class="space-y-2"><div class="flex items-center gap-2"><input type="radio" name="q-correct-${qId}" value="0" required><input type="text" name="q-choice-${qId}-0" class="flex-grow p-1 bg-gray-600 rounded" placeholder="Choice 1" required></div><div class="flex items-center gap-2"><input type="radio" name="q-correct-${qId}" value="1"><input type="text" name="q-choice-${qId}-1" class="flex-grow p-1 bg-gray-600 rounded" placeholder="Choice 2" required></div><div class="flex items-center gap-2"><input type="radio" name="q-correct-${qId}" value="2"><input type="text" name="q-choice-${qId}-2" class="flex-grow p-1 bg-gray-600 rounded" placeholder="Choice 3"></div><div class="flex items-center gap-2"><input type="radio" name="q-correct-${qId}" value="3"><input type="text" name="q-choice-${qId}-3" class="flex-grow p-1 bg-gray-600 rounded" placeholder="Choice 4"></div></div>`; } }); modal.querySelector('#new-quiz-form').addEventListener('submit', async e => { e.preventDefault(); const form = e.target; const quizData = { title: form.title.value, description: form.description.value, time_limit: form.time_limit.value, questions: [] }; document.querySelectorAll('#questions-container > div').forEach((qDiv, i) => { const qId = i; const qText = qDiv.querySelector(`textarea[name="q-text-${qId}"]`).value; const qType = qDiv.querySelector(`select[name="q-type-${qId}"]`).value; const question = { text: qText, type: qType, choices: [] }; if(qType === 'multiple_choice') { const correctIndex = qDiv.querySelector(`input[name="q-correct-${qId}"]:checked`).value; qDiv.querySelectorAll('input[type="text"]').forEach((cInput, cIndex) => { if(cInput.value) question.choices.push({ text: cInput.value, is_correct: cIndex == correctIndex }); }); } quizData.questions.push(question); }); const result = await apiCall(`/classes/${appState.selectedClass.id}/quizzes`, { method: 'POST', body: quizData }); if(result.success) { hideModal(); showToast('Quiz created!', 'success'); switchClassView('quizzes'); } }); addQuestion(); }); }
        async function viewQuizDetails(quizId) { const result = await apiCall(`/quizzes/${quizId}`); if(!result.success) return; const quiz = result.quiz; if(appState.currentUser.role === 'teacher') { let modalContent = `<h3 class="text-2xl font-bold text-white mb-2">${quiz.title}</h3><p class="text-gray-400 mb-4">${quiz.description}</p><h4 class="text-lg font-semibold text-white mb-2">Attempts</h4>`; if(quiz.attempts.length === 0) modalContent += `<p class="text-gray-400">No attempts yet.</p>`; else modalContent += `<div class="overflow-x-auto"><table class="w-full text-left"><thead><tr><th>Student</th><th>Score</th><th>Submitted</th></tr></thead><tbody>${quiz.attempts.map(a => `<tr><td>${a.student_name}</td><td>${a.score.toFixed(2)}%</td><td>${new Date(a.end_time).toLocaleString()}</td></tr>`).join('')}</tbody></table></div>`; showModal(modalContent); } else { const studentAttempt = quiz.student_attempt; if(studentAttempt) { showModal(`<h3 class="text-2xl font-bold text-white mb-2">Quiz Results: ${quiz.title}</h3><p class="text-4xl font-bold text-center my-8">${studentAttempt.score.toFixed(2)}%</p><p class="text-center text-gray-400">You have already completed this quiz.</p>`); } else { if(confirm(`Start quiz: ${quiz.title}?\\nYou will have ${quiz.time_limit} minutes.`)) startQuiz(quizId); } } }
        async function startQuiz(quizId) { const result = await apiCall(`/quizzes/${quizId}/start`, { method: 'POST' }); if(!result.success) return; const { attempt_id, questions, time_limit, start_time } = result; let currentQuestionIndex = 0; const userAnswers = {}; const deadline = new Date(new Date(start_time).getTime() + time_limit * 60000); const renderQuestion = () => { const q = questions[currentQuestionIndex]; let choicesHtml = ''; if(q.question_type === 'multiple_choice') { choicesHtml = `<div class="space-y-3 mt-4">${q.choices.map(c => `<label class="flex items-center p-3 bg-gray-800 rounded-lg cursor-pointer hover:bg-gray-700"><input type="radio" name="answer" value="${c.id}" class="mr-3"><span class="text-white">${c.text}</span></label>`).join('')}</div>`; } const content = `<div class="flex justify-between items-center"><h3 class="text-2xl font-bold text-white">${appState.selectedClass.name} Quiz</h3><div id="quiz-timer" class="text-xl font-mono text-red-500"></div></div><hr class="my-4 border-gray-600"><p class="text-gray-400 mb-2">Question ${currentQuestionIndex + 1} of ${questions.length}</p><h4 class="text-xl font-semibold text-white">${q.text}</h4>${choicesHtml}<div class="flex justify-between mt-8"><button id="prev-btn" class="bg-gray-600 py-2 px-4 rounded-lg">Previous</button><button id="next-btn" class="brand-gradient-bg shiny-button py-2 px-4 rounded-lg">Next</button></div>`; showModal(content, modal => { if(currentQuestionIndex === 0) modal.querySelector('#prev-btn').style.visibility = 'hidden'; if(currentQuestionIndex === questions.length - 1) { modal.querySelector('#next-btn').textContent = 'Submit'; } modal.querySelector('#prev-btn').addEventListener('click', () => { saveAnswer(); currentQuestionIndex--; renderQuestion(); }); modal.querySelector('#next-btn').addEventListener('click', () => { saveAnswer(); if(currentQuestionIndex === questions.length - 1) submitQuiz(attempt_id, userAnswers); else { currentQuestionIndex++; renderQuestion(); } }); if(userAnswers[q.id]) modal.querySelector(`input[value="${userAnswers[q.id]}"]`).checked = true; }, 'max-w-4xl'); }; const saveAnswer = () => { const selected = document.querySelector('input[name="answer"]:checked'); if(selected) userAnswers[questions[currentQuestionIndex].id] = selected.value; }; const updateTimer = () => { const now = new Date(); const diff = deadline - now; if(diff <= 0) { clearInterval(appState.quizTimer); submitQuiz(attempt_id, userAnswers); } else { const minutes = Math.floor(diff / 60000); const seconds = Math.floor((diff % 60000) / 1000); document.getElementById('quiz-timer').textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`; } }; if(appState.quizTimer) clearInterval(appState.quizTimer); appState.quizTimer = setInterval(updateTimer, 1000); renderQuestion(); }
        async function submitQuiz(attempt_id, answers) { if(appState.quizTimer) clearInterval(appState.quizTimer); const result = await apiCall(`/attempts/${attempt_id}/submit`, { method: 'POST', body: { answers } }); if(result.success) { showModal(`<h3 class="text-2xl font-bold text-white mb-2">Quiz Submitted!</h3><p class="text-4xl font-bold text-center my-8">${result.attempt.score.toFixed(2)}%</p><p class="text-center text-gray-400">Your results have been saved.</p>`); switchClassView('quizzes'); } }
        function handleAdminUserAction(action, userId) { if(action === 'delete') { if(confirm('Are you sure you want to delete this user? This is irreversible.')) { apiCall(`/admin/user/${userId}`, { method: 'DELETE' }).then(res => { if(res.success) { showToast(res.message, 'success'); switchAdminView('users'); } }); } } }
        function handleAdminDeleteClass(classId) { if(confirm('Are you sure you want to delete this class? This will delete all associated data.')) { apiCall(`/admin/class/${classId}`, { method: 'DELETE' }).then(res => { if(res.success) { showToast(res.message, 'success'); switchAdminView('classes'); } }); } }
        async function handleAdminUpdateSettings(e) { e.preventDefault(); const result = await apiCall('/admin/update_settings', { method: 'POST', body: Object.fromEntries(new FormData(e.target)) }); if(result.success) showToast(result.message, 'success'); }
        async function handleToggleMaintenance() { if(confirm('Are you sure you want to toggle maintenance mode?')) { const result = await apiCall('/admin/toggle_maintenance', { method: 'POST' }); if(result.success) { showToast(result.message, 'success'); } } }
        async function setupNotificationBell() { const container = document.getElementById('notification-bell-container'); container.innerHTML = `<button id="notification-bell" class="relative text-gray-400 hover:text-white"><svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" /></svg><div id="notification-dot" class="hidden absolute top-0 right-0 w-2 h-2 bg-red-500 rounded-full"></div></button><div id="notification-panel" class="hidden absolute bottom-full right-0 w-80 bg-gray-800 rounded-lg shadow-lg mb-2 z-50"></div>`; document.getElementById('notification-bell').addEventListener('click', toggleNotificationPanel); const result = await apiCall('/notifications'); if(result.success && result.notifications.some(n => !n.is_read)) updateNotificationBell(true); }
        function updateNotificationBell(hasUnread) { const dot = document.getElementById('notification-dot'); if(dot) dot.classList.toggle('hidden', !hasUnread); }
        async function toggleNotificationPanel() { const panel = document.getElementById('notification-panel'); if(panel.classList.toggle('hidden')) return; panel.innerHTML = `<div class="p-4"><div class="loader mx-auto"></div></div>`; const result = await apiCall('/notifications'); if(result.success) { if(result.notifications.length === 0) panel.innerHTML = `<div class="p-4 text-center text-gray-400">No notifications.</div>`; else panel.innerHTML = result.notifications.map(n => `<div class="p-3 border-b border-gray-700 ${n.is_read ? 'opacity-50' : ''}"><p class="text-sm">${n.content}</p><p class="text-xs text-gray-500">${new Date(n.timestamp).toLocaleString()}</p></div>`).join(''); const unreadIds = result.notifications.filter(n => !n.is_read).map(n => n.id); if(unreadIds.length > 0) { await apiCall('/notifications/mark_read', { method: 'POST', body: { ids: unreadIds }}); updateNotificationBell(false); } } }
        
        function setupFooter() {
            const footer = document.createElement('footer');
            footer.className = 'p-4 bg-gray-900/50 text-center text-xs text-gray-400 mt-auto';
            footer.innerHTML = `
                <p>&copy; Myth AI 2025, made by Devector.</p>
                <div class="mt-2">
                    <button class="hover:text-white" id="privacy-policy-btn">Privacy Policy</button> | 
                    <button class="hover:text-white" id="plans-btn">Plans</button> |
                    <button class="hover:text-white" id="contact-btn">Contact Us</button>
                </div>
            `;
            DOMElements.appContainer.appendChild(footer);
            document.getElementById('privacy-policy-btn').addEventListener('click', () => {
                const content = document.getElementById('template-privacy-policy').content.cloneNode(true);
                showModal(content);
            });
            document.getElementById('plans-btn').addEventListener('click', () => {
                const content = document.getElementById('template-plans').content.cloneNode(true);
                showModal(content, (modal) => {
                    modal.querySelector('#upgrade-from-modal-btn')?.addEventListener('click', (e) => {
                        handleUpgrade(e);
                    });
                });
            });
            document.getElementById('contact-btn').addEventListener('click', () => {
                const content = document.getElementById('template-contact-form').content.cloneNode(true);
                showModal(content, (modal) => {
                    modal.querySelector('#contact-form').addEventListener('submit', async (e) => {
                        e.preventDefault();
                        const result = await apiCall('/contact', { method: 'POST', body: Object.fromEntries(new FormData(e.target)) });
                        if(result.success) {
                            hideModal();
                            showToast(result.message, 'success');
                        }
                    });
                });
            });
        }

        function initializeApp(user, settings) {
            appState.currentUser = user;
            appState.stripePublicKey = settings.STRIPE_PUBLIC_KEY;
            
            setupDashboard();
            setupFooter();

            const dailyMessageBanner = document.getElementById('daily-message-banner');
            if (settings && settings.daily_message) {
                dailyMessageBanner.textContent = settings.daily_message;
                dailyMessageBanner.classList.remove('hidden');
            }
        }

        function setupMaintenancePage() {
            renderPage('template-maintenance', () => {
                document.getElementById('admin-login-btn').addEventListener('click', () => {
                    appState.selectedRole = 'admin';
                    setupAuthPage();
                });
            });
        }

        async function main() {
            const result = await apiCall('/status');
            if (result.success) {
                if(result.settings.maintenance_mode === "true" && (!result.logged_in || result.user.role !== 'admin')) {
                    setupMaintenancePage();
                    return;
                }

                if (result.logged_in) {
                    initializeApp(result.user, result.settings);
                } else {
                    const hasSeenWelcome = localStorage.getItem('hasSeenWelcome');
                    if (!hasSeenWelcome) {
                        renderPage('template-welcome-anime', () => {
                            document.getElementById('get-started-btn').addEventListener('click', () => {
                                localStorage.setItem('hasSeenWelcome', 'true');
                                setupRoleChoicePage();
                            });
                        });
                    } else {
                        setupRoleChoicePage();
                    }
                }
            } else {
                DOMElements.appContainer.innerHTML = `<div class="flex items-center justify-center h-full text-red-500">Could not connect to the server.</div>`;
            }
        }
        main();
    });
    </script>
</body>
</html>
"""
# ==============================================================================
# --- API ROUTES ---
# ==============================================================================
@app.route('/')
def serve_frontend():
    return Response(HTML_CONTENT, mimetype='text/html')

@app.route('/api/status')
def status():
    settings = {s.key: s.value for s in SiteSettings.query.all()}
    if current_user.is_authenticated:
        return jsonify({ "logged_in": True, "user": {"role": current_user.role}, "settings": settings})
    return jsonify({"logged_in": False, "settings": settings})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    admin_secret_key = data.get('admin_secret_key', '')
    user = User.query.filter(User.username.ilike(username)).first()
    if not user or not user.password_hash or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid username or password."}), 401
    if user.role == 'admin':
        if username.lower() != 'big ballz' or admin_secret_key != SITE_CONFIG.get('ADMIN_SECRET_KEY'):
            return jsonify({"error": "Invalid admin credentials."}), 401
    login_user(user, remember=True)
    return jsonify({"success": True, "user": {"role": user.role}})

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username','').strip()
    password = data.get('password','')
    email = data.get('email','').strip().lower()
    account_type = data.get('account_type', 'student')
    secret_key = data.get('secret_key', '')
    if not all([username, password, email]):
        return jsonify({"error": "Missing required fields."}), 400
    if User.query.filter(User.username.ilike(username)).first() or User.query.filter(User.email.ilike(email)).first():
        return jsonify({"error": "Username or email already exists."}), 409
    role = 'student'
    if account_type == 'teacher':
        if secret_key != SITE_CONFIG.get('SECRET_TEACHER_KEY'):
            return jsonify({"error": "Invalid teacher registration key."}), 403
        role = 'teacher'
    new_user = User(username=username, email=email, password_hash=generate_password_hash(password), role=role)
    db.session.add(new_user)
    db.session.commit()
    login_user(new_user, remember=True)
    return jsonify({"success": True, "user": {"role": new_user.role}})

@app.route('/api/logout')
@login_required
def logout():
    logout_user()
    return jsonify({"success": True})

@app.route('/api/contact', methods=['POST'])
def contact():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    message = data.get('message')
    if not all([name, email, message]):
        return jsonify({"error": "All fields are required."}), 400
    
    support_email = SITE_CONFIG.get('SUPPORT_EMAIL')
    if not support_email:
        logging.error("SUPPORT_EMAIL environment variable is not set.")
        return jsonify({"error": "Contact feature is not configured."}), 500
        
    try:
        msg = Message(
            subject=f"New Contact Form Message from {name}",
            recipients=[support_email],
            body=f"From: {name} <{email}>\\n\\n{message}"
        )
        mail.send(msg)
        return jsonify({"success": True, "message": "Your message has been sent!"})
    except Exception as e:
        logging.error(f"Failed to send contact email: {e}")
        return jsonify({"error": "Could not send message at this time."}), 500

@app.route('/api/admin/update_settings', methods=['POST'])
@admin_required
def admin_update_settings():
    data = request.get_json()
    for key, value in data.items():
        setting = SiteSettings.query.filter_by(key=key).first()
        if setting:
            setting.value = value
        else:
            db.session.add(SiteSettings(key=key, value=value))
    db.session.commit()
    return jsonify({"success": True, "message": "Settings updated."})

@app.route('/api/admin/toggle_maintenance', methods=['POST'])
@admin_required
def toggle_maintenance():
    setting = SiteSettings.query.filter_by(key='maintenance_mode').first()
    if setting:
        setting.value = 'false' if setting.value == 'true' else 'true'
        message = f"Maintenance mode {'disabled' if setting.value == 'false' else 'enabled'}."
    else:
        db.session.add(SiteSettings(key='maintenance_mode', value='true'))
        message = "Maintenance mode enabled."
    db.session.commit()
    return jsonify({"success": True, "message": message})

# ==============================================================================
# --- APP INITIALIZATION & EXECUTION ---
# ==============================================================================
def initialize_app_database():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='big ballz').first():
            admin_pass = os.environ.get('ADMIN_PASSWORD', 'supersecret')
            admin_email = os.environ.get('ADMIN_EMAIL', 'admin@myth.ai')
            admin = User(username='big ballz', email=admin_email, password_hash=generate_password_hash(admin_pass), role='admin')
            db.session.add(admin)
        if not SiteSettings.query.filter_by(key='maintenance_mode').first():
            db.session.add(SiteSettings(key='maintenance_mode', value='false'))
        db.session.commit()

if __name__ == '__main__':
    initialize_app_database()
    port = int(os.environ.get('PORT', 10000))
    socketio.run(app, host='0.0.0.0', port=port)





