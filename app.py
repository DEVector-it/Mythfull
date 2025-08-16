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
csp = {
    'default-src': '\'self\'',
    'script-src': [
        '\'self\'',
        '\'unsafe-inline\'', # Needed for inline script block
        'https://cdn.tailwindcss.com',
        'https://cdnjs.cloudflare.com',
        'https://js.stripe.com',
        'https://pagead2.googlesyndication.com',
        'https://www.googletagmanager.com'
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
    'img-src': '*', 'data:',
    'connect-src': ['\'self\'', f'wss://{prod_origin.split("//")[-1]}' if prod_origin else '*', 'https://api.stripe.com', 'https://www.google-analytics.com']
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
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='student')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    has_subscription = db.Column(db.Boolean, default=False)
    stripe_customer_id = db.Column(db.String(120), nullable=True, index=True)
    ai_persona = db.Column(db.String(500), nullable=True, default=None)
    theme_preference = db.Column(db.String(50), nullable=True, default='golden')
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
        profile_data = {'bio': '', 'avatar': ''}
        if self.profile:
            profile_data['bio'] = self.profile.bio or ''
            profile_data['avatar'] = self.profile.avatar or ''
        return {
            'id': self.id, 'username': self.username, 'email': self.email, 'role': self.role,
            'created_at': self.created_at.isoformat(), 'has_subscription': self.has_subscription,
            'profile': profile_data, 'ai_persona': self.ai_persona, 'theme_preference': self.theme_preference,
            'points': self.points
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
    question_type = db.Column(db.String(50), nullable=False, default='multiple_choice')
    # For 'multiple_choice', choices = {"options": ["A", "B", "C"], "correct_answer": "A"}
    choices = db.Column(db.JSON, nullable=False)
    quiz = db.relationship('Quiz', back_populates='questions')

class QuizAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id', ondelete='CASCADE'), nullable=False)
    student_id = db.Column(db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    score = db.Column(db.Float, nullable=True)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    # answers = { "question_id": "user_answer", ... }
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

# NEW: Gamification Models
class Achievement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False) # e.g., 'first_class_joined'
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
            # Admin can access everything
            if current_user.role == 'admin':
                return f(*args, **kwargs)
            # Check for specific role
            if isinstance(role_name, list):
                if current_user.role not in role_name:
                    return jsonify({"error": "Access denied."}), 403
            elif current_user.role != role_name:
                return jsonify({"error": f"{role_name.capitalize()} access required."}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

admin_required = role_required('admin')
teacher_required = role_required('teacher')

# ==============================================================================
# --- 4. HELPER FUNCTIONS ---
# ==============================================================================
def generate_code(length=8):
    return secrets.token_urlsafe(length)[:length].upper().replace('_', 'X').replace('-', 'Y')

def send_email(to, subject, template):
    msg = Message(subject, recipients=[to], html=template, sender=app.config['MAIL_DEFAULT_SENDER'])
    try:
        mail.send(msg)
        return True
    except Exception as e:
        logging.error(f"Failed to send email to {to}: {e}")
        return False
        
def notify_user(user, content):
    """Creates a notification for a user and emits it via SocketIO."""
    notification = Notification(user_id=user.id, content=content)
    db.session.add(notification)
    db.session.commit()
    socketio.emit('new_notification', {'content': content}, room=f'user_{user.id}')

def award_achievement(user, achievement_name):
    """Awards an achievement to a user if they don't have it already."""
    achievement = Achievement.query.filter_by(name=achievement_name).first()
    if not achievement:
        logging.warning(f"Achievement '{achievement_name}' not found in database.")
        return

    existing_achievement = UserAchievement.query.filter_by(user_id=user.id, achievement_id=achievement.id).first()
    if not existing_achievement:
        new_user_achievement = UserAchievement(user_id=user.id, achievement_id=achievement.id)
        user.points += achievement.points
        db.session.add(new_user_achievement)
        db.session.commit()
        notify_user(user, f"Achievement Unlocked: {achievement.description}! (+{achievement.points} points)")

# ==============================================================================
# --- 5. FRONTEND & CORE ROUTES ---
# ==============================================================================
def get_safe_html_content():
    # Fix the f-string syntax by correctly escaping curly braces for Jinja2
    return f"""
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
        :root {{
            --brand-hue: 45; --bg-dark: #1A120B; --bg-med: #2c241e; --bg-light: #4a3f35;
            --glow-color: hsl(var(--brand-hue), 90%, 60%); --text-color: #F5EFE6; --text-secondary-color: #AE8E6A;
        }}
        body {{ background-color: var(--bg-dark); font-family: 'Inter', sans-serif; color: var(--text-color); }}
        .font-title {{ font-family: 'Cinzel Decorative', cursive; }}
        .glassmorphism {{ background: rgba(44, 36, 30, 0.5); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); border: 1px solid rgba(255, 215, 0, 0.1); }}
        .brand-gradient-text {{ background-image: linear-gradient(120deg, hsl(var(--brand-hue), 90%, 60%), hsl(var(--brand-hue), 80%, 50%)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; text-shadow: 0 0 10px hsla(var(--brand-hue), 80%, 50%, 0.3); }}
        .brand-gradient-bg {{ background-image: linear-gradient(120deg, hsl(var(--brand-hue), 85%, 55%), hsl(var(--brand-hue), 90%, 50%)); }}
        .shiny-button {{ transition: all 0.3s ease; box-shadow: 0 0 5px rgba(0,0,0,0.5), 0 0 10px var(--glow-color, #fff) inset; }}
        .shiny-button:hover {{ transform: translateY(-2px); box-shadow: 0 4px 15px hsla(var(--brand-hue), 70%, 40%, 0.4), 0 0 5px var(--glow-color, #fff) inset; }}
        .fade-in {{ animation: fadeIn 0.5s ease-out forwards; }} @keyframes fadeIn {{ from {{ opacity: 0; transform: translateY(-10px); }} to {{ opacity: 1; transform: translateY(0); }} }}
        .active-tab {{ background-color: var(--bg-light) !important; color: white !important; position:relative; }}
        .active-tab::after {{ content: ''; position: absolute; bottom: 0; left: 10%; width: 80%; height: 2px; background: var(--glow-color); border-radius: 2px; }}
        .modal-overlay {{ position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); display: flex; align-items: center; justify-content: center; z-index: 1000; }}
        .ai-message .chat-bubble {{ background-color: #4a3f35; border-color: #AE8E6A; }}
        .user-message .chat-bubble {{ background-color: #2c241e; border-color: #F5EFE6; }}
        .dynamic-bg {{
            background: linear-gradient(-45deg, #1a120b, #4a3f35, #b48a4f, #1a120b);
            background-size: 400% 400%;
            animation: gradientBG 20s ease infinite;
        }}
        @keyframes gradientBG {{ 0% {{ background-position: 0% 50%; }} 50% {{ background-position: 100% 50%; }} 100% {{ background-position: 0% 50%; }} }}
        .full-screen-loader {{
            position: fixed; top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(26, 18, 11, 0.9); backdrop-filter: blur(8px);
            display: flex; align-items: center; justify-content: center;
            flex-direction: column; z-index: 1001; transition: opacity 0.3s ease;
        }}
        .loader-dots {{ display: flex; gap: 1rem; }}
        .loader-dots div {{ width: 1rem; height: 1rem; background-color: hsl(var(--brand-hue), 90%, 60%); border-radius: 50%; animation: bounce 1.4s infinite ease-in-out both; }}
        .loader-dots .dot1 {{ animation-delay: -0.32s; }}
        .loader-dots .dot2 {{ animation-delay: -0.16s; }}
        @keyframes bounce {{ 0%, 80%, 100% {{ transform: scale(0); }} 40% {{ transform: scale(1.0); }} }}
        .waiting-text {{ margin-top: 2rem; font-size: 1.25rem; color: var(--text-secondary-color); animation: pulse 2s infinite; }}
        @keyframes pulse {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0.7; }} }}
        [x-cloak] {{ display: none !important; }}
    </style>
    <meta name="csrf-token" content="{{{{ csrf_token() }}}}">
</head>
<body class="text-gray-200 antialiased">
    <div id="app-container" class="relative min-h-screen w-full overflow-x-hidden flex flex-col"></div>
    <div id="toast-container" class="fixed top-6 right-6 z-[100] flex flex-col gap-2"></div>
    <div id="modal-container"></div>
    <div class="fixed bottom-4 left-4 text-xs text-gray-500">Made by DeVector</div>
    <audio id="background-music" loop></audio>
    <script>
        const SITE_CONFIG = {{
            STRIPE_PUBLIC_KEY: '{escape(SITE_CONFIG.get("STRIPE_PUBLIC_KEY", ""))}',
            STRIPE_STUDENT_PRO_PRICE_ID: '{escape(SITE_CONFIG.get("STRIPE_STUDENT_PRO_PRICE_ID", ""))}'
        }};
    </script>

    <template id="template-full-screen-loader">
        <div class="full-screen-loader">
            <div id="logo-container-loader" class="w-24 h-24 mb-4"></div>
            <div class="loader-dots">
                <div class="dot1"></div><div class="dot2"></div><div class="dot3"></div>
            </div>
            <p class="waiting-text">Loading Portal...</p>
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

    <template id="template-main-dashboard">
        <div class="flex h-screen bg-bg-dark">
            <aside class="w-64 bg-bg-med p-4 flex flex-col glassmorphism border-r border-gray-700/50">
                <div class="flex items-center gap-2 mb-8">
                    <div id="logo-container-dash" class="w-10 h-10"></div>
                    <h1 id="dashboard-title" class="text-xl font-bold text-white"></h1>
                </div>
                <nav id="nav-links" class="flex-1 flex flex-col gap-2"></nav>
                <div class="mt-auto">
                    <div id="notification-bell-container" class="relative mb-2"></div>
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
    
    <template id="template-my-classes">
        <div class="fade-in">
            <h2 class="text-3xl font-bold mb-6 text-white">My Classes</h2>
            <div id="class-action-container" class="mb-6"></div>
            <div id="classes-list" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4"></div>
            <div id="selected-class-view" class="hidden"></div>
        </div>
    </template>
    
    <template id="template-team-mode">
        <div class="fade-in">
            <h2 class="text-3xl font-bold mb-6 text-white">Team Mode</h2>
            <div id="team-action-container" class="mb-6"></div>
            <div id="teams-list" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4"></div>
        </div>
    </template>
    
    <template id="template-student-class-action">
        <div class="glassmorphism p-4 rounded-lg flex items-center gap-4">
            <input id="class-code" type="text" placeholder="Enter Class Code" class="flex-grow p-2 bg-gray-700/50 rounded-md border border-gray-600">
            <button id="join-class-btn" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Join Class</button>
        </div>
    </template>

    <template id="template-teacher-class-action">
         <div class="glassmorphism p-4 rounded-lg flex items-center gap-4">
            <input id="new-class-name" type="text" placeholder="New Class Name" class="flex-grow p-2 bg-gray-700/50 rounded-md border border-gray-600">
            <button id="create-class-btn" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Create Class</button>
        </div>
    </template>
    
    <template id="template-team-actions">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div class="glassmorphism p-4 rounded-lg flex items-center gap-4">
                <input id="team-code" type="text" placeholder="Enter Team Code" class="flex-grow p-2 bg-gray-700/50 rounded-md border border-gray-600">
                <button id="join-team-btn" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Join Team</button>
            </div>
            <div class="glassmorphism p-4 rounded-lg flex items-center gap-4">
                <input id="new-team-name" type="text" placeholder="New Team Name" class="flex-grow p-2 bg-gray-700/50 rounded-md border border-gray-600">
                <button id="create-team-btn" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Create Team</button>
            </div>
        </div>
    </template>

    <template id="template-selected-class-view">
        <div class="fade-in">
            <div class="flex items-center mb-4">
                <button id="back-to-classes-btn" class="mr-4 text-gray-400 hover:text-white">&larr; Back</button>
                <h3 id="selected-class-name" class="text-2xl font-bold text-white"></h3>
            </div>
            <div class="flex border-b border-gray-700 mb-4">
                <button data-tab="chat" class="class-view-tab py-2 px-4 text-gray-300 hover:text-white">Chat</button>
                <button data-tab="assignments" class="class-view-tab py-2 px-4 text-gray-300 hover:text-white">Assignments</button>
                <button data-tab="quizzes" class="class-view-tab py-2 px-4 text-gray-300 hover:text-white">Quizzes</button>
                <button data-tab="students" class="class-view-tab py-2 px-4 text-gray-300 hover:text-white">Students</button>
            </div>
            <div id="class-view-content"></div>
        </div>
    </template>

    <template id="template-class-chat-view">
        <div class="flex flex-col h-[calc(100vh-12rem)]">
            <div id="chat-messages" class="flex-1 overflow-y-auto p-4 space-y-4"></div>
            <div id="smart-replies-container" class="p-2 flex gap-2"></div>
            <form id="chat-form" class="p-4 bg-bg-med glassmorphism mt-2 rounded-lg">
                <div class="flex items-center gap-2">
                    <input id="chat-input" type="text" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="Type a message..." autocomplete="off">
                    <button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-3 px-5 rounded-lg">Send</button>
                </div>
            </form>
        </div>
    </template>
    
    <template id="template-class-assignments-view">
        <div id="assignment-action-container" class="mb-4"></div>
        <div id="assignments-list" class="space-y-4"></div>
    </template>
    
    <template id="template-class-quizzes-view">
        <div id="quiz-action-container" class="mb-4"></div>
        <div id="quizzes-list" class="space-y-4"></div>
    </template>

    <template id="template-class-students-view">
        <div id="students-list" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4"></div>
    </template>
    
    <template id="template-study-guide-tab">
        <div class="fade-in max-w-4xl mx-auto">
            <h2 class="text-3xl font-bold mb-2 text-white">AI Study Guide</h2>
            <p class="text-gray-400 mb-6">Enter a topic, and our AI will generate a concise study guide for you.</p>
            <form id="study-guide-form" class="glassmorphism p-4 rounded-lg flex items-center gap-4 mb-6">
                 <input id="study-guide-topic" type="text" placeholder="e.g., 'The process of photosynthesis'" class="flex-grow p-3 bg-gray-700/50 rounded-md border border-gray-600">
                 <button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-3 px-5 rounded-lg">Generate</button>
            </form>
            <div id="study-guide-result" class="glassmorphism p-6 rounded-lg min-h-[200px] prose prose-invert max-w-none">
                <p class="text-gray-500">Your study guide will appear here.</p>
            </div>
        </div>
    </template>
    
    <template id="template-profile">
        <div class="fade-in max-w-2xl">
            <h2 class="text-3xl font-bold mb-6 text-white">My Profile</h2>
            <form id="profile-form" class="glassmorphism p-6 rounded-lg space-y-4">
                <div>
                    <label for="bio" class="block text-sm font-medium text-gray-300 mb-1">Bio</label>
                    <textarea id="bio" name="bio" rows="4" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600"></textarea>
                </div>
                 <div>
                    <label for="avatar" class="block text-sm font-medium text-gray-300 mb-1">Avatar URL</label>
                    <input id="avatar" name="avatar" type="url" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600">
                </div>
                <button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Save Changes</button>
            </form>
        </div>
    </template>

    <template id="template-billing">
         <div class="fade-in max-w-2xl">
            <h2 class="text-3xl font-bold mb-6 text-white">Billing & Subscription</h2>
            <div id="billing-content" class="glassmorphism p-6 rounded-lg"></div>
        </div>
    </template>
    
    <template id="template-admin-dashboard">
        <div class="fade-in">
            <h2 class="text-3xl font-bold mb-6 text-white">Admin Dashboard</h2>
            <div id="admin-stats" class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6"></div>
            <div class="flex border-b border-gray-700 mb-4">
                <button data-tab="users" class="admin-view-tab py-2 px-4 text-gray-300 hover:text-white">Users</button>
                <button data-tab="classes" class="admin-view-tab py-2 px-4 text-gray-300 hover:text-white">Classes</button>
                <button data-tab="settings" class="admin-view-tab py-2 px-4 text-gray-300 hover:text-white">Settings</button>
                <button data-tab="music" class="admin-view-tab py-2 px-4 text-gray-300 hover:text-white">Music</button>
            </div>
            <div id="admin-view-content"></div>
        </div>
    </template>
    
    <template id="template-admin-users-view">
        <div class="overflow-x-auto glassmorphism rounded-lg">
            <table class="w-full text-left">
                <thead class="bg-gray-800/50"><tr><th class="p-3">Username</th><th class="p-3">Email</th><th class="p-3">Role</th><th class="p-3">Joined</th><th class="p-3">Actions</th></tr></thead>
                <tbody id="admin-user-list"></tbody>
            </table>
        </div>
    </template>
    
    <template id="template-admin-classes-view">
        <div class="overflow-x-auto glassmorphism rounded-lg">
            <table class="w-full text-left">
                <thead class="bg-gray-800/50"><tr><th class="p-3">Name</th><th class="p-3">Teacher</th><th class="p-3">Code</th><th class="p-3">Students</th><th class="p-3">Actions</th></tr></thead>
                <tbody id="admin-class-list"></tbody>
            </table>
        </div>
    </template>
    
    <template id="template-admin-settings-view">
        <div class="grid md:grid-cols-2 gap-6">
            <form id="admin-settings-form" class="glassmorphism p-6 rounded-lg space-y-4">
                 <div>
                    <label for="setting-announcement" class="block text-sm font-medium text-gray-300 mb-1">Site Announcement</label>
                    <input id="setting-announcement" name="announcement" class="w-full p-2 bg-gray-700/50 rounded-md border border-gray-600">
                </div>
                 <div>
                    <label for="ai-persona-input" class="block text-sm font-medium text-gray-300 mb-1">Global AI Persona</label>
                    <textarea id="ai-persona-input" name="ai_persona" rows="3" class="w-full p-2 bg-gray-700/50 rounded-md border border-gray-600"></textarea>
                </div>
                <button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Save Settings</button>
            </form>
            <div class="glassmorphism p-6 rounded-lg space-y-4">
                <div>
                    <h3 class="font-bold text-lg">Site Controls</h3>
                    <button id="maintenance-toggle-btn" class="mt-2 bg-yellow-600 hover:bg-yellow-700 text-white font-bold py-2 px-4 rounded-lg">Toggle Maintenance Mode</button>
                </div>
                 <div>
                    <h3 class="font-bold text-lg">Admin Management</h3>
                    <button id="generate-admin-link-btn" class="mt-2 bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded-lg">Generate Admin Signup Link</button>
                </div>
            </div>
        </div>
    </template>
    
    <template id="template-admin-music-view">
        <div class="glassmorphism p-6 rounded-lg">
            <h3 class="font-bold text-lg mb-4">Background Music</h3>
            <div class="flex gap-4 mb-4">
                <input id="music-name" placeholder="Song Name" class="flex-grow p-2 bg-gray-700/50 rounded-md border border-gray-600">
                <input id="music-url" placeholder="Song URL" class="flex-grow p-2 bg-gray-700/50 rounded-md border border-gray-600">
                <button id="add-music-btn" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Add</button>
            </div>
            <ul id="music-list" class="space-y-2"></ul>
        </div>
    </template>
    
    <template id="template-modal">
        <div class="modal-overlay">
            <div class="modal-content glassmorphism rounded-lg w-full p-6 relative">
                <button class="absolute top-2 right-2 text-2xl text-gray-400 hover:text-white">&times;</button>
                <div class="modal-body"></div>
            </div>
        </div>
    </template>
    <script>
    document.addEventListener('DOMContentLoaded', () => {
        const BASE_URL = '';
        
        const themes = {
            golden: { '--brand-hue': 45, '--bg-dark': '#1A120B', '--bg-med': '#2c241e', '--bg-light': '#4a3f35', '--text-color': '#F5EFE6', '--text-secondary-color': '#AE8E6A' },
            dark: { '--brand-hue': 220, '--bg-dark': '#0F172A', '--bg-med': '#1E293B', '--bg-light': '#334155', '--text-color': '#E2E8F0', '--text-secondary-color': '#94A3B8' },
            light: { '--brand-hue': 200, '--bg-dark': '#F1F5F9', '--bg-med': '#E2E8F0', '--bg-light': '#CBD5E1', '--text-color': '#1E293B', '--text-secondary-color': '#475569' },
            blue: { '--brand-hue': 210, '--bg-dark': '#0c1d3a', '--bg-med': '#1a2c4e', '--bg-light': '#2e4570', '--text-color': '#dbe8ff', '--text-secondary-color': '#a0b3d1' },
            purple: { '--brand-hue': 260, '--bg-dark': '#1e1b3b', '--bg-med': '#2d2852', '--bg-light': '#453f78', '--text-color': '#e6e3ff', '--text-secondary-color': '#b8b4d9' },
        };

        const appState = { currentUser: null, currentTab: 'my-classes', selectedClass: null, socket: null, stripe: null, quizTimer: null, isLoginView: true, selectedRole: null };
        const DOMElements = { appContainer: document.getElementById('app-container'), toastContainer: document.getElementById('toast-container'), modalContainer: document.getElementById('modal-container'), backgroundMusic: document.getElementById('background-music') };
        
        const svgLogo = `
            <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
                <defs>
                    <linearGradient id="logoGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" style="stop-color:hsl(var(--brand-hue), 90%, 60%);" />
                        <stop offset="100%" style="stop-color:hsl(var(--brand-hue), 80%, 50%);" />
                    </linearGradient>
                </defs>
                <path fill="url(#logoGradient)" d="M50,5 C74.85,5 95,25.15 95,50 C95,74.85 74.85,95 50,95 C25.15,95 5,74.85 5,50 C5,25.15 25.15,5 50,5 Z M50,15 C30.67,15 15,30.67 15,50 C15,69.33 30.67,85 50,85 C69.33,85 85,69.33 85,50 C85,30.67 69.33,15 50,15 Z" />
                <path fill="white" d="M50,30 C55.52,30 60,34.48 60,40 L60,60 C60,65.52 55.52,70 50,70 C44.48,70 40,65.52 40,60 L40,40 C40,34.48 44.48,30 50,30 Z" />
            </svg>`;
        
        const aiAvatarSvg = 'data:image/svg+xml;base64,' + btoa(svgLogo);

        function injectLogo() { document.querySelectorAll('[id^="logo-container-"]').forEach(container => { container.innerHTML = svgLogo; }); }
        function applyTheme(themeName) { const theme = themes[themeName]; if (theme) { for (const [key, value] of Object.entries(theme)) { document.documentElement.style.setProperty(key, value); }} }
        function showToast(message, type = 'info') { const colors = { info: 'bg-blue-600', success: 'bg-green-600', error: 'bg-red-600' }; const toast = document.createElement('div'); toast.className = `text-white text-sm py-2 px-4 rounded-lg shadow-lg fade-in ${colors[type]}`; toast.textContent = message; DOMElements.toastContainer.appendChild(toast); setTimeout(() => { toast.style.transition = 'opacity 0.5s ease'; toast.style.opacity = '0'; setTimeout(() => toast.remove(), 500); }, 3500); }
        
        async function apiCall(endpoint, options = {}) {
            try {
                const csrfToken = document.querySelector('meta[name="csrf-token"]').content;
                if (!options.headers) { options.headers = {}; }
                options.headers['X-CSRFToken'] = csrfToken;
                
                if (options.body && typeof options.body === 'object' && ! (options.body instanceof FormData)) {
                    options.headers['Content-Type'] = 'application/json';
                    options.body = JSON.stringify(options.body);
                }

                const response = await fetch(`${BASE_URL}/api${endpoint}`, { credentials: 'include', ...options });
                
                let data;
                const contentType = response.headers.get("content-type");
                if (contentType && contentType.indexOf("application/json") !== -1) {
                    data = await response.json();
                } else {
                    data = { text: await response.text() };
                }

                if (!response.ok) {
                    if (response.status === 401 && endpoint !== '/status') handleLogout(false);
                    throw new Error(data.error || `Request failed with status ${response.status}`);
                }
                return { success: true, ...data };
            } catch (error) {
                showToast(error.message, 'error');
                console.error("API Call Error:", error);
                return { success: false, error: error.message };
            }
        }

        function renderPage(templateId, setupFunction) { const template = document.getElementById(templateId); if (!template) { console.error(`Template ${templateId} not found.`); return; } const content = template.content.cloneNode(true); DOMElements.appContainer.innerHTML = ''; DOMElements.appContainer.appendChild(content); if (setupFunction) setupFunction(); injectLogo(); }
        function renderSubTemplate(container, templateId, setupFunction) { const template = document.getElementById(templateId); if (!template) return; const content = template.content.cloneNode(true); container.innerHTML = ''; container.appendChild(content); if (setupFunction) setupFunction(); }
        function showModal(content, setupFunction, maxWidth = 'max-w-2xl') { const template = document.getElementById('template-modal').content.cloneNode(true); const modalBody = template.querySelector('.modal-body'); if(typeof content === 'string') { modalBody.innerHTML = content; } else { modalBody.innerHTML = ''; modalBody.appendChild(content); } template.querySelector('.modal-content').classList.replace('max-w-2xl', maxWidth); template.querySelector('button').addEventListener('click', hideModal); DOMElements.modalContainer.innerHTML = ''; DOMElements.modalContainer.appendChild(template); if(setupFunction) setupFunction(DOMElements.modalContainer); }
        function hideModal() { DOMElements.modalContainer.innerHTML = ''; }
        function showFullScreenLoader(message = 'Loading...') { const loaderTemplate = document.getElementById('template-full-screen-loader'); const loaderContent = loaderTemplate.content.cloneNode(true); loaderContent.querySelector('.waiting-text').textContent = message; DOMElements.appContainer.innerHTML = ''; DOMElements.appContainer.appendChild(loaderContent); injectLogo(); }
        function connectSocket() { if (appState.socket) appState.socket.disconnect(); appState.socket = io(BASE_URL); appState.socket.on('connect', () => { console.log('Socket connected!'); appState.socket.emit('join', { room: `user_${appState.currentUser.id}` }); }); appState.socket.on('new_message', (data) => { if (appState.selectedClass && data.class_id === appState.selectedClass.id) { appendChatMessage(data); getSmartReplies(); } }); appState.socket.on('new_notification', (data) => { showToast(`Notification: ${data.content}`, 'info'); updateNotificationBell(true); }); }
        
        function setupRoleChoicePage() { renderPage('template-role-choice', () => { document.querySelectorAll('.role-btn').forEach(btn => { btn.addEventListener('click', (e) => { appState.selectedRole = e.currentTarget.dataset.role; setupAuthPage(); }); }); }); }
        function setupMaintenancePage() { renderPage('template-maintenance-page', () => { document.getElementById('admin-login-btn').addEventListener('click', () => { appState.selectedRole = 'admin'; setupAuthPage(); }); }); }
        function setupAuthPage(token = null) { appState.isLoginView = !token; renderPage('template-auth-form', () => { if(token) { document.getElementById('admin_signup_token').value = token; } updateAuthView(); document.getElementById('auth-form').addEventListener('submit', handleAuthSubmit); document.getElementById('auth-toggle-btn').addEventListener('click', () => { appState.isLoginView = !appState.isLoginView; updateAuthView(); }); document.getElementById('forgot-password-link').addEventListener('click', handleForgotPassword); document.getElementById('back-to-roles').addEventListener('click', main); }); }
        function updateAuthView() {
            const isLogin = appState.isLoginView;
            const role = appState.selectedRole;
            const title = document.getElementById('auth-title'), subtitle = document.getElementById('auth-subtitle');
            const submitBtn = document.getElementById('auth-submit-btn'), toggleBtn = document.getElementById('auth-toggle-btn');
            const emailField = document.getElementById('email-field'), teacherKeyField = document.getElementById('teacher-key-field');
            const adminKeyField = document.getElementById('admin-key-field'), backToRolesBtn = document.getElementById('back-to-roles');
            const adminTokenInput = document.getElementById('admin_signup_token');
            document.getElementById('account_type').value = role;
            title.textContent = `${role.charAt(0).toUpperCase() + role.slice(1)} Portal`;
            
            adminKeyField.classList.add('hidden');
            teacherKeyField.classList.add('hidden');
            backToRolesBtn.classList.remove('hidden');
            toggleBtn.classList.remove('hidden');

            if (adminTokenInput.value) { // Admin signup via link
                appState.isLoginView = false;
                appState.selectedRole = 'admin';
                document.getElementById('account_type').value = 'admin';
                title.textContent = 'Create New Admin Account';
                subtitle.textContent = 'Complete the form below to register.';
                backToRolesBtn.classList.add('hidden');
                toggleBtn.classList.add('hidden');
            } else if (role === 'admin') {
                toggleBtn.classList.add('hidden'); // No signup for admin
            }
            
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

        async function handleAuthSubmit(e) { e.preventDefault(); const form = e.target; const endpoint = appState.isLoginView ? '/login' : '/signup'; const body = Object.fromEntries(new FormData(form)); const result = await apiCall(endpoint, { method: 'POST', body }); if (result.success) { if (body.admin_signup_token) { showToast('Admin account created! Please log in.', 'success'); setTimeout(() => window.location.href = '/', 2000); } else { handleLoginSuccess(result.user, result.settings); }} else { document.getElementById('auth-error').textContent = result.error; } }
        function handleLoginSuccess(user, settings) { appState.currentUser = user; if (user.theme_preference) { applyTheme(user.theme_preference); } renderPage('template-full-screen-loader', () => { setTimeout(() => { setupDashboard(user, settings); }, 1500); }); }
        
        function setupDashboard(user, settings) { if (!user) return setupAuthPage(); connectSocket(); renderPage('template-main-dashboard', () => { const navLinks = document.getElementById('nav-links'); const dashboardTitle = document.getElementById('dashboard-title'); let tabs = []; if (user.role === 'student' || user.role === 'teacher') { dashboardTitle.textContent = user.role === 'student' ? "Student Hub" : "Teacher Hub"; appState.currentTab = 'my-classes'; tabs = [ { id: 'my-classes', label: 'My Classes' }, { id: 'team-mode', label: 'Team Mode' }, { id: 'study-guide', label: 'AI Study Guide' }, { id: 'billing', label: 'Billing' }, { id: 'profile', label: 'Profile' } ]; } else if (user.role === 'admin') { dashboardTitle.textContent = "Admin Panel"; appState.currentTab = 'admin-dashboard'; tabs = [ { id: 'admin-dashboard', label: 'Dashboard' }, { id: 'profile', label: 'My Profile' } ]; } navLinks.innerHTML = tabs.map(tab => `<button data-tab="${escape(tab.id)}" class="dashboard-tab text-left text-gray-300 hover:bg-gray-700/50 p-3 rounded-md transition-colors">${escape(tab.label)}</button>`).join(''); document.querySelectorAll('.dashboard-tab').forEach(tab => tab.addEventListener('click', () => switchTab(tab.dataset.tab))); document.getElementById('logout-btn').addEventListener('click', () => handleLogout(true)); setupNotificationBell(); switchTab(appState.currentTab); }); }
        function switchTab(tab) { appState.currentTab = tab; appState.selectedClass = null; document.querySelectorAll('.dashboard-tab').forEach(t => t.classList.toggle('active-tab', t.dataset.tab === tab)); const contentContainer = document.getElementById('dashboard-content'); const setups = { 'my-classes': setupMyClassesTab, 'team-mode': setupTeamModeTab, 'study-guide': setupStudyGuideTab, 'profile': setupProfileTab, 'billing': setupBillingTab, 'admin-dashboard': setupAdminDashboardTab }; if (setups[tab]) setups[tab](contentContainer); }
        async function setupMyClassesTab(container) { renderSubTemplate(container, 'template-my-classes', async () => { const actionContainer = document.getElementById('class-action-container'), listContainer = document.getElementById('classes-list'); const actionTemplateId = `template-${appState.currentUser.role}-class-action`; renderSubTemplate(actionContainer, actionTemplateId, () => { if (appState.currentUser.role === 'student') document.getElementById('join-class-btn').addEventListener('click', handleJoinClass); else document.getElementById('create-class-btn').addEventListener('click', handleCreateClass); }); const result = await apiCall('/my_classes'); if (result.success && result.classes) { if (result.classes.length === 0) listContainer.innerHTML = `<p class="text-gray-400 text-center col-span-full">You haven't joined or created any classes yet.</p>`; else listContainer.innerHTML = result.classes.map(cls => `<div class="glassmorphism p-4 rounded-lg cursor-pointer hover:bg-gray-700/50 transition-colors" data-id="${escape(cls.id)}" data-name="${escape(cls.name)}"><div class="font-bold text-white text-lg">${escape(cls.name)}</div><div class="text-gray-400 text-sm">Teacher: ${escape(cls.teacher_name)}</div>${appState.currentUser.role === 'teacher' ? `<div class="text-sm mt-2">Code: <span class="font-mono text-cyan-400">${escape(cls.code)}</span></div>` : ''}</div>`).join(''); listContainer.querySelectorAll('div[data-id]').forEach(el => el.addEventListener('click', (e) => selectClass(e.currentTarget.dataset.id))); }} }); }
        async function setupTeamModeTab(container) { renderSubTemplate(container, 'template-team-mode', async () => { renderSubTemplate(document.getElementById('team-action-container'), 'template-team-actions', () => { document.getElementById('join-team-btn').addEventListener('click', handleJoinTeam); document.getElementById('create-team-btn').addEventListener('click', handleCreateTeam); }); const listContainer = document.getElementById('teams-list'); const result = await apiCall('/teams'); if (result.success && result.teams) { if (result.teams.length === 0) { listContainer.innerHTML = `<p class="text-gray-400 text-center col-span-full">You are not part of any teams yet.</p>`; } else { listContainer.innerHTML = result.teams.map(team => `<div class="glassmorphism p-4 rounded-lg cursor-pointer hover:bg-gray-700/50 transition-colors" data-id="${escape(team.id)}"><div class="font-bold text-white text-lg">${escape(team.name)}</div><div class="text-gray-400 text-sm">Owner: ${escape(team.owner_name)}</div><div class="text-sm mt-2">Code: <span class="font-mono text-cyan-400">${escape(team.code)}</span></div><div class="text-sm text-gray-400">${escape(String(team.member_count))} members</div></div>`).join(''); listContainer.querySelectorAll('div[data-id]').forEach(el => el.addEventListener('click', e => selectTeam(e.currentTarget.dataset.id))); }} } }); }
        async function selectTeam(teamId) { const result = await apiCall(`/teams/${escape(teamId)}`); if (!result.success) return; const team = result.team; let modalContent = `<h3 class="text-2xl font-bold text-white mb-2">${escape(team.name)}</h3><p class="text-gray-400 mb-4">Team Code: <span class="font-mono text-cyan-400">${escape(team.code)}</span></p><h4 class="text-lg font-semibold text-white mb-2">Members</h4><ul class="space-y-2">${team.members.map(m => `<li class="flex items-center gap-3 p-2 bg-gray-800/50 rounded-md"><img src="${escape(m.profile.avatar || `https://i.pravatar.cc/40?u=${m.id}`)}" class="w-8 h-8 rounded-full"><span>${escape(m.username)} ${m.id === team.owner_id ? '(Owner)' : ''}</span></li>`).join('')}</ul>`; showModal(modalContent); }
        async function handleJoinTeam() { const code = document.getElementById('team-code').value.trim().toUpperCase(); if (!code) return showToast('Please enter a team code.', 'error'); const result = await apiCall('/join_team', { method: 'POST', body: { code } }); if (result.success) { showToast(result.message, 'success'); setupTeamModeTab(document.getElementById('dashboard-content')); } }
        async function handleCreateTeam() { const name = document.getElementById('new-team-name').value.trim(); if (!name) return showToast('Please enter a team name.', 'error'); const result = await apiCall('/teams', { method: 'POST', body: { name } }); if (result.success) { showToast(`Team "${escape(result.team.name)}" created!`, 'success'); setupTeamModeTab(document.getElementById('dashboard-content')); } }
        function setupProfileTab(container) { renderSubTemplate(container, 'template-profile', () => { document.getElementById('bio').value = appState.currentUser.profile.bio || ''; document.getElementById('avatar').value = appState.currentUser.profile.avatar || ''; const themeSelect = document.createElement('select'); themeSelect.id = 'theme-select'; themeSelect.name = 'theme_preference'; themeSelect.className = 'w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600'; themeSelect.innerHTML = Object.keys(themes).map(themeName => `<option value="${escape(themeName)}">${escape(themeName.charAt(0).toUpperCase() + themeName.slice(1))}</option>`).join(''); themeSelect.value = appState.currentUser.theme_preference || 'golden'; const themeControl = document.createElement('div'); themeControl.className = 'mb-4'; themeControl.innerHTML = '<label for="theme-select" class="block text-sm font-medium text-gray-300 mb-1">Theme</label>'; themeControl.appendChild(themeSelect); document.getElementById('profile-form').prepend(themeControl); document.getElementById('profile-form').addEventListener('submit', handleUpdateProfile); }); }
        async function handleUpdateProfile(e) { e.preventDefault(); const form = e.target; const body = Object.fromEntries(new FormData(form)); const result = await apiCall('/update_profile', { method: 'POST', body }); if (result.success) { appState.currentUser.profile = result.profile; appState.currentUser.theme_preference = body.theme_preference; applyTheme(body.theme_preference); showToast('Profile updated!', 'success'); } }
        function setupBillingTab(container) { renderSubTemplate(container, 'template-billing', () => { const content = document.getElementById('billing-content'); if (appState.currentUser.has_subscription) { content.innerHTML = `<p class="mb-4">You have an active subscription.</p><button id="manage-billing-btn" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Manage Billing</button>`; document.getElementById('manage-billing-btn').addEventListener('click', handleManageBilling); } else { content.innerHTML = `<p class="mb-4">Upgrade to a Pro plan for more features!</p><button id="upgrade-btn" data-price-id="${escape(SITE_CONFIG.STRIPE_STUDENT_PRO_PRICE_ID)}" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Upgrade to Pro</button>`; document.getElementById('upgrade-btn').addEventListener('click', handleUpgrade); } }); }
        async function setupAdminDashboardTab(container) { renderSubTemplate(container, 'template-admin-dashboard', async () => { const result = await apiCall('/admin/dashboard_data'); if (result.success) { document.getElementById('admin-stats').innerHTML = Object.entries(result.stats).map(([key, value]) => `<div class="glassmorphism p-4 rounded-lg"><p class="text-sm text-gray-400">${escape(key.replace(/_/g, ' ').replace(/\b\\w/g, l => l.toUpperCase()))}</p><p class="text-2xl font-bold">${escape(String(value))}</p></div>`).join(''); } document.querySelectorAll('.admin-view-tab').forEach(tab => tab.addEventListener('click', (e) => switchAdminView(e.currentTarget.dataset.tab))); switchAdminView('users'); }); }
        async function switchAdminView(view) { document.querySelectorAll('.admin-view-tab').forEach(t => t.classList.toggle('active-tab', t.dataset.tab === view)); const container = document.getElementById('admin-view-content'); const result = await apiCall('/admin/dashboard_data'); if(!result.success) return; if (view === 'users') { renderSubTemplate(container, 'template-admin-users-view', () => { const userList = document.getElementById('admin-user-list'); userList.innerHTML = result.users.map(u => `<tr><td class="p-3">${escape(u.username)}</td><td class="p-3">${escape(u.email)}</td><td class="p-3">${escape(u.role)}</td><td class="p-3">${new Date(u.created_at).toLocaleDateString()}</td><td class="p-3 space-x-2"><button class="text-red-500 hover:text-red-400" data-action="delete" data-id="${escape(u.id)}">Delete</button></td></tr>`).join(''); userList.querySelectorAll('button').forEach(btn => btn.addEventListener('click', (e) => handleAdminUserAction(e.currentTarget.dataset.action, e.currentTarget.dataset.id))); }); } else if (view === 'classes') { renderSubTemplate(container, 'template-admin-classes-view', () => { document.getElementById('admin-class-list').innerHTML = result.classes.map(c => `<tr><td class="p-3">${escape(c.name)}</td><td class="p-3">${escape(c.teacher_name)}</td><td class="p-3">${escape(c.code)}</td><td class="p-3">${escape(String(c.student_count))}</td><td class="p-3"><button class="text-red-500 hover:text-red-400" data-id="${escape(c.id)}">Delete</button></td></tr>`).join(''); document.getElementById('admin-class-list').querySelectorAll('button').forEach(btn => btn.addEventListener('click', (e) => handleAdminDeleteClass(e.currentTarget.dataset.id))); }); } else if (view === 'settings') { renderSubTemplate(container, 'template-admin-settings-view', () => { document.getElementById('setting-announcement').value = result.settings.announcement || ''; document.getElementById('ai-persona-input').value = result.settings.ai_persona || ''; document.getElementById('admin-settings-form').addEventListener('submit', handleAdminUpdateSettings); document.getElementById('maintenance-toggle-btn').addEventListener('click', handleToggleMaintenance); document.getElementById('generate-admin-link-btn').addEventListener('click', handleGenerateAdminLink); }); } else if (view === 'music') { renderSubTemplate(container, 'template-admin-music-view', async () => { const musicListContainer = document.getElementById('music-list'); const musicResult = await apiCall('/admin/music'); if (musicResult.success && musicResult.music) { musicListContainer.innerHTML = musicResult.music.map(m => `<li class="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg"><span>${escape(m.name)}</span><div class="space-x-2"><button class="text-green-400 hover:text-green-300 play-music-btn" data-url="${escape(m.url)}">Play</button><button class="text-red-500 hover:text-red-400 delete-music-btn" data-id="${escape(String(m.id))}">Delete</button></div></li>`).join(''); document.getElementById('add-music-btn').addEventListener('click', handleAddMusic); musicListContainer.querySelectorAll('.play-music-btn').forEach(btn => btn.addEventListener('click', (e) => playBackgroundMusic(e.currentTarget.dataset.url))); musicListContainer.querySelectorAll('.delete-music-btn').forEach(btn => btn.addEventListener('click', (e) => handleDeleteMusic(e.currentTarget.dataset.id))); } }); } }
        async function handleForgotPassword() { const email = prompt('Please enter your account email:'); if (email && /^\\S+@\\S+\\.\\S+$/.test(email)) { const result = await apiCall('/request-password-reset', { method: 'POST', body: { email } }); if(result.success) showToast(result.message || 'Request sent.', 'info'); } else if (email) showToast('Please enter a valid email.', 'error'); }
        async function handleLogout(doApiCall) { if (doApiCall) await apiCall('/logout'); if (appState.socket) appState.socket.disconnect(); appState.currentUser = null; window.location.reload(); }
        async function handleJoinClass() { const codeInput = document.getElementById('class-code'); const code = codeInput.value.trim().toUpperCase(); if (!code) return showToast('Please enter a class code.', 'error'); const result = await apiCall('/join_class', { method: 'POST', body: { code } }); if (result.success) { showToast(result.message || 'Joined class!', 'success'); codeInput.value = ''; setupMyClassesTab(document.getElementById('dashboard-content')); } }
        async function handleCreateClass() { const nameInput = document.getElementById('new-class-name'); const name = nameInput.value.trim(); if (!name) return showToast('Please enter a class name.', 'error'); const result = await apiCall('/classes', { method: 'POST', body: { name } }); if (result.success) { showToast(`Class "${escape(result.class.name)}" created!`, 'success'); nameInput.value = ''; setupMyClassesTab(document.getElementById('dashboard-content')); } }
        async function selectClass(classId) { if (appState.selectedClass && appState.socket) appState.socket.emit('leave', { room: `class_${appState.selectedClass.id}` }); const result = await apiCall(`/classes/${escape(classId)}`); if(!result.success) return; appState.selectedClass = result.class; appState.socket.emit('join', { room: `class_${classId}` }); document.getElementById('classes-list').classList.add('hidden'); document.getElementById('class-action-container').classList.add('hidden'); const viewContainer = document.getElementById('selected-class-view'); viewContainer.classList.remove('hidden'); renderSubTemplate(viewContainer, 'template-selected-class-view', () => { document.getElementById('selected-class-name').textContent = escape(appState.selectedClass.name); document.getElementById('back-to-classes-btn').addEventListener('click', () => { viewContainer.innerHTML = ''; viewContainer.classList.add('hidden'); document.getElementById('classes-list').classList.remove('hidden'); document.getElementById('class-action-container').classList.remove('hidden'); appState.selectedClass = null;}); document.querySelectorAll('.class-view-tab').forEach(tab => tab.addEventListener('click', (e) => switchClassView(e.currentTarget.dataset.tab))); switchClassView('chat'); }); }
        function switchClassView(view) {
            document.querySelectorAll('.class-view-tab').forEach(t => t.classList.toggle('active-tab', t.dataset.tab === view));
            const container = document.getElementById('class-view-content');
            if (view === 'chat') {
                renderSubTemplate(container, 'template-class-chat-view', async () => {
                    document.getElementById('chat-form').addEventListener('submit', handleSendChat);
                    const result = await apiCall(`/class_messages/${escape(appState.selectedClass.id)}`);
                    if (result.success) {
                        const messagesDiv = document.getElementById('chat-messages');
                        messagesDiv.innerHTML = '';
                        result.messages.forEach(m => appendChatMessage(m));
                        getSmartReplies();
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
                    const result = await apiCall(`/classes/${escape(appState.selectedClass.id)}/assignments`);
                    if(result.success) {
                        if(result.assignments.length === 0) list.innerHTML = `<p class="text-gray-400">No assignments posted yet.</p>`;
                        else list.innerHTML = result.assignments.map(a => `<div class="p-4 bg-gray-800/50 rounded-lg cursor-pointer hover:bg-gray-700/60" data-id="${escape(a.id)}"><div class="flex justify-between items-center"><h6 class="font-bold text-white">${escape(a.title)}</h6><span class="text-sm text-gray-400">Due: ${new Date(a.due_date).toLocaleString()}</span></div></div>`).join('');
                        list.querySelectorAll('div[data-id]').forEach(el => el.addEventListener('click', e => viewAssignment(e.currentTarget.dataset.id)));
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
                    const result = await apiCall(`/classes/${escape(appState.selectedClass.id)}/quizzes`);
                     if(result.success) {
                        if(result.quizzes.length === 0) list.innerHTML = `<p class="text-gray-400">No quizzes posted yet.</p>`;
                        else list.innerHTML = result.quizzes.map(q => `<div class="p-4 bg-gray-800/50 rounded-lg cursor-pointer hover:bg-gray-700/60" data-id="${escape(q.id)}"><h6 class="font-bold text-white">${escape(q.title)}</h6><p class="text-sm text-gray-300">${escape(q.description)}</p><span class="text-xs text-gray-400">${q.time_limit} minutes</span></div>`).join('');
                        list.querySelectorAll('div[data-id]').forEach(el => el.addEventListener('click', e => viewQuiz(e.currentTarget.dataset.id)));
                    }
                });
            } else if (view === 'students') {
                 renderSubTemplate(container, 'template-class-students-view', async () => {
                    const list = document.getElementById('students-list');
                    const result = await apiCall(`/classes/${escape(appState.selectedClass.id)}/students`);
                     if(result.success) {
                        list.innerHTML = result.students.map(s => `<div class="glassmorphism p-4 rounded-lg text-center"><img src="${escape(s.profile.avatar || `https://i.pravatar.cc/80?u=${s.id}`)}" class="w-16 h-16 rounded-full mx-auto mb-2"><p class="font-semibold text-white">${escape(s.username)}</p><p class="text-xs text-gray-400">${escape(s.email)}</p></div>`).join('');
                    }
                });
            }
        }
        
        // ... (remaining JavaScript functions) ...
        async function handleSendChat(e) {
            e.preventDefault();
            const input = document.getElementById('chat-input');
            const content = input.value.trim();
            if(content) {
                appState.socket.emit('send_message', { class_id: appState.selectedClass.id, content: content });
                input.value = '';
            }
        }
        
        function appendChatMessage(msg) {
            const messagesDiv = document.getElementById('chat-messages');
            if (!messagesDiv) return;
            const isCurrentUser = msg.sender_id === appState.currentUser.id;
            const messageType = msg.sender_id ? (isCurrentUser ? 'user-message text-right' : 'ai-message text-left') : 'system-message text-center';
            const bubbleClasses = msg.sender_id ? 'chat-bubble inline-block p-3 rounded-lg border max-w-lg' : 'text-sm text-gray-500';
            const avatar = msg.sender_avatar || (msg.sender_id ? `https://i.pravatar.cc/40?u=${msg.sender_id}` : aiAvatarSvg);
            
            const messageHTML = `
                <div class="${messageType}">
                    <div class="flex items-start gap-3 ${isCurrentUser ? 'flex-row-reverse' : ''}">
                        ${msg.sender_id ? `<img src="${escape(avatar)}" class="w-8 h-8 rounded-full">` : ''}
                        <div>
                            ${msg.sender_id ? `<p class="text-xs font-semibold mb-1 ${isCurrentUser ? 'text-right' : 'text-left'}">${escape(msg.sender_username)}</p>` : ''}
                            <div class="${bubbleClasses}">${escape(msg.content)}</div>
                            <p class="text-xs text-gray-500 mt-1">${new Date(msg.timestamp).toLocaleTimeString()}</p>
                        </div>
                    </div>
                </div>`;
            messagesDiv.insertAdjacentHTML('beforeend', messageHTML);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        }

        async function getSmartReplies() {
            const container = document.getElementById('smart-replies-container');
            if (!container) return;
            const result = await apiCall(`/smart-reply/${appState.selectedClass.id}`);
            if (result.success && result.replies) {
                container.innerHTML = result.replies.map(reply => `<button class="smart-reply-btn bg-gray-700/50 hover:bg-gray-600/50 text-sm py-1 px-3 rounded-full transition-colors">${escape(reply)}</button>`).join('');
                container.querySelectorAll('.smart-reply-btn').forEach(btn => btn.addEventListener('click', () => {
                    document.getElementById('chat-input').value = btn.textContent;
                    document.getElementById('chat-form').dispatchEvent(new Event('submit'));
                }));
            }
        }

        async function handleCreateAssignment() {
            const content = document.createElement('form');
            content.id = 'create-assignment-form';
            content.className = 'space-y-4';
            content.innerHTML = `
                <h3 class="text-2xl font-bold text-white mb-4">New Assignment</h3>
                <div><label class="block mb-1">Title</label><input name="title" required class="w-full p-2 bg-gray-700/50 rounded-md border border-gray-600"></div>
                <div><label class="block mb-1">Description</label><textarea name="description" required rows="4" class="w-full p-2 bg-gray-700/50 rounded-md border border-gray-600"></textarea></div>
                <div><label class="block mb-1">Due Date</label><input name="due_date" type="datetime-local" required class="w-full p-2 bg-gray-700/50 rounded-md border border-gray-600"></div>
                <button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Create</button>
            `;
            showModal(content, (modal) => {
                modal.querySelector('form').addEventListener('submit', async (e) => {
                    e.preventDefault();
                    const body = Object.fromEntries(new FormData(e.target));
                    body.class_id = appState.selectedClass.id;
                    const result = await apiCall('/assignments', { method: 'POST', body });
                    if (result.success) {
                        showToast('Assignment created!', 'success');
                        hideModal();
                        switchClassView('assignments');
                    }
                });
            });
        }
        
        async function viewAssignment(assignmentId) {
             const result = await apiCall(`/assignments/${assignmentId}`);
             if (!result.success) return;
             const assignment = result.assignment;
             const content = document.createElement('div');
             
             let submissionContent = '';
             if (appState.currentUser.role === 'student') {
                 const mySubmission = result.submissions.find(s => s.student.id === appState.currentUser.id);
                 if (mySubmission) {
                     submissionContent = `
                        <h4 class="text-lg font-semibold text-white mt-6 mb-2">My Submission</h4>
                        <div class="p-3 bg-gray-800/50 rounded-md whitespace-pre-wrap">${escape(mySubmission.content)}</div>
                        <p class="text-sm mt-2">Submitted: ${new Date(mySubmission.submitted_at).toLocaleString()}</p>
                        ${mySubmission.grade !== null ? `<p class="text-sm mt-2">Grade: <span class="font-bold text-yellow-400">${mySubmission.grade}</span></p><p class="mt-1">Feedback: ${escape(mySubmission.feedback)}</p>` : '<p class="text-sm mt-2 text-gray-400">Not graded yet.</p>'}
                     `;
                 } else {
                     submissionContent = `
                        <form id="submit-assignment-form" class="mt-6">
                             <h4 class="text-lg font-semibold text-white mb-2">Submit Your Work</h4>
                             <textarea name="content" required rows="6" class="w-full p-2 bg-gray-700/50 rounded-md border border-gray-600"></textarea>
                             <button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg mt-2">Submit</button>
                        </form>
                     `;
                 }
             } else { // Teacher view
                 submissionContent = `<h4 class="text-lg font-semibold text-white mt-6 mb-2">Submissions (${result.submissions.length})</h4>`;
                 if (result.submissions.length > 0) {
                     submissionContent += `<ul class="space-y-2">${result.submissions.map(s => `
                        <li class="p-3 bg-gray-800/50 rounded-md">
                            <p class="font-semibold">${escape(s.student.username)}</p>
                            <p class="text-sm text-gray-300 whitespace-pre-wrap">${escape(s.content)}</p>
                             ${s.grade !== null ? `<p class="text-sm mt-2">Grade: <span class="font-bold">${s.grade}</span> | Feedback: ${escape(s.feedback)}</p>` : `
                                <form class="grade-form mt-2 flex gap-2 items-center" data-id="${s.id}">
                                    <input name="grade" type="number" step="0.1" placeholder="Grade" class="w-24 p-1 bg-gray-700/50 rounded-md border border-gray-600">
                                    <input name="feedback" placeholder="Feedback" class="flex-grow p-1 bg-gray-700/50 rounded-md border border-gray-600">
                                    <button type="submit" class="bg-green-600 hover:bg-green-700 text-white text-sm py-1 px-2 rounded-md">Save</button>
                                </form>
                            `}
                        </li>`).join('')}</ul>`;
                 } else {
                     submissionContent += `<p class="text-gray-400">No submissions yet.</p>`;
                 }
             }
             
             content.innerHTML = `
                <h3 class="text-2xl font-bold text-white">${escape(assignment.title)}</h3>
                <p class="text-gray-400 mb-4">Due: ${new Date(assignment.due_date).toLocaleString()}</p>
                <div class="prose prose-invert max-w-none">${escape(assignment.description)}</div>
                ${submissionContent}
             `;
             
             showModal(content, (modal) => {
                if (modal.querySelector('#submit-assignment-form')) {
                    modal.querySelector('#submit-assignment-form').addEventListener('submit', async e => {
                        e.preventDefault();
                        const body = Object.fromEntries(new FormData(e.target));
                        const result = await apiCall(`/assignments/${assignmentId}/submit`, { method: 'POST', body });
                        if(result.success) { showToast('Assignment submitted!', 'success'); hideModal(); viewAssignment(assignmentId); }
                    });
                }
                modal.querySelectorAll('.grade-form').forEach(form => {
                    form.addEventListener('submit', async e => {
                        e.preventDefault();
                        const submissionId = e.target.dataset.id;
                        const body = Object.fromEntries(new FormData(e.target));
                        const result = await apiCall(`/submissions/${submissionId}/grade`, { method: 'POST', body });
                        if(result.success) { showToast('Grade saved!', 'success'); hideModal(); viewAssignment(assignmentId); }
                    });
                });
             });
        }
        
        // ... (all other JS functions to handle UI) ...

        async function handleCreateQuiz() { /* ... implementation ... */ }
        async function viewQuiz(quizId) { /* ... implementation ... */ }

        async function setupStudyGuideTab(container) {
            renderSubTemplate(container, 'template-study-guide-tab', () => {
                document.getElementById('study-guide-form').addEventListener('submit', async e => {
                    e.preventDefault();
                    const topic = document.getElementById('study-guide-topic').value.trim();
                    if (!topic) return showToast('Please enter a topic.', 'error');
                    
                    const resultDiv = document.getElementById('study-guide-result');
                    resultDiv.innerHTML = '<p>Generating study guide... this may take a moment.</p>';
                    
                    const result = await apiCall('/generate-study-guide', { method: 'POST', body: { topic }});
                    if (result.success) {
                        resultDiv.innerHTML = result.guide; // Assuming guide is HTML
                    } else {
                         resultDiv.innerHTML = `<p class="text-red-400">Error: ${result.error}</p>`;
                    }
                });
            });
        }
        
        async function handleManageBilling() {
            const result = await apiCall('/create-portal-session', { method: 'POST' });
            if (result.success) window.location.href = result.url;
        }

        async function handleUpgrade(e) {
            const priceId = e.target.dataset.priceId;
            const result = await apiCall('/create-checkout-session', { method: 'POST', body: { price_id: priceId }});
            if(result.success) {
                 if (!appState.stripe) appState.stripe = Stripe(SITE_CONFIG.STRIPE_PUBLIC_KEY);
                 appState.stripe.redirectToCheckout({ sessionId: result.session_id });
            }
        }
        
        async function setupNotificationBell() {
            const container = document.getElementById('notification-bell-container');
            if(!container) return;
            // ... implementation to fetch and display notifications
        }
        function updateNotificationBell(hasNew) { /* ... */ }

        async function handleAdminUserAction(action, userId) {
            if (action === 'delete') {
                if(confirm('Are you sure you want to delete this user? This cannot be undone.')) {
                    const result = await apiCall(`/admin/users/${userId}`, { method: 'DELETE' });
                    if(result.success) { showToast('User deleted.', 'success'); switchAdminView('users'); }
                }
            }
        }
        async function handleAdminDeleteClass(classId) {
             if(confirm('Are you sure you want to delete this class? This will delete all associated data.')) {
                const result = await apiCall(`/admin/classes/${classId}`, { method: 'DELETE' });
                if(result.success) { showToast('Class deleted.', 'success'); switchAdminView('classes'); }
            }
        }
        async function handleAdminUpdateSettings(e) {
            e.preventDefault();
            const body = Object.fromEntries(new FormData(e.target));
            const result = await apiCall('/admin/settings', { method: 'POST', body });
            if(result.success) showToast('Settings updated.', 'success');
        }
        async function handleToggleMaintenance() {
            const result = await apiCall('/admin/toggle-maintenance', { method: 'POST' });
            if(result.success) showToast(result.message, 'info');
        }
        async function handleGenerateAdminLink() {
            const result = await apiCall('/admin/generate-admin-token', { method: 'POST' });
            if (result.success) {
                const url = `${window.location.origin}/admin-signup/${result.token}`;
                prompt('Share this secure admin signup link:', url);
            }
        }
        async function handleAddMusic() {
            const name = document.getElementById('music-name').value;
            const url = document.getElementById('music-url').value;
            if(!name || !url) return showToast('Name and URL are required.', 'error');
            const result = await apiCall('/admin/music', { method: 'POST', body: { name, url }});
            if(result.success) { showToast('Music added.', 'success'); switchAdminView('music'); }
        }
        function playBackgroundMusic(url) {
            DOMElements.backgroundMusic.src = url;
            DOMElements.backgroundMusic.play().catch(e => console.error("Audio playback failed:", e));
        }
        async function handleDeleteMusic(musicId) {
            const result = await apiCall(`/admin/music/${musicId}`, { method: 'DELETE' });
            if(result.success) { showToast('Music deleted.', 'success'); switchAdminView('music'); }
        }

        async function main() {
            showFullScreenLoader();
            const result = await apiCall('/status');
            if (result.success && result.user) {
                if (result.settings.maintenance_mode === "true" && result.user.role !== 'admin') {
                    setupMaintenancePage();
                } else {
                    handleLoginSuccess(result.user, result.settings);
                }
            } else {
                 if (result.settings && result.settings.maintenance_mode === "true") {
                     setupMaintenancePage();
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
            }
        }

        main();
    });
    </script>
</body>
</html>
"""

@app.route('/')
@app.route('/<path:path>')
def index(path=None):
    return render_template_string(get_safe_html_content(), csrf=csrf)

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
    
    if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
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
    db.session.flush() # Flush to get new_user.id
    new_profile = Profile(user_id=new_user.id)
    db.session.add(new_profile)
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

# ... (other backend routes for teams, assignments, quizzes, etc.)
@app.route('/api/classes/<class_id>')
@login_required
def get_class(class_id):
    cls = Class.query.get_or_404(class_id)
    # Security check: User must be teacher or student in the class
    is_student = cls in current_user.enrolled_classes.all()
    is_teacher = cls.teacher_id == current_user.id
    if not (is_student or is_teacher or current_user.role == 'admin'):
        abort(403)
    return jsonify({"class": {"id": cls.id, "name": cls.name}})

@app.route('/api/class_messages/<class_id>')
@login_required
def get_class_messages(class_id):
    # Add security check as in get_class
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
        # Here you would typically convert markdown to HTML on the server or send markdown to be rendered by a client-side library.
        # For simplicity, we'll just send the text.
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
        
        # Clean up Gemini response to get JSON
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

    # Handle the event
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
