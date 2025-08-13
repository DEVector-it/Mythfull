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

# --- Flask App Initialization ---
app = Flask(__name__)

# --- CORS Configuration ---
# This is crucial for allowing the frontend to communicate with the backend.
allowed_origins = [
    "https://reallymythai.netlify.app", # Your new Netlify frontend
    "https://mythproal.netlify.app",    # Previous Netlify frontend
    "https://myth-ai.onrender.com",     # Your deployed backend
    "http://127.0.0.1:5000",         # Common local server addresses
    "http://localhost:5000",
    "http://127.0.0.1:5500",         # Common live server addresses
    "http://localhost:5500",
    "null"                          # Allows opening the HTML file directly from your computer
]
CORS(app, supports_credentials=True, origins=allowed_origins)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-fallback-secret-key-for-development')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get('SECURITY_PASSWORD_SALT', 'a-fallback-salt')


# --- Security Check for Essential Environment Variables ---
REQUIRED_KEYS = [
    'SECRET_KEY', 'SECURITY_PASSWORD_SALT', 'SECRET_TEACHER_KEY', 'ADMIN_SECRET_KEY',
    'STRIPE_WEBHOOK_SECRET', 'STRIPE_SECRET_KEY', 'STRIPE_PUBLIC_KEY', 'STRIPE_STUDENT_PRICE_ID', 'STRIPE_STUDENT_PRO_PRICE_ID',
    'MAIL_SERVER', 'MAIL_PORT', 'MAIL_USERNAME', 'MAIL_PASSWORD', 'MAIL_SENDER',
    'GEMINI_API_KEY'
]
for key in REQUIRED_KEYS:
    if not os.environ.get(key):
        logging.warning(f"WARNING: Environment variable '{key}' is not set. Some features may not work.")


# --- Security: Content Security Policy (CSP) ---
csp = {
    'default-src': "'self'",
    'script-src': ["'self'", "https://js.stripe.com", "https://cdn.tailwindcss.com", "https://cdnjs.cloudflare.com", "'unsafe-inline'"],
    'style-src': ["'self'", "https://fonts.googleapis.com", "'unsafe-inline'"],
    'font-src': ["'self'", "https://fonts.gstatic.com"],
    'img-src': ["'self'", "https://*", "data:"],
    'connect-src': ["'self'", "https://api.stripe.com", "https://generativelanguage.googleapis.com", "https://myth-ai.onrender.com", "ws://myth-ai.onrender.com", "wss://myth-ai.onrender.com", "http://127.0.0.1:5000", "ws://127.0.0.1:5000", "wss://127.0.0.1:5000", "https://mythproal.netlify.app", "https://reallymythai.netlify.app"],
}
Talisman(app, content_security_policy=csp)

# --- Site & API Configuration ---
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
}

# --- Service Initializations (Stripe, Mail, DB, SocketIO) ---
stripe.api_key = SITE_CONFIG["STRIPE_SECRET_KEY"]
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
# --- 2. DATABASE MODELS (SQLALCHEMY) ---
# ==============================================================================
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
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
    plan = db.Column(db.String(50), nullable=False, default='free')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    profile_bio = db.Column(db.Text, default='')
    profile_avatar = db.Column(db.String(200), default='')
    stripe_customer_id = db.Column(db.String(255), unique=True, nullable=True)
    stripe_subscription_id = db.Column(db.String(255), unique=True, nullable=True)
    taught_classes = db.relationship('Class', back_populates='teacher', lazy=True, foreign_keys='Class.teacher_id', cascade="all, delete-orphan")
    enrolled_classes = db.relationship('Class', secondary=student_class_association, back_populates='students', lazy='dynamic')
    submissions = db.relationship('AssignmentSubmission', back_populates='student', lazy=True, cascade="all, delete-orphan")
    notifications = db.relationship('Notification', back_populates='user', lazy=True, cascade="all, delete-orphan")
    quiz_attempts = db.relationship('QuizAttempt', back_populates='student', lazy=True, cascade="all, delete-orphan")
    teams = db.relationship('Team', secondary=team_member_association, back_populates='members', lazy='dynamic')

    def to_dict(self):
        return {
            "id": self.id, "username": self.username, "email": self.email, "role": self.role, "plan": self.plan,
            "profile": {"bio": self.profile_bio, "avatar": self.profile_avatar},
            "classes": [c.id for c in self.enrolled_classes] if self.role == 'student' else [c.id for c in self.taught_classes],
            "teams": [t.id for t in self.teams],
            "created_at": self.created_at.isoformat(), "has_subscription": bool(self.stripe_subscription_id)
        }

class Team(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(8), unique=True, nullable=False)
    owner_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    owner = db.relationship('User', foreign_keys=[owner_id])
    members = db.relationship('User', secondary=team_member_association, back_populates='teams', lazy='dynamic')

    def to_dict(self, include_members=False, member_count=False):
        data = { "id": self.id, "name": self.name, "code": self.code, "owner_id": self.owner_id, "owner_name": self.owner.username if self.owner else "N/A" }
        if include_members: data['members'] = [m.to_dict() for m in self.members]
        if member_count: data['member_count'] = self.members.count()
        return data

class Class(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(8), unique=True, nullable=False)
    teacher_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    teacher = db.relationship('User', back_populates='taught_classes', foreign_keys=[teacher_id])
    students = db.relationship('User', secondary=student_class_association, back_populates='enrolled_classes', lazy='dynamic')
    messages = db.relationship('Message', back_populates='class_obj', lazy=True, cascade="all, delete-orphan")
    assignments = db.relationship('Assignment', back_populates='class_obj', lazy=True, cascade="all, delete-orphan")
    quizzes = db.relationship('Quiz', back_populates='class_obj', lazy=True, cascade="all, delete-orphan")

    def to_dict(self, include_students=False, student_count=False):
        data = { "id": self.id, "name": self.name, "code": self.code, "teacher_id": self.teacher_id, "teacher_name": self.teacher.username if self.teacher else "N/A" }
        if include_students: data['students'] = [s.to_dict() for s in self.students]
        if student_count: data['student_count'] = self.students.count()
        return data

class Message(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    class_id = db.Column(db.String(36), db.ForeignKey('class.id', ondelete='CASCADE'), nullable=False)
    sender_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    class_obj = db.relationship('Class', back_populates='messages')
    sender = db.relationship('User')

    def to_dict(self):
        sender_name = "AI Assistant"
        sender_avatar = None
        if self.sender:
            sender_name = self.sender.username
            sender_avatar = self.sender.profile_avatar
        return { "id": self.id, "class_id": self.class_id, "sender_id": self.sender_id, "sender_name": sender_name, "sender_avatar": sender_avatar, "content": self.content, "timestamp": self.timestamp.isoformat() }

class Assignment(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    due_date = db.Column(db.DateTime, nullable=False)
    class_id = db.Column(db.String(36), db.ForeignKey('class.id', ondelete='CASCADE'), nullable=False)
    class_obj = db.relationship('Class', back_populates='assignments')
    submissions = db.relationship('AssignmentSubmission', back_populates='assignment', lazy='dynamic', cascade="all, delete-orphan")

    def to_dict(self, student_id=None):
        data = { "id": self.id, "title": self.title, "description": self.description, "due_date": self.due_date.isoformat(), "class_id": self.class_id, "submission_count": self.submissions.count() }
        if student_id:
            submission = self.submissions.filter_by(student_id=student_id).first()
            data['student_submission'] = submission.to_dict() if submission else None
        return data

class AssignmentSubmission(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    assignment_id = db.Column(db.String(36), db.ForeignKey('assignment.id', ondelete='CASCADE'), nullable=False)
    student_id = db.Column(db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    grade = db.Column(db.String(10), nullable=True)
    feedback = db.Column(db.Text, nullable=True)
    assignment = db.relationship('Assignment', back_populates='submissions')
    student = db.relationship('User', back_populates='submissions')

    def to_dict(self):
        return { "id": self.id, "assignment_id": self.assignment_id, "student_id": self.student_id, "student_name": self.student.username, "content": self.content, "submitted_at": self.submitted_at.isoformat(), "grade": self.grade, "feedback": self.feedback }

class Quiz(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    time_limit = db.Column(db.Integer, nullable=False)
    class_id = db.Column(db.String(36), db.ForeignKey('class.id', ondelete='CASCADE'), nullable=False)
    class_obj = db.relationship('Class', back_populates='quizzes')
    questions = db.relationship('Question', back_populates='quiz', lazy='dynamic', cascade="all, delete-orphan")
    attempts = db.relationship('QuizAttempt', back_populates='quiz', lazy='dynamic', cascade="all, delete-orphan")

    def to_dict(self, student_id=None):
        data = { "id": self.id, "title": self.title, "description": self.description, "time_limit": self.time_limit, "class_id": self.class_id, "question_count": self.questions.count() }
        if student_id:
            attempt = self.attempts.filter_by(student_id=student_id).first()
            data['student_attempt'] = attempt.to_dict() if attempt else None
        return data

class Question(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    quiz_id = db.Column(db.String(36), db.ForeignKey('quiz.id', ondelete='CASCADE'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    question_type = db.Column(db.String(50), nullable=False)
    order = db.Column(db.Integer, nullable=False)
    quiz = db.relationship('Quiz', back_populates='questions')
    choices = db.relationship('Choice', back_populates='question', lazy='dynamic', cascade="all, delete-orphan")

    def to_dict(self, include_correct=False):
        data = { "id": self.id, "text": self.text, "question_type": self.question_type, "order": self.order, "choices": [c.to_dict(include_correct) for c in self.choices] }
        return data

class Choice(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    question_id = db.Column(db.String(36), db.ForeignKey('question.id', ondelete='CASCADE'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    is_correct = db.Column(db.Boolean, default=False, nullable=False)
    question = db.relationship('Question', back_populates='choices')

    def to_dict(self, include_correct=False):
        data = { "id": self.id, "text": self.text }
        if include_correct: data['is_correct'] = self.is_correct
        return data

class QuizAttempt(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    quiz_id = db.Column(db.String(36), db.ForeignKey('quiz.id', ondelete='CASCADE'), nullable=False)
    student_id = db.Column(db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    score = db.Column(db.Float, nullable=True)
    quiz = db.relationship('Quiz', back_populates='attempts')
    student = db.relationship('User', back_populates='quiz_attempts')
    answers = db.relationship('Answer', back_populates='attempt', lazy='dynamic', cascade="all, delete-orphan")

    def to_dict(self):
        return { "id": self.id, "quiz_id": self.quiz_id, "student_id": self.student_id, "student_name": self.student.username, "start_time": self.start_time.isoformat(), "end_time": self.end_time.isoformat() if self.end_time else None, "score": self.score }

class Answer(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    attempt_id = db.Column(db.String(36), db.ForeignKey('quiz_attempt.id', ondelete='CASCADE'), nullable=False)
    question_id = db.Column(db.String(36), db.ForeignKey('question.id', ondelete='CASCADE'), nullable=False)
    choice_id = db.Column(db.String(36), db.ForeignKey('choice.id'), nullable=True)
    answer_text = db.Column(db.Text, nullable=True)
    is_correct = db.Column(db.Boolean, nullable=True)
    attempt = db.relationship('QuizAttempt', back_populates='answers')
    question = db.relationship('Question')
    choice = db.relationship('Choice')

    def to_dict(self):
        return { "id": self.id, "question_id": self.question_id, "choice_id": self.choice_id, "answer_text": self.answer_text, "is_correct": self.is_correct }

class Notification(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    url = db.Column(db.String(255), nullable=True)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', back_populates='notifications')

    def to_dict(self):
        return { "id": self.id, "content": self.content, "url": self.url, "is_read": self.is_read, "timestamp": self.timestamp.isoformat() }

class SiteSettings(db.Model):
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.String(500))

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

# ==============================================================================
# --- 4. DECORATORS & HELPER FUNCTIONS ---
# ==============================================================================
def get_site_settings(): return {s.key: s.value for s in SiteSettings.query.all()}

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
student_required = role_required('student')

def send_password_reset_email(user):
    # Placeholder for email sending logic
    pass

def generate_code(length=8):
    return secrets.token_hex(length // 2).upper()

def create_notification(user_id, content, url=None):
    with app.app_context():
        notification = Notification(user_id=user_id, content=content, url=url)
        db.session.add(notification)
        db.session.commit()
        socketio.emit('new_notification', notification.to_dict(), room=f'user_{user_id}')

# ==============================================================================
# --- 5. CORE API ROUTES ---
# ==============================================================================
@app.route('/')
def index():
    return jsonify({"message": "Welcome to the Myth AI Backend!"})

@app.route('/api/status')
def status():
    config = {"email_enabled": bool(app.config.get('MAIL_SERVER'))}
    settings = get_site_settings()
    if current_user.is_authenticated:
        return jsonify({ "logged_in": True, "user": current_user.to_dict(), "settings": settings, "config": config })
    return jsonify({"logged_in": False, "config": config, "settings": settings})

# ==============================================================================
# --- 6. AUTHENTICATION API ROUTES ---
# ==============================================================================
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data: return jsonify({"error": "Invalid request"}), 400
    
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
    return jsonify({"success": True, "user": user.to_dict()})

@app.route('/api/logout')
@login_required
def logout():
    logout_user()
    return jsonify({"success": True})

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    if not data: return jsonify({"error": "Invalid request"}), 400
    username, password, email = data.get('username','').strip(), data.get('password',''), data.get('email','').strip().lower()
    account_type = data.get('account_type', 'student')
    secret_key = data.get('secret_key', '')

    if not all([username, password, email]) or len(username) < 3 or len(password) < 6 or '@' not in email: return jsonify({"error": "Valid email, username (min 3 chars), and password (min 6 chars) are required."}), 400
    if User.query.filter(User.username.ilike(username)).first(): return jsonify({"error": "Username already exists."}), 409
    if User.query.filter(User.email.ilike(email)).first(): return jsonify({"error": "Email already in use."}), 409

    role = 'student'
    if account_type == 'teacher':
        if secret_key != SITE_CONFIG.get('SECRET_TEACHER_KEY'): return jsonify({"error": "Invalid teacher registration key."}), 403
        role = 'teacher'
    
    new_user = User(username=username, email=email, password_hash=generate_password_hash(password), role=role)
    db.session.add(new_user)
    db.session.commit()
    login_user(new_user, remember=True)
    return jsonify({"success": True, "user": new_user.to_dict()})

# ==============================================================================
# --- 7. ADMIN DASHBOARD API ROUTES ---
# ==============================================================================
@app.route('/api/admin/dashboard_data', methods=['GET'])
@admin_required
def admin_dashboard_data():
    users = User.query.order_by(User.created_at.desc()).all()
    classes = Class.query.all()
    stats = {
        'total_users': len(users), 'total_students': User.query.filter_by(role='student').count(),
        'total_teachers': User.query.filter_by(role='teacher').count(), 'total_classes': len(classes),
        'active_subscriptions': User.query.filter(User.stripe_subscription_id.isnot(None)).count(),
    }
    return jsonify({ "success": True, "stats": stats, "users": [u.to_dict() for u in users], "classes": [c.to_dict(student_count=True) for c in classes], "settings": get_site_settings() })

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
        if setting.value == 'true':
            setting.value = 'false'
            message = "Maintenance mode disabled."
        else:
            setting.value = 'true'
            message = "Maintenance mode enabled."
    else:
        db.session.add(SiteSettings(key='maintenance_mode', value='true'))
        message = "Maintenance mode enabled."
    db.session.commit()
    return jsonify({"success": True, "message": message})
    
# ... other admin routes ...

# ==============================================================================
# --- 12. GEMINI AI API ROUTE ---
# ==============================================================================
@app.route('/api/generate_ai_response', methods=['POST'])
@login_required
def generate_ai_response():
    data = request.get_json()
    prompt = data.get('prompt')
    class_id = data.get('class_id')
    if not prompt or not class_id:
        return jsonify({"error": "Prompt and Class ID are required."}), 400

    cls = Class.query.get_or_404(class_id)
    is_member = current_user.role == 'teacher' and cls.teacher_id == current_user.id or \
                current_user.role == 'student' and cls.students.filter_by(id=current_user.id).first()
    if not is_member and current_user.role != 'admin':
        return jsonify({"error": "Access denied."}), 403

    api_key = SITE_CONFIG.get('GEMINI_API_KEY')
    if not api_key:
        return jsonify({"error": "AI service is not configured."}), 500

    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={api_key}"
    headers = {"Content-Type": "application/json"}
    payload = {"contents": [{"parts": [{"text": prompt}]}]}

    try:
        response = requests.post(api_url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        api_data = response.json()
        
        ai_text = api_data.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', 'Sorry, I could not generate a response.')

        ai_message = Message(class_id=class_id, sender_id=None, content=ai_text)
        db.session.add(ai_message)
        db.session.commit()
        
        socketio.emit('new_message', ai_message.to_dict(), room=f'class_{class_id}')
        
        return jsonify({"success": True, "message": ai_message.to_dict()})

    except requests.exceptions.RequestException as e:
        logging.error(f"Gemini API request failed: {e}")
        return jsonify({"error": "Failed to get response from AI."}), 500
    except (KeyError, IndexError) as e:
        logging.error(f"Error parsing Gemini API response: {e} - Response: {api_data}")
        return jsonify({"error": "Invalid response from AI."}), 500

# ==============================================================================
# --- APP INITIALIZATION & EXECUTION ---
# ==============================================================================
def initialize_app_database():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='big ballz').first():
            admin_pass = os.environ.get('ADMIN_PASSWORD', 'change-this-default-password')
            admin_email = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
            admin = User(username='big ballz', email=admin_email, password_hash=generate_password_hash(admin_pass), role='admin', plan='admin')
            db.session.add(admin)
            logging.info(f"Created default admin user with email {admin_email}.")
        
        default_settings = {
            'announcement': 'Welcome to the new Myth AI Portal!',
            'daily_message': 'Tip: Use the Team Mode to collaborate on projects with your peers!',
            'maintenance_mode': 'false'
        }
        for key, value in default_settings.items():
            if not SiteSettings.query.filter_by(key=key).first():
                db.session.add(SiteSettings(key=key, value=value))
                logging.info(f"Created default site setting for '{key}'.")
        
        db.session.commit()

if __name__ == '__main__':
    initialize_app_database()
    port = int(os.environ.get('PORT', 10000))
    socketio.run(app, host='0.0.0.0', port=port)
