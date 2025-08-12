# --- Imports ---
import os
import json
import logging
import time
import uuid
import secrets
from flask import Flask, Response, request, session, jsonify, redirect, url_for, render_template_string
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from datetime import datetime, date
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
import stripe
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from flask_mail import Mail, Message
from flask_talisman import Talisman
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
from sqlalchemy.engine import Engine
from flask_socketio import SocketIO, emit, join_room, leave_room

# ==============================================================================
# --- 1. INITIAL CONFIGURATION & SETUP ---
# ==============================================================================
load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Security Check for Essential Environment Variables ---
REQUIRED_KEYS = [
    'SECRET_KEY', 'SECURITY_PASSWORD_SALT', 'SECRET_TEACHER_KEY',
    'STRIPE_WEBHOOK_SECRET', 'STRIPE_SECRET_KEY', 'STRIPE_PUBLIC_KEY', 'STRIPE_STUDENT_PRICE_ID', 'STRIPE_STUDENT_PRO_PRICE_ID',
    'MAIL_SERVER', 'MAIL_PORT', 'MAIL_USERNAME', 'MAIL_PASSWORD', 'MAIL_SENDER'
]
for key in REQUIRED_KEYS:
    if not os.environ.get(key):
        logging.critical(f"CRITICAL ERROR: Environment variable '{key}' is not set.")
        exit(f"Error: Missing required environment variable '{key}'.")

# --- Flask App Initialization ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Security: Content Security Policy (CSP) ---
csp = {
    'default-src': "'self'",
    'script-src': [
        "'self'",
        "https://js.stripe.com",
        "https://cdn.tailwindcss.com",
        "https://cdnjs.cloudflare.com",
        "'unsafe-inline'" # Required for Socket.IO
    ],
    'style-src': ["'self'", "https://fonts.googleapis.com", "'unsafe-inline'"],
    'font-src': ["'self'", "https://fonts.gstatic.com"],
}
Talisman(app, content_security_policy=csp)

# --- Site & API Configuration ---
SITE_CONFIG = {
    "STRIPE_SECRET_KEY": os.environ.get('STRIPE_SECRET_KEY'),
    "STRIPE_PUBLIC_KEY": os.environ.get('STRIPE_PUBLIC_KEY'),
    "STRIPE_STUDENT_PRICE_ID": os.environ.get('STRIPE_STUDENT_PRICE_ID'),
    "STRIPE_STUDENT_PRO_PRICE_ID": os.environ.get('STRIPE_STUDENT_PRO_PRICE_ID'),
    "YOUR_DOMAIN": os.environ.get('YOUR_DOMAIN', 'http://localhost:5000'),
    "SECRET_REGISTRATION_KEY": os.environ.get('SECRET_REGISTRATION_KEY'),
    "SECRET_TEACHER_KEY": os.environ.get('SECRET_TEACHER_KEY'),
    "STRIPE_WEBHOOK_SECRET": os.environ.get('STRIPE_WEBHOOK_SECRET'),
}

# --- Service Initializations (Stripe, Mail, DB, SocketIO) ---
stripe.api_key = SITE_CONFIG["STRIPE_SECRET_KEY"]
password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")

app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_SENDER')
mail = Mail(app)

# ==============================================================================
# --- 2. DATABASE MODELS (SQLALCHEMY) ---
# ==============================================================================

# Enable foreign key support for SQLite
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

# Association table for student-class relationship
student_class_association = db.Table('student_class_association',
    db.Column('user_id', db.String(36), db.ForeignKey('user.id'), primary_key=True),
    db.Column('class_id', db.String(36), db.ForeignKey('class.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True)
    role = db.Column(db.String(20), nullable=False, default='student') # student, teacher, admin
    plan = db.Column(db.String(50), nullable=False, default='student')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    profile_bio = db.Column(db.Text, default='')
    profile_avatar = db.Column(db.String(200), default='')
    
    # For teachers: classes they teach
    taught_classes = db.relationship('Class', back_populates='teacher', lazy=True, foreign_keys='Class.teacher_id')
    
    # For students: classes they are enrolled in
    enrolled_classes = db.relationship('Class', secondary=student_class_association, back_populates='students', lazy='dynamic')
    
    submissions = db.relationship('AssignmentSubmission', back_populates='student', lazy=True)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "plan": self.plan,
            "profile": {"bio": self.profile_bio, "avatar": self.profile_avatar},
            "classes": [c.id for c in self.enrolled_classes] if self.role == 'student' else [c.id for c in self.taught_classes],
            "created_at": self.created_at.isoformat()
        }

class Class(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(8), unique=True, nullable=False)
    teacher_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    
    teacher = db.relationship('User', back_populates='taught_classes', foreign_keys=[teacher_id])
    students = db.relationship('User', secondary=student_class_association, back_populates='enrolled_classes', lazy='dynamic')
    messages = db.relationship('Message', back_populates='class_obj', lazy=True, cascade="all, delete-orphan")
    assignments = db.relationship('Assignment', back_populates='class_obj', lazy=True, cascade="all, delete-orphan")

    def to_dict(self, include_students=False):
        data = {
            "id": self.id,
            "name": self.name,
            "code": self.code,
            "teacher_id": self.teacher_id,
            "teacher_name": self.teacher.username if self.teacher else "N/A"
        }
        if include_students:
            data['students'] = [s.to_dict() for s in self.students]
        return data

class Message(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    class_id = db.Column(db.String(36), db.ForeignKey('class.id'), nullable=False)
    sender_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=True) # Nullable for AI/System messages
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    class_obj = db.relationship('Class', back_populates='messages')
    sender = db.relationship('User')

    def to_dict(self):
        return {
            "id": self.id,
            "class_id": self.class_id,
            "sender_id": self.sender_id,
            "sender_name": self.sender.username if self.sender else "AI System",
            "content": self.content,
            "timestamp": self.timestamp.isoformat()
        }

class Assignment(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    due_date = db.Column(db.DateTime, nullable=False)
    class_id = db.Column(db.String(36), db.ForeignKey('class.id'), nullable=False)
    
    class_obj = db.relationship('Class', back_populates='assignments')
    submissions = db.relationship('AssignmentSubmission', back_populates='assignment', lazy='dynamic', cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "due_date": self.due_date.isoformat(),
            "class_id": self.class_id
        }

class AssignmentSubmission(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    assignment_id = db.Column(db.String(36), db.ForeignKey('assignment.id'), nullable=False)
    student_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    grade = db.Column(db.String(10), nullable=True)
    feedback = db.Column(db.Text, nullable=True)

    assignment = db.relationship('Assignment', back_populates='submissions')
    student = db.relationship('User', back_populates='submissions')

    def to_dict(self):
        return {
            "id": self.id,
            "assignment_id": self.assignment_id,
            "student_id": self.student_id,
            "student_name": self.student.username,
            "content": self.content,
            "submitted_at": self.submitted_at.isoformat(),
            "grade": self.grade,
            "feedback": self.feedback
        }

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
    if request.path.startswith('/api/'):
        return jsonify({"error": "Login required.", "logged_in": False}), 401
    return redirect(url_for('index'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

# ==============================================================================
# --- 4. DECORATORS & HELPER FUNCTIONS ---
# ==============================================================================
def get_site_settings():
    settings = SiteSettings.query.all()
    return {s.key: s.value for s in settings}

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
student_required = role_required('student')

def send_password_reset_email(user):
    try:
        token = password_reset_serializer.dumps(user.email, salt='password-reset-salt')
        reset_url = url_for('index', _external=True) + f"reset-password/{token}"
        msg = Message("Reset Your Password", recipients=[user.email])
        msg.body = f"Click the link to reset your password: {reset_url}\nThis link is valid for one hour."
        mail.send(msg)
        return True
    except Exception as e:
        logging.error(f"Email sending failed for {user.email}: {e}")
        return False

def generate_class_code():
    while True:
        code = secrets.token_hex(4).upper()
        if not Class.query.filter_by(code=code).first():
            return code

# ==============================================================================
# --- 5. FRONTEND & CORE ROUTES ---
# ==============================================================================
@app.route('/')
@app.route('/reset-password/<token>')
def index(token=None):
    nonce = secrets.token_hex(16)
    session['_csp_nonce'] = nonce
    final_html = HTML_CONTENT.replace('{csp_nonce}', nonce)
    return Response(final_html, mimetype='text/html')

@app.route('/api/status')
def status():
    config = {"email_enabled": bool(app.config.get('MAIL_SERVER'))}
    settings = get_site_settings()
    if current_user.is_authenticated:
        return jsonify({
            "logged_in": True, "user": current_user.to_dict(),
            "settings": settings, "config": config
        })
    return jsonify({"logged_in": False, "config": config, "settings": settings})

# ==============================================================================
# --- 6. AUTHENTICATION API ROUTES ---
# ==============================================================================
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter(User.username.ilike(data.get('username'))).first()
    if user and user.password_hash and check_password_hash(user.password_hash, data.get('password', '')):
        login_user(user, remember=True)
        return jsonify({"success": True, "user": user.to_dict()})
    return jsonify({"error": "Invalid username or password."}), 401

@app.route('/api/logout')
@login_required
def logout():
    logout_user()
    return jsonify({"success": True})

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username, password, email = data.get('username','').strip(), data.get('password',''), data.get('email','').strip().lower()
    account_type = data.get('account_type', 'student') # 'student' or 'teacher'
    secret_key = data.get('secret_key')

    if not all([username, password, email]) or len(username) < 3 or len(password) < 6 or '@' not in email:
        return jsonify({"error": "Valid email, username (min 3 chars), and password (min 6 chars) are required."}), 400
    if User.query.filter(User.username.ilike(username)).first():
        return jsonify({"error": "Username already exists."}), 409
    if User.query.filter(User.email.ilike(email)).first():
        return jsonify({"error": "Email already in use."}), 409

    role = 'student'
    if account_type == 'teacher':
        if secret_key != SITE_CONFIG['SECRET_TEACHER_KEY']:
            return jsonify({"error": "Invalid teacher registration key."}), 403
        role = 'teacher'

    new_user = User(
        username=username,
        email=email,
        password_hash=generate_password_hash(password),
        role=role
    )
    db.session.add(new_user)
    db.session.commit()
    login_user(new_user, remember=True)
    return jsonify({"success": True, "user": new_user.to_dict()})

# --- Password Reset Routes ---
@app.route('/api/request-password-reset', methods=['POST'])
def request_password_reset():
    email = request.json.get('email', '').lower()
    user = User.query.filter_by(email=email).first()
    if user:
        send_password_reset_email(user)
    return jsonify({"message": "If an account with that email exists, a reset link has been sent."})

@app.route('/api/reset-with-token', methods=['POST'])
def reset_with_token():
    token, password = request.json.get('token'), request.json.get('password')
    try:
        email = password_reset_serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except (SignatureExpired, BadTimeSignature):
        return jsonify({"error": "The password reset link is invalid or has expired."}), 400
    
    user = User.query.filter_by(email=email).first()
    if not user: return jsonify({"error": "User not found."}), 404
    
    user.password_hash = generate_password_hash(password)
    db.session.commit()
    return jsonify({"message": "Password has been updated successfully."})

# ==============================================================================
# --- 7. ADMIN DASHBOARD API ROUTES ---
# ==============================================================================
@app.route('/api/admin/dashboard_data')
@admin_required
def admin_dashboard_data():
    users = User.query.order_by(User.created_at.desc()).all()
    classes = Class.query.all()
    messages = Message.query.count()
    
    stats = {
        'total_users': len(users),
        'total_students': User.query.filter_by(role='student').count(),
        'total_teachers': User.query.filter_by(role='teacher').count(),
        'total_classes': len(classes),
        'total_messages': messages
    }
    
    return jsonify({
        "success": True, 
        "stats": stats,
        "users": [u.to_dict() for u in users],
        "classes": [c.to_dict() for c in classes],
        "settings": get_site_settings()
    })

@app.route('/api/admin/update_settings', methods=['POST'])
@admin_required
def admin_update_settings():
    data = request.get_json()
    for key, value in data.items():
        setting = SiteSettings.query.get(key)
        if setting:
            setting.value = value
        else:
            db.session.add(SiteSettings(key=key, value=value))
    db.session.commit()
    return jsonify({"success": True, "message": "Settings updated."})

@app.route('/api/admin/user/<user_id>', methods=['PUT', 'DELETE'])
@admin_required
def admin_manage_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == 'admin':
        return jsonify({"error": "Cannot modify admin accounts."}), 403

    if request.method == 'DELETE':
        db.session.delete(user)
        db.session.commit()
        return jsonify({"success": True, "message": f"User {user.username} deleted."})

    if request.method == 'PUT':
        data = request.get_json()
        user.username = data.get('username', user.username)
        user.email = data.get('email', user.email)
        user.role = data.get('role', user.role)
        if 'password' in data and data['password']:
            user.password_hash = generate_password_hash(data['password'])
        db.session.commit()
        return jsonify({"success": True, "user": user.to_dict()})

# ==============================================================================
# --- 8. CLASSES API ROUTES ---
# ==============================================================================
@app.route('/api/classes', methods=['POST'])
@teacher_required
def create_class():
    data = request.get_json()
    name = data.get('name')
    if not name:
        return jsonify({"error": "Class name is required."}), 400
    
    new_class = Class(
        name=name,
        code=generate_class_code(),
        teacher_id=current_user.id
    )
    db.session.add(new_class)
    db.session.commit()
    return jsonify({"success": True, "class": new_class.to_dict()})

@app.route('/api/my_classes', methods=['GET'])
@login_required
def my_classes():
    if current_user.role == 'teacher':
        classes = current_user.taught_classes
    elif current_user.role == 'student':
        classes = current_user.enrolled_classes.all()
    else: # Admin
        classes = Class.query.all()
        
    return jsonify({"success": True, "classes": [c.to_dict() for c in classes]})

@app.route('/api/classes/<class_id>', methods=['GET'])
@login_required
def get_class_details(class_id):
    cls = Class.query.get_or_404(class_id)
    # Authorization check
    if current_user.role != 'admin' and cls.teacher_id != current_user.id and not cls.students.filter_by(id=current_user.id).first():
        return jsonify({"error": "Access denied."}), 403
    return jsonify({"success": True, "class": cls.to_dict(include_students=True)})


@app.route('/api/join_class', methods=['POST'])
@student_required
def join_class():
    data = request.get_json()
    code = data.get('code', '').upper()
    if not code:
        return jsonify({"error": "Class code is required."}), 400
    
    cls = Class.query.filter_by(code=code).first()
    if not cls:
        return jsonify({"error": "Invalid class code."}), 404
    if current_user in cls.students:
        return jsonify({"error": "Already in this class."}), 400
    
    cls.students.append(current_user)
    db.session.commit()
    return jsonify({"success": True, "message": f"Successfully joined {cls.name}."})

# ==============================================================================
# --- 9. PROFILE & PERKS API ROUTES ---
# ==============================================================================
@app.route('/api/profile', methods=['PUT'])
@login_required
def update_profile():
    data = request.get_json()
    current_user.profile_bio = data.get('bio', current_user.profile_bio)[:500]
    current_user.profile_avatar = data.get('avatar', current_user.profile_avatar)
    db.session.commit()
    return jsonify({"success": True, "profile": {"bio": current_user.profile_bio, "avatar": current_user.profile_avatar}})

@app.route('/api/perks', methods=['GET'])
@login_required
def get_perks():
    perks = {
        'student': ['Basic access', 'Join classes', 'Real-time Chat', 'Submit Assignments'],
        'student_pro': ['Unlimited AI chat', 'Priority support', 'Custom profiles', 'Advanced Analytics'],
        'teacher': ['Create Classes', 'Manage Students', 'Create & Grade Assignments'],
        'admin': ['Full System Control', 'User Management', 'Site Analytics']
    }
    return jsonify({"success": True, "perks": perks.get(current_user.role, [])})

# ==============================================================================
# --- 10. MESSAGING & SOCKET.IO ROUTES ---
# ==============================================================================
@app.route('/api/class_messages/<class_id>', methods=['GET'])
@login_required
def get_class_messages(class_id):
    cls = Class.query.get_or_404(class_id)
    # Authorization check
    if current_user.role != 'admin' and cls.teacher_id != current_user.id and not cls.students.filter_by(id=current_user.id).first():
        return jsonify({"error": "Access denied."}), 403
        
    messages = Message.query.filter_by(class_id=class_id).order_by(Message.timestamp.asc()).all()
    return jsonify({"success": True, "messages": [m.to_dict() for m in messages]})

@socketio.on('join')
def on_join(data):
    username = current_user.username
    room = data['room']
    join_room(room)
    # emit('status', {'msg': username + ' has entered the room.'}, room=room)

@socketio.on('leave')
def on_leave(data):
    username = current_user.username
    room = data['room']
    leave_room(room)
    # emit('status', {'msg': username + ' has left the room.'}, room=room)

@socketio.on('send_message')
def handle_send_message(json_data):
    class_id = json_data.get('class_id')
    content = json_data.get('message')
    
    if not class_id or not content:
        return # Or emit an error back to the client

    # Authorization check
    cls = Class.query.get(class_id)
    if not cls or (current_user.role != 'admin' and cls.teacher_id != current_user.id and not cls.students.filter_by(id=current_user.id).first()):
        return # Silently fail for unauthorized messages

    # Save message to DB
    new_message = Message(class_id=class_id, sender_id=current_user.id, content=content)
    db.session.add(new_message)
    db.session.commit()

    # Emit to room
    emit('new_message', new_message.to_dict(), room=class_id)

    # Trigger AI response if student talks
    if current_user.role == 'student':
        ai_response_content = f"This is a placeholder AI response to: \"{content}\""
        ai_message = Message(class_id=class_id, sender_id=None, content=ai_response_content) # sender_id=None for AI
        db.session.add(ai_message)
        db.session.commit()
        emit('new_message', ai_message.to_dict(), room=class_id, broadcast=True)

# ==============================================================================
# --- 11. ASSIGNMENTS API ROUTES ---
# ==============================================================================
@app.route('/api/classes/<class_id>/assignments', methods=['GET', 'POST'])
@login_required
def manage_assignments(class_id):
    cls = Class.query.get_or_404(class_id)
    
    if request.method == 'GET':
        assignments = Assignment.query.filter_by(class_id=class_id).all()
        return jsonify({"success": True, "assignments": [a.to_dict() for a in assignments]})

    if request.method == 'POST':
        if current_user.id != cls.teacher_id:
            return jsonify({"error": "Only the class teacher can create assignments."}), 403
        data = request.get_json()
        try:
            due_date = datetime.fromisoformat(data['due_date'])
        except (ValueError, KeyError):
            return jsonify({"error": "Invalid date format for due_date."}), 400

        new_assignment = Assignment(
            title=data['title'],
            description=data['description'],
            due_date=due_date,
            class_id=class_id
        )
        db.session.add(new_assignment)
        db.session.commit()
        return jsonify({"success": True, "assignment": new_assignment.to_dict()}), 201

@app.route('/api/assignments/<assignment_id>/submissions', methods=['GET', 'POST'])
@login_required
def manage_submissions(assignment_id):
    assignment = Assignment.query.get_or_404(assignment_id)

    if request.method == 'GET':
        # Teacher sees all submissions, student sees their own
        if current_user.id == assignment.class_obj.teacher_id:
            submissions = assignment.submissions.all()
        else:
            submissions = assignment.submissions.filter_by(student_id=current_user.id).all()
        return jsonify({"success": True, "submissions": [s.to_dict() for s in submissions]})

    if request.method == 'POST':
        if current_user.role != 'student':
            return jsonify({"error": "Only students can submit assignments."}), 403
        
        existing_submission = AssignmentSubmission.query.filter_by(assignment_id=assignment_id, student_id=current_user.id).first()
        if existing_submission:
            return jsonify({"error": "You have already submitted this assignment."}), 409

        data = request.get_json()
        new_submission = AssignmentSubmission(
            assignment_id=assignment_id,
            student_id=current_user.id,
            content=data['content']
        )
        db.session.add(new_submission)
        db.session.commit()
        return jsonify({"success": True, "submission": new_submission.to_dict()}), 201

@app.route('/api/submissions/<submission_id>/grade', methods=['POST'])
@teacher_required
def grade_submission(submission_id):
    submission = AssignmentSubmission.query.get_or_404(submission_id)
    if current_user.id != submission.assignment.class_obj.teacher_id:
        return jsonify({"error": "You are not authorized to grade this submission."}), 403
    
    data = request.get_json()
    submission.grade = data.get('grade')
    submission.feedback = data.get('feedback')
    db.session.commit()
    return jsonify({"success": True, "submission": submission.to_dict()})

# ==============================================================================
# --- 12. HTML & JAVASCRIPT FRONTEND ---
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
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body { background-color: #111827; font-family: 'Inter', sans-serif; }
        .glassmorphism { background: rgba(31, 41, 55, 0.5); backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px); border: 1px solid rgba(255, 255, 255, 0.1); }
        .brand-gradient { background-image: linear-gradient(to right, #3b82f6, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .fade-in { animation: fadeIn 0.5s ease-out forwards; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
        .active-tab { background-color: #374151; color: white; }
    </style>
</head>
<body class="text-gray-200 antialiased">
    <div id="announcement-banner" class="hidden text-center p-2 bg-indigo-600 text-white text-sm"></div>
    <div id="app-container" class="relative h-screen w-screen overflow-hidden"></div>
    <div id="toast-container" class="fixed top-6 right-6 z-[100] flex flex-col gap-2"></div>

    <!-- TEMPLATES START -->
    <template id="template-auth-page">
        <div class="flex flex-col items-center justify-center h-full w-full bg-gray-900 p-4 fade-in">
            <div class="w-full max-w-md glassmorphism rounded-2xl p-8 shadow-2xl">
                <h1 class="text-4xl font-bold text-center brand-gradient mb-4">Myth AI Portal</h1>
                <p class="text-gray-400 text-center mb-8" id="auth-subtitle">Sign in to continue</p>
                <form id="auth-form">
                    <div class="mb-4">
                        <label for="username" class="block text-sm font-medium text-gray-300 mb-1">Username</label>
                        <input type="text" id="username" name="username" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" required>
                    </div>
                    <div class="mb-4">
                        <label for="password" class="block text-sm font-medium text-gray-300 mb-1">Password</label>
                        <input type="password" id="password" name="password" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" required>
                    </div>
                    <div class="flex justify-end mb-6">
                        <button type="button" id="forgot-password-link" class="text-xs text-blue-400 hover:text-blue-300">Forgot Password?</button>
                    </div>
                    <button type="submit" id="auth-submit-btn" class="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:opacity-90 text-white font-bold py-3 px-4 rounded-lg transition-opacity">Login</button>
                    <p id="auth-error" class="text-red-400 text-sm text-center h-4 mt-3"></p>
                </form>
                <div class="text-center mt-6">
                    <button id="auth-toggle-btn" class="text-sm text-blue-400 hover:text-blue-300">Don't have an account? Sign Up</button>
                </div>
                <div class="text-center mt-4">
                    <button id="teacher-signup-btn" class="text-sm text-green-400 hover:text-green-300">Sign Up as Teacher</button>
                </div>
            </div>
        </div>
    </template>
    
    <template id="template-signup-page">
        <div class="flex flex-col items-center justify-center h-full w-full bg-gray-900 p-4 fade-in">
            <div class="w-full max-w-md glassmorphism rounded-2xl p-8 shadow-2xl">
                <h2 class="text-3xl font-bold text-center text-white mb-2" id="signup-title">Create Account</h2>
                <p class="text-gray-400 text-center mb-8" id="signup-subtitle">Begin your journey.</p>
                <form id="signup-form">
                    <input type="hidden" id="account_type" name="account_type" value="student">
                    <div class="mb-4">
                        <label for="signup-username" class="block text-sm font-medium text-gray-300 mb-1">Username</label>
                        <input type="text" id="signup-username" name="username" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" required minlength="3">
                    </div>
                    <div class="mb-4">
                        <label for="signup-email" class="block text-sm font-medium text-gray-300 mb-1">Email</label>
                        <input type="email" id="signup-email" name="email" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" required>
                    </div>
                    <div class="mb-4">
                        <label for="signup-password" class="block text-sm font-medium text-gray-300 mb-1">Password (min. 6 characters)</label>
                        <input type="password" id="signup-password" name="password" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" required minlength="6">
                    </div>
                    <div id="teacher-key-field" class="hidden mb-4">
                         <label for="teacher-secret-key" class="block text-sm font-medium text-gray-300 mb-1">Secret Teacher Key</label>
                         <input type="text" id="teacher-secret-key" name="secret_key" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500">
                    </div>
                    <button type="submit" class="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:opacity-90 text-white font-bold py-3 px-4 rounded-lg">Sign Up</button>
                    <p id="signup-error" class="text-red-400 text-sm text-center h-4 mt-3"></p>
                </form>
                <div class="text-center mt-6">
                    <button id="back-to-login" class="text-sm text-blue-400 hover:text-blue-300">Back to Login</button>
                </div>
            </div>
        </div>
    </template>

    <template id="template-main-dashboard">
        <div class="flex h-full w-full bg-gray-800 fade-in">
            <nav class="w-64 bg-gray-900 p-6 flex flex-col gap-4 flex-shrink-0">
                <h2 class="text-2xl font-bold text-white mb-4" id="dashboard-title">Dashboard</h2>
                <div id="nav-links" class="flex flex-col gap-2"></div>
                <button id="logout-btn" class="mt-auto bg-red-600 hover:bg-red-500 text-white font-bold py-2 px-4 rounded-lg">Logout</button>
            </nav>
            <main class="flex-1 p-8 overflow-y-auto">
                <div id="dashboard-content"></div>
            </main>
        </div>
    </template>
    
    <template id="template-my-classes">
        <h3 class="text-3xl font-bold text-white mb-6">My Classes</h3>
        <div id="class-action-container" class="mb-6"></div>
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6" id="classes-list"></div>
        <div id="selected-class-view" class="mt-8 hidden"></div>
    </template>
    
    <template id="template-student-class-action">
        <div class="glassmorphism p-4 rounded-lg">
            <h4 class="font-semibold text-lg mb-2 text-white">Join a New Class</h4>
            <div class="flex items-center gap-2">
                <input type="text" id="class-code" placeholder="Enter class code" class="flex-grow p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500">
                <button id="join-class-btn" class="bg-blue-600 hover:bg-blue-500 text-white font-bold py-3 px-4 rounded-lg">Join</button>
            </div>
        </div>
    </template>

    <template id="template-teacher-class-action">
        <div class="glassmorphism p-4 rounded-lg">
            <h4 class="font-semibold text-lg mb-2 text-white">Create a New Class</h4>
            <div class="flex items-center gap-2">
                <input type="text" id="new-class-name" placeholder="New class name" class="flex-grow p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500">
                <button id="create-class-btn" class="bg-blue-600 hover:bg-blue-500 text-white font-bold py-3 px-4 rounded-lg">Create</button>
            </div>
        </div>
    </template>

    <template id="template-selected-class-view">
        <div class="glassmorphism p-6 rounded-lg">
            <h4 class="text-2xl font-bold text-white mb-4">Class: <span id="selected-class-name"></span></h4>
            <div class="flex border-b border-gray-600 mb-4">
                <button class="py-2 px-4 text-gray-300 hover:text-white class-view-tab active-tab" data-tab="chat">Chat</button>
                <button class="py-2 px-4 text-gray-300 hover:text-white class-view-tab" data-tab="assignments">Assignments</button>
                <button class="py-2 px-4 text-gray-300 hover:text-white class-view-tab" data-tab="students">Students</button>
            </div>
            <div id="class-view-content"></div>
        </div>
    </template>
    
    <template id="template-class-chat-view">
        <div id="chat-messages" class="bg-gray-900/50 p-4 rounded-lg h-80 overflow-y-auto mb-4 border border-gray-700"></div>
        <form id="chat-form" class="flex items-center gap-2">
            <input type="text" id="chat-input" placeholder="Type a message..." class="flex-grow w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500">
            <button type="submit" id="send-chat-btn" class="bg-green-600 hover:bg-green-500 text-white font-bold py-3 px-4 rounded-lg">Send</button>
        </form>
    </template>

    <template id="template-class-assignments-view">
        <div id="assignments-list" class="space-y-4"></div>
        <div id="assignment-action-container" class="mt-6"></div>
    </template>

    <template id="template-class-students-view">
        <h5 class="text-xl font-semibold text-white mb-4">Enrolled Students</h5>
        <ul id="class-students-list" class="space-y-2"></ul>
    </template>
    
    <template id="template-profile">
        <h3 class="text-3xl font-bold text-white mb-6">Customize Profile</h3>
        <form id="profile-form" class="glassmorphism p-6 rounded-lg max-w-lg">
            <div class="mb-4">
                <label for="bio" class="block text-sm font-medium text-gray-300 mb-1">Bio</label>
                <textarea id="bio" name="bio" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" rows="4"></textarea>
            </div>
            <div class="mb-4">
                <label for="avatar" class="block text-sm font-medium text-gray-300 mb-1">Avatar URL</label>
                <input type="url" id="avatar" name="avatar" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500">
            </div>
            <button type="submit" class="bg-blue-600 hover:bg-blue-500 text-white font-bold py-2 px-4 rounded-lg">Save Profile</button>
        </form>
    </template>
    
    <template id="template-admin-dashboard">
        <h3 class="text-3xl font-bold text-white mb-6">Admin Dashboard</h3>
        <div id="admin-stats" class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8"></div>
        <div class="flex border-b border-gray-600 mb-4">
            <button class="py-2 px-4 text-gray-300 hover:text-white admin-view-tab active-tab" data-tab="users">Users</button>
            <button class="py-2 px-4 text-gray-300 hover:text-white admin-view-tab" data-tab="classes">Classes</button>
            <button class="py-2 px-4 text-gray-300 hover:text-white admin-view-tab" data-tab="settings">Settings</button>
        </div>
        <div id="admin-view-content"></div>
    </template>

    <template id="template-admin-users-view">
        <h4 class="text-xl font-bold text-white mb-4">User Management</h4>
        <div class="overflow-x-auto glassmorphism p-4 rounded-lg">
            <table class="w-full text-left text-sm text-gray-300">
                <thead>
                    <tr class="border-b border-gray-600">
                        <th class="p-3">Username</th><th class="p-3">Email</th><th class="p-3">Role</th><th class="p-3">Created At</th><th class="p-3">Actions</th>
                    </tr>
                </thead>
                <tbody id="admin-user-list" class="divide-y divide-gray-700/50"></tbody>
            </table>
        </div>
    </template>
    <!-- TEMPLATES END -->

    <script nonce="{csp_nonce}">
    document.addEventListener('DOMContentLoaded', () => {
        const appState = { 
            currentUser: null, 
            currentTab: 'my-classes', 
            selectedClass: null,
            socket: null,
        };
        const DOMElements = {
            appContainer: document.getElementById('app-container'),
            toastContainer: document.getElementById('toast-container'),
            announcementBanner: document.getElementById('announcement-banner'),
        };

        // --- UTILITY FUNCTIONS ---
        function showToast(message, type = 'info') {
            const colors = { info: 'bg-blue-600', success: 'bg-green-600', error: 'bg-red-600' };
            const toast = document.createElement('div');
            toast.className = `text-white text-sm py-2 px-4 rounded-lg shadow-lg fade-in ${colors[type]}`;
            toast.textContent = message;
            DOMElements.toastContainer.appendChild(toast);
            setTimeout(() => {
                toast.style.opacity = '0';
                setTimeout(() => toast.remove(), 500);
            }, 3500);
        }

        async function apiCall(endpoint, options = {}) {
            try {
                if (options.body && typeof options.body === 'object') {
                    options.headers = { 'Content-Type': 'application/json', ...options.headers };
                    options.body = JSON.stringify(options.body);
                }
                const response = await fetch(endpoint, { credentials: 'include', ...options });
                const data = await response.json();
                if (!response.ok) {
                    if (response.status === 401 && !window.location.pathname.includes('reset-password')) {
                        handleLogout(false);
                    }
                    throw new Error(data.error || `Request failed with status ${response.status}`);
                }
                return { success: true, ...data };
            } catch (error) {
                showToast(error.message, 'error');
                console.error("API Call Error:", error);
                return { success: false, error: error.message };
            }
        }

        function renderPage(templateId, setupFunction) {
            const template = document.getElementById(templateId);
            if (!template) {
                console.error(`Template ${templateId} not found.`);
                return;
            }
            const content = template.content.cloneNode(true);
            DOMElements.appContainer.innerHTML = '';
            DOMElements.appContainer.appendChild(content);
            if (setupFunction) setupFunction();
        }

        function renderSubTemplate(container, templateId, setupFunction) {
            const template = document.getElementById(templateId);
            if (!template) return;
            const content = template.content.cloneNode(true);
            container.innerHTML = '';
            container.appendChild(content);
            if (setupFunction) setupFunction();
        }
        
        function connectSocket() {
            if (appState.socket) {
                appState.socket.disconnect();
            }
            appState.socket = io();

            appState.socket.on('connect', () => {
                console.log('Socket connected!');
            });

            appState.socket.on('new_message', (data) => {
                if (appState.selectedClass && data.class_id === appState.selectedClass.id) {
                    appendChatMessage(data);
                }
            });
        }

        // --- PAGE & ROUTER SETUP ---
        function setupAuthPage() {
            renderPage('template-auth-page', () => {
                document.getElementById('auth-form').addEventListener('submit', handleLoginSubmit);
                document.getElementById('auth-toggle-btn').addEventListener('click', () => setupSignupPage('student'));
                document.getElementById('teacher-signup-btn').addEventListener('click', () => setupSignupPage('teacher'));
                document.getElementById('forgot-password-link').addEventListener('click', handleForgotPassword);
            });
        }
        
        function setupSignupPage(type = 'student') {
            renderPage('template-signup-page', () => {
                document.getElementById('signup-form').addEventListener('submit', handleSignupSubmit);
                document.getElementById('back-to-login').addEventListener('click', setupAuthPage);

                const title = document.getElementById('signup-title');
                const subtitle = document.getElementById('signup-subtitle');
                const accountTypeInput = document.getElementById('account_type');
                const teacherKeyField = document.getElementById('teacher-key-field');

                if (type === 'teacher') {
                    title.textContent = 'Create Teacher Account';
                    subtitle.textContent = 'A valid secret key is required.';
                    accountTypeInput.value = 'teacher';
                    teacherKeyField.classList.remove('hidden');
                    teacherKeyField.querySelector('input').required = true;
                } else {
                    title.textContent = 'Create Student Account';
                    subtitle.textContent = 'Begin your learning journey.';
                    accountTypeInput.value = 'student';
                    teacherKeyField.classList.add('hidden');
                    teacherKeyField.querySelector('input').required = false;
                }
            });
        }

        function setupDashboard() {
            const user = appState.currentUser;
            if (!user) return setupAuthPage();
            
            connectSocket();

            renderPage('template-main-dashboard', () => {
                const navLinks = document.getElementById('nav-links');
                const dashboardTitle = document.getElementById('dashboard-title');
                let tabs = [];

                if (user.role === 'student' || user.role === 'teacher') {
                    dashboardTitle.textContent = `${user.role.charAt(0).toUpperCase() + user.role.slice(1)} Portal`;
                    tabs = [
                        { id: 'my-classes', label: 'My Classes' },
                        { id: 'profile', label: 'Profile' }
                    ];
                } else if (user.role === 'admin') {
                    dashboardTitle.textContent = 'Admin Dashboard';
                    tabs = [
                        { id: 'admin-dashboard', label: 'Dashboard' },
                        { id: 'profile', label: 'My Profile' }
                    ];
                    appState.currentTab = 'admin-dashboard';
                }

                navLinks.innerHTML = tabs.map(tab => 
                    `<button data-tab="${tab.id}" class="dashboard-tab text-left text-gray-300 hover:text-white p-2 rounded-md">${tab.label}</button>`
                ).join('');

                document.querySelectorAll('.dashboard-tab').forEach(tab => {
                    tab.addEventListener('click', () => switchTab(tab.dataset.tab));
                });
                document.getElementById('logout-btn').addEventListener('click', () => handleLogout(true));
                switchTab(appState.currentTab);
            });
        }

        // --- TAB & CONTENT SETUP FUNCTIONS ---
        function switchTab(tab) {
            appState.currentTab = tab;
            document.querySelectorAll('.dashboard-tab').forEach(t => {
                t.classList.toggle('active-tab', t.dataset.tab === tab);
            });

            const contentContainer = document.getElementById('dashboard-content');
            const setups = {
                'my-classes': setupMyClassesTab,
                'profile': setupProfileTab,
                'admin-dashboard': setupAdminDashboardTab,
            };
            if (setups[tab]) {
                setups[tab](contentContainer);
            }
        }
        
        async function setupMyClassesTab(container) {
            renderSubTemplate(container, 'template-my-classes', async () => {
                const actionContainer = document.getElementById('class-action-container');
                const listContainer = document.getElementById('classes-list');
                const actionTemplateId = `template-${appState.currentUser.role}-class-action`;
                renderSubTemplate(actionContainer, actionTemplateId, () => {
                    if (appState.currentUser.role === 'student') {
                        document.getElementById('join-class-btn').addEventListener('click', handleJoinClass);
                    } else {
                        document.getElementById('create-class-btn').addEventListener('click', handleCreateClass);
                    }
                });

                const result = await apiCall('/api/my_classes');
                if (result.success && result.classes) {
                    if (result.classes.length === 0) {
                        listContainer.innerHTML = `<p class="text-gray-400 text-center col-span-full">You haven't joined or created any classes yet.</p>`;
                    } else {
                        listContainer.innerHTML = result.classes.map(cls => `
                            <div class="glassmorphism p-4 rounded-lg cursor-pointer hover:bg-gray-700/50 transition-colors" data-id="${cls.id}" data-name="${cls.name}">
                                <div class="font-bold text-white text-lg">${cls.name}</div>
                                <div class="text-gray-400 text-sm">Teacher: ${cls.teacher_name}</div>
                                ${appState.currentUser.role === 'teacher' ? `<div class="text-sm mt-2">Code: <span class="font-mono text-cyan-400">${cls.code}</span></div>` : ''}
                            </div>
                        `).join('');
                    }
                    listContainer.querySelectorAll('div[data-id]').forEach(el => el.addEventListener('click', (e) => {
                        selectClass(e.currentTarget.dataset.id, e.currentTarget.dataset.name);
                    }));
                }
            });
        }

        function setupProfileTab(container) {
            renderSubTemplate(container, 'template-profile', () => {
                document.getElementById('bio').value = appState.currentUser.profile.bio || '';
                document.getElementById('avatar').value = appState.currentUser.profile.avatar || '';
                document.getElementById('profile-form').addEventListener('submit', handleUpdateProfile);
            });
        }
        
        async function setupAdminDashboardTab(container) {
            renderSubTemplate(container, 'template-admin-dashboard', async () => {
                const result = await apiCall('/api/admin/dashboard_data');
                if (result.success) {
                    const statsContainer = document.getElementById('admin-stats');
                    statsContainer.innerHTML = `
                        <div class="glassmorphism p-4 rounded-lg"><p class="text-sm text-gray-400">Total Users</p><p class="text-2xl font-bold">${result.stats.total_users}</p></div>
                        <div class="glassmorphism p-4 rounded-lg"><p class="text-sm text-gray-400">Students</p><p class="text-2xl font-bold">${result.stats.total_students}</p></div>
                        <div class="glassmorphism p-4 rounded-lg"><p class="text-sm text-gray-400">Teachers</p><p class="text-2xl font-bold">${result.stats.total_teachers}</p></div>
                        <div class="glassmorphism p-4 rounded-lg"><p class="text-sm text-gray-400">Total Classes</p><p class="text-2xl font-bold">${result.stats.total_classes}</p></div>
                    `;
                }
                document.querySelectorAll('.admin-view-tab').forEach(tab => tab.addEventListener('click', (e) => {
                    switchAdminView(e.currentTarget.dataset.tab);
                }));
                switchAdminView('users'); // Default view
            });
        }
        
        function switchAdminView(view) {
             document.querySelectorAll('.admin-view-tab').forEach(t => {
                t.classList.toggle('active-tab', t.dataset.tab === view);
            });
            const container = document.getElementById('admin-view-content');
            if (view === 'users') {
                renderSubTemplate(container, 'template-admin-users-view', async () => {
                    const result = await apiCall('/api/admin/dashboard_data');
                    if(result.success) {
                        const userList = document.getElementById('admin-user-list');
                        userList.innerHTML = result.users.map(u => `
                            <tr>
                                <td class="p-3">${u.username}</td>
                                <td class="p-3">${u.email}</td>
                                <td class="p-3">${u.role}</td>
                                <td class="p-3">${new Date(u.created_at).toLocaleDateString()}</td>
                                <td class="p-3"><button class="text-red-500 hover:text-red-400" data-id="${u.id}">Delete</button></td>
                            </tr>
                        `).join('');
                    }
                });
            }
        }

        // --- EVENT HANDLERS ---
        async function handleLoginSubmit(e) {
            e.preventDefault();
            const result = await apiCall('/api/login', { method: 'POST', body: Object.fromEntries(new FormData(e.target)) });
            if (result.success) initializeApp(result.user, result.settings);
            else document.getElementById('auth-error').textContent = result.error;
        }
        
        async function handleSignupSubmit(e) {
            e.preventDefault();
            const result = await apiCall('/api/signup', { method: 'POST', body: Object.fromEntries(new FormData(e.target)) });
            if (result.success) initializeApp(result.user, {});
            else document.getElementById('signup-error').textContent = result.error;
        }
        
        async function handleForgotPassword() {
            const email = prompt('Please enter your account email address:');
            if (email && /^\\S+@\\S+\\.\\S+$/.test(email)) {
                const result = await apiCall('/api/request-password-reset', { method: 'POST', body: { email } });
                if(result.success) showToast(result.message || 'Request sent.', 'info');
            } else if (email) {
                showToast('Please enter a valid email address.', 'error');
            }
        }
        
        async function handleLogout(doApiCall) {
            if (doApiCall) await apiCall('/api/logout');
            if (appState.socket) appState.socket.disconnect();
            appState.currentUser = null;
            window.location.replace('/');
        }
        
        async function handleJoinClass() {
            const codeInput = document.getElementById('class-code');
            const code = codeInput.value.trim().toUpperCase();
            if (!code) return showToast('Please enter a class code.', 'error');
            const result = await apiCall('/api/join_class', { method: 'POST', body: { code } });
            if (result.success) {
                showToast(result.message || 'Joined class!', 'success');
                codeInput.value = '';
                setupMyClassesTab(document.getElementById('dashboard-content'));
            }
        }
        
        async function handleCreateClass() {
            const nameInput = document.getElementById('new-class-name');
            const name = nameInput.value.trim();
            if (!name) return showToast('Please enter a class name.', 'error');
            const result = await apiCall('/api/classes', { method: 'POST', body: { name } });
            if (result.success) {
                showToast(`Class "${result.class.name}" created!`, 'success');
                nameInput.value = '';
                setupMyClassesTab(document.getElementById('dashboard-content'));
            }
        }

        function selectClass(classId, className) {
            if (appState.selectedClass && appState.socket) {
                appState.socket.emit('leave', { room: appState.selectedClass.id });
            }
            appState.selectedClass = { id: classId, name: className };
            appState.socket.emit('join', { room: classId });

            const viewContainer = document.getElementById('selected-class-view');
            viewContainer.classList.remove('hidden');
            renderSubTemplate(viewContainer, 'template-selected-class-view', () => {
                document.getElementById('selected-class-name').textContent = className;
                document.querySelectorAll('.class-view-tab').forEach(tab => tab.addEventListener('click', (e) => {
                    switchClassView(e.currentTarget.dataset.tab);
                }));
                switchClassView('chat'); // Default view
            });
        }
        
        function switchClassView(view) {
            document.querySelectorAll('.class-view-tab').forEach(t => {
                t.classList.toggle('active-tab', t.dataset.tab === view);
            });
            const container = document.getElementById('class-view-content');
            if (view === 'chat') {
                renderSubTemplate(container, 'template-class-chat-view', async () => {
                    document.getElementById('chat-form').addEventListener('submit', handleSendChat);
                    const result = await apiCall(`/api/class_messages/${appState.selectedClass.id}`);
                    if (result.success) {
                        const messagesDiv = document.getElementById('chat-messages');
                        messagesDiv.innerHTML = '';
                        result.messages.forEach(m => appendChatMessage(m));
                    }
                });
            } else if (view === 'assignments') {
                renderSubTemplate(container, 'template-class-assignments-view', () => {
                    // TODO: Implement assignment view logic
                    container.innerHTML = '<p>Assignments feature coming soon!</p>';
                });
            } else if (view === 'students') {
                renderSubTemplate(container, 'template-class-students-view', async () => {
                    const result = await apiCall(`/api/classes/${appState.selectedClass.id}`);
                    if (result.success) {
                        const studentList = document.getElementById('class-students-list');
                        studentList.innerHTML = result.class.students.map(s => `
                            <li class="flex items-center gap-3 p-2 bg-gray-800/50 rounded-md">
                                <img src="${s.profile.avatar || 'https://i.pravatar.cc/40'}" class="w-8 h-8 rounded-full">
                                <span>${s.username}</span>
                            </li>
                        `).join('');
                    }
                });
            }
        }
        
        function handleSendChat(e) {
            e.preventDefault();
            const input = document.getElementById('chat-input');
            const message = input.value.trim();
            if (!message || !appState.socket) return;
            
            appState.socket.emit('send_message', {
                class_id: appState.selectedClass.id,
                message: message
            });
            input.value = '';
            input.focus();
        }

        function appendChatMessage(message) {
            const messagesDiv = document.getElementById('chat-messages');
            if (!messagesDiv) return;

            const isCurrentUser = message.sender_id === appState.currentUser.id;
            const isAI = message.sender_id === null;
            let senderClass = 'text-yellow-400';
            if (isCurrentUser) senderClass = 'text-green-400';
            if (isAI) senderClass = 'text-cyan-400';

            const msgEl = document.createElement('div');
            msgEl.className = 'mb-2 text-sm';
            msgEl.innerHTML = `
                <span class="font-bold ${senderClass}">${message.sender_name}:</span> 
                <span class="text-gray-200">${message.content}</span>
            `;
            messagesDiv.appendChild(msgEl);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        }
        
        async function handleUpdateProfile(e) {
            e.preventDefault();
            const result = await apiCall('/api/profile', { method: 'PUT', body: Object.fromEntries(new FormData(e.target)) });
            if (result.success) {
                appState.currentUser.profile = result.profile;
                showToast('Profile updated!', 'success');
            }
        }

        // --- APP INITIALIZATION ---
        function initializeApp(user, settings) {
            appState.currentUser = user;
            if (settings && settings.announcement) {
                DOMElements.announcementBanner.textContent = settings.announcement;
                DOMElements.announcementBanner.classList.remove('hidden');
            }
            setupDashboard();
        }

        async function main() {
            const result = await apiCall('/api/status');
            if (result.success && result.logged_in) {
                initializeApp(result.user, result.settings);
            } else {
                setupAuthPage();
            }
        }

        main();
    });
    </script>
</body>
</html>
"""

# ==============================================================================
# --- 13. APP INITIALIZATION & EXECUTION ---
# ==============================================================================
def initialize_app_database():
    with app.app_context():
        db.create_all()
        # Check if admin exists
        if not User.query.filter_by(role='admin').first():
            admin_pass = os.environ.get('ADMIN_PASSWORD', 'change-this-default-password')
            admin_email = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
            admin = User(
                username='admin',
                email=admin_email,
                password_hash=generate_password_hash(admin_pass),
                role='admin',
                plan='admin_plan'
            )
            db.session.add(admin)
            logging.info(f"Created default admin user with email {admin_email}.")

        # Check for default site settings
        if not SiteSettings.query.get('announcement'):
            db.session.add(SiteSettings(key='announcement', value='Welcome to the new Myth AI Portal!'))
            logging.info("Created default site announcement.")
            
        db.session.commit()

if __name__ == '__main__':
    initialize_app_database()
    port = int(os.environ.get('PORT', 5000))
    # Use socketio.run() to enable WebSocket support
    socketio.run(app, host='0.0.0.0', port=port, debug=True)

