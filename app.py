# --- app.py ---
# ==============================================================================
# --- 1. INITIAL CONFIGURATION & SETUP ---
# ==============================================================================
import os
import secrets
import logging
from flask import Flask, render_template, g, request, jsonify
from flask_talisman import Talisman
from flask_wtf.csrf import generate_csrf
from dotenv import load_dotenv

# --- Local Imports ---
from config import Config, setup_logging
from extensions import db, bcrypt, login_manager, mail, socketio, csrf, limiter, talisman
from models import User # Import User model for login_manager
from routes.main import main_bp
from routes.auth import auth_bp
from routes.classes import classes_bp
from routes.admin import admin_bp
from routes.billing import billing_bp
from sockets import register_socket_events
from commands import register_commands

# --- Setup ---
setup_logging()
load_dotenv()

def create_app(config_class=Config):
    """
    Application factory pattern.
    Creates and configures the Flask application.
    """
    app = Flask(__name__, static_folder='static', template_folder='templates')
    app.config.from_object(config_class)

    # --- Initialize Extensions ---
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    socketio.init_app(app, async_mode='eventlet', cors_allowed_origins="*")
    csrf.init_app(app)
    limiter.init_app(app)
    talisman.init_app(
        app,
        content_security_policy=app.config['TALISMAN_CSP'],
        force_https=app.config.get('IS_PRODUCTION', False),
        strict_transport_security=app.config.get('IS_PRODUCTION', False),
        frame_options='DENY',
        referrer_policy='strict-origin-when-cross-origin'
    )

    # --- User Loader ---
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(user_id)

    # --- Register Blueprints ---
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(classes_bp, url_prefix='/api/classes')
    app.register_blueprint(admin_bp, url_prefix='/api/admin')
    app.register_blueprint(billing_bp, url_prefix='/api/billing')

    # --- Register Socket.IO Events ---
    register_socket_events(socketio)

    # --- Register CLI Commands ---
    register_commands(app)

    # --- Request Hooks ---
    @app.before_request
    def before_request_func():
        g.nonce = secrets.token_hex(16)

    # --- Error Handling ---
    @app.errorhandler(404)
    def not_found_error(error):
        # For API routes, return JSON. For others, let the SPA handle it.
        if request.path.startswith('/api/'):
            return jsonify({"error": "Not Found"}), 404
        return render_template("index.html", csrf_token=generate_csrf(), nonce=g.get('nonce'))

    @app.errorhandler(Exception)
    def handle_exception(e):
        logging.error(f"An unhandled exception occurred: {e}", exc_info=True)
        return jsonify(error="An internal server error occurred."), 500

    return app

# --- Main Execution ---
app = create_app()

if __name__ == '__main__':
    # Use eventlet for production-like async environment
    import eventlet
    eventlet.monkey_patch()
    socketio.run(app, debug=not app.config.get('IS_PRODUCTION', False), host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

# --- config.py ---
import os
import logging
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

class Config:
    # --- Basic App Config ---
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-very-secret-key'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)

    # --- Security Config ---
    SECURITY_PASSWORD_SALT = os.environ.get('SECURITY_PASSWORD_SALT') or 'another-secret-salt'
    IS_PRODUCTION = os.environ.get('FLASK_ENV') == 'production'

    # --- Site-wide Keys & Settings ---
    STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY')
    STRIPE_PUBLIC_KEY = os.environ.get('STRIPE_PUBLIC_KEY')
    STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET')
    STRIPE_STUDENT_PRO_PRICE_ID = os.environ.get('STRIPE_STUDENT_PRO_PRICE_ID')
    YOUR_DOMAIN = os.environ.get('YOUR_DOMAIN', 'http://localhost:5000')
    SECRET_TEACHER_KEY = os.environ.get('SECRET_TEACHER_KEY')
    ADMIN_SECRET_KEY = os.environ.get('ADMIN_SECRET_KEY')
    GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')
    SUPPORT_EMAIL = os.environ.get('MAIL_SENDER')

    # --- Flask-Mail Config ---
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_SENDER')

    # --- Production Overrides ---
    if IS_PRODUCTION:
        SESSION_COOKIE_SECURE = True
        REMEMBER_COOKIE_SECURE = True
        SESSION_COOKIE_HTTPONLY = True
        REMEMBER_COOKIE_HTTPONLY = True
        SESSION_COOKIE_SAMESITE = 'Lax'

    # --- Content Security Policy (CSP) for Talisman ---
    PROD_ORIGIN = YOUR_DOMAIN.split("//")[-1]
    TALISMAN_CSP = {
        'default-src': '\'self\'',
        'script-src': [
            '\'self\'',
            'https://cdn.tailwindcss.com',
            'https://cdnjs.cloudflare.com',
            'https://js.stripe.com',
            '\'nonce-{nonce}\''
        ],
        'style-src': [
            '\'self\'',
            '\'unsafe-inline\'', # Kept for dynamic styles, but can be improved
            'https://cdn.tailwindcss.com',
            'https://fonts.googleapis.com',
            '\'nonce-{nonce}\''
        ],
        'font-src': ['\'self\'', 'https://fonts.gstatic.com'],
        'img-src': ['\'self\'', 'data:', 'https://i.pravatar.cc'],
        'connect-src': [
            '\'self\'',
            f'wss://{PROD_ORIGIN}' if IS_PRODUCTION else 'ws://localhost:5000',
            'https://api.stripe.com',
            'https://generativelanguage.googleapis.com'
        ],
        'object-src': '\'none\'',
        'base-uri': '\'self\'',
        'form-action': '\'self\''
    }

def setup_logging():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [SECURITY] - %(message)s')
    if Config.IS_PRODUCTION:
        # Add more robust logging for production if needed (e.g., file handler)
        pass

# --- extensions.py ---
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail
from flask_socketio import SocketIO
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
mail = Mail()
socketio = SocketIO()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
talisman = Talisman()

# --- models.py ---
import uuid
from datetime import datetime
from extensions import db, bcrypt
from sqlalchemy import event
from sqlalchemy.engine import Engine

# Set PRAGMA for SQLite on connection to enforce foreign keys
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if db.get_app().config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite'):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

# Association Table for Students and Classes
student_class_association = db.Table('student_class_association',
    db.Column('user_id', db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True),
    db.Column('class_id', db.String(36), db.ForeignKey('class.id', ondelete='CASCADE'), primary_key=True)
)

class User(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='student', index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    profile = db.relationship('Profile', back_populates='user', uselist=False, cascade="all, delete-orphan")
    taught_classes = db.relationship('Class', back_populates='teacher', lazy='dynamic', foreign_keys='Class.teacher_id', cascade="all, delete-orphan")
    enrolled_classes = db.relationship('Class', secondary=student_class_association, back_populates='students', lazy='dynamic')
    subscription = db.relationship('Subscription', back_populates='user', uselist=False, cascade="all, delete-orphan")

    # Flask-Login properties
    @property
    def is_active(self):
        return True

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def to_dict(self, include_email=False):
        profile_data = {
            'bio': self.profile.bio if self.profile else '',
            'avatar': self.profile.avatar if self.profile else '',
            'theme_preference': self.profile.theme_preference if self.profile else 'edgy_purple',
        }
        data = {
            'id': self.id,
            'username': self.username,
            'role': self.role,
            'profile': profile_data,
            'subscription_status': self.subscription.status if self.subscription else 'free'
        }
        if include_email:
            data['email'] = self.email
        return data

class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False, unique=True)
    bio = db.Column(db.Text, nullable=True)
    avatar = db.Column(db.String(500), nullable=True)
    theme_preference = db.Column(db.String(50), nullable=True, default='edgy_purple')
    user = db.relationship('User', back_populates='profile')

class Class(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(8), unique=True, nullable=False, index=True)
    teacher_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False, index=True)
    
    teacher = db.relationship('User', back_populates='taught_classes', foreign_keys=[teacher_id])
    students = db.relationship('User', secondary=student_class_association, back_populates='enrolled_classes', lazy='dynamic')
    messages = db.relationship('ChatMessage', back_populates='class_obj', lazy='dynamic', cascade="all, delete-orphan")

    def to_dict(self):
        return {
            'id': self.id, 'name': self.name, 'code': self.code,
            'teacher_name': self.teacher.username,
            'student_count': self.students.count()
        }

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    class_id = db.Column(db.String(36), db.ForeignKey('class.id', ondelete='CASCADE'), nullable=False, index=True)
    sender_id = db.Column(db.String(36), db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    class_obj = db.relationship('Class', back_populates='messages')
    sender = db.relationship('User', backref='sent_messages')

    def to_dict(self):
        return {
            'id': self.id,
            'class_id': self.class_id,
            'sender': self.sender.to_dict() if self.sender else {'username': 'Unknown User', 'id': None, 'profile': {}},
            'content': self.content,
            'timestamp': self.timestamp.isoformat()
        }

class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False, unique=True)
    stripe_customer_id = db.Column(db.String(255), unique=True)
    stripe_subscription_id = db.Column(db.String(255), unique=True)
    status = db.Column(db.String(50), default='free', index=True)
    user = db.relationship('User', back_populates='subscription')

class SiteSettings(db.Model):
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.Text)

# --- utils/decorators.py ---
from functools import wraps
from flask import jsonify, abort
from flask_login import current_user
from models import Class, student_class_association
from extensions import db
import logging

def role_required(role_names):
    if not isinstance(role_names, list):
        role_names = [role_names]
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({"error": "Login required."}), 401
            if current_user.role != 'admin' and current_user.role not in role_names:
                logging.warning(f"SECURITY: User {current_user.id} with role {current_user.role} attempted unauthorized access.")
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

admin_required = role_required(['admin'])
teacher_required = role_required(['teacher'])

def class_member_required(f):
    @wraps(f)
    def decorated_function(class_id, *args, **kwargs):
        target_class = Class.query.get_or_404(class_id)
        is_student = db.session.query(student_class_association.c.user_id).filter_by(user_id=current_user.id, class_id=class_id).first() is not None
        is_teacher = target_class.teacher_id == current_user.id
        is_admin = current_user.role == 'admin'
        if not (is_student or is_teacher or is_admin):
            logging.warning(f"SECURITY: User {current_user.id} attempted unauthorized access to class {class_id}.")
            abort(403)
        return f(target_class, *args, **kwargs)
    return decorated_function

# --- utils/helpers.py ---
from flask import current_app, render_template
from flask_mail import Message
from itsdangerous import TimestampSigner, SignatureExpired, BadTimeSignature
from extensions import mail

def send_email(subject, recipients, template_name, **kwargs):
    """Helper function to send emails."""
    msg = Message(subject, sender=current_app.config['MAIL_DEFAULT_SENDER'], recipients=recipients)
    msg.html = render_template(template_name, **kwargs)
    try:
        mail.send(msg)
        return True
    except Exception as e:
        current_app.logger.error(f"Failed to send email: {e}")
        return False

def generate_reset_token(user_email):
    """Generates a timed, signed token for password reset."""
    signer = TimestampSigner(current_app.config['SECRET_KEY'])
    return signer.sign(user_email.encode('utf-8')).decode('utf-8')

def verify_reset_token(token, max_age_seconds=3600):
    """Verifies a password reset token and returns the email if valid."""
    signer = TimestampSigner(current_app.config['SECRET_KEY'])
    try:
        email = signer.unsign(token, max_age=max_age_seconds).decode('utf-8')
        return email
    except (SignatureExpired, BadTimeSignature):
        return None

# --- routes/main.py ---
from flask import Blueprint, render_template, jsonify, g
from flask_login import current_user
from flask_wtf.csrf import generate_csrf
from models import SiteSettings

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
@main_bp.route('/<path:path>')
def render_spa(path=None):
    """Serves the main Single-Page Application."""
    return render_template("index.html", csrf_token=generate_csrf(), nonce=g.get('nonce'))

@main_bp.route('/api/status')
def status():
    """Provides initial status, user info, and site settings to the frontend."""
    settings_raw = SiteSettings.query.all()
    settings = {s.key: s.value for s in settings_raw}
    user_data = current_user.to_dict(include_email=True) if current_user.is_authenticated else None
    return jsonify({"user": user_data, "settings": settings})

# --- routes/auth.py ---
import logging
import bleach
from flask import Blueprint, request, jsonify, current_app, session
from flask_login import login_user, logout_user, current_user
from sqlalchemy import or_
from password_strength import PasswordPolicy

from extensions import db, limiter
from models import User, Profile, SiteSettings
from utils.helpers import generate_reset_token, send_email, verify_reset_token

auth_bp = Blueprint('auth', __name__)
password_policy = PasswordPolicy.from_names(length=12, uppercase=1, numbers=1, special=1)

@auth_bp.route('/signup', methods=['POST'])
@limiter.limit("5 per 15 minutes")
def signup():
    data = request.json
    username = bleach.clean(data.get('username', '')).strip()
    email = bleach.clean(data.get('email', '')).strip().lower()
    password = data.get('password')
    role = bleach.clean(data.get('account_type', 'student'))

    if not all([username, email, password, role]):
        return jsonify({"error": "Missing required fields."}), 400
    
    if password_policy.test(password):
        return jsonify({"error": "Password is too weak."}), 400

    if User.query.filter(or_(User.username == username, User.email == email)).first():
        return jsonify({"error": "Username or email already exists."}), 409

    if role == 'teacher' and data.get('secret_key') != current_app.config['SECRET_TEACHER_KEY']:
        return jsonify({"error": "Invalid teacher secret key."}), 403

    new_user = User(username=username, email=email, role=role)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    
    # Create profile and subscription stubs
    db.session.add(Profile(user_id=new_user.id))
    db.session.commit()

    login_user(new_user)
    settings = {s.key: s.value for s in SiteSettings.query.all()}
    return jsonify({"success": True, "user": new_user.to_dict(include_email=True), "settings": settings})

@auth_bp.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()

    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid username or password"}), 401

    if user.role == 'admin' and data.get('admin_secret_key') != current_app.config['ADMIN_SECRET_KEY']:
        return jsonify({"error": "Invalid admin secret key."}), 403

    login_user(user, remember=True)
    settings = {s.key: s.value for s in SiteSettings.query.all()}
    return jsonify({"success": True, "user": user.to_dict(include_email=True), "settings": settings})

@auth_bp.route('/logout', methods=['POST'])
def logout():
    if current_user.is_authenticated:
        logout_user()
    return jsonify({"success": True})

@auth_bp.route('/update_profile', methods=['POST'])
def update_profile():
    if not current_user.is_authenticated:
        return jsonify({"error": "Authentication required"}), 401
    
    data = request.json
    profile = current_user.profile
    profile.bio = bleach.clean(data.get('bio', profile.bio))
    profile.avatar = bleach.clean(data.get('avatar', profile.avatar))
    profile.theme_preference = bleach.clean(data.get('theme_preference', profile.theme_preference))
    db.session.commit()
    return jsonify({"success": True, "profile": {"bio": profile.bio, "avatar": profile.avatar, "theme_preference": profile.theme_preference}})

@auth_bp.route('/forgot_password', methods=['POST'])
@limiter.limit("3 per hour")
def forgot_password():
    email = bleach.clean(request.json.get('email', '')).lower()
    user = User.query.filter_by(email=email).first()
    if user:
        token = generate_reset_token(email)
        reset_url = f"{current_app.config['YOUR_DOMAIN']}/reset-password/{token}"
        send_email(
            subject="Reset Your Password for Myth AI",
            recipients=[email],
            template_name="emails/password_reset.html",
            reset_url=reset_url
        )
    # Always return success to prevent email enumeration
    return jsonify({"success": True, "message": "If an account with that email exists, a reset link has been sent."})

@auth_bp.route('/reset_password', methods=['POST'])
@limiter.limit("5 per 15 minutes")
def reset_password():
    data = request.json
    token = data.get('token')
    new_password = data.get('password')

    if not token or not new_password:
        return jsonify({"error": "Token and password are required."}), 400

    if password_policy.test(new_password):
        return jsonify({"error": "New password is too weak."}), 400
        
    email = verify_reset_token(token)
    if not email:
        return jsonify({"error": "Invalid or expired token."}), 400
        
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found."}), 404
        
    user.set_password(new_password)
    db.session.commit()
    
    # Log the user in after a successful password reset
    login_user(user)
    
    return jsonify({"success": True, "message": "Password has been reset successfully."})

# --- routes/classes.py ---
import secrets
import bleach
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from sqlalchemy.orm import selectinload

from extensions import db
from models import Class, ChatMessage, User
from utils.decorators import teacher_required, class_member_required

classes_bp = Blueprint('classes', __name__)

@classes_bp.route('/', methods=['GET'])
@login_required
def get_classes():
    query = current_user.taught_classes if current_user.role == 'teacher' else current_user.enrolled_classes
    classes = query.options(selectinload(Class.teacher)).all()
    return jsonify({"success": True, "classes": [c.to_dict() for c in classes]})

@classes_bp.route('/create', methods=['POST'])
@login_required
@teacher_required
def create_class():
    name = bleach.clean(request.json.get('name'))
    if not name or len(name) > 100:
        return jsonify({"error": "Invalid class name."}), 400
    
    code = secrets.token_urlsafe(6).upper()
    while Class.query.filter_by(code=code).first():
        code = secrets.token_urlsafe(6).upper()
        
    new_class = Class(name=name, teacher_id=current_user.id, code=code)
    db.session.add(new_class)
    db.session.commit()
    return jsonify({"success": True, "class": new_class.to_dict()}), 201

@classes_bp.route('/join', methods=['POST'])
@login_required
def join_class():
    code = bleach.clean(request.json.get('code', '')).upper()
    target_class = Class.query.filter_by(code=code).first()
    if not target_class:
        return jsonify({"error": "Invalid class code."}), 404
    if current_user in target_class.students:
        return jsonify({"error": "You are already in this class."}), 409
        
    target_class.students.append(current_user)
    db.session.commit()
    return jsonify({"success": True, "class_name": target_class.name})

@classes_bp.route('/<string:class_id>/messages', methods=['GET'])
@login_required
@class_member_required
def get_messages(target_class):
    messages = target_class.messages.options(
        selectinload(ChatMessage.sender).selectinload(User.profile)
    ).order_by(ChatMessage.timestamp.asc()).limit(100).all()
    return jsonify({"success": True, "messages": [m.to_dict() for m in messages]})

# --- routes/admin.py ---
from flask import Blueprint, request, jsonify
from flask_login import login_required
from sqlalchemy.orm import selectinload
import bleach

from extensions import db
from models import User, SiteSettings
from utils.decorators import admin_required

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/users', methods=['GET'])
@login_required
@admin_required
def get_all_users():
    users = User.query.options(selectinload(User.profile)).all()
    return jsonify({"success": True, "users": [user.to_dict(include_email=True) for user in users]})

@admin_bp.route('/settings', methods=['POST'])
@login_required
@admin_required
def update_admin_settings():
    data = request.json
    allowed_keys = ['site_wide_theme', 'background_image_url', 'music_url']
    for key, value in data.items():
        clean_key = bleach.clean(key)
        if clean_key not in allowed_keys: continue
        
        setting = SiteSettings.query.filter_by(key=clean_key).first()
        clean_value = bleach.clean(value)
        
        if setting:
            setting.value = clean_value
        else:
            db.session.add(SiteSettings(key=clean_key, value=clean_value))
            
    db.session.commit()
    settings = {s.key: s.value for s in SiteSettings.query.all()}
    return jsonify({"success": True, "settings": settings})

# --- routes/billing.py ---
import stripe
from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from models import Subscription
from extensions import db

billing_bp = Blueprint('billing', __name__)
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')

@billing_bp.route('/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    try:
        # Create a Stripe Customer if one doesn't exist
        if not current_user.subscription or not current_user.subscription.stripe_customer_id:
            customer = stripe.Customer.create(email=current_user.email, name=current_user.username)
            customer_id = customer.id
            if current_user.subscription:
                current_user.subscription.stripe_customer_id = customer_id
            else:
                sub = Subscription(user_id=current_user.id, stripe_customer_id=customer_id)
                db.session.add(sub)
            db.session.commit()
        else:
            customer_id = current_user.subscription.stripe_customer_id

        checkout_session = stripe.checkout.Session.create(
            customer=customer_id,
            line_items=[{'price': current_app.config['STRIPE_STUDENT_PRO_PRICE_ID'], 'quantity': 1}],
            mode='subscription',
            success_url=current_app.config['YOUR_DOMAIN'] + '/?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=current_app.config['YOUR_DOMAIN'] + '/',
        )
        return jsonify({
            "session_id": checkout_session.id,
            "public_key": current_app.config['STRIPE_PUBLIC_KEY']
        })
    except Exception as e:
        return jsonify(error=str(e)), 403

@billing_bp.route('/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    endpoint_secret = current_app.config['STRIPE_WEBHOOK_SECRET']
    event = None

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
    except ValueError as e:
        # Invalid payload
        return 'Invalid payload', 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        return 'Invalid signature', 400

    # Handle the event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        customer_id = session.get('customer')
        subscription_id = session.get('subscription')
        
        # Find user by customer_id and update their subscription
        sub = Subscription.query.filter_by(stripe_customer_id=customer_id).first()
        if sub:
            sub.stripe_subscription_id = subscription_id
            sub.status = 'active'
            db.session.commit()
            logging.info(f"Subscription activated for customer {customer_id}")

    elif event['type'] == 'customer.subscription.deleted' or event['type'] == 'customer.subscription.updated':
        session = event['data']['object']
        subscription_id = session.get('id')
        status = session.get('status')
        
        sub = Subscription.query.filter_by(stripe_subscription_id=subscription_id).first()
        if sub:
            # Handle states like 'canceled', 'past_due', etc.
            sub.status = status if status != 'canceled' else 'free'
            db.session.commit()
            logging.info(f"Subscription status updated to {status} for subscription {subscription_id}")

    return 'Success', 200


# --- sockets.py ---
import logging
import bleach
from flask_socketio import emit, join_room, leave_room
from flask_login import current_user
from extensions import db
from models import Class, ChatMessage

def register_socket_events(socketio):
    @socketio.on('join')
    def on_join(data):
        if not current_user.is_authenticated: return
        room = data['room']
        target_class = Class.query.get(room)
        if not target_class or (current_user not in target_class.students and target_class.teacher_id != current_user.id):
            return
        join_room(room)
        logging.info(f"User {current_user.username} joined room {room}")

    @socketio.on('leave')
    def on_leave(data):
        if not current_user.is_authenticated: return
        room = data['room']
        leave_room(room)
        logging.info(f"User {current_user.username} left room {room}")

    @socketio.on('send_message')
    def handle_send_message(data):
        if not current_user.is_authenticated: return
        room = data['room']
        content = bleach.clean(data['content'])
        msg = ChatMessage(class_id=room, sender_id=current_user.id, content=content)
        db.session.add(msg)
        db.session.commit()
        emit('new_message', msg.to_dict(), to=room)

# --- commands.py ---
import logging
from extensions import db
from models import SiteSettings

def register_commands(app):
    @app.cli.command("init-db")
    def init_db_command():
        """Creates database tables and seeds initial settings."""
        db.create_all()
        default_settings = {
            'site_wide_theme': 'default',
            'background_image_url': '',
            'music_url': ''
        }
        for key, value in default_settings.items():
            if not SiteSettings.query.filter_by(key=key).first():
                db.session.add(SiteSettings(key=key, value=value))
        db.session.commit()
        logging.info("Database initialized and seeded.")

# --- templates/index.html ---
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Myth AI Portal</title>
    <script src="https://js.stripe.com/v3/"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Cinzel+Decorative:wght@700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
    <meta name="csrf-token" content="{{ csrf_token() }}">
</head>
<body class="text-gray-200 antialiased">
    <div id="app-container" class="relative min-h-screen w-full overflow-x-hidden flex flex-col"></div>
    <div id="toast-container" class="fixed top-6 right-6 z-[100] flex flex-col gap-2"></div>
    <div id="modal-container"></div>
    <div id="music-player-container" class="fixed bottom-4 left-4 z-50"></div>
    <div class="fixed bottom-4 right-4 text-xs text-gray-400 z-0">Built by Devector</div>

    <template id="template-welcome-screen">
        <div class="relative h-screen w-screen flex flex-col items-center justify-center overflow-hidden bg-bg-dark">
            <div class="absolute inset-0 overflow-hidden">
                <div class="particles"></div>
                <div class="gradient-overlay"></div>
            </div>
            <div class="relative z-10 flex flex-col items-center text-center px-4">
                <div id="logo-container-welcome" class="w-32 h-32 mb-6 transform hover:scale-110 transition-transform duration-500"></div>
                <h1 class="text-6xl md:text-7xl font-title brand-gradient-text animate-pulse-slow">Hi Myth!</h1>
                <p class="text-xl md:text-2xl text-text-secondary-color mt-4 max-w-lg animate-fade-in-up">
                    Let me help you with your homework.
                </p>
                <button id="enter-portal-btn" class="mt-8 brand-gradient-bg shiny-button text-white font-bold py-3 px-6 rounded-lg text-lg transform hover:scale-105 transition-all duration-300">
                    Enter the Portal
                </button>
            </div>
        </div>
    </template>
    <template id="template-full-screen-loader">
        <div class="full-screen-loader fade-in">
            <div id="logo-container-loader" class="h-16 w-16 mx-auto mb-4 animate-spin"></div>
            <div class="waiting-text">Loading Portal...</div>
        </div>
    </template>
    <template id="template-role-choice">
        <div class="h-screen w-screen flex flex-col items-center justify-center dynamic-bg p-4">
            <div class="text-center mb-8">
                <div id="logo-container-role" class="w-24 h-24 mx-auto mb-2"></div>
                <h1 class="text-5xl font-title brand-gradient-text">Select Your Role</h1>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-4xl w-full">
                <div class="role-btn glassmorphism p-6 rounded-lg text-center cursor-pointer hover:scale-105 transition-transform" data-role="student"><h2 class="text-2xl font-bold">Student</h2></div>
                <div class="role-btn glassmorphism p-6 rounded-lg text-center cursor-pointer hover:scale-105 transition-transform" data-role="teacher"><h2 class="text-2xl font-bold">Teacher</h2></div>
                <div class="role-btn glassmorphism p-6 rounded-lg text-center cursor-pointer hover:scale-105 transition-transform" data-role="admin"><h2 class="text-2xl font-bold">Admin</h2></div>
            </div>
        </div>
    </template>
    <template id="template-main-dashboard">
        <div class="flex h-screen bg-bg-dark">
            <aside class="w-64 bg-bg-med p-4 flex-col glassmorphism border-r border-gray-700/50 hidden md:flex">
                <div class="flex items-center gap-2 mb-4">
                    <div id="logo-container-dash" class="w-10 h-10"></div>
                    <h1 id="dashboard-title" class="text-xl font-bold text-white"></h1>
                </div>
                <div id="welcome-message" class="mb-4 text-center text-sm text-gray-300 p-2 border border-gray-600 rounded-md"></div>
                <nav id="nav-links" class="flex-1 flex flex-col gap-2"></nav>
                <div class="mt-auto">
                    <button id="logout-btn" class="w-full text-left text-gray-300 hover:bg-red-800/50 p-3 rounded-md transition-colors">Logout</button>
                </div>
            </aside>
            <main id="dashboard-content" class="flex-1 p-4 md:p-6 overflow-y-auto"></main>
        </div>
    </template>
     <template id="template-main-search-view">
        <div class="fade-in flex flex-col items-center justify-center h-full">
            <div id="logo-container-main" class="w-24 h-24 mb-4"></div>
            <div class="w-full max-w-2xl">
                <input type="text" placeholder="What do you want to know?" class="w-full p-4 bg-bg-med rounded-lg border border-gray-700/50 text-lg focus:ring-2 focus:ring-purple-500 outline-none">
                <div class="flex justify-center gap-4 mt-4">
                    <button class="dashboard-tab shiny-button bg-bg-med p-2 px-4 rounded-lg" data-tab="deep-search">DeepSearch</button>
                    <button class="dashboard-tab shiny-button bg-bg-med p-2 px-4 rounded-lg" data-tab="create-images">Create Images</button>
                    <button class="dashboard-tab shiny-button bg-bg-med p-2 px-4 rounded-lg" data-tab="latest-news">Latest News</button>
                    <button class="dashboard-tab shiny-button bg-bg-med p-2 px-4 rounded-lg" data-tab="personas">Personas</button>
                </div>
            </div>
        </div>
    </template>
    <template id="template-auth-form">
        <div class="min-h-screen flex items-center justify-center dynamic-bg px-4">
            <div class="max-w-md w-full glassmorphism p-8 rounded-2xl">
                <button id="back-to-roles" class="text-sm text-gray-400 hover:text-white mb-4">&larr; Back</button>
                <div class="text-center">
                    <div id="logo-container-auth" class="w-16 h-16 mx-auto mb-2"></div>
                    <h2 id="auth-title" class="text-3xl font-bold text-white"></h2>
                    <p id="auth-subtitle" class="mt-2 text-gray-300"></p>
                </div>
                <form id="auth-form" class="mt-8 space-y-4">
                    <input type="hidden" name="account_type" id="account_type">
                    <div id="username-field"><input id="username" name="username" type="text" autocomplete="username" required class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="Username"></div>
                    <div id="email-field"><input id="email" name="email" type="email" autocomplete="email" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="Email address"></div>
                    <div><input id="password" name="password" type="password" required class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="Password"></div>
                    <div id="teacher-key-field" class="hidden"><input id="teacher-secret-key" name="secret_key" type="password" class="w-full p-3 bg-gray-700/50 rounded-lg" placeholder="Teacher Secret Key"></div>
                    <div id="admin-key-field" class="hidden"><input id="admin-secret-key" name="admin_secret_key" type="password" class="w-full p-3 bg-gray-700/50 rounded-lg" placeholder="Admin Secret Key"></div>
                    <p id="auth-error" class="text-red-400 text-sm text-center h-4"></p>
                    <div><button id="auth-submit-btn" type="submit" class="w-full brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg">Sign In</button></div>
                </form>
                <div class="mt-4 text-sm text-center">
                    <button id="auth-toggle-btn" class="font-medium text-purple-400 hover:text-purple-300"></button>
                    <span class="text-gray-400 mx-1">|</span>
                    <button id="forgot-password-btn" class="font-medium text-purple-400 hover:text-purple-300">Forgot Password?</button>
                </div>
            </div>
        </div>
    </template>
    <template id="template-reset-password-form">
        <div class="min-h-screen flex items-center justify-center dynamic-bg px-4">
            <div class="max-w-md w-full glassmorphism p-8 rounded-2xl">
                <div class="text-center">
                    <div id="logo-container-reset" class="w-16 h-16 mx-auto mb-2"></div>
                    <h2 class="text-3xl font-bold text-white">Reset Your Password</h2>
                </div>
                <form id="reset-password-form" class="mt-8 space-y-4">
                    <div><input id="new-password" name="password" type="password" required class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="New Password"></div>
                    <p id="reset-error" class="text-red-400 text-sm text-center h-4"></p>
                    <div><button type="submit" class="w-full brand-gradient-bg shiny-button text-white font-bold py-3 px-4 rounded-lg">Set New Password</button></div>
                </form>
            </div>
        </div>
    </template>
    <template id="template-my-classes">
        <div class="fade-in">
            <div class="flex justify-between items-center mb-6">
                <h2 id="my-classes-title" class="text-3xl font-bold text-white">My Classes</h2>
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
        <form id="join-class-form" class="glassmorphism p-4 rounded-lg flex flex-col md:flex-row gap-2">
            <input type="text" name="code" placeholder="Enter Class Code" class="flex-grow p-2 bg-gray-700/50 rounded-md border border-gray-600" required>
            <button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Join</button>
        </form>
    </template>
    <template id="template-teacher-class-action">
        <form id="create-class-form" class="glassmorphism p-4 rounded-lg flex flex-col md:flex-row gap-2">
            <input type="text" name="name" placeholder="New Class Name" class="flex-grow p-2 bg-gray-700/50 rounded-md border border-gray-600" required>
            <button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Create</button>
        </form>
    </template>
    <template id="template-selected-class-view">
        <div class="flex border-b border-gray-700 mb-4">
            <button data-tab="chat" class="class-view-tab py-2 px-4 text-gray-300 hover:text-white">Chat</button>
        </div>
        <div id="class-view-content"></div>
    </template>
    <template id="template-class-chat-view">
        <div class="flex flex-col h-[calc(100vh-15rem)]">
            <div id="chat-messages" class="flex-1 overflow-y-auto p-4 space-y-4"></div>
            <form id="chat-form" class="p-4 bg-bg-med glassmorphism mt-2 rounded-lg">
                <div class="flex items-center gap-2">
                    <input id="chat-input" type="text" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" placeholder="Type a message..." autocomplete="off">
                    <button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-3 px-5 rounded-lg">Send</button>
                </div>
            </form>
        </div>
    </template>
    <template id="template-profile">
        <div class="fade-in max-w-2xl mx-auto">
            <h2 class="text-3xl font-bold mb-6 text-white">My Profile</h2>
            <div class="flex border-b border-gray-700 mb-4">
                <button data-tab="settings" class="profile-view-tab py-2 px-4 text-gray-300 hover:text-white">Settings</button>
                <button data-tab="billing" class="profile-view-tab py-2 px-4 text-gray-300 hover:text-white">Billing</button>
            </div>
            <div id="profile-view-content"></div>
        </div>
    </template>
    <template id="template-profile-settings">
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
    </template>
    <template id="template-profile-billing">
        <div class="glassmorphism p-6 rounded-lg space-y-4">
            <h3 class="text-2xl font-bold">Subscription</h3>
            <div id="subscription-status"></div>
            <div id="billing-actions"></div>
        </div>
    </template>
    <template id="template-admin-dashboard">
       <div class="fade-in">
            <h2 class="text-3xl font-bold mb-6 text-white">Admin Dashboard</h2>
            <div class="flex border-b border-gray-700 mb-4">
                <button data-tab="users" class="admin-view-tab py-2 px-4 text-gray-300 hover:text-white">Users</button>
                <button data-tab="settings" class="admin-view-tab py-2 px-4 text-gray-300 hover:text-white">Settings</button>
            </div>
            <div id="admin-view-content"></div>
       </div>
    </template>
    <template id="template-admin-users-view">
        <div class="glassmorphism p-4 rounded-lg">
            <h3 class="text-2xl font-bold mb-4">User Management</h3>
            <div class="overflow-auto max-h-96">
                <table class="w-full text-left">
                    <thead class="bg-bg-light sticky top-0"><tr><th class="p-3">Username</th><th class="p-3">Email</th><th class="p-3">Role</th></tr></thead>
                    <tbody id="users-table-body"></tbody>
                </table>
            </div>
        </div>
    </template>
    <template id="template-admin-settings-view">
        <div class="glassmorphism p-4 rounded-lg">
            <h3 class="text-2xl font-bold mb-4">Site Settings</h3>
            <form id="admin-settings-form" class="space-y-4">
                <div>
                    <label for="site-wide-theme-select" class="block text-sm font-medium text-gray-300 mb-1">Global Theme</label>
                    <select id="site-wide-theme-select" name="site_wide_theme" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600"></select>
                </div>
                 <div>
                    <label for="background-image-url" class="block text-sm font-medium text-gray-300 mb-1">Background Image URL</label>
                    <input id="background-image-url" name="background_image_url" type="url" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600">
                </div>
                <div>
                    <label for="music-url" class="block text-sm font-medium text-gray-300 mb-1">Background Music URL</label>
                    <input id="music-url" name="music_url" type="url" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600">
                </div>
                <button type="submit" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Save Settings</button>
            </form>
        </div>
    </template>
    <template id="template-deep-search-view">
        <div class="fade-in">
            <h2 class="text-3xl font-bold mb-6 text-white">DeepSearch</h2>
            <p class="text-gray-400">This is the DeepSearch feature. In-depth analysis and research tools would go here.</p>
        </div>
    </template>
    <template id="template-create-images-view">
        <div class="fade-in">
            <h2 class="text-3xl font-bold mb-6 text-white">Create Images</h2>
            <p class="text-gray-400">This is the Create Images feature. AI image generation prompts and results would go here.</p>
        </div>
    </template>
    <template id="template-latest-news-view">
        <div class="fade-in">
            <h2 class="text-3xl font-bold mb-6 text-white">Latest News</h2>
            <p class="text-gray-400">This is the Latest News feature. A feed of current events and topics would go here.</p>
        </div>
    </template>
    <template id="template-personas-view">
        <div class="fade-in">
            <h2 class="text-3xl font-bold mb-6 text-white">Personas</h2>
            <p class="text-gray-400">This is the Personas feature. Users could select different AI personalities to chat with here.</p>
        </div>
    </template>

    <script src="{{ url_for('static', filename='js/app.js') }}" nonce="{{ nonce }}"></script>
</body>
</html>

# --- templates/emails/password_reset.html ---
<!DOCTYPE html>
<html>
<head>
    <title>Password Reset</title>
    <style>
        body { font-family: sans-serif; color: #333; }
        .container { padding: 20px; max-width: 600px; margin: auto; border: 1px solid #ddd; border-radius: 5px; }
        .button { background-color: #5a3fc0; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Password Reset Request</h2>
        <p>Hello,</p>
        <p>You requested a password reset for your Myth AI account. Please click the button below to set a new password. This link is valid for one hour.</p>
        <p style="text-align: center; margin: 20px 0;">
            <a href="{{ reset_url }}" class="button">Reset Password</a>
        </p>
        <p>If you did not request this, please ignore this email.</p>
        <p>Thanks,<br>The Myth AI Team</p>
    </div>
</body>
</html>

# --- static/js/app.js ---
document.addEventListener('DOMContentLoaded', () => {
    try {
        const DOMElements = {
            appContainer: document.getElementById('app-container'),
            toastContainer: document.getElementById('toast-container'),
            modalContainer: document.getElementById('modal-container'),
            musicPlayerContainer: document.getElementById('music-player-container'),
        };
        let appState = { currentUser: null, isLoginView: true, selectedRole: 'student', siteSettings: {}, currentClass: null, socket: null };

        const themes = {
            golden: { '--brand-hue': 45, '--bg-dark': '#1A120B', '--bg-med': '#2c241e', '--bg-light': '#4a3f35', '--text-color': '#F5EFE6', '--text-secondary-color': '#AE8E6A' },
            dark: { '--brand-hue': 220, '--bg-dark': '#0F172A', '--bg-med': '#1E293B', '--bg-light': '#334155', '--text-color': '#E2E8F0', '--text-secondary-color': '#94A3B8' },
            edgy_purple: { '--brand-hue': 260, '--bg-dark': '#110D19', '--bg-med': '#211A2E', '--bg-light': '#3B2D4F', '--text-color': '#EADFFF', '--text-secondary-color': '#A17DFF' },
            light_green: { '--brand-hue': 140, '--bg-dark': '#131f17', '--bg-med': '#1a2e23', '--bg-light': '#274a34', '--text-color': '#e1f2e9', '--text-secondary-color': '#6fdc9d' }
        };
        const svgLogo = `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="logoGradient" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" style="stop-color:hsl(var(--brand-hue), 90%, 60%);" /><stop offset="100%" style="stop-color:hsl(var(--brand-hue), 80%, 50%);" /></linearGradient></defs><path fill="url(#logoGradient)" d="M50,14.7C30.5,14.7,14.7,30.5,14.7,50S30.5,85.3,50,85.3S85.3,69.5,85.3,50S69.5,14.7,50,14.7z M50,77.6 C34.8,77.6,22.4,65.2,22.4,50S34.8,22.4,50,22.4s27.6,12.4,27.6,27.6S65.2,77.6,50,77.6z"/><circle cx="50" cy="50" r="10" fill="white"/></svg>`;

        // --- UTILITY FUNCTIONS ---
        function escapeHtml(unsafe) { if (typeof unsafe !== 'string') return ''; return unsafe.replace(/[&<>"']/g, m => ({'&': '&amp;','<': '&lt;','>': '&gt;','"': '&quot;',"'": '&#039;'})[m]); }
        function injectLogo() { document.querySelectorAll('[id^="logo-container-"]').forEach(c => c.innerHTML = svgLogo); }

        function applyTheme(userPreference) {
            const siteTheme = appState.siteSettings.site_wide_theme;
            const themeToApply = (siteTheme && siteTheme !== 'default') ? siteTheme : userPreference;
            const t = themes[themeToApply] || themes.edgy_purple;
            Object.entries(t).forEach(([k, v]) => document.documentElement.style.setProperty(k, v));
        }
        
        function applyCustomizations(settings) {
            if (settings.background_image_url) {
                document.body.style.backgroundImage = `url(${settings.background_image_url})`;
                document.querySelectorAll('.dynamic-bg').forEach(el => el.classList.remove('dynamic-bg'));
            } else {
                document.body.style.backgroundImage = 'none';
            }
            DOMElements.musicPlayerContainer.innerHTML = '';
            if (settings.music_url) {
                const audio = new Audio(settings.music_url);
                audio.loop = true; audio.autoplay = true; audio.muted = true;
                const player = document.createElement('div');
                player.className = 'glassmorphism p-2 rounded-full flex items-center gap-2';
                const btn = document.createElement('button');
                btn.className = 'text-2xl'; btn.textContent = '🔇';
                btn.onclick = () => {
                    if (audio.muted) {
                        audio.muted = false; audio.play(); btn.textContent = '🔊';
                    } else {
                        audio.muted = true; btn.textContent = '🔇';
                    }
                };
                player.appendChild(btn);
                DOMElements.musicPlayerContainer.appendChild(player);
                setTimeout(() => audio.play().catch(e => console.log("Autoplay blocked.")), 500);
            }
        }

        function showToast(message, type = 'info') { const colors = { info: 'bg-blue-600', success: 'bg-green-600', error: 'bg-red-600' }; const toast = document.createElement('div'); toast.className = `text-white text-sm py-2 px-4 rounded-lg shadow-lg fade-in ${colors[type]}`; toast.textContent = message; DOMElements.toastContainer.appendChild(toast); setTimeout(() => { toast.style.transition = 'opacity 0.5s ease'; toast.style.opacity = '0'; setTimeout(() => toast.remove(), 500); }, 3500); }
        function setButtonLoadingState(button, isLoading) { if (!button) return; if (isLoading) { button.disabled = true; button.dataset.originalText = button.innerHTML; button.innerHTML = `<svg class="animate-spin h-5 w-5 text-white inline-block" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>`; } else { button.disabled = false; if (button.dataset.originalText) { button.innerHTML = button.dataset.originalText; } } }
        async function apiCall(endpoint, options = {}) { try { const csrfToken = document.querySelector('meta[name="csrf-token"]').content; if (!options.headers) options.headers = {}; options.headers['X-CSRFToken'] = csrfToken; if (options.body && typeof options.body === 'object') { options.headers['Content-Type'] = 'application/json'; options.body = JSON.stringify(options.body); } const response = await fetch(`/api${endpoint}`, { credentials: 'include', ...options }); const data = await response.json(); if (!response.ok) { if (response.status === 401) handleLogout(false); throw new Error(data.error || 'Request failed'); } return { success: true, ...data }; } catch (error) { showToast(error.message, 'error'); return { success: false, error: error.message }; } }
        function renderPage(templateId, setupFunction) { const template = document.getElementById(templateId); if (!template) return; DOMElements.appContainer.innerHTML = ''; DOMElements.appContainer.appendChild(template.content.cloneNode(true)); if (setupFunction) setupFunction(); injectLogo(); }
        function renderSubTemplate(container, templateId, setupFunction) { const template = document.getElementById(templateId); if (!container || !template) return; container.innerHTML = ''; container.appendChild(template.content.cloneNode(true)); if (setupFunction) setupFunction(); }
        function showFullScreenLoader(message = 'Loading...') { renderPage('template-full-screen-loader', () => { document.querySelector('.waiting-text').textContent = message; }); }

        // --- AUTH & SESSION ---
        function connectSocket() { if (appState.socket && appState.socket.connected) return; appState.socket = io({ transports: ['websocket'] }); appState.socket.on('connect', () => console.log('Socket connected')); appState.socket.on('disconnect', () => console.log('Socket disconnected')); appState.socket.on('new_message', (msg) => renderChatMessage(msg, true)); }
        function handleLoginSuccess(user, settings) { appState.currentUser = user; appState.siteSettings = settings; applyTheme(user.profile.theme_preference); applyCustomizations(settings); connectSocket(); showFullScreenLoader(); setTimeout(() => { setupDashboard(user); }, 1000); }
        async function handleLogout(doApiCall = true) { if (doApiCall) await apiCall('/auth/logout', { method: 'POST' }); if (appState.socket) appState.socket.disconnect(); appState.currentUser = null; window.location.href = '/'; }
        function setupRoleChoicePage() { renderPage('template-role-choice', () => { document.querySelectorAll('.role-btn').forEach(btn => btn.addEventListener('click', (e) => { appState.selectedRole = e.currentTarget.dataset.role; setupAuthPage(); })); }); }
        function setupAuthPage() { renderPage('template-auth-form', () => { updateAuthView(); document.getElementById('auth-form').addEventListener('submit', handleAuthSubmit); document.getElementById('auth-toggle-btn').addEventListener('click', () => { appState.isLoginView = !appState.isLoginView; updateAuthView(); }); document.getElementById('back-to-roles').addEventListener('click', setupRoleChoicePage); document.getElementById('forgot-password-btn').addEventListener('click', handleForgotPassword); }); }
        function updateAuthView() { const isLogin = appState.isLoginView, role = appState.selectedRole; document.getElementById('auth-title').textContent = `${role.charAt(0).toUpperCase() + role.slice(1)} Portal`; document.getElementById('auth-subtitle').textContent = isLogin ? 'Sign in to continue' : 'Create your Account'; document.getElementById('auth-submit-btn').textContent = isLogin ? 'Login' : 'Sign Up'; document.getElementById('auth-toggle-btn').innerHTML = isLogin ? "Don't have an account? <span class='font-semibold'>Sign Up</span>" : "Already have an account? <span class='font-semibold'>Login</span>"; document.getElementById('email-field').style.display = isLogin ? 'none' : 'block'; document.getElementById('email').required = !isLogin; document.getElementById('teacher-key-field').style.display = (!isLogin && role === 'teacher') ? 'block' : 'none'; document.getElementById('teacher-secret-key').required = !isLogin && role === 'teacher'; document.getElementById('admin-key-field').style.display = (isLogin && role === 'admin') ? 'block' : 'none'; document.getElementById('admin-secret-key').required = isLogin && role === 'admin'; document.getElementById('account_type').value = role; }
        async function handleAuthSubmit(e) { e.preventDefault(); const form = e.target; const btn = form.querySelector('button[type="submit"]'); setButtonLoadingState(btn, true); const body = Object.fromEntries(new FormData(form)); const endpoint = appState.isLoginView ? '/auth/login' : '/auth/signup'; const result = await apiCall(endpoint, { method: 'POST', body }); if (result.success) { handleLoginSuccess(result.user, result.settings); } else { document.getElementById('auth-error').textContent = result.error; } setButtonLoadingState(btn, false); }
        async function handleForgotPassword() { const email = prompt("Please enter your email address to receive a password reset link:"); if (email) { showFullScreenLoader("Sending reset link..."); const result = await apiCall('/auth/forgot_password', { method: 'POST', body: { email } }); showToast(result.message, result.success ? 'success' : 'error'); setupAuthPage(); } }

        // --- DASHBOARD & TABS ---
        function setupDashboard(user) {
            renderPage('template-main-dashboard', () => {
                document.getElementById('welcome-message').innerHTML = `Welcome, ${escapeHtml(user.username)}!`;
                let tabs = [
                    { id: 'main-search', label: 'Home' },
                    { id: 'deep-search', label: 'DeepSearch' },
                    { id: 'create-images', label: 'Create Images' },
                    { id: 'latest-news', label: 'Latest News' },
                    { id: 'personas', label: 'Personas' },
                    { id: 'profile', label: 'Profile' }
                ];

                if (['student', 'teacher'].includes(user.role)) {
                    document.getElementById('dashboard-title').textContent = user.role === 'student' ? "Student Hub" : "Teacher Hub";
                    tabs.splice(1, 0, { id: 'my-classes', label: 'My Classes' });
                } else if (user.role === 'admin') {
                    document.getElementById('dashboard-title').textContent = "Admin Panel";
                    tabs.unshift({ id: 'admin-dashboard', label: 'Admin' });
                }
                
                appState.currentTab = 'main-search';

                const navLinks = document.getElementById('nav-links');
                navLinks.innerHTML = tabs.map(tab => `<button data-tab="${escapeHtml(tab.id)}" class="dashboard-tab text-left text-gray-300 hover:bg-gray-700/50 p-3 rounded-md transition-colors">${escapeHtml(tab.label)}</button>`).join('');
                
                navLinks.querySelectorAll('.dashboard-tab').forEach(tab => tab.addEventListener('click', (e) => switchTab(e.currentTarget.dataset.tab)));
                document.getElementById('logout-btn').addEventListener('click', () => handleLogout(true));
                switchTab(appState.currentTab);
            });
        }
        function switchTab(tab) {
            const setups = {
                'main-search': setupMainSearchTab,
                'my-classes': setupMyClassesTab,
                'profile': setupProfileTab,
                'admin-dashboard': setupAdminDashboardTab,
                'deep-search': setupDeepSearchTab,
                'create-images': setupCreateImagesTab,
                'latest-news': setupLatestNewsTab,
                'personas': setupPersonasTab
            };
            if (setups[tab]) {
                appState.currentTab = tab;
                document.querySelectorAll('.dashboard-tab').forEach(t => t.classList.toggle('active-tab', t.dataset.tab === tab));
                setups[tab](document.getElementById('dashboard-content'));
            }
        }

        // --- TAB IMPLEMENTATIONS ---
        function setupMainSearchTab(container) {
            renderSubTemplate(container, 'template-main-search-view', () => {
                // Add event listeners to the buttons in the main search view
                container.querySelectorAll('.dashboard-tab').forEach(tab => tab.addEventListener('click', (e) => switchTab(e.currentTarget.dataset.tab)));
            });
        }
        async function setupMyClassesTab(container) { renderSubTemplate(container, 'template-my-classes', () => { document.getElementById('back-to-classes-list').addEventListener('click', () => showClassList(true)); showClassList(false); }); }
        async function showClassList(isRefresh) { document.getElementById('classes-main-view').classList.remove('hidden'); const selectedView = document.getElementById('selected-class-view'); selectedView.classList.add('hidden'); selectedView.innerHTML = ''; document.getElementById('back-to-classes-list').classList.add('hidden'); document.getElementById('my-classes-title').textContent = "My Classes"; const actionContainer = document.getElementById('class-action-container'); const role = appState.currentUser.role; const actionTemplateId = `template-${role}-class-action`; renderSubTemplate(actionContainer, actionTemplateId, () => { if (role === 'student') document.getElementById('join-class-form').addEventListener('submit', handleJoinClass); else if (role === 'teacher') document.getElementById('create-class-form').addEventListener('submit', handleCreateClass); }); const classesList = document.getElementById('classes-list'); classesList.innerHTML = '<p class="text-gray-400">Loading classes...</p>'; const result = await apiCall('/classes/'); if (result.success) { renderClasses(result.classes); } }
        function renderClasses(classes) { const classesList = document.getElementById('classes-list'); if (classes.length === 0) { classesList.innerHTML = `<p class="text-gray-400 col-span-full">You are not in any classes yet.</p>`; } else { classesList.innerHTML = classes.map(c => ` <div class="class-card glassmorphism p-4 rounded-lg cursor-pointer hover:scale-105 transition-transform" data-class-id="${escapeHtml(c.id)}" data-class-name="${escapeHtml(c.name)}"> <h3 class="text-xl font-bold">${escapeHtml(c.name)}</h3> <p class="text-sm text-gray-400">Teacher: ${escapeHtml(c.teacher_name)}</p> <p class="text-sm text-gray-400 mt-2">Code: <span class="font-mono bg-bg-dark p-1 rounded">${escapeHtml(c.code)}</span></p> </div>`).join(''); classesList.querySelectorAll('.class-card').forEach(card => card.addEventListener('click', (e) => showClassDetail(e.currentTarget.dataset.classId, e.currentTarget.dataset.className))); } }
        function showClassDetail(classId, className) { appState.currentClass = { id: classId, name: className }; document.getElementById('classes-main-view').classList.add('hidden'); document.getElementById('selected-class-view').classList.remove('hidden'); document.getElementById('back-to-classes-list').classList.remove('hidden'); document.getElementById('my-classes-title').textContent = className; const container = document.getElementById('selected-class-view'); renderSubTemplate(container, 'template-selected-class-view', () => { container.querySelector('.class-view-tab').addEventListener('click', (e) => switchClassTab(e.currentTarget.dataset.tab)); switchClassTab('chat'); }); }
        function switchClassTab(tab) { document.querySelectorAll('.class-view-tab').forEach(t => t.classList.toggle('active-tab', t.dataset.tab === tab)); const contentContainer = document.getElementById('class-view-content'); if (tab === 'chat') { setupClassChatTab(contentContainer); } }
        async function setupClassChatTab(container) { renderSubTemplate(container, 'template-class-chat-view', async () => { if (appState.socket) appState.socket.emit('join', { room: appState.currentClass.id }); const chatMessages = document.getElementById('chat-messages'); chatMessages.innerHTML = '<p class="text-gray-400">Loading messages...</p>'; const result = await apiCall(`/classes/${appState.currentClass.id}/messages`); if (result.success) { chatMessages.innerHTML = ''; result.messages.forEach(msg => renderChatMessage(msg, false)); chatMessages.scrollTop = chatMessages.scrollHeight; } document.getElementById('chat-form').addEventListener('submit', (e) => { e.preventDefault(); const input = document.getElementById('chat-input'); const content = input.value.trim(); if (content && appState.socket) { appState.socket.emit('send_message', { room: appState.currentClass.id, content: content }); input.value = ''; } }); }); }
        function renderChatMessage(msg, shouldScroll) { const messagesContainer = document.getElementById('chat-messages'); if (!messagesContainer) return; const isCurrentUser = msg.sender.id === appState.currentUser.id; const messageEl = document.createElement('div'); messageEl.className = `flex items-start gap-3 ${isCurrentUser ? 'justify-end' : ''}`; messageEl.innerHTML = ` ${!isCurrentUser ? `<img src="${escapeHtml(msg.sender.profile?.avatar || `https://i.pravatar.cc/40?u=${msg.sender.id}`)}" class="w-8 h-8 rounded-full">` : ''} <div class="flex flex-col ${isCurrentUser ? 'items-end' : 'items-start'}"> <div class="flex items-center gap-2"> ${!isCurrentUser ? `<span class="font-bold text-sm">${escapeHtml(msg.sender.username)}</span>` : ''} <span class="text-xs text-gray-400">${new Date(msg.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</span> </div> <div class="bg-bg-med p-3 rounded-lg max-w-xs md:max-w-md"><p>${escapeHtml(msg.content)}</p></div> </div>`; messagesContainer.appendChild(messageEl); if (shouldScroll) messagesContainer.scrollTop = messagesContainer.scrollHeight; }
        async function handleJoinClass(e) { e.preventDefault(); const btn = e.target.querySelector('button'); setButtonLoadingState(btn, true); const code = e.target.elements.code.value; const result = await apiCall('/classes/join', { method: 'POST', body: { code } }); if (result.success) { showToast(`Joined ${result.class_name}!`, 'success'); showClassList(true); } setButtonLoadingState(btn, false); }
        async function handleCreateClass(e) { e.preventDefault(); const btn = e.target.querySelector('button'); setButtonLoadingState(btn, true); const name = e.target.elements.name.value; const result = await apiCall('/classes/create', { method: 'POST', body: { name } }); if (result.success) { showToast(`Class "${result.class.name}" created!`, 'success'); showClassList(true); } setButtonLoadingState(btn, false); }
        async function setupProfileTab(container) { renderSubTemplate(container, 'template-profile', () => { container.querySelectorAll('.profile-view-tab').forEach(tab => tab.addEventListener('click', (e) => switchProfileTab(e.currentTarget.dataset.tab))); switchProfileTab('settings'); }); }
        function switchProfileTab(tab) { document.querySelectorAll('.profile-view-tab').forEach(t => t.classList.toggle('active-tab', t.dataset.tab === tab)); const contentContainer = document.getElementById('profile-view-content'); if (tab === 'settings') setupProfileSettingsTab(contentContainer); else if (tab === 'billing') setupProfileBillingTab(contentContainer); }
        async function setupProfileSettingsTab(container) { renderSubTemplate(container, 'template-profile-settings', () => { const profile = appState.currentUser.profile; document.getElementById('bio').value = profile.bio || ''; document.getElementById('avatar').value = profile.avatar || ''; const themeSelect = document.getElementById('theme-select'); themeSelect.innerHTML = Object.keys(themes).map(name => `<option value="${name}">${name.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</option>`).join(''); themeSelect.value = profile.theme_preference || 'edgy_purple'; document.getElementById('profile-form').addEventListener('submit', handleUpdateProfile); }); }
        async function setupProfileBillingTab(container) { renderSubTemplate(container, 'template-profile-billing', () => { const statusContainer = document.getElementById('subscription-status'); const actionsContainer = document.getElementById('billing-actions'); const status = appState.currentUser.subscription_status; statusContainer.innerHTML = `<p>Current Plan: <span class="font-bold capitalize ${status === 'active' ? 'text-green-400' : 'text-purple-400'}">${status}</span></p>`; if (status !== 'active') { actionsContainer.innerHTML = `<button id="upgrade-btn" class="brand-gradient-bg shiny-button text-white font-bold py-2 px-4 rounded-lg">Upgrade to Pro</button>`; document.getElementById('upgrade-btn').addEventListener('click', handleUpgrade); } else { actionsContainer.innerHTML = `<p class="text-gray-400">You are on the Pro plan!</p>`; } }); }
        async function handleUpgrade() { const btn = document.getElementById('upgrade-btn'); setButtonLoadingState(btn, true); const result = await apiCall('/billing/create-checkout-session', { method: 'POST' }); if (result.success) { const stripe = Stripe(result.public_key); stripe.redirectToCheckout({ sessionId: result.session_id }); } setButtonLoadingState(btn, false); }
        async function handleUpdateProfile(e) { e.preventDefault(); const form = e.target; const btn = form.querySelector('button[type="submit"]'); setButtonLoadingState(btn, true); const body = Object.fromEntries(new FormData(form)); const result = await apiCall('/auth/update_profile', { method: 'POST', body }); if (result.success) { appState.currentUser.profile = result.profile; applyTheme(body.theme_preference); showToast('Profile updated!', 'success'); } setButtonLoadingState(btn, false); }
        async function setupAdminDashboardTab(container) { renderSubTemplate(container, 'template-admin-dashboard', () => { container.querySelectorAll('.admin-view-tab').forEach(tab => tab.addEventListener('click', (e) => switchAdminTab(e.currentTarget.dataset.tab))); switchAdminTab('users'); }); }
        function switchAdminTab(tab) { document.querySelectorAll('.admin-view-tab').forEach(t => t.classList.toggle('active-tab', t.dataset.tab === tab)); const contentContainer = document.getElementById('admin-view-content'); if (tab === 'users') setupAdminUsersTab(contentContainer); else if (tab === 'settings') setupAdminSettingsTab(contentContainer); }
        function setupAdminUsersTab(container) { renderSubTemplate(container, 'template-admin-users-view', async () => { const result = await apiCall('/admin/users'); if (result.success) { document.getElementById('users-table-body').innerHTML = result.users.map(user => ` <tr class="border-b border-gray-700/50"> <td class="p-3">${escapeHtml(user.username)}</td> <td class="p-3">${escapeHtml(user.email)}</td> <td class="p-3">${escapeHtml(user.role)}</td> </tr>`).join(''); } }); }
        function setupAdminSettingsTab(container) { renderSubTemplate(container, 'template-admin-settings-view', () => { const themeSelect = document.getElementById('site-wide-theme-select'); themeSelect.innerHTML = '<option value="default">Default (User Choice)</option>' + Object.keys(themes).map(name => `<option value="${name}">${name.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</option>`).join(''); themeSelect.value = appState.siteSettings.site_wide_theme || 'default'; document.getElementById('background-image-url').value = appState.siteSettings.background_image_url || ''; document.getElementById('music-url').value = appState.siteSettings.music_url || ''; document.getElementById('admin-settings-form').addEventListener('submit', async e => { e.preventDefault(); const btn = e.target.querySelector('button[type="submit"]'); setButtonLoadingState(btn, true); const body = Object.fromEntries(new FormData(e.target)); const result = await apiCall('/admin/settings', { method: 'POST', body }); if (result.success) { showToast('Site settings updated!', 'success'); appState.siteSettings = result.settings; applyTheme(appState.currentUser.profile.theme_preference); applyCustomizations(appState.siteSettings); } setButtonLoadingState(btn, false); }); }); }
        
        // --- NEW FEATURE TABS ---
        function setupDeepSearchTab(container) { renderSubTemplate(container, 'template-deep-search-view'); }
        function setupCreateImagesTab(container) { renderSubTemplate(container, 'template-create-images-view'); }
        function setupLatestNewsTab(container) { renderSubTemplate(container, 'template-latest-news-view'); }
        function setupPersonasTab(container) { renderSubTemplate(container, 'template-personas-view'); }

        function setupResetPasswordPage(token) {
            renderPage('template-reset-password-form', () => {
                const form = document.getElementById('reset-password-form');
                form.addEventListener('submit', async (e) => {
                    e.preventDefault();
                    const btn = form.querySelector('button[type="submit"]');
                    setButtonLoadingState(btn, true);
                    const password = document.getElementById('new-password').value;
                    const result = await apiCall('/auth/reset_password', { method: 'POST', body: { token, password } });
                    if (result.success) {
                        showToast('Password reset! Logging you in.', 'success');
                        const statusResult = await apiCall('/status');
                        if (statusResult.success && statusResult.user) {
                            handleLoginSuccess(statusResult.user, statusResult.settings);
                        }
                    } else {
                         document.getElementById('reset-error').textContent = result.error;
                    }
                    setButtonLoadingState(btn, false);
                });
            });
        }
        
        // --- MAIN APP INITIALIZATION ---
        async function main() {
            const path = window.location.pathname;
            if (path.startsWith('/reset-password/')) {
                const token = path.split('/')[2];
                setupResetPasswordPage(token);
                return;
            }

            showFullScreenLoader('Initializing Portal...');
            const result = await apiCall('/status');
            if (result.success) {
                appState.siteSettings = result.settings;
                if (result.user) {
                    handleLoginSuccess(result.user, result.settings);
                } else {
                    applyCustomizations(result.settings);
                    renderPage('template-welcome-screen', () => {
                        document.getElementById('enter-portal-btn').addEventListener('click', setupRoleChoicePage);
                    });
                }
            } else {
                // Failsafe if status check fails
                setupRoleChoicePage();
            }
        }

        main();
    } catch (error) {
        console.error("A critical error occurred:", error);
        document.body.innerHTML = `<div style="background-color: #110D19; color: #EADFFF; font-family: sans-serif; padding: 2rem; height: 100vh; text-align: center;"><h1>Application Error</h1><p>A critical error occurred. Please check the console.</p><pre style="background-color:#211A2E; padding: 1rem; border-radius: 8px; text-align: left; margin-top: 1rem;">${error.stack}</pre></div>`;
    }
});

# --- static/css/style.css ---
:root {
    --brand-hue: 260; 
    --bg-dark: #110D19; 
    --bg-med: #211A2E; 
    --bg-light: #3B2D4F;
    --glow-color: hsl(var(--brand-hue), 90%, 60%); 
    --text-color: #EADFFF; 
    --text-secondary-color: #A17DFF;
}
body {
    background-color: var(--bg-dark); 
    font-family: 'Inter', sans-serif; 
    color: var(--text-color);
    background-size: cover; 
    background-position: center; 
    background-attachment: fixed; 
    transition: background-image 0.5s ease-in-out;
}
.font-title { font-family: 'Cinzel Decorative', cursive; }
.glassmorphism { 
    background: rgba(33, 26, 46, 0.5); 
    backdrop-filter: blur(12px); 
    -webkit-backdrop-filter: blur(12px); 
    border: 1px solid rgba(161, 125, 255, 0.1); 
}
.brand-gradient-text { 
    background-image: linear-gradient(120deg, hsl(var(--brand-hue), 90%, 60%), hsl(var(--brand-hue), 80%, 50%)); 
    -webkit-background-clip: text; 
    -webkit-text-fill-color: transparent; 
    text-shadow: 0 0 10px hsla(var(--brand-hue), 80%, 50%, 0.3); 
}
.brand-gradient-bg { 
    background-image: linear-gradient(120deg, hsl(var(--brand-hue), 85%, 55%), hsl(var(--brand-hue), 90%, 50%)); 
}
.shiny-button { 
    transition: all 0.2s ease-in-out; 
    box-shadow: 0 0 5px rgba(0,0,0,0.5), 0 0 10px var(--glow-color, #fff) inset; 
}
.shiny-button:hover:not(:disabled) { 
    transform: translateY(-2px); 
    box-shadow: 0 4px 15px hsla(var(--brand-hue), 70%, 40%, 0.4), 0 0 5px var(--glow-color, #fff) inset; 
}
.shiny-button:disabled { 
    cursor: not-allowed; 
    filter: grayscale(50%); 
    opacity: 0.7; 
}
.fade-in { 
    animation: fadeIn 0.5s ease-out forwards; 
}
@keyframes fadeIn { 
    from { opacity: 0; transform: translateY(-10px); } 
    to { opacity: 1; transform: translateY(0); } 
}
.active-tab { 
    background-color: var(--bg-light) !important; 
    color: white !important; 
    position:relative; 
}
.active-tab::after { 
    content: ''; 
    position: absolute; 
    bottom: 0; 
    left: 10%; 
    width: 80%; 
    height: 2px; 
    background: var(--glow-color); 
    border-radius: 2px; 
}
.dynamic-bg { 
    background: linear-gradient(-45deg, var(--bg-dark), var(--bg-light), var(--bg-med), var(--bg-dark)); 
    background-size: 400% 400%; 
    animation: gradientBG 20s ease infinite; 
}
@keyframes gradientBG { 
    0% { background-position: 0% 50%; } 
    50% { background-position: 100% 50%; } 
    100% { background-position: 0% 50%; } 
}
.full-screen-loader { 
    position: fixed; 
    top: 0; left: 0; right: 0; bottom: 0; 
    background: rgba(17, 13, 25, 0.9); 
    backdrop-filter: blur(8px); 
    display: flex; 
    align-items: center; 
    justify-content: center; 
    flex-direction: column; 
    z-index: 1001; 
    transition: opacity 0.3s ease; 
}
.waiting-text { 
    margin-top: 1rem; 
    font-size: 1.25rem; 
    color: var(--text-secondary-color); 
    animation: pulse 2s infinite; 
}
@keyframes pulse { 
    0%, 100% { opacity: 1; } 
    50% { opacity: 0.7; } 
}
.gradient-overlay { 
    position: absolute; 
    inset: 0; 
    background: radial-gradient(circle at center, hsla(var(--brand-hue), 90%, 60%, 0.15) 0%, transparent 70%); 
}
.particles { 
    position: absolute; 
    inset: 0; 
    background: transparent; 
    animation: particles 20s linear infinite; 
}
.particles::before {
    content: ''; 
    position: absolute; 
    width: 2px; 
    height: 2px; 
    background: hsla(var(--brand-hue), 90%, 60%, 0.3);
    box-shadow: 10vw 20vh 2px hsla(var(--brand-hue), 90%, 60%, 0.2), 30vw 40vh 2px hsla(var(--brand-hue), 90%, 60%, 0.3), 50vw 10vh 2px hsla(var(--brand-hue), 90%, 60%, 0.25), 70vw 70vh 2px hsla(var(--brand-hue), 90%, 60%, 0.2), 90vw 30vh 2px hsla(var(--brand-hue), 90%, 60%, 0.3);
    animation: float 15s ease-in-out infinite;
}
@keyframes float { 
    0%, 100% { transform: translateY(0); opacity: 0.5; } 
    50% { transform: translateY(-20px); opacity: 0.8; } 
}
@keyframes particles { 
    0% { transform: translateY(0); } 
    100% { transform: translateY(-1000px); } 
}
.animate-pulse-slow { 
    animation: pulse-slow 3s ease-in-out infinite; 
}
@keyframes pulse-slow { 
    0%, 100% { transform: scale(1); opacity: 1; } 
    50% { transform: scale(1.02); opacity: 0.95; } 
}
.animate-fade-in-up { 
    animation: fade-in-up 0.8s ease-out forwards; 
}
@keyframes fade-in-up { 
    from { opacity: 0; transform: translateY(20px); } 
    to { opacity: 1; transform: translateY(0); } 
}

