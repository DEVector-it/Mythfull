# --- Imports ---
import os
import json
import logging
import time
import uuid
import secrets
from flask import Flask, Response, request, session, jsonify, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from datetime import datetime, date
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
import stripe
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from flask_mail import Mail, Message
from flask_talisman import Talisman, CSP

# ==============================================================================
# --- 1. INITIAL CONFIGURATION & SETUP ---
# ==============================================================================
load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Security Check for Essential Environment Variables ---
REQUIRED_KEYS = [
    'SECRET_KEY', 'SECURITY_PASSWORD_SALT', 'SECRET_REGISTRATION_KEY', 'SECRET_TEACHER_KEY',
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

# --- Security: Content Security Policy (CSP) ---
# NOTE: The lambda for the nonce was removed. Talisman injects the nonce automatically.
csp = {
    'default-src': "'self'",
    'script-src': [
        "'self'",
        "https://js.stripe.com",
        "https://cdn.tailwindcss.com",
        "https://cdnjs.cloudflare.com"
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

# --- Service Initializations (Stripe, Mail) ---
stripe.api_key = SITE_CONFIG["STRIPE_SECRET_KEY"]
password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_SENDER')
mail = Mail(app)

# ==============================================================================
# --- 2. DATABASE MANAGEMENT ---
# ==============================================================================
DATA_DIR = 'data'
DATABASE_FILE = os.path.join(DATA_DIR, 'database.json')
DB = {"users": {}, "classes": {}, "messages": {}, "site_settings": {"announcement": "Welcome!"}}

def setup_database_dir():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)

def save_database():
    setup_database_dir()
    temp_file = f"{DATABASE_FILE}.tmp"
    try:
        with open(temp_file, 'w') as f:
            serializable_db = {
                "users": {uid: user.to_dict() for uid, user in DB['users'].items()},
                "classes": DB['classes'],
                "messages": DB['messages'],
                "site_settings": DB['site_settings'],
            }
            json.dump(serializable_db, f, indent=4)
        os.replace(temp_file, DATABASE_FILE)
    except Exception as e:
        logging.error(f"FATAL: Failed to save database: {e}")

def load_database():
    global DB
    setup_database_dir()
    if not os.path.exists(DATABASE_FILE): return
    try:
        with open(DATABASE_FILE, 'r') as f: data = json.load(f)
        DB['site_settings'] = data.get('site_settings', {"announcement": ""})
        DB['classes'] = data.get('classes', {})
        DB['messages'] = data.get('messages', {})
        DB['users'] = {uid: User.from_dict(u_data) for uid, u_data in data.get('users', {}).items()}
    except Exception as e:
        logging.error(f"Could not load database file '{DATABASE_FILE}'. Error: {e}.")

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

class User(UserMixin):
    def __init__(self, id, username, email, password_hash=None, role='user', plan='student', account_type='student', classes=None, profile=None):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.role = role
        self.plan = plan
        self.account_type = account_type
        self.classes = classes or []  # List of class IDs
        self.profile = profile or {"bio": "", "avatar": ""}  # Customizable profile
    
    @staticmethod
    def get(user_id): return DB['users'].get(user_id)
    @staticmethod
    def get_by_email(email): return next((u for u in DB['users'].values() if u.email and u.email.lower() == email.lower()), None)
    @staticmethod
    def get_by_username(username): return next((u for u in DB['users'].values() if u.username.lower() == username.lower()), None)
    
    def to_dict(self):
        return {k: v for k, v in self.__dict__.items()}

    @staticmethod
    def from_dict(data): return User(**data)

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)
    
# ==============================================================================
# --- 4. HELPER FUNCTIONS ---
# ==============================================================================
def get_user_data_for_frontend(user):
    if not user: return {}
    return {
        "id": user.id, "username": user.username, "email": user.email, "role": user.role,
        "plan": user.plan, "account_type": user.account_type, "classes": user.classes,
        "profile": user.profile,
    }

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
    return secrets.token_hex(4).upper()  # Simple 8-char hex code
        
def teacher_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.account_type != 'teacher':
            return jsonify({"error": "Teacher access required."}), 403
        return f(*args, **kwargs)
    return decorated_function

def student_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.account_type != 'student':
            return jsonify({"error": "Student access required."}), 403
        return f(*args, **kwargs)
    return decorated_function
        
# ==============================================================================
# --- 5. FRONTEND & CORE ROUTES ---
# ==============================================================================
@app.route('/')
@app.route('/reset-password/<token>')
def index(token=None):
    # Serves the main HTML file. JS handles routing.
    # NOTE: The nonce is now retrieved from the session object.
    return Response(HTML_CONTENT.format(csp_nonce=session.get('_csp_nonce')), mimetype='text/html')

@app.route('/api/status')
def status():
    config = {"email_enabled": bool(app.config.get('MAIL_SERVER'))}
    if current_user.is_authenticated:
        return jsonify({
            "logged_in": True, "user": get_user_data_for_frontend(current_user),
            "settings": DB['site_settings'], "config": config
        })
    return jsonify({"logged_in": False, "config": config, "settings": DB['site_settings']})
    
# ==============================================================================
# --- 6. AUTHENTICATION API ROUTES ---
# ==============================================================================
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.get_by_username(data.get('username'))
    if user and user.password_hash and check_password_hash(user.password_hash, data.get('password', '')):
        login_user(user, remember=True)
        return jsonify({"success": True, "user": get_user_data_for_frontend(user)})
    return jsonify({"error": "Invalid username or password."}), 401

@app.route('/api/logout')
def logout():
    logout_user()
    return jsonify({"success": True})
    
@app.route('/api/student_signup', methods=['POST'])
def student_signup():
    data = request.get_json()
    username, password, email = data.get('username','').strip(), data.get('password',''), data.get('email','').strip().lower()
    
    if not all([username, password, email]) or len(username) < 3 or len(password) < 6 or '@' not in email:
        return jsonify({"error": "Valid email, username (min 3 chars), and password (min 6 chars) are required."}), 400
    if User.get_by_username(username): return jsonify({"error": "Username already exists."}), 409
    if User.get_by_email(email): return jsonify({"error": "Email already in use."}), 409
        
    new_user = User(id=str(uuid.uuid4()), username=username, email=email, password_hash=generate_password_hash(password))
    DB['users'][new_user.id] = new_user
    save_database()
    login_user(new_user, remember=True)
    return jsonify({"success": True, "user": get_user_data_for_frontend(new_user)})

@app.route('/api/teacher_signup', methods=['POST'])
def teacher_signup():
    data = request.get_json()
    username, password, email, secret_key = data.get('username','').strip(), data.get('password',''), data.get('email','').strip().lower(), data.get('secret_key')
    
    if secret_key != SITE_CONFIG['SECRET_TEACHER_KEY']:
        return jsonify({"error": "Invalid teacher registration key."}), 403
    
    if not all([username, password, email]) or len(username) < 3 or len(password) < 6 or '@' not in email:
        return jsonify({"error": "Valid email, username (min 3 chars), and password (min 6 chars) are required."}), 400
    
    # BUG FIX: Was 'jupytext', now 'jsonify'
    if User.get_by_username(username): return jsonify({"error": "Username already exists."}), 409
    if User.get_by_email(email): return jsonify({"error": "Email already in use."}), 409
        
    new_user = User(id=str(uuid.uuid4()), username=username, email=email, password_hash=generate_password_hash(password), account_type='teacher')
    DB['users'][new_user.id] = new_user
    save_database()
    login_user(new_user, remember=True)
    return jsonify({"success": True, "user": get_user_data_for_frontend(new_user)})

# --- Password Reset Routes ---
@app.route('/api/request-password-reset', methods=['POST'])
def request_password_reset():
    email = request.json.get('email', '').lower()
    user = User.get_by_email(email)
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
    
    user = User.get_by_email(email)
    if not user: return jsonify({"error": "User not found."}), 404
    
    user.password_hash = generate_password_hash(password)
    save_database()
    return jsonify({"message": "Password has been updated successfully."})
    
# ==============================================================================
# --- 7. DASHBOARD API ROUTES ---
# ==============================================================================
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.account_type != 'admin':
            return jsonify({"error": "Admin access required."}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/api/admin_data')
@admin_required
def admin_data():
    users_list = [get_user_data_for_frontend(u) for u in DB['users'].values() if u.role != 'admin']
    stats = { 'total_users': len(users_list) }
    return jsonify({
        "success": True, "stats": stats, "users": users_list,
        "announcement": DB['site_settings']['announcement']
    })

# ==============================================================================
# --- 8. CLASSES API ROUTES ---
# ==============================================================================
@app.route('/api/create_class', methods=['POST'])
@teacher_required
def create_class():
    data = request.get_json()
    name = data.get('name')
    if not name:
        return jsonify({"error": "Class name is required."}), 400
    
    class_id = str(uuid.uuid4())
    code = generate_class_code()
    DB['classes'][class_id] = {
        "id": class_id,
        "name": name,
        "code": code,
        "teacher_id": current_user.id,
        "students": []
    }
    current_user.classes.append(class_id)
    save_database()
    return jsonify({"success": True, "class": DB['classes'][class_id]})

@app.route('/api/my_classes', methods=['GET'])
@login_required
def my_classes():
    user_classes = []
    for class_id in current_user.classes:
        if class_id in DB['classes']:
            cls = DB['classes'][class_id]
            user_classes.append({
                "id": cls["id"],
                "name": cls["name"],
                "code": cls["code"] if current_user.account_type == 'teacher' else None,
                "teacher": User.get(cls["teacher_id"]).username if cls.get("teacher_id") else "Unknown"
            })
    return jsonify({"success": True, "classes": user_classes})

@app.route('/api/join_class', methods=['POST'])
@student_required
def join_class():
    data = request.get_json()
    code = data.get('code').upper()
    if not code:
        return jsonify({"error": "Class code is required."}), 400
    
    matching_class = next((cid for cid, cls in DB['classes'].items() if cls['code'] == code), None)
    if not matching_class:
        return jsonify({"error": "Invalid class code."}), 404
    if matching_class in current_user.classes:
        return jsonify({"error": "Already joined this class."}), 400
    
    DB['classes'][matching_class]['students'].append(current_user.id)
    current_user.classes.append(matching_class)
    save_database()
    return jsonify({"success": True})

# ==============================================================================
# --- 9. PROFILE & PERKS API ROUTES ---
# ==============================================================================
@app.route('/api/update_profile', methods=['POST'])
@login_required
def update_profile():
    data = request.get_json()
    bio = data.get('bio', '')
    avatar = data.get('avatar', '')  # Assume URL for now
    current_user.profile['bio'] = bio[:500]  # Limit length
    current_user.profile['avatar'] = avatar
    save_database()
    return jsonify({"success": True, "profile": current_user.profile})

@app.route('/api/perks', methods=['GET'])
@login_required
def get_perks():
    perks = {
        'student': ['Basic access', 'Join classes', 'Chat with AI (limited)'],
        'student_pro': ['Unlimited AI chat', 'Priority support', 'Custom profiles'],
    }
    return jsonify({"success": True, "perks": perks.get(current_user.plan, [])})

# ==============================================================================
# --- 10. MESSAGING API ROUTES ---
# ==============================================================================
@app.route('/api/send_message', methods=['POST'])
@student_required
def send_message():
    data = request.get_json()
    class_id = data.get('class_id')
    message = data.get('message')
    if not class_id or not message or class_id not in current_user.classes:
        return jsonify({"error": "Invalid class or message."}), 400
    
    cls = DB['classes'][class_id]
    message_id = str(uuid.uuid4())
    if class_id not in DB['messages']:
        DB['messages'][class_id] = []
    DB['messages'][class_id].append({
        "id": message_id,
        "sender_id": current_user.id,
        "message": message,
        "timestamp": datetime.now().isoformat()
    })
    # Optionally send email to teacher
    teacher = User.get(cls['teacher_id'])
    if teacher:
        msg = Message("New Message from Student", recipients=[teacher.email])
        msg.body = f"Student {current_user.username} sent: {message}"
        mail.send(msg)
    save_database()
    return jsonify({"success": True})

@app.route('/api/class_messages/<class_id>', methods=['GET'])
@login_required
def get_class_messages(class_id):
    if class_id not in current_user.classes:
        return jsonify({"error": "Access denied."}), 403
    messages = DB['messages'].get(class_id, [])
    formatted = [{
        "sender": User.get(m['sender_id']).username if m.get('sender_id') else "AI",
        "message": m['message'],
        "timestamp": m['timestamp']
    } for m in messages]
    return jsonify({"success": True, "messages": formatted})

# ==============================================================================
# --- 11. AI CHAT PLACEHOLDER ---
# ==============================================================================
@app.route('/api/ai_chat', methods=['POST'])
@login_required
def ai_chat():
    data = request.get_json()
    message = data.get('message')
    class_id = data.get('class_id')  # Optional, for class-specific chat
    # Placeholder AI response (integrate real AI here, e.g., OpenAI)
    ai_response = f"AI response to: {message}"  # Mock
    if class_id and class_id in current_user.classes:
        if class_id not in DB['messages']:
            DB['messages'][class_id] = []
        DB['messages'][class_id].append({
            "id": str(uuid.uuid4()),
            "sender_id": "AI",
            "message": ai_response,
            "timestamp": datetime.now().isoformat()
        })
        save_database()
    return jsonify({"success": True, "response": ai_response})

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
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body { background-color: #111827; font-family: 'Inter', sans-serif; }
        .glassmorphism { background: rgba(31, 41, 55, 0.5); backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px); border: 1px solid rgba(255, 255, 255, 0.1); }
        .brand-gradient { background-image: linear-gradient(to right, #3b82f6, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .fade-in { animation: fadeIn 0.5s ease-out forwards; }
        @keyframes fadeIn { '0%': { opacity: 0 }, '100%': { opacity: 1 } }
    </style>
</head>
<body class="text-gray-200 antialiased">
    <div id="announcement-banner" class="hidden text-center p-2 bg-indigo-600 text-white text-sm"></div>
    <div id="app-container" class="relative h-screen w-screen overflow-hidden"></div>
    <div id="toast-container" class="fixed top-6 right-6 z-[100] flex flex-col gap-2"></div>

    <template id="template-logo">
        </template>

    <template id="template-auth-page">
        <div class="flex flex-col items-center justify-center h-full w-full bg-gray-900 p-4 fade-in">
            <div class="w-full max-w-md glassmorphism rounded-2xl p-8 shadow-2xl">
                <div class="flex justify-center mb-6" id="auth-logo-container"></div>
                <h2 class="text-3xl font-bold text-center text-white mb-2" id="auth-title">Welcome</h2>
                <p class="text-gray-400 text-center mb-8" id="auth-subtitle">Sign in to your account.</p>
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
                    <button type="submit" id="auth-submit-btn" class="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:opacity-90 text-white font-bold py-3 px-4 rounded-lg">Login</button>
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
                <h2 class="text-3xl font-bold text-center text-white mb-2">Sign Up</h2>
                <p class="text-gray-400 text-center mb-8">Create a new account.</p>
                <form id="signup-form">
                    <div class="mb-4">
                        <label for="signup-username" class="block text-sm font-medium text-gray-300 mb-1">Username</label>
                        <input type="text" id="signup-username" name="username" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" required>
                    </div>
                    <div class="mb-4">
                        <label for="signup-email" class="block text-sm font-medium text-gray-300 mb-1">Email</label>
                        <input type="email" id="signup-email" name="email" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" required>
                    </div>
                    <div class="mb-4">
                        <label for="signup-password" class="block text-sm font-medium text-gray-300 mb-1">Password</label>
                        <input type="password" id="signup-password" name="password" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" required>
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

    <template id="template-teacher-signup-page">
        <div class="flex flex-col items-center justify-center h-full w-full bg-gray-900 p-4 fade-in">
            <div class="w-full max-w-md glassmorphism rounded-2xl p-8 shadow-2xl">
                <h2 class="text-3xl font-bold text-center text-white mb-2">Teacher Sign Up</h2>
                <p class="text-gray-400 text-center mb-8">Create a teacher account.</p>
                <form id="teacher-signup-form">
                    <div class="mb-4">
                        <label for="teacher-username" class="block text-sm font-medium text-gray-300 mb-1">Username</label>
                        <input type="text" id="teacher-username" name="username" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" required>
                    </div>
                    <div class="mb-4">
                        <label for="teacher-email" class="block text-sm font-medium text-gray-300 mb-1">Email</label>
                        <input type="email" id="teacher-email" name="email" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" required>
                    </div>
                    <div class="mb-4">
                        <label for="teacher-password" class="block text-sm font-medium text-gray-300 mb-1">Password</label>
                        <input type="password" id="teacher-password" name="password" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" required>
                    </div>
                    <div class="mb-4">
                        <label for="teacher-secret-key" class="block text-sm font-medium text-gray-300 mb-1">Secret Teacher Key</label>
                        <input type="text" id="teacher-secret-key" name="secret_key" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" required>
                    </div>
                    <button type="submit" class="w-full bg-gradient-to-r from-green-600 to-teal-600 hover:opacity-90 text-white font-bold py-3 px-4 rounded-lg">Sign Up as Teacher</button>
                    <p id="teacher-signup-error" class="text-red-400 text-sm text-center h-4 mt-3"></p>
                </form>
                <div class="text-center mt-6">
                    <button id="back-to-login" class="text-sm text-blue-400 hover:text-blue-300">Back to Login</button>
                </div>
            </div>
        </div>
    </template>

    <template id="template-student-dashboard">
        <div class="flex h-full w-full bg-gray-800 fade-in">
            <nav class="w-64 bg-gray-900 p-6 flex flex-col gap-4">
                <h2 class="text-2xl font-bold text-white mb-4">Student Dashboard</h2>
                <button id="tab-my-classes" class="text-left text-gray-300 hover:text-white">My Classes</button>
                <button id="tab-ai-chat" class="text-left text-gray-300 hover:text-white">Chat with AI</button>
                <button id="tab-perks" class="text-left text-gray-300 hover:text-white">Perks</button>
                <button id="tab-profile" class="text-left text-gray-300 hover:text-white">Customize Profile</button>
                <button id="logout-btn" class="mt-auto bg-red-600 hover:bg-red-500 text-white font-bold py-2 px-4 rounded-lg">Logout</button>
            </nav>
            <main class="flex-1 p-8 overflow-y-auto">
                <div id="dashboard-content"></div>
            </main>
        </div>
    </template>
    
    <template id="template-my-classes">
        <h3 class="text-2xl font-bold text-white mb-4">My Classes</h3>
        <div class="mb-6">
            <input type="text" id="class-code" placeholder="Enter class code" class="p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500">
            <button id="join-class-btn" class="ml-2 bg-blue-600 hover:bg-blue-500 text-white py-2 px-4 rounded-lg">Join</button>
        </div>
        <ul id="classes-list" class="space-y-4"></ul>
        <div id="selected-class-chat" class="mt-8 hidden">
            <h4 class="text-xl font-bold text-white mb-2">Chat for <span id="selected-class-name"></span></h4>
            <div id="chat-messages" class="bg-gray-700/50 p-4 rounded-lg h-64 overflow-y-auto mb-4"></div>
            <input type="text" id="chat-input" placeholder="Type message or AI query" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500">
            <button id="send-chat-btn" class="mt-2 bg-green-600 hover:bg-green-500 text-white py-2 px-4 rounded-lg">Send</button>
        </div>
    </template>
    
    <template id="template-ai-chat-global">
        <h3 class="text-2xl font-bold text-white mb-4">Global AI Chat</h3>
        <div id="global-chat-messages" class="bg-gray-700/50 p-4 rounded-lg h-96 overflow-y-auto mb-4"></div>
        <input type="text" id="global-chat-input" placeholder="Ask AI anything..." class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500">
        <button id="send-global-chat-btn" class="mt-2 bg-green-600 hover:bg-green-500 text-white py-2 px-4 rounded-lg">Send</button>
    </template>
    
    <template id="template-perks">
        <h3 class="text-2xl font-bold text-white mb-4">Your Perks</h3>
        <ul id="perks-list" class="space-y-2 text-gray-300"></ul>
    </template>
    
    <template id="template-profile">
        <h3 class="text-2xl font-bold text-white mb-4">Customize Profile</h3>
        <form id="profile-form">
            <div class="mb-4">
                <label for="bio" class="block text-sm font-medium text-gray-300 mb-1">Bio</label>
                <textarea id="bio" name="bio" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500"></textarea>
            </div>
            <div class="mb-4">
                <label for="avatar" class="block text-sm font-medium text-gray-300 mb-1">Avatar URL</label>
                <input type="text" id="avatar" name="avatar" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500">
            </div>
            <button type="submit" class="bg-blue-600 hover:bg-blue-500 text-white font-bold py-2 px-4 rounded-lg">Save</button>
        </form>
    </template>
    
    <template id="template-teacher-dashboard">
        <div class="flex h-full w-full bg-gray-800 fade-in">
            <nav class="w-64 bg-gray-900 p-6 flex flex-col gap-4">
                <h2 class="text-2xl font-bold text-white mb-4">Teacher Dashboard</h2>
                <button id="tab-my-classes" class="text-left text-gray-300 hover:text-white">My Classes</button>
                <button id="logout-btn" class="mt-auto bg-red-600 hover:bg-red-500 text-white font-bold py-2 px-4 rounded-lg">Logout</button>
            </nav>
            <main class="flex-1 p-8 overflow-y-auto">
                <div id="dashboard-content"></div>
            </main>
        </div>
    </template>
    
    <template id="template-teacher-classes">
        <h3 class="text-2xl font-bold text-white mb-4">My Classes</h3>
        <div class="mb-6">
            <input type="text" id="new-class-name" placeholder="New class name" class="p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500">
            <button id="create-class-btn" class="ml-2 bg-blue-600 hover:bg-blue-500 text-white py-2 px-4 rounded-lg">Create</button>
        </div>
        <ul id="classes-list" class="space-y-4"></ul>
        <div id="selected-class-chat" class="mt-8 hidden">
            <h4 class="text-xl font-bold text-white mb-2">Chat for <span id="selected-class-name"></span></h4>
            <div id="chat-messages" class="bg-gray-700/50 p-4 rounded-lg h-64 overflow-y-auto mb-4"></div>
            <input type="text" id="chat-input" placeholder="Type message" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500">
            <button id="send-chat-btn" class="mt-2 bg-green-600 hover:bg-green-500 text-white py-2 px-4 rounded-lg">Send</button>
        </div>
    </template>
    
    <template id="template-admin-dashboard">
        <div class="w-full h-full bg-gray-900 p-8 overflow-y-auto fade-in">
            <header class="flex justify-between items-center mb-8">
                <h1 class="text-3xl font-bold brand-gradient">Admin Dashboard</h1>
                <button id="logout-btn" class="bg-red-600 hover:bg-red-500 text-white font-bold py-2 px-4 rounded-lg">Logout</button>
            </header>
            <div class="p-6 glassmorphism rounded-lg">
                <h2 class="text-xl font-semibold mb-4 text-white">User Management (<span id="admin-total-users">0</span>)</h2>
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-white">
                        <thead>
                            <tr class="border-b border-gray-600">
                                <th class="p-2">Username</th>
                                <th class="p-2">Email</th>
                                <th class="p-2">Role</th>
                                <th class="p-2">Plan</th>
                            </tr>
                        </thead>
                        <tbody id="admin-user-list"></tbody>
                    </table>
                </div>
            </div>
        </div>
    </template>

    <script nonce="{csp_nonce}">
    document.addEventListener('DOMContentLoaded', () => {
        const appState = { currentUser: null, currentTab: 'my-classes', selectedClass: null, globalChatHistory: [] };
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
            setTimeout(() => toast.remove(), 4000);
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
                    if (response.status === 401) handleLogout(false); // Force logout on auth error
                    throw new Error(data.error || 'An unknown error occurred.');
                }
                return { success: true, ...data };
            } catch (error) {
                showToast(error.message, 'error');
                return { success: false, error: error.message };
            }
        }

        function renderPage(templateId, setupFunction) {
            const template = document.getElementById(templateId);
            if (!template) {
                console.error(`Template ${templateId} not found.`);
                return;
            }
            DOMElements.appContainer.innerHTML = '';
            DOMElements.appContainer.appendChild(template.content.cloneNode(true));
            if (setupFunction) setupFunction();
        }

        function renderSubTemplate(container, templateId, setupFunction) {
            const template = document.getElementById(templateId);
            if (!template) return;
            container.innerHTML = '';
            container.appendChild(template.content.cloneNode(true));
            if (setupFunction) setupFunction();
        }

        // --- PAGE SETUP FUNCTIONS ---
        function setupAuthPage() {
            document.getElementById('auth-form').addEventListener('submit', handleLoginSubmit);
            document.getElementById('auth-toggle-btn').addEventListener('click', () => renderPage('template-signup-page', setupSignupPage));
            document.getElementById('teacher-signup-btn').addEventListener('click', () => renderPage('template-teacher-signup-page', setupTeacherSignupPage));
            document.getElementById('forgot-password-link').addEventListener('click', handleForgotPassword);
        }
        
        function setupSignupPage() {
            document.getElementById('signup-form').addEventListener('submit', handleStudentSignupSubmit);
            document.getElementById('back-to-login').addEventListener('click', () => renderPage('template-auth-page', setupAuthPage));
        }
        
        function setupTeacherSignupPage() {
            document.getElementById('teacher-signup-form').addEventListener('submit', handleTeacherSignupSubmit);
            document.getElementById('back-to-login').addEventListener('click', () => renderPage('template-auth-page', setupAuthPage));
        }

        function setupStudentDashboard() {
            const tabs = {
                'my-classes': setupMyClassesTab,
                'ai-chat': setupAiChatTab,
                'perks': setupPerksTab,
                'profile': setupProfileTab,
            };
            Object.keys(tabs).forEach(tab => {
                const btn = document.getElementById(`tab-${tab}`);
                if (btn) btn.addEventListener('click', () => switchTab(tab));
            });
            document.getElementById('logout-btn').addEventListener('click', () => handleLogout(true));
            switchTab(appState.currentTab);
        }
        
        function setupTeacherDashboard() {
            document.getElementById('tab-my-classes').addEventListener('click', () => switchTab('my-classes'));
            document.getElementById('logout-btn').addEventListener('click', () => handleLogout(true));
            switchTab('my-classes');
        }

        async function setupAdminDashboard() {
            document.getElementById('logout-btn').addEventListener('click', () => handleLogout(true));
            const result = await apiCall('/api/admin_data');
            if(result.success) {
                document.getElementById('admin-total-users').textContent = result.stats.total_users;
                const userList = document.getElementById('admin-user-list');
                userList.innerHTML = result.users.map(user => `
                    <tr class="border-b border-gray-700/50">
                        <td class="p-2">${user.username}</td>
                        <td class="p-2">${user.email}</td>
                        <td class="p-2">${user.role}</td>
                        <td class="p-2">${user.plan}</td>
                    </tr>
                `).join('');
            }
        }

        // --- TAB SETUP FUNCTIONS ---
        async function setupMyClassesTab() {
            const content = document.getElementById('dashboard-content');
            renderSubTemplate(content, appState.currentUser.account_type === 'teacher' ? 'template-teacher-classes' : 'template-my-classes', async () => {
                const result = await apiCall('/api/my_classes');
                if (result.success) {
                    const list = document.getElementById('classes-list');
                    list.innerHTML = result.classes.map(cls => `
                        <li class="glassmorphism p-4 rounded-lg cursor-pointer hover:bg-gray-700/50" data-id="${cls.id}">
                            <div class="font-bold text-white">${cls.name}</div>
                            <div class="text-gray-400 text-sm">Teacher: ${cls.teacher}${appState.currentUser.account_type === 'teacher' ? ` | Code: ${cls.code}` : ''}</div>
                        </li>
                    `).join('');
                    list.querySelectorAll('li').forEach(li => li.addEventListener('click', () => selectClass(li.dataset.id)));
                }
                if (appState.currentUser.account_type === 'student') {
                    document.getElementById('join-class-btn').addEventListener('click', handleJoinClass);
                } else {
                    document.getElementById('create-class-btn').addEventListener('click', handleCreateClass);
                }
            });
        }

        function setupAiChatTab() {
            const content = document.getElementById('dashboard-content');
            renderSubTemplate(content, 'template-ai-chat-global', () => {
                updateGlobalChatMessages();
                document.getElementById('send-global-chat-btn').addEventListener('click', handleGlobalAiChat);
            });
        }

        async function setupPerksTab() {
            const content = document.getElementById('dashboard-content');
            renderSubTemplate(content, 'template-perks', async () => {
                const result = await apiCall('/api/perks');
                if (result.success) {
                    document.getElementById('perks-list').innerHTML = result.perks.map(perk => `<li>- ${perk}</li>`).join('');
                }
            });
        }

        function setupProfileTab() {
            const content = document.getElementById('dashboard-content');
            renderSubTemplate(content, 'template-profile', () => {
                document.getElementById('bio').value = appState.currentUser.profile.bio || '';
                document.getElementById('avatar').value = appState.currentUser.profile.avatar || '';
                document.getElementById('profile-form').addEventListener('submit', handleUpdateProfile);
            });
        }

        // --- EVENT HANDLERS ---
        async function handleLoginSubmit(e) {
            e.preventDefault();
            const form = e.target;
            const errorEl = document.getElementById('auth-error');
            errorEl.textContent = '';
            const data = Object.fromEntries(new FormData(form).entries());
            const result = await apiCall('/api/login', { method: 'POST', body: data });
            if (result.success) {
                initializeApp(result.user, result.settings);
            } else {
                errorEl.textContent = result.error;
            }
        }
        
        async function handleStudentSignupSubmit(e) {
            e.preventDefault();
            const form = e.target;
            const errorEl = document.getElementById('signup-error');
            errorEl.textContent = '';
            const data = Object.fromEntries(new FormData(form).entries());
            const result = await apiCall('/api/student_signup', { method: 'POST', body: data });
            if (result.success) {
                initializeApp(result.user, {});
            } else {
                errorEl.textContent = result.error;
            }
        }
        
        async function handleTeacherSignupSubmit(e) {
            e.preventDefault();
            const form = e.target;
            const errorEl = document.getElementById('teacher-signup-error');
            errorEl.textContent = '';
            const data = Object.fromEntries(new FormData(form).entries());
            const result = await apiCall('/api/teacher_signup', { method: 'POST', body: data });
            if (result.success) {
                initializeApp(result.user, {});
            } else {
                errorEl.textContent = result.error;
            }
        }
        
        async function handleForgotPassword() {
            const email = prompt('Enter your email:');
            if (email) {
                const result = await apiCall('/api/request-password-reset', { method: 'POST', body: { email } });
                showToast(result.message || 'Request sent.', 'info');
            }
        }
        
        async function handleLogout(doApiCall) {
            if (doApiCall) await apiCall('/api/logout');
            appState.currentUser = null;
            window.location.replace('/');
        }
        
        async function handleJoinClass() {
            const code = document.getElementById('class-code').value.trim().toUpperCase();
            if (!code) return showToast('Enter a code.', 'error');
            const result = await apiCall('/api/join_class', { method: 'POST', body: { code } });
            if (result.success) {
                showToast('Joined class!', 'success');
                setupMyClassesTab();
            }
        }
        
        async function handleCreateClass() {
            const name = document.getElementById('new-class-name').value.trim();
            if (!name) return showToast('Enter a class name.', 'error');
            const result = await apiCall('/api/create_class', { method: 'POST', body: { name } });
            if (result.success) {
                showToast('Class created!', 'success');
                setupMyClassesTab();
            }
        }
        
        async function selectClass(classId) {
            appState.selectedClass = classId;
            document.getElementById('selected-class-chat').classList.remove('hidden');
            const cls = (await apiCall('/api/my_classes')).classes.find(c => c.id === classId);
            document.getElementById('selected-class-name').textContent = cls.name;
            updateChatMessages(classId);
            const sendBtn = document.getElementById('send-chat-btn');
            sendBtn.removeEventListener('click', handleSendChat); // Prevent multiple listeners
            sendBtn.addEventListener('click', handleSendChat);
        }
        
        async function handleSendChat() {
            const input = document.getElementById('chat-input');
            const message = input.value.trim();
            if (!message || !appState.selectedClass) return;
            const endpoint = appState.currentUser.account_type === 'student' ? '/api/send_message' : '/api/send_message'; // Same for now
            const result = await apiCall(endpoint, { method: 'POST', body: { class_id: appState.selectedClass, message } });
            if (result.success) {
                input.value = '';
                updateChatMessages(appState.selectedClass);
            }
            // For students, optionally chat with AI in class
            if (appState.currentUser.account_type === 'student') {
                const aiResult = await apiCall('/api/ai_chat', { method: 'POST', body: { message, class_id: appState.selectedClass } });
                if (aiResult.success) {
                    updateChatMessages(appState.selectedClass);
                }
            }
        }
        
        async function updateChatMessages(classId) {
            const result = await apiCall(`/api/class_messages/${classId}`);
            if (result.success) {
                const messagesDiv = document.getElementById('chat-messages');
                messagesDiv.innerHTML = result.messages.map(m => `
                    <div class="mb-2">
                        <span class="font-bold ${m.sender === 'AI' ? 'text-blue-400' : 'text-green-400'}">${m.sender}:</span> ${m.message}
                        <span class="text-gray-500 text-xs">${new Date(m.timestamp).toLocaleString()}</span>
                    </div>
                `).join('');
                messagesDiv.scrollTop = messagesDiv.scrollHeight;
            }
        }
        
        async function handleGlobalAiChat() {
            const input = document.getElementById('global-chat-input');
            const message = input.value.trim();
            if (!message) return;
            appState.globalChatHistory.push({ sender: appState.currentUser.username, message, timestamp: new Date().toISOString() });
            updateGlobalChatMessages();
            const result = await apiCall('/api/ai_chat', { method: 'POST', body: { message } });
            if (result.success) {
                appState.globalChatHistory.push({ sender: 'AI', message: result.response, timestamp: new Date().toISOString() });
                updateGlobalChatMessages();
            }
            input.value = '';
        }
        
        function updateGlobalChatMessages() {
            const messagesDiv = document.getElementById('global-chat-messages');
            messagesDiv.innerHTML = appState.globalChatHistory.map(m => `
                <div class="mb-2">
                    <span class="font-bold ${m.sender === 'AI' ? 'text-blue-400' : 'text-green-400'}">${m.sender}:</span> ${m.message}
                    <span class="text-gray-500 text-xs">${new Date(m.timestamp).toLocaleString()}</span>
                </div>
            `).join('');
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        }
        
        async function handleUpdateProfile(e) {
            e.preventDefault();
            const form = e.target;
            const data = Object.fromEntries(new FormData(form).entries());
            const result = await apiCall('/api/update_profile', { method: 'POST', body: data });
            if (result.success) {
                appState.currentUser.profile = result.profile;
                showToast('Profile updated!', 'success');
            }
        }
        
        function switchTab(tab) {
            appState.currentTab = tab;
            const setups = {
                'my-classes': setupMyClassesTab,
                'ai-chat': setupAiChatTab,
                'perks': setupPerksTab,
                'profile': setupProfileTab,
            };
            setups[tab]();
        }

        // --- INITIALIZATION ---
        function initializeApp(user, settings) {
            appState.currentUser = user;
            if (settings.announcement) {
                DOMElements.announcementBanner.textContent = settings.announcement;
                DOMElements.announcementBanner.classList.remove('hidden');
            }
            
            // Route to the correct dashboard based on role
            switch(user.account_type) {
                case 'teacher':
                    renderPage('template-teacher-dashboard', setupTeacherDashboard);
                    break;
                case 'admin':
                    renderPage('template-admin-dashboard', setupAdminDashboard);
                    break;
                default: // 'student' and any other type
                    renderPage('template-student-dashboard', setupStudentDashboard);
                    break;
            }
        }

        async function checkLoginStatus() {
            const result = await apiCall('/api/status');
            if (result.success && result.logged_in) {
                initializeApp(result.user, result.settings);
            } else {
                renderPage('template-auth-page', setupAuthPage);
            }
        }

        checkLoginStatus();
    });
    </script>
</body>
</html>
"""

# ==============================================================================
# --- 13. APP INITIALIZATION & EXECUTION ---
# ==============================================================================
def initialize_app():
    load_database()
    with app.app_context():
        if not User.get_by_username('admin'):
            admin_pass = os.environ.get('ADMIN_PASSWORD', 'change-this-default-password')
            admin_email = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
            admin = User(
                id=str(uuid.uuid4()), username='admin', email=admin_email,
                password_hash=generate_password_hash(admin_pass),
                role='admin', plan='student_pro', account_type='admin'
            )
            DB['users'][admin.id] = admin
            save_database()
            logging.info(f"Created default admin user with email {admin_email}.")

if __name__ == '__main__':
    initialize_app()
    # Create the index.html file if it doesn't exist for easier development
    if not os.path.exists('index.html'):
        with open('index.html', 'w', encoding='utf-8') as f:
            f.write(HTML_CONTENT.format(csp_nonce="development-nonce")) # Add a placeholder for local file
            
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
