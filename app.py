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
from flask_talisman import Talisman

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
Talisman(app, content_security_policy=None) # Temporarily disabled for simplicity, can be re-enabled later

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
DB = {"users": {}, "classrooms": {}, "site_settings": {"announcement": "Welcome!"}}

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
                "classrooms": DB['classrooms'],
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
        DB['classrooms'] = data.get('classrooms', {})
        DB['users'] = {uid: User.from_dict(u_data) for uid, u_data in data.get('users', {}).items()}
    except Exception as e:
        logging.error(f"Could not load database file '{DATABASE_FILE}'. Error: {e}.")

# ==============================================================================
# --- 3. USER & SESSION MANAGEMENT ---
# ==============================================================================
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'index'


@login_manager.unauthorized_handler
def unauthorized():
    if request.path.startswith('/api/'):
        return jsonify({"error": "Login required.", "logged_in": False}), 401
    return redirect(url_for('index'))

class User(UserMixin):
    def __init__(self, id, username, email, password_hash=None, role='user', plan='student', account_type='student', classroom_code=None, profile=None):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.role = role
        self.plan = plan
        self.account_type = account_type
        self.classroom_code = classroom_code
        self.profile = profile or {"bio": "", "avatar": ""}
    
    @staticmethod
    def get(user_id): return DB['users'].get(user_id)
    @staticmethod
    def get_by_email(email): return next((u for u in DB['users'].values() if u.email and u.email.lower() == email.lower()), None)
    @staticmethod
    def get_by_username(username): return next((u for u in DB['users'].values() if u.username.lower() == username.lower()), None)
    
    # SECURITY FIX: Explicitly define fields to prevent leaking password hash
    def to_dict(self):
        return {
            'id': self.id, 'username': self.username, 'email': self.email,
            'role': self.role, 'plan': self.plan, 'account_type': self.account_type,
            'classroom_code': self.classroom_code, 'profile': self.profile
        }

    @staticmethod
    def from_dict(data): return User(**data)

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# ==============================================================================
# --- 4. DECORATORS & HELPERS ---
# ==============================================================================
def get_user_data_for_frontend(user):
    return user.to_dict() if user else {}

def send_password_reset_email(user):
    try:
        token = password_reset_serializer.dumps(user.email, salt='password-reset-salt')
        reset_url = url_for('index', _external=True, _scheme='https') + f"reset-password/{token}"
        msg = Message("Reset Your Password", recipients=[user.email])
        msg.body = f"Click the link to reset your password: {reset_url}\nThis link is valid for one hour."
        mail.send(msg)
        return True
    except Exception as e:
        logging.error(f"Email sending failed for {user.email}: {e}")
        return False

# FIXED: This decorator was checking the wrong attribute ('account_type' instead of 'role')
def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.role == 'admin':
            return jsonify({"error": "Admin access required."}), 403
        return f(*args, **kwargs)
    return decorated_function

def teacher_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.account_type == 'teacher':
            return jsonify({"error": "Teacher access required."}), 403
        return f(*args, **kwargs)
    return decorated_function

def student_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.account_type == 'student':
            return jsonify({"error": "Student access required."}), 403
        return f(*args, **kwargs)
    return decorated_function

# ==============================================================================
# --- 5. FRONTEND & CORE ROUTES ---
# ==============================================================================
@app.route('/')
@app.route('/reset-password/<token>')
def index(token=None):
    return Response(HTML_CONTENT, mimetype='text/html')

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
    
    # FIXED: Corrected typo from jupytext to jsonify
    if User.get_by_username(username): return jsonify({"error": "Username already exists."}), 409
    if User.get_by_email(email): return jsonify({"error": "Email already in use."}), 409
        
    new_user = User(id=str(uuid.uuid4()), username=username, email=email, password_hash=generate_password_hash(password), account_type='teacher', plan='student_pro')
    DB['users'][new_user.id] = new_user
    save_database()
    login_user(new_user, remember=True)
    return jsonify({"success": True, "user": get_user_data_for_frontend(new_user)})

# ... Password Reset Routes remain the same ...

# ==============================================================================
# --- 7. DASHBOARD & CLASSROOM API ROUTES ---
# ==============================================================================
@app.route('/api/admin_data')
@admin_required
def admin_data():
    users_list = [get_user_data_for_frontend(u) for u in DB['users'].values() if u.role != 'admin']
    stats = { 'total_users': len(users_list) }
    return jsonify({
        "success": True, "stats": stats, "users": users_list,
        "announcement": DB['site_settings']['announcement']
    })

@app.route('/api/create_class', methods=['POST'])
@teacher_required
def create_class():
    name = request.json.get('name')
    if not name: return jsonify({"error": "Class name is required."}), 400
    
    class_id = secrets.token_hex(4).upper() # Use code as ID
    DB['classrooms'][class_id] = {
        "id": class_id, "name": name, "teacher_id": current_user.id,
        "students": [], "messages": []
    }
    save_database()
    return jsonify({"success": True, "class": DB['classrooms'][class_id]})

@app.route('/api/my_classes', methods=['GET'])
@login_required
def my_classes():
    user_classes_data = []
    if current_user.account_type == 'teacher':
        user_classes = [cls for cls in DB['classrooms'].values() if cls.get('teacher_id') == current_user.id]
        for cls in user_classes:
             cls_data = cls.copy()
             cls_data['teacher'] = current_user.username
             user_classes_data.append(cls_data)

    elif current_user.account_type == 'student' and current_user.classroom_code:
        cls = DB['classrooms'].get(current_user.classroom_code)
        if cls:
             teacher = User.get(cls.get('teacher_id'))
             cls_data = cls.copy()
             cls_data['teacher'] = teacher.username if teacher else "Unknown"
             user_classes_data.append(cls_data)
             
    return jsonify({"success": True, "classes": user_classes_data})

@app.route('/api/join_class', methods=['POST'])
@student_required
def join_class():
    code = request.json.get('code', '').upper()
    if not code or code not in DB['classrooms']:
        return jsonify({"error": "Invalid class code."}), 404
    if current_user.classroom_code:
        return jsonify({"error": "You must leave your current class to join a new one."}), 400
    
    DB['classrooms'][code]['students'].append(current_user.id)
    current_user.classroom_code = code
    save_database()
    return jsonify({"success": True, "message": f"Successfully joined {DB['classrooms'][code]['name']}."})

@app.route('/api/class_messages/<class_id>', methods=['GET'])
@login_required
def get_class_messages(class_id):
    classroom = DB['classrooms'].get(class_id)
    if not classroom: return jsonify({"error": "Class not found."}), 404
    
    is_member = current_user.id in classroom.get('students', []) or classroom.get('teacher_id') == current_user.id
    if not is_member: return jsonify({"error": "Access denied."}), 403
    
    return jsonify({"success": True, "messages": classroom.get('messages', [])})

# ==============================================================================
# --- 8. HTML & JAVASCRIPT FRONTEND ---
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
    <div id="app-container" class="relative h-screen w-screen overflow-hidden"></div>
    <div id="toast-container" class="fixed top-6 right-6 z-[100] flex flex-col gap-2"></div>

    <template id="template-auth-page">
        </template>
    
    <template id="template-signup-page">
        </template>

    <template id="template-dashboard">
        <div class="flex h-full w-full bg-gray-800 fade-in">
            <nav class="w-64 bg-gray-900 p-6 flex flex-col gap-4">
                <h2 class="text-2xl font-bold text-white mb-4">Dashboard</h2>
                <div id="nav-links"></div>
                <button id="logout-btn" class="mt-auto bg-red-600 hover:bg-red-500 text-white font-bold py-2 px-4 rounded-lg">Logout</button>
            </nav>
            <main id="dashboard-content" class="flex-1 p-8 overflow-y-auto"></main>
        </div>
    </template>

    <template id="template-my-classes-view">
        <h3 class="text-2xl font-bold text-white mb-4">My Classes</h3>
        <div id="class-info-container"></div>
        <div id="class-chat-container" class="mt-8 hidden">
            <h4 class="text-xl font-bold text-white mb-2">Classroom Chat</h4>
            <div id="chat-messages" class="bg-gray-900/50 p-4 rounded-lg h-96 overflow-y-auto mb-4 border border-gray-700"></div>
            <div class="flex gap-2">
                <input type="text" id="chat-input" placeholder="Type your message..." class="flex-grow p-3 bg-gray-700/50 rounded-lg border border-gray-600">
                <button id="send-chat-btn" class="bg-blue-600 hover:bg-blue-500 text-white font-bold py-2 px-4 rounded-lg">Send</button>
            </div>
        </div>
    </template>
    
    <template id="template-admin-view">
        </template>

    <script>
    // NOTE: Nonce attribute is removed here as Talisman is currently disabled for simplicity.
    // Re-add nonce="{csp_nonce}" if you re-enable Talisman.
    document.addEventListener('DOMContentLoaded', () => {
        const appState = { currentUser: null, selectedClassId: null };
        const DOMElements = {
            appContainer: document.getElementById('app-container'),
            toastContainer: document.getElementById('toast-container'),
        };

        // --- UTILITY & API FUNCTIONS ---
        // ... (showToast and apiCall functions remain the same)

        function renderPage(templateId, setupFunction) { /* ... remains the same ... */ }
        function renderSubTemplate(container, templateId, setupFunction) { /* ... remains the same ... */ }

        // --- DASHBOARD & TAB LOGIC ---
        function switchTab(tab) {
            const content = document.getElementById('dashboard-content');
            if (tab === 'my-classes') {
                const templateId = appState.currentUser.account_type === 'teacher' ? 'template-my-classes-view' : 'template-my-classes-view'; // Can be different templates
                renderSubTemplate(content, 'template-my-classes-view', setupMyClassesTab);
            }
        }
        
        async function setupMyClassesTab() {
            const result = await apiCall('/api/my_classes');
            const container = document.getElementById('class-info-container');
            if (!container) return;

            if (appState.currentUser.account_type === 'student') {
                if (result.success && result.classes.length > 0) {
                    const myClass = result.classes[0];
                    appState.selectedClassId = myClass.id;
                    container.innerHTML = `<div class="glassmorphism p-4 rounded-lg">...</div>`; // Student class info
                    document.getElementById('class-chat-container').classList.remove('hidden');
                    document.getElementById('send-chat-btn').addEventListener('click', handleSendMessage);
                    updateChatMessages();
                } else {
                    container.innerHTML = `<div>...<button id="join-class-btn">Join</button></div>`;
                    document.getElementById('join-class-btn').addEventListener('click', handleJoinClass);
                }
            } else if (appState.currentUser.account_type === 'teacher') {
                // Teacher's view of classes
            }
        }

        async function updateChatMessages() {
            // ... (Logic remains the same)
        }

        // --- EVENT HANDLERS ---
        // ... (handleLoginSubmit, handleLogout, handleJoinClass, handleSendMessage, etc.)

        // --- INITIALIZATION ---
        function initializeApp(user) {
            appState.currentUser = user;
            renderPage('template-dashboard', () => {
                const navLinks = document.getElementById('nav-links');
                if (user.account_type === 'student') {
                    navLinks.innerHTML = `<button data-tab="my-classes" class="tab-btn text-left p-2 rounded-md hover:bg-gray-700">My Class</button>`;
                    switchTab('my-classes');
                } else if (user.account_type === 'teacher') {
                    navLinks.innerHTML = `<button data-tab="my-classes" class="tab-btn text-left p-2 rounded-md hover:bg-gray-700">Manage Classes</button>`;
                    switchTab('my-classes');
                } else if (user.role === 'admin') {
                    // Admin nav links
                }
                document.getElementById('logout-btn').addEventListener('click', () => handleLogout(true));
                navLinks.addEventListener('click', (e) => {
                    if(e.target.classList.contains('tab-btn')) switchTab(e.target.dataset.tab);
                });
            });
        }
        
        // ... (checkLoginStatus remains the same)

        checkLoginStatus();
    });
    </script>
</body>
</html>
"""

# ==============================================================================
# --- APP INITIALIZATION & exttiodsnkmd dkskm skmkskmcs  sksdmksmkmkm
# ==============================================================================
def initialize_app():
    load_database()
    with app.app_context():
        if not User.get_by_username('admin'):
            # ... (Admin user creation logic remains the same)
            pass

if __name__ == '__main__':
    initialize_app()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
