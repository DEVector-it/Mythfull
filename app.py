# --- Imports ---
import os
import json
import logging
import time
import uuid
import secrets
import smtplib
from io import BytesIO
from email.mime.text import MIMEText
from flask import Flask, Response, request, stream_with_context, session, jsonify, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from datetime import datetime, date, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
import stripe
from PIL import Image
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from authlib.integrations.flask_client import OAuth # For Google Sign-In
import requests
from flask_mail import Mail, Message

# ==============================================================================
# --- 1. INITIAL CONFIGURATION & SETUP ---
# ==============================================================================
load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Security Check for Essential Environment Variables ---
REQUIRED_KEYS = [
    'SECRET_KEY', 'SECURITY_PASSWORD_SALT', 'DEEPSEEK_API_KEY', 
    'SECRET_REGISTRATION_KEY', 'SECRET_TEACHER_KEY', 'STRIPE_WEBHOOK_SECRET',
    'STRIPE_SECRET_KEY', 'STRIPE_PUBLIC_KEY', 'STRIPE_STUDENT_PRICE_ID', 'STRIPE_STUDENT_PRO_PRICE_ID',
    'MAIL_SERVER', 'MAIL_PORT', 'MAIL_USERNAME', 'MAIL_PASSWORD', 'MAIL_SENDER'
]
for key in REQUIRED_KEYS:
    if not os.environ.get(key):
        logging.critical(f"CRITICAL ERROR: Environment variable '{key}' is not set. Application cannot start.")
        exit(f"Error: Missing required environment variable '{key}'. Please set it in your .env file.")

# --- Flask App Initialization ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

# --- Site & API Configuration ---
SITE_CONFIG = {
    "DEEPSEEK_API_KEY": os.environ.get("DEEPSEEK_API_KEY"),
    "DEEPSEEK_API_URL": "https://api.deepseek.com/v1/chat/completions",
    "STRIPE_SECRET_KEY": os.environ.get('STRIPE_SECRET_KEY'),
    "STRIPE_PUBLIC_KEY": os.environ.get('STRIPE_PUBLIC_KEY'),
    "STRIPE_STUDENT_PRICE_ID": os.environ.get('STRIPE_STUDENT_PRICE_ID'),
    "STRIPE_STUDENT_PRO_PRICE_ID": os.environ.get('STRIPE_STUDENT_PRO_PRICE_ID'),
    "YOUR_DOMAIN": os.environ.get('YOUR_DOMAIN', 'http://localhost:5000'),
    "SECRET_REGISTRATION_KEY": os.environ.get('SECRET_REGISTRATION_KEY'),
    "SECRET_TEACHER_KEY": os.environ.get('SECRET_TEACHER_KEY'),
    "STRIPE_WEBHOOK_SECRET": os.environ.get('STRIPE_WEBHOOK_SECRET'),
}

# --- Service Initializations (Stripe, Mail, OAuth) ---
stripe.api_key = SITE_CONFIG["STRIPE_SECRET_KEY"]
password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_SENDER')
mail = Mail(app)

# Google OAuth Setup
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
GOOGLE_SIGN_IN_ENABLED = bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)
if GOOGLE_SIGN_IN_ENABLED:
    oauth = OAuth(app)
    oauth.register(
        name='google',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'}
    )

# ==============================================================================
# --- 2. DATABASE MANAGEMENT ---
# ==============================================================================
DATA_DIR = 'data'
DATABASE_FILE = os.path.join(DATA_DIR, 'database.json')
DB = {"users": {}, "chats": {}, "classrooms": {}, "site_settings": {"announcement": "Welcome to Myth AI for Students!"}}

def setup_database_dir():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
        logging.info(f"Created data directory at: {DATA_DIR}")

def save_database():
    """Atomically saves the in-memory DB to a JSON file."""
    setup_database_dir()
    temp_file = f"{DATABASE_FILE}.tmp"
    try:
        with open(temp_file, 'w') as f:
            serializable_db = {
                "users": {uid: user.to_dict() for uid, user in DB['users'].items()},
                "chats": DB['chats'],
                "classrooms": DB['classrooms'],
                "site_settings": DB['site_settings'],
            }
            json.dump(serializable_db, f, indent=4)
        os.replace(temp_file, DATABASE_FILE)
    except Exception as e:
        logging.error(f"FATAL: Failed to save database: {e}")
        if os.path.exists(temp_file):
            os.remove(temp_file)

def load_database():
    """Loads the database from JSON file on startup."""
    global DB
    setup_database_dir()
    if not os.path.exists(DATABASE_FILE):
        logging.warning(f"Database file not found at {DATABASE_FILE}. A new one will be created.")
        return
    try:
        with open(DATABASE_FILE, 'r') as f:
            data = json.load(f)
        DB['chats'] = data.get('chats', {})
        DB['site_settings'] = data.get('site_settings', {"announcement": ""})
        DB['classrooms'] = data.get('classrooms', {})
        DB['users'] = {uid: User.from_dict(u_data) for uid, u_data in data.get('users', {}).items()}
        logging.info(f"Successfully loaded database from {DATABASE_FILE}")
    except (json.JSONDecodeError, FileNotFoundError, TypeError) as e:
        logging.error(f"Could not load or parse database file '{DATABASE_FILE}'. Error: {e}. Starting fresh.")
        DB = {"users": {}, "chats": {}, "classrooms": {}, "site_settings": {"announcement": "Welcome!"}}

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
    def __init__(self, id, username, email, password_hash=None, role='user', plan='student', account_type='student', daily_messages=0, last_message_date=None, classroom_code=None, streak=0, last_streak_date=None, message_limit_override=None):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.role = role
        self.plan = plan
        self.account_type = account_type
        self.daily_messages = daily_messages
        self.last_message_date = last_message_date or date.today().isoformat()
        self.classroom_code = classroom_code
        self.streak = streak
        self.last_streak_date = last_streak_date or date.today().isoformat()
        self.message_limit_override = message_limit_override
    
    @staticmethod
    def get(user_id):
        return DB['users'].get(user_id)
        
    @staticmethod
    def get_by_email(email):
        if not email: return None
        return next((user for user in DB['users'].values() if user.email and user.email.lower() == email.lower()), None)

    @staticmethod
    def get_by_username(username):
        if not username: return None
        return next((user for user in DB['users'].values() if user.username and user.username.lower() == username.lower()), None)
    
    def to_dict(self):
        return {
            'id': self.id, 'username': self.username, 'email': self.email, 'password_hash': self.password_hash,
            'role': self.role, 'plan': self.plan, 'account_type': self.account_type,
            'daily_messages': self.daily_messages, 'last_message_date': self.last_message_date,
            'classroom_code': self.classroom_code, 'streak': self.streak,
            'last_streak_date': self.last_streak_date, 'message_limit_override': self.message_limit_override
        }

    @staticmethod
    def from_dict(data):
        return User(**data)

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# ==============================================================================
# --- 4. PLANS & DECORATORS ---
# ==============================================================================
PLAN_CONFIG = {
    "student": {"name": "Student", "price_string": "$4.99 / month", "features": ["100 Daily Messages", "Study Buddy Persona", "Streak & Leaderboard", "No Image Uploads"], "color": "text-amber-400", "message_limit": 100, "can_upload": False, "model": "deepseek-chat"},
    "student_pro": {"name": "Student Pro", "price_string": "$7.99 / month", "features": ["200 Daily Messages", "Image Uploads", "All AI Personas", "Streak & Leaderboard"], "color": "text-amber-300", "message_limit": 200, "can_upload": True, "model": "deepseek-coder"}
}

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            return jsonify({"error": "Administrator access required."}), 403
        return f(*args, **kwargs)
    return decorated_function

def teacher_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.account_type != 'teacher':
            return jsonify({"error": "Teacher access required."}), 403
        return f(*args, **kwargs)
    return decorated_function

# ==============================================================================
# --- 5. BUSINESS LOGIC & HELPERS ---
# ==============================================================================
def check_and_update_streak(user):
    """Resets daily message count and updates student streaks."""
    if not user: return
    today = date.today()
    last_message_day = date.fromisoformat(user.last_message_date)
    
    if last_message_day < today:
        user.last_message_date = today.isoformat()
        user.daily_messages = 0
        user.message_limit_override = None # Reset teacher override
        
        if user.account_type == 'student':
            last_streak_day = date.fromisoformat(user.last_streak_date)
            if (today - last_streak_day).days > 1:
                user.streak = 0
    return True

def get_user_data_for_frontend(user):
    """Prepares a safe-to-send dictionary of user data."""
    if not user: return {}
    
    plan_details = PLAN_CONFIG.get(user.plan, PLAN_CONFIG['student'])
    message_limit = user.message_limit_override if user.message_limit_override is not None else plan_details["message_limit"]
    
    return {
        "id": user.id, "username": user.username, "email": user.email, "role": user.role, "plan": user.plan,
        "account_type": user.account_type, "daily_messages": user.daily_messages,
        "message_limit": message_limit, "can_upload": plan_details["can_upload"],
        "is_student_in_class": user.account_type == 'student' and user.classroom_code is not None,
        "streak": user.streak,
    }

def send_password_reset_email(user):
    """Generates a password reset token and sends it to the user's email."""
    try:
        token = password_reset_serializer.dumps(user.email, salt='password-reset-salt')
        reset_url = url_for('index', _external=True) + f"reset-password/{token}"
        msg = Message(
            "Reset Your Myth AI Password",
            recipients=[user.email]
        )
        msg.body = f"Click the link to reset your password: {reset_url}\nThis link is valid for one hour."
        mail.send(msg)
        return True
    except Exception as e:
        logging.error(f"Email sending failed for {user.email}: {e}")
        return False

def generate_unique_classroom_code():
    while True:
        code = secrets.token_hex(4).upper()
        if code not in DB['classrooms']:
            return code

# ==============================================================================
# --- 6. FRONTEND & CORE ROUTES ---
# ==============================================================================
@app.route('/')
@app.route('/reset-password/<token>')
@app.route('/share/<chat_id>')
def index(token=None, chat_id=None):
    # This route now serves the static HTML for all main entry points.
    # The JavaScript router will handle the specific page rendering.
    try:
        with open('index.html', 'r', encoding='utf-8') as f:
            return Response(f.read(), mimetype='text/html')
    except FileNotFoundError:
        # Fallback if index.html is not created yet
        return Response(HTML_CONTENT, mimetype='text/html')

@app.route('/api/status')
def status():
    config = {"google_oauth_enabled": GOOGLE_SIGN_IN_ENABLED, "email_enabled": bool(app.config.get('MAIL_SERVER'))}
    if current_user.is_authenticated:
        check_and_update_streak(current_user)
        save_database()
        return jsonify({
            "logged_in": True, "user": get_user_data_for_frontend(current_user),
            "chats": DB['chats'].get(current_user.id, {}),
            "settings": DB['site_settings'], "config": config
        })
    return jsonify({"logged_in": False, "config": config, "settings": DB['site_settings']})
    
# ==============================================================================
# --- 7. AUTHENTICATION API ROUTES ---
# ==============================================================================
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.get_by_username(data.get('username'))
    if user and user.password_hash and check_password_hash(user.password_hash, data.get('password', '')):
        login_user(user, remember=True)
        return jsonify({"success": True})
    return jsonify({"error": "Invalid username or password."}), 401

@app.route('/api/logout')
def logout():
    logout_user()
    return jsonify({"success": True})
    
@app.route('/api/student_signup', methods=['POST'])
def student_signup():
    data = request.get_json()
    username, password, email = data.get('username','').strip(), data.get('password',''), data.get('email','').strip().lower()
    classroom_code = data.get('classroom_code', '').strip().upper()

    if not all([username, password, email]) or len(username) < 3 or len(password) < 6 or '@' not in email:
        return jsonify({"error": "Valid email, username (min 3 chars), and password (min 6 chars) are required."}), 400
    if User.get_by_username(username): return jsonify({"error": "Username already exists."}), 409
    if User.get_by_email(email): return jsonify({"error": "Email already in use."}), 409
    
    final_code = None
    if classroom_code:
        if classroom_code not in DB['classrooms']: return jsonify({"error": "Invalid classroom code."}), 403
        final_code = classroom_code
        
    new_user = User(
        id=str(uuid.uuid4()), username=username, email=email, 
        password_hash=generate_password_hash(password), 
        account_type='student', plan='student', classroom_code=final_code
    )
    DB['users'][new_user.id] = new_user
    if final_code:
        DB['classrooms'][final_code]['students'].append(new_user.id)
    
    save_database()
    login_user(new_user, remember=True)
    return jsonify({"success": True, "user": get_user_data_for_frontend(new_user)})

# ... Other signup routes (teacher, admin) can be similarly refactored ...

# --- Password Reset Routes ---
@app.route('/api/request-password-reset', methods=['POST'])
def request_password_reset():
    email = request.json.get('email', '').lower()
    user = User.get_by_email(email)
    if user:
        send_password_reset_email(user)
    # Always return success to prevent user enumeration
    return jsonify({"success": True, "message": "If an account with that email exists, a reset link has been sent."})

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
    return jsonify({"success": True, "message": "Password has been updated successfully."})
    
# ==============================================================================
# --- 8. CHAT API ROUTES (REWORKED) ---
# ==============================================================================
@app.route('/api/chat/new', methods=['POST'])
@login_required
def new_chat():
    user_id = current_user.id
    chat_id = str(uuid.uuid4())
    new_chat_data = {
        "id": chat_id, "user_id": user_id, "title": "New Chat",
        "messages": [], "created_at": datetime.now().isoformat(),
    }
    if user_id not in DB['chats']:
        DB['chats'][user_id] = {}
    DB['chats'][user_id][chat_id] = new_chat_data
    save_database()
    return jsonify({"success": True, "chat": new_chat_data})

@app.route('/api/chat', methods=['POST'])
@login_required
def chat_api():
    chat_id = request.form.get('chat_id')
    prompt = request.form.get('prompt', '').strip()
    ai_mode = request.form.get('ai_mode', 'study_buddy')

    # Basic validation
    if not chat_id or not prompt:
        return jsonify({"error": "Missing chat ID or prompt."}), 400
    user_chats = DB['chats'].get(current_user.id, {})
    if chat_id not in user_chats:
        return jsonify({"error": "Chat not found or access denied."}), 404
    
    # ... (Daily limit and streak logic remains the same) ...

    # Persona / System Prompt Logic
    system_instructions = {
        # ... (same as your provided code) ...
    }
    system_instruction = system_instructions.get(ai_mode, system_instructions['study_buddy'])
    
    chat_history = user_chats[chat_id]['messages']
    chat_history.append({'sender': 'user', 'content': prompt})

    # This is the new "Lego piece" structure for the API call
    api_messages = [{"role": "system", "content": system_instruction}]
    for msg in chat_history[-10:]: # Use last 10 messages for context
        role = "assistant" if msg['sender'] == 'model' else 'user'
        api_messages.append({"role": role, "content": msg['content']})

    def generate_stream():
        full_response = ""
        try:
            payload = {"model": "deepseek-chat", "messages": api_messages, "stream": True}
            headers = {"Authorization": f"Bearer {SITE_CONFIG['DEEPSEEK_API_KEY']}", "Content-Type": "application/json"}
            
            with requests.post(SITE_CONFIG['DEEPSEEK_API_URL'], json=payload, headers=headers, stream=True) as response:
                response.raise_for_status()
                for line in response.iter_lines():
                    if line:
                        decoded_line = line.decode('utf-8')
                        if decoded_line.startswith('data: '):
                            try:
                                data = json.loads(decoded_line[6:])
                                chunk = data['choices'][0]['delta'].get('content', '')
                                if chunk:
                                    full_response += chunk
                                    yield chunk
                            except (json.JSONDecodeError, IndexError):
                                continue
            
            # After stream ends, save the full response
            chat_history.append({'sender': 'model', 'content': full_response})
            # ... (Auto-generate title logic remains the same) ...
            save_database()

        except Exception as e:
            logging.error(f"Chat API stream error: {e}")
            yield "STREAM_ERROR: An error occurred with the AI model."

    return Response(stream_with_context(generate_stream()), mimetype='text/plain')

# ... (Other chat routes like rename, delete, share remain largely the same) ...

# ==============================================================================
# --- 9. PAYMENTS & WEBHOOKS ---
# ==============================================================================
@app.route('/api/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    plan_id = request.json.get('plan_id')
    price_map = {
        "student": SITE_CONFIG["STRIPE_STUDENT_PRICE_ID"],
        "student_pro": SITE_CONFIG["STRIPE_STUDENT_PRO_PRICE_ID"],
    }
    if plan_id not in price_map:
        return jsonify(error={'message': 'Invalid plan.'}), 400

    try:
        checkout_session = stripe.checkout.Session.create(
            line_items=[{'price': price_map[plan_id], 'quantity': 1}],
            mode='subscription',
            success_url=SITE_CONFIG["YOUR_DOMAIN"] + '/?payment=success',
            cancel_url=SITE_CONFIG["YOUR_DOMAIN"] + '/?payment=cancel',
            client_reference_id=current_user.id # Securely link session to user
        )
        return jsonify({'id': checkout_session.id})
    except Exception as e:
        logging.error(f"Stripe session error: {e}")
        return jsonify(error={'message': "Could not create payment session."}), 500

@app.route('/stripe-webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, SITE_CONFIG['STRIPE_WEBHOOK_SECRET'])
    except (ValueError, stripe.error.SignatureVerificationError) as e:
        logging.warning(f"Stripe webhook error: {e}")
        return 'Invalid webhook signature', 400

    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        user_id = session.get('client_reference_id')
        user = User.get(user_id)
        if user:
            # Retrieve the session with line items to know which price was paid
            session_with_line_items = stripe.checkout.Session.retrieve(session.id, expand=['line_items'])
            price_id = session_with_line_items.line_items.data[0].price.id
            
            new_plan = None
            if price_id == SITE_CONFIG['STRIPE_STUDENT_PRICE_ID']:
                new_plan = 'student'
            elif price_id == SITE_CONFIG['STRIPE_STUDENT_PRO_PRICE_ID']:
                new_plan = 'student_pro'
            
            if new_plan:
                user.plan = new_plan
                save_database()
                logging.info(f"User {user.id} upgraded to {user.plan} via Stripe webhook.")

    # Handle other events like subscription cancellations
    elif event['type'] == 'customer.subscription.deleted':
        subscription = event['data']['object']
        customer_id = subscription.get('customer')
        # You'll need to find the user by their Stripe customer ID,
        # which you should save when they first subscribe.
        # For this example, we'll log it.
        logging.info(f"Subscription canceled for customer {customer_id}. Find user and downgrade plan.")

    return 'Success', 200
    
# ... The rest of the Admin, Teacher, and Student routes can remain as they are,
#     but should be checked for consistency with the new User and DB models.

# ==============================================================================
# --- 10. APP INITIALIZATION ---
# ==============================================================================
def initialize_app():
    load_database()
    with app.app_context():
        # Create a default admin user if one doesn't exist
        if not User.get_by_username('admin'):
            admin_pass = os.environ.get('ADMIN_PASSWORD', 'change-this-default-password')
            admin_email = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
            admin = User(
                id='admin', username='admin', email=admin_email,
                password_hash=generate_password_hash(admin_pass),
                role='admin', plan='student_pro', account_type='admin'
            )
            DB['users']['admin'] = admin
            save_database()
            logging.info(f"Created default admin user with email {admin_email}.")

if __name__ == '__main__':
    initialize_app()
    # Create the index.html file if it doesn't exist
    if not os.path.exists('index.html'):
        with open('index.html', 'w', encoding='utf-8') as f:
            f.write(HTML_CONTENT)
            logging.info("Created index.html from template.")
            
    port = int(os.environ.get('PORT', 5000))
    # Use debug=False in production!
    app.run(host='0.0.0.0', port=port, debug=True)
