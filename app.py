from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import sendgrid
from sendgrid.helpers.mail import Mail as SG_Mail
import re
import os
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import os
from authlib.integrations.flask_client import OAuth
app = Flask(__name__)
CORS(app)

# Session Security
app.secret_key = os.environ.get("SECRET_KEY", "ai_debugger_secure_key_2024_final")

# --- DATABASE CONFIGURATION ---
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
if app.config['SQLALCHEMY_DATABASE_URI'].startswith("postgres://"):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- EMAIL CONFIGURATION (LEGACY SMTP - KEPT FOR COMPATIBILITY) ---
app.config['MAIL_SERVER'] = 'smtp.sendgrid.net'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'apikey' 
app.config['MAIL_PASSWORD'] = os.environ.get('SENDGRID_API_KEY')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')
mail = Mail(app)

# --- DATABASE MODELS ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    history = db.relationship('History', backref='owner', lazy=True)

class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code_content = db.Column(db.Text, nullable=False)
    result = db.Column(db.String(500)) 
    language = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

with app.app_context():
    db.create_all()

# --- GOOGLE OAUTH SETUP ---
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)
# --- AUTHENTICATION ROUTES ---

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        if User.query.filter_by(email=email).first():
            return "Email already registered.", 400
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_pw)
        db.session.add(new_user)
        # Check if database is read-only (Railway Volume issue)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return f"Database Error: {str(e)}", 500
        return redirect(url_for("login"))
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session.clear() 
            session["user_id"] = user.id
            session["user"] = user.username
            return redirect(url_for("home"))
        return "Invalid credentials", 401
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# --- PASSWORD RESET ROUTE (STABLE API VERSION) ---

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")
        user = User.query.filter_by(email=email).first()
        
        if user:
            try:
                # Get variables from Railway
                api_key = os.environ.get('SENDGRID_API_KEY')
                sender_email = os.environ.get('MAIL_DEFAULT_SENDER')
                
                if not api_key or not sender_email:
                    return render_template("forgot_password.html", error="Server configuration missing: Check Railway Variables.")

                sg = sendgrid.SendGridAPIClient(api_key=api_key)
                
                # --- CUSTOMIZATION ---
                custom_subject = "AI Code Corrector | Secure Password Reset"
                custom_sender_name = "AI Support Team"
                
                # NEW LOGIC: Generate a specific URL for resetting the password
                reset_url = url_for('reset_password', email=user.email, _external=True)

                # UPDATED TEXT: Now tells the user to click the reset link
                content_text = (
                    f"Hello {user.username},\n\n"
                    f"You requested a password reset. Please click the link below to set a new password:\n\n"
                    f"{reset_url}\n\n"
                    f"If you did not request this, please ignore this email."
                )
                
                # Create the message
                message = SG_Mail(
                    from_email=(sender_email, custom_sender_name),
                    to_emails=email,
                    subject=custom_subject,
                    plain_text_content=content_text
                )
                
                sg.send(message)
                return render_template("forgot_password.html", success=True, email=email)
            
            except Exception as e:
                print(f"DEBUG: {str(e)}")
                return render_template("forgot_password.html", error=f"Email failed: {str(e)}")
        else:
            return render_template("forgot_password.html", error="Email address not found.")
            
    return render_template("forgot_password.html")

# --- PAGE ROUTES ---

@app.route("/")
def home():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("index.html", user=session.get("user"))

@app.route("/about")
def about():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("about.html", user=session.get("user"))

@app.route("/history")
def view_history():
    if "user_id" not in session:
        return redirect(url_for("login"))
    user = User.query.get(session["user_id"])
    if not user:
        session.clear()
        return redirect(url_for("login"))
    user_history = History.query.filter_by(user_id=user.id).order_by(History.timestamp.desc()).all()
    return render_template("history.html", history=user_history, user=session.get("user"))
@app.route("/reset-password/<email>", methods=["GET", "POST"])
def reset_password(email):
    if request.method == "POST":
        new_password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Update the password with a new hash
            user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
            db.session.commit()
            return redirect(url_for('login'))
            
    return render_template("reset_password.html", email=email)
# --- ANALYZER ROUTE ---
@app.route("/analyze", methods=["POST"])
def analyze():
    if "user_id" not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "No data received"}), 400
        
    code = data.get("code", "")
    language = data.get("language", "Python")
    
    # Run the Basic + Complex analysis
    message = analyze_code(code, language)
    status = "error" if "Error" in message or "Warning" in message else "success"

    # Save to Database History
    new_entry = History(
        code_content=code, 
        result=message, 
        language=language, 
        user_id=session["user_id"]
    )
    db.session.add(new_entry)
    db.session.commit()

    return jsonify({"status": status, "message": message})


# --- ENHANCED ANALYZER FUNCTION (Basic + Complex) ---
def analyze_code(code, language):
    errors = []
    
    # --- 1. PYTHON DETAILED CHECK ---
    if language == "Python":
        try:
            compile(code, "<string>", "exec")
        except SyntaxError as e:
            errors.append(f"<b>Syntax Error:</b> '{e.msg}' on line {e.lineno}.")
        
        # Complex Logic Details
        if "/" in code and "if len" not in code and "if scores" not in code:
            errors.append("<b>Logic Warning:</b> Potential ZeroDivisionError. You should check if your list is empty before dividing.")

    # --- 2. C++ DETAILED CHECK ---
    elif language == "C++":
        if code.count('{') != code.count('}'):
            errors.append("<b>Brace Error:</b> You have mismatched curly braces { }.")
        
        if re.search(r'(class|struct)\s+\w+\s*\{[\s\S]*?\}\s*(?!;)', code):
            errors.append("<b>Missing Semicolon:</b> C++ requires a ';' immediately after a class or struct closing brace.")
            
        if re.search(r'<=\s*\w+\.size\(\)', code):
            errors.append("<b>Logic Error:</b> Potential Out-of-Bounds. Using '<=' with .size() targets an index that doesn't exist. Use '<' instead.")

    # --- 3. JAVA DETAILED CHECK ---
    elif language == "Java":
        if code.count('{') != code.count('}'):
            errors.append("<b>Brace Error:</b> Mismatched curly braces { }.")
            
        if "public static void main" in code and re.search(r'(?<!new\s)\b\w+\(\);', code):
            if not re.search(r'\b(System|if|for|while|switch|return)\b', code):
                errors.append("<b>Static Context Error:</b> You cannot call a non-static method directly from 'main'. Create an object or make the method 'static'.")

        # Semicolon Scanner
        lines = code.split('\n')
        for i, line in enumerate(lines):
            code_part = line.split('//')[0].strip()
            if code_part and not code_part.endswith(('{', '}', ';', ':', ',')):
                if any(op in code_part for op in ['=', '(', 'println']):
                    if not any(k in code_part for k in ['public', 'static', 'void', 'class']):
                        errors.append(f"<b>Missing Semicolon:</b> Line {i+1} needs a ';' at the end.")

    # --- RETURN ALL ERRORS IN DETAIL ---
    if errors:
        # Join errors with line breaks for a detailed list
        return "<br>• " + "<br>• ".join(errors)
    return "Success: No syntax errors found!"

@app.route('/login/google')
def google_login():
    # External=True is vital for Railway to generate the correct URL
    redirect_uri = url_for('google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/login/google/authorized')
def google_authorize():
    token = google.authorize_access_token()
    user_info = token.get('userinfo')
    
    # Check if user exists
    user = User.query.filter_by(email=user_info['email']).first()
    if not user:
        # Create user if they are new
        user = User(username=user_info['name'], email=user_info['email'], password="google_auth_user")
        db.session.add(user)
        db.session.commit()
    
    session["user_id"] = user.id
    return redirect(url_for('dashboard'))
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=True)