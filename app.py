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
    
    # --- 1. PYTHON CHECK (Basic + Complex) ---
    if language == "Python":
        try:
            # Basic: Catches syntax, colons, and indentation
            compile(code, "<string>", "exec") 
            
            # Complex: Logic check for potential crash
            if "/" in code and "len(" not in code and "if" not in code:
                errors.append("Python Logic Warning: Potential ZeroDivisionError in calculation.")
        except SyntaxError as e:
            errors.append(f"Python Error: '{e.msg}' on line {e.lineno}.")

    # --- 2. C++ CHECK (Basic + Complex) ---
    elif language == "C++":
        # Basic: Braces
        if code.count('{') != code.count('}'):
            errors.append("C++ Error: Mismatched Curly Braces.")
        
        # Complex: Missing semicolon after class
        if re.search(r'(class|struct)\s+\w+\s*\{[\s\S]*?\}\s*(?!;)', code):
            errors.append("C++ Error: Missing semicolon ';' after class definition.")
            
        # Complex: Out of bounds
        if re.search(r'<=\s*\w+\.size\(\)', code):
            errors.append("C++ Logic Error: Potential Out-of-Bounds (use '<' instead of '<=').")

    # --- 3. JAVA CHECK (Basic + Complex) ---
    elif language == "Java":
        # 1. Basic: Mismatched Braces
        if code.count('{') != code.count('}'):
            errors.append("Java Error: Mismatched Curly Braces.")
            
        # 2. Complex: Static vs Non-static
        if "public static void main" in code and re.search(r'(?<!new\s)\b\w+\(\);', code):
            # If it's not a standard keyword, it's likely an invalid non-static call
            if not re.search(r'\b(System|if|for|while|switch|return|super|this)\b', code):
                errors.append("Java Error: Cannot call non-static method from static main.")

        # 3. Basic & Complex: Missing Semicolons (Line-by-Line)
        lines = code.split('\n')
        for i, line in enumerate(lines):
            stripped = line.strip()
            # Ignore comments and empty lines
            code_only = stripped.split('//')[0].strip()
            
            if code_only and not code_only.endswith(('{', '}', ';', ':', ',')):
                # If the line looks like an assignment or a method call, it NEEDS a semicolon
                if any(char in code_only for char in ['=', '(', ')']):
                    # Safety check: ignore class/method headers
                    if not any(word in code_only for word in ['class', 'public', 'static', 'void']):
                        errors.append(f"Java Error: Missing semicolon ';' on line {i+1}.")
                        break

    return errors[0] if errors else "Success: No syntax errors found!"
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=True)