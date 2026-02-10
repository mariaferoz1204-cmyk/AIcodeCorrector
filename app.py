from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import sendgrid
from sendgrid.helpers.mail import Mail as SG_Mail
import google.generativeai as genai

app = Flask(__name__)
CORS(app)

# Session Security
app.secret_key = os.environ.get("SECRET_KEY", "ai_debugger_secure_key_2024_final")

# --- AI CONFIGURATION (GEMINI) ---
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
genai.configure(api_key=GEMINI_API_KEY)

# --- DATABASE CONFIGURATION ---
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
if app.config['SQLALCHEMY_DATABASE_URI'].startswith("postgres://"):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- EMAIL CONFIGURATION (LEGACY SMTP) ---
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
    result = db.Column(db.Text) # Changed to Text to accommodate detailed AI fixes
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

# --- PASSWORD RESET ROUTE ---

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")
        user = User.query.filter_by(email=email).first()
        if user:
            try:
                api_key = os.environ.get('SENDGRID_API_KEY')
                sender_email = os.environ.get('MAIL_DEFAULT_SENDER')
                if not api_key or not sender_email:
                    return render_template("forgot_password.html", error="Server configuration missing.")

                sg = sendgrid.SendGridAPIClient(api_key=api_key)
                custom_subject = "AI Code Corrector | Secure Password Reset"
                custom_sender_name = "AI Support Team"
                content_text = f"Hello {user.username},\n\nYou requested a password reset. Use this link: {url_for('login', _external=True)}"
                
                message = SG_Mail(
                    from_email=(sender_email, custom_sender_name),
                    to_emails=email,
                    subject=custom_subject,
                    plain_text_content=content_text
                )
                sg.send(message)
                return render_template("forgot_password.html", success=True, email=email)
            except Exception as e:
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

@app.route("/history")
def view_history():
    if "user_id" not in session:
        return redirect(url_for("login"))
    user = User.query.get(session["user_id"])
    user_history = History.query.filter_by(user_id=user.id).order_by(History.timestamp.desc()).all()
    return render_template("history.html", history=user_history, user=session.get("user"))

# --- IMPROVED ANALYZER LOGIC ---

@app.route("/analyze", methods=["POST"])
def analyze():
    if "user_id" not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "No data received"}), 400
        
    code = data.get("code", "")
    language = data.get("language", "Python")
    
    status = "success"
    message = "No syntax errors found!"

    # 1. KEPT ORIGINAL LOGIC (Internal Checks)
    if language == "Python":
        try:
            compile(code, "<string>", "exec")
        except SyntaxError as e:
            status = "error"
            message = f"Local Python Error: '{e.msg}' on line {e.lineno}."
    
    elif language == "Java" or language == "C++":
        if code.count("{") != code.count("}"):
            status = "error"
            message = f"Local {language} Error: Mismatched Curly Braces."

    # 2. ADDED AI LOGIC (Deep Analysis for all 3 languages)
    # If local check passes, we still use AI to find deep bugs/typos
    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        ai_prompt = f"Analyze this {language} code for any typos, syntax errors, or logical bugs. If there are errors, explain them briefly and provide the corrected code. If it's perfect, say 'No errors found'.\n\nCode:\n{code}"
        
        response = model.generate_content(ai_prompt)
        ai_message = response.text

        if "No errors found" not in ai_message:
            status = "issue_found" # Differentiates between hard syntax error and AI suggestions
            message = ai_message
            
    except Exception as e:
        print(f"AI Error: {e}")
        # If AI fails, we just stick with the result from your original local logic

    new_entry = History(code_content=code, result=message, language=language, user_id=session["user_id"])
    db.session.add(new_entry)
    db.session.commit()

    return jsonify({"status": status, "message": message})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=True)