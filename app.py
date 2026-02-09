from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
CORS(app)

# Session Security
app.secret_key = os.environ.get("SECRET_KEY", "ai_debugger_secure_key_2024_final")

# --- DATABASE CONFIGURATION ---
# Use PostgreSQL on Railway if available, otherwise fallback to SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
if app.config['SQLALCHEMY_DATABASE_URI'].startswith("postgres://"):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- EMAIL CONFIGURATION (SENDGRID) ---
# --- EMAIL CONFIGURATION (SENDGRID) ---
app.config['MAIL_SERVER'] = 'smtp.sendgrid.net'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False  # <--- THIS MUST BE FALSE
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
        db.session.commit()
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
            msg = Message("Password Reset Request - AI Code Corrector",
                          recipients=[email])
            msg.body = f"Hello {user.username},\n\nYou requested a password reset. Use the link below to login and change your settings:\n\n{url_for('login', _external=True)}\n\nIf you did not request this, please ignore this email."
            
            try:
                mail.send(msg)
                return render_template("forgot_password.html", success=True, email=email)
            except Exception as e:
                print(f"SMTP Error: {e}")
                return render_template("forgot_password.html", error=f"Email service failed: {str(e)}")
        else:
            return render_template("forgot_password.html", error="Email address not found in our system.")
            
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

# --- ANALYZER LOGIC ---

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
    message = "No syntax errors found! Your code structure looks correct."

    if language == "Python":
        try:
            compile(code, "<string>", "exec")
        except SyntaxError as e:
            status = "error"
            message = f"Python Error: '{e.msg}' on line {e.lineno}. Hint: Check colons (:) or indentation."
    
    elif language == "Java" or language == "C++":
        lines = code.split('\n')
        bracket_count = 0
        
        for i, line in enumerate(lines):
            clean_line = line.strip()
            if not clean_line or clean_line.startswith(("//", "/*", "*", "#", "public class", "class", "void", "int main")):
                bracket_count += clean_line.count("{") - clean_line.count("}")
                continue
            
            bracket_count += clean_line.count("{") - clean_line.count("}")
            
            if clean_line and not clean_line.endswith((';', '{', '}', ',')):
                status = "error"
                message = f"{language} Error: Missing semicolon (;) on line {i+1}."
                break
        
        if status == "success" and bracket_count != 0:
            status = "error"
            message = f"{language} Error: Mismatched Curly Braces. Check your opening and closing '{{ }}'."

    new_entry = History(code_content=code, result=message, language=language, user_id=session["user_id"])
    db.session.add(new_entry)
    db.session.commit()

    return jsonify({"status": status, "message": message})

if __name__ == "__main__":
    # Railway provides the PORT variable; locally it uses 3000
    port = int(os.environ.get("PORT", 3000))
    app.run(host="0.0.0.0", port=port)