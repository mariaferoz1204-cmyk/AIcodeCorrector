from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
CORS(app)

# Session Security
app.secret_key = os.environ.get("SECRET_KEY", "ai_corrector_dev_key_123")

# --- DATABASE CONFIGURATION ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

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
    result = db.Column(db.String(200))
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
            session["user_id"] = user.id
            session["user"] = user.username
            session["email"] = user.email 
            return redirect(url_for("home"))
        return "Invalid credentials", 401
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# --- PAGE ROUTES ---

@app.route("/", methods=["GET"])
def home():
    if "user_id" not in session:
        return redirect(url_for("login"))
    # Passing 'user' ensures {{ user }} in index.html works
    return render_template("index.html", user=session.get("user"))

@app.route("/about")
def about():
    if "user_id" not in session:
        return redirect(url_for("login"))
    # Passing 'user' ensures the navbar in about.html doesn't crash
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
    code = data.get("code", "")
    language = data.get("language", "Python")
    user_id = session["user_id"]

    status = "success"
    message = "No syntax errors found!"

    if language == "Python":
        try:
            compile(code, "<string>", "exec")
        except SyntaxError as e:
            status = "error"
            message = f"Python Syntax Error: {str(e)}"
    
    elif language in ["Java", "C++"]:
        stripped_code = code.strip()
        if not stripped_code.endswith(";") and not stripped_code.endswith("}"):
            status = "error"
            message = f"{language} Error: Possible missing semicolon ';' at the end of the statement."
        elif code.count("{") != code.count("}"):
            status = "error"
            message = f"{language} Error: Mismatched curly braces {{ }}."
        elif code.count("(") != code.count(")"):
            status = "error"
            message = f"{language} Error: Mismatched parentheses ( )."

    new_entry = History(
        code_content=code,
        result=message,
        language=language,
        user_id=user_id
    )
    db.session.add(new_entry)
    db.session.commit()

    return jsonify({"status": status, "message": message})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=True)