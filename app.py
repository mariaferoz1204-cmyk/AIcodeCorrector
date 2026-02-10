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
if app.config['SQLALCHEMY_DATABASE_URI'] and app.config['SQLALCHEMY_DATABASE_URI'].startswith("postgres://"):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace("postgres://", "postgresql://", 1)

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
    result = db.Column(db.Text) 
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
            return redirect(url_for("login"))
        except Exception as e:
            db.session.rollback()
            return f"Database Error: {str(e)}", 500
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
    user_history = History.query.filter_by(user_id=session["user_id"]).order_by(History.timestamp.desc()).all()
    return render_template("history.html", history=user_history, user=session.get("user"))

# --- ANALYZER LOGIC ---

@app.route("/analyze", methods=["POST"])
def analyze():
    if "user_id" not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    data = request.get_json(silent=True)
    if not data or not data.get("code"):
        return jsonify({"status": "error", "message": "No code provided"}), 400
        
    code = data.get("code", "")
    language = data.get("language", "Python")
    
    # AI Logic - Carefully check the indentation below!
    try:
        model = genai.GenerativeModel('gemini-1.0-pro')
        prompt = f"Analyze this {language} code for syntax and logical errors. If there are errors, explain and provide corrected code. If perfect, say 'Success: No errors found!'.\n\nCode:\n{code}"
        response = model.generate_content(prompt)
        message = response.text
        status = "success"
    except Exception as e:
        status = "error"
        message = f"AI Error: {str(e)}"

    new_entry = History(code_content=code, result=message, language=language, user_id=session["user_id"])
    db.session.add(new_entry)
    db.session.commit()

    return jsonify({"status": status, "message": message})

    new_entry = History(code_content=code, result=message, language=language, user_id=session["user_id"])
    db.session.add(new_entry)
    db.session.commit()

    return jsonify({"status": status, "message": message})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)