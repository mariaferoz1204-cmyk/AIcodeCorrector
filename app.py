from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
CORS(app)

# Session Security
app.secret_key = os.environ.get("SECRET_KEY", "ai_corrector_dev_key_123")

# --- DATABASE CONFIGURATION ---
# This creates a 'database.db' file in your project folder
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- DATABASE MODEL ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Create the database and tables automatically
with app.app_context():
    db.create_all()

# --- AUTHENTICATION ROUTES ---

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            return "Email already registered. Please login.", 400

        # Hash password and save to DB
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_pw)
        
        db.session.add(new_user)
        db.session.commit()
        
        print(f"New User Created: {username}")
        return redirect(url_for("login"))

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        
        user = User.query.filter_by(email=email).first()
        
        # Verify user exists and password is correct
        if user and check_password_hash(user.password, password):
            session["user"] = user.username
            session["email"] = user.email
            print(f"User Logged In: {user.username}")
            return redirect(url_for("home"))
        
        return "Invalid email or password", 401

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# --- CODE ANALYZER ROUTES ---

@app.route("/", methods=["GET"])
def home():
    # Force login: Redirect to login if user session doesn't exist
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("index.html", user=session["user"])

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Invalid or missing JSON body"}), 400

    code = data.get("code", "")
    language = data.get("language", "")

    if not code.strip():
        return jsonify({"status": "error", "message": "No code provided"})

    if language == "Python":
        try:
            compile(code, "<string>", "exec")
        except SyntaxError as e:
            return jsonify({"status": "error", "message": str(e), "line": e.lineno})
        return jsonify({"status": "success", "message": "No syntax errors"})

    return jsonify({"status": "error", "message": f"{language} not supported yet"})

# --- SERVER START ---

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    app.run(host="0.0.0.0", port=port, debug=True)