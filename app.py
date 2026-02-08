from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_cors import CORS
import os, tempfile, subprocess

app = Flask(__name__)
CORS(app)

# Required for session management (Remember me functionality)
app.secret_key = os.environ.get("SECRET_KEY", "ai_corrector_dev_key_123")

# --- AUTHENTICATION ROUTES ---

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        # Capture registration data from the form
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        terms = request.form.get("terms") # 'on' if checked

        # Logic: Here you would typically save the user to a database
        print(f"New Registration - Name: {username}, Email: {email}, Terms: {terms}")
        
        # After successful signup, send them to the login page
        return redirect(url_for("login"))

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        remember = request.form.get("remember")

        # Logic: Verify credentials against your database
        print(f"Login attempt: {email}, Remember: {remember}")
        
        # Set session and redirect to the analyzer home page
        session["user"] = email
        return redirect(url_for("home"))

    return render_template("login.html")

@app.route("/login/google")
def login_google():
    print("Redirecting to Google Auth...")
    return redirect("https://accounts.google.com/")

@app.route("/login/apple")
def login_apple():
    print("Redirecting to Apple Auth...")
    return redirect("https://appleid.apple.com/")

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

# --- CODE ANALYZER ROUTES ---

@app.route("/", methods=["GET"])
def home():
    # If you want to force users to login before using the analyzer, 
    # uncomment the lines below:
    # if "user" not in session:
    #     return redirect(url_for("login"))
    return render_template("index.html")

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

    if language == "Java":
        return jsonify({"status": "error", "message": "Java not supported yet"})
    if language == "C++":
        return jsonify({"status": "error", "message": "C++ not supported yet"})

    return jsonify({"status": "error", "message": "Unsupported language"})

# --- SERVER START ---

if __name__ == "__main__":
    # Using port 3000 as per your requirements
    port = int(os.environ.get("PORT", 3000))
    app.run(host="0.0.0.0", port=port, debug=True)