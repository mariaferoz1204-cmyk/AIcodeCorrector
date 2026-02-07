from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os, tempfile, subprocess

app = Flask(__name__)
CORS(app)

# Serve homepage
@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")  # loads index.html from templates folder

# Analyze code endpoint (your existing code)
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

    # Temporary placeholders for Java/C++
    if language == "Java":
        return jsonify({"status": "error", "message": "Java not supported yet"})
    if language == "C++":
        return jsonify({"status": "error", "message": "C++ not supported yet"})

    return jsonify({"status": "error", "message": "Unsupported language"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    app.run(host="0.0.0.0", port=port)
