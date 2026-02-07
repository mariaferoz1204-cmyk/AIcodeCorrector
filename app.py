from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import tempfile
import subprocess

app = Flask(__name__)
CORS(app)

@app.route("/", methods=["GET"])
def home():
    return jsonify({"status": "ok", "message": "AI Code Corrector backend is running"})

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Invalid or missing JSON body"}), 400

    code = data.get("code", "")
    language = data.get("language", "")

    if not code.strip():
        return jsonify({"status": "error", "message": "No code provided"})

    # Python code checking
    if language == "Python":
        try:
            compile(code, "<string>", "exec")
        except SyntaxError as e:
            return jsonify({"status": "error", "message": str(e), "line": e.lineno})
        return jsonify({"status": "success", "message": "No syntax errors"})

    # Java placeholder
    if language == "Java":
        return jsonify({"status": "error", "message": "Java checking not supported on this deployment yet"})

    # C++ placeholder
    if language == "C++":
        return jsonify({"status": "error", "message": "C++ checking not supported on this deployment yet"})

    return jsonify({"status": "error", "message": "Unsupported language"})

# ✅ Railway-ready run command
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))  # Railway assigns the port
    app.run(host="0.0.0.0", port=port)
