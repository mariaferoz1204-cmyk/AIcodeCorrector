from flask import Flask, request, jsonify
from flask_cors import CORS
import tempfile, subprocess, os

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

    if language == "Python":
        try:
            compile(code, "<string>", "exec")
        except SyntaxError as e:
            return jsonify({"status": "error", "message": str(e), "line": e.lineno})
        return jsonify({"status": "success", "message": "No syntax errors"})

    if language == "Java":
        return check_java_syntax(code)

    if language == "C++":
        return check_cpp_syntax(code)

    return jsonify({"status": "error", "message": "Unsupported language"})

# Helper functions
def check_java_syntax(code):
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "Main.java")
        with open(path, "w") as f:
            f.write(code)
        result = subprocess.run(["javac", path], capture_output=True, text=True)
        if result.returncode != 0:
            return {"status": "error", "message": result.stderr}
        return {"status": "success", "message": "No syntax errors"}

def check_cpp_syntax(code):
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "main.cpp")
        with open(path, "w") as f:
            f.write(code)
        result = subprocess.run(["g++", "-fsyntax-only", path], capture_output=True, text=True)
        if result.returncode != 0:
            return {"status": "error", "message": result.stderr}
        return {"status": "success", "message": "No syntax errors"}
