from flask import Flask, request, jsonify
from flask_cors import CORS
import ast
import subprocess
import tempfile
import os
import traceback

app = Flask(__name__)
CORS(app)  # allows frontend to call backend

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.json
    code = data.get("code", "")
    language = data.get("language", "")

    if not code.strip():
        return jsonify({
            "status": "error",
            "language": language,
            "line": "-",
            "message": "No code provided",
            "explanation": "Please paste code before submitting."
        })

    # ---------------- PYTHON ----------------
    if language == "Python":
        # 1️⃣ Syntax check
        try:
            compile(code, "<string>", "exec")  # checks Python syntax
        except SyntaxError as e:
            return jsonify({
                "status": "error",
                "language": "Python",
                "line": e.lineno,
                "message": e.msg,
                "explanation": "Python requires proper indentation, colons (:), and closed strings."
            })

        # 2️⃣ Runtime check
        try:
            exec(code, {})  # run code safely in empty namespace
        except Exception as e:
            # Try to get line number from traceback if available
            tb = traceback.extract_tb(e.__traceback__)
            line_no = tb[-1].lineno if tb else "-"
            return jsonify({
                "status": "error",
                "language": "Python",
                "line": line_no,
                "message": f"{type(e).__name__}: {str(e)}",
                "explanation": "Python runtime error occurred while executing your code."
            })

        # No errors found
        return jsonify({
            "status": "success",
            "language": "Python",
            "explanation": "Your Python code has no syntax or runtime errors!"
        })

    # ---------------- JAVA ----------------
    if language == "Java":
        return jsonify({
            "status": "error",
            "language": "Java",
            "line": "?",
            "message": "Java compilation not configured yet",
            "explanation": "Java code needs a compiler (javac) to detect errors."
        })

    # ---------------- C++ ----------------
    if language == "C++":
        return jsonify({
            "status": "error",
            "language": "C++",
            "line": "?",
            "message": "C++ compilation not configured yet",
            "explanation": "C++ code requires a compiler (g++) to detect errors."
        })

    return jsonify({
        "status": "error",
        "message": "Unsupported language"
    })


if __name__ == "__main__":
    app.run(debug=True)
