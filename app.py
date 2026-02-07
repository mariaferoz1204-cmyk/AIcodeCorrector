from flask import Flask, request, jsonify
from flask_cors import CORS
import traceback

app = Flask(__name__)
CORS(app)  # allows frontend to call backend


# ✅ Health check route (VERY IMPORTANT for Vercel)
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "ok",
        "message": "AI Code Corrector backend is running"
    })


@app.route("/analyze", methods=["POST"])
def analyze():
    # ✅ Safe JSON handling (prevents 500 crash)
    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "status": "error",
            "message": "Invalid or missing JSON body"
        }), 400

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
            compile(code, "<string>", "exec")
        except SyntaxError as e:
            return jsonify({
                "status": "error",
                "language": "Python",
                "line": e.lineno,
                "message": e.msg,
                "explanation": "Python requires proper indentation, colons (:), and closed strings."
            })

        # ⚠️ Runtime execution REMOVED for Vercel safety
        # Serverless functions should NOT exec arbitrary code

        return jsonify({
            "status": "success",
            "language": "Python",
            "explanation": "Your Python code has no syntax errors!"
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


# ❌ DO NOT run app.run() on Vercel
# Vercel handles execution itself
