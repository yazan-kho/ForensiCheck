"""
app.py — Flask web server for the File Signature Checker.
"""

import os
import uuid
import tempfile

from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename

from engine.analyzer import analyze_file

app = Flask(__name__)

# Max upload size: 256 MB (large enough for ISOs if needed)
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024 * 1024

ALLOWED_ANY = True  # Accept any file extension


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    if "file" not in request.files:
        return jsonify({"error": "No file part in request."}), 400

    uploaded_file = request.files["file"]
    if uploaded_file.filename == "":
        return jsonify({"error": "No file selected."}), 400

    original_filename = uploaded_file.filename

    # Save to a temporary file
    tmp_dir = tempfile.mkdtemp()
    # Use a UUID to avoid collisions; keep the extension for OS awareness
    safe_name = f"{uuid.uuid4().hex}_{secure_filename(original_filename)}"
    tmp_path = os.path.join(tmp_dir, safe_name)

    try:
        uploaded_file.save(tmp_path)
        result = analyze_file(tmp_path, original_filename)
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": f"Analysis failed: {str(exc)}"}), 500
    finally:
        # Always clean up the temp file
        try:
            os.remove(tmp_path)
            os.rmdir(tmp_dir)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("  File Signature Checker — Digital Forensics Tool")
    print("  Running at: http://127.0.0.1:5000")
    print("=" * 60)
    app.run(debug=True, host="127.0.0.1", port=5000)
