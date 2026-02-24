from flask import Flask, render_template, request, redirect, session
import os
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

from utils.pdf_reader import read_pdf
from utils.docx_reader import read_docx
from utils.pptx_reader import read_pptx
from utils.excel_reader import read_excel
from utils.summarizer import summarize_text
import re

def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*()_+=\-]", password):
        return False
    return True


# ---------------- APP SETUP ----------------
app = Flask(__name__)
app.secret_key = "secret123"   # OK for college project

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# ---------------- DATABASE ----------------
def get_db():
    return sqlite3.connect("users.db")

# ---------------- ROUTES ----------------

@app.route("/")
def home():
    if "user" not in session:
        return redirect("/login")
    return render_template("index.html")


# -------- REGISTER --------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = generate_password_hash(request.form["password"])

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password)
            )
            db.commit()
        except sqlite3.IntegrityError:
            db.close()
            return "⚠️ Username already exists"
        db.close()

        return redirect("/login")

    return render_template("register.html")


# -------- LOGIN --------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        ).fetchone()
        db.close()

        if user and check_password_hash(user[2], password):
            session["user"] = username
            return redirect("/")
        else:
            return "❌ Invalid username or password"

    return render_template("login.html")


# -------- LOGOUT --------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# -------- SUMMARIZE --------
@app.route("/summarize", methods=["POST"])
def summarize():
    if "user" not in session:
        return redirect("/login")

    if "file" not in request.files:
        return "❌ No file uploaded"

    file = request.files["file"]
    if file.filename == "":
        return "❌ No file selected"

    # user folder
    user_folder = os.path.join(app.config["UPLOAD_FOLDER"], session["user"])
    os.makedirs(user_folder, exist_ok=True)

    filepath = os.path.join(user_folder, file.filename)
    file.save(filepath)

    # -------- FILE READING (ALL TYPES SAFE) --------
    text = ""
    filename = file.filename.lower()

    try:
        if filename.endswith(".pdf"):
            text = read_pdf(filepath)

        elif filename.endswith(".docx"):
            text = read_docx(filepath)

        elif filename.endswith(".pptx"):
            text = read_pptx(filepath)

        elif filename.endswith(".xlsx"):
            text = read_excel(filepath)

        elif filename.endswith(".txt"):
            text = open(filepath, "r", encoding="utf-8", errors="ignore").read()

        else:
            # fallback for ANY file type
            text = open(filepath, "rb").read().decode("utf-8", errors="ignore")

    except Exception:
        return "❌ Unable to extract text from this file"

    if not text or len(text.strip()) < 50:
        return "⚠️ File content too small to summarize"

    summary = summarize_text(text)
    return render_template("result.html", summary=summary)


# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)
