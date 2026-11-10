
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from threading import Timer
import webbrowser
import hashlib
import sqlite3
import os

app = Flask(__name__)

# For local student project use only. Change before public deployment.
app.secret_key = "cybershield-local-development-key-change-before-deployment"
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

DATABASE = os.path.join(app.root_path, "cybershield.db")


# Create and connect to the database
def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


# Create the users table
def init_db():
    connection = get_db()
    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    connection.commit()
    connection.close()


# Protect pages so only logged-in users can access them
def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "info")
            return redirect(url_for("login"))
        return function(*args, **kwargs)
    return wrapper


# Home dashboard
@app.route("/")
@login_required
def home():
    return render_template("index.html")


# Registration page
@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not password or not confirm_password:
            flash("Please fill in all fields.", "error")

        elif len(username) < 3:
            flash("Username must contain at least 3 characters.", "error")

        elif len(username) > 50:
            flash("Username must not exceed 50 characters.", "error")

        elif len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")

        elif password != confirm_password:
            flash("Passwords do not match.", "error")

        else:
            connection = get_db()

            try:
                connection.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, generate_password_hash(password))
                )
                connection.commit()
                flash("Account created successfully! Please log in.", "success")
                return redirect(url_for("login"))

            except sqlite3.IntegrityError:
                flash("This username already exists. Choose another.", "error")

            finally:
                connection.close()

    return render_template("register.html")


# Login page
@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        connection = get_db()

        try:
            user = connection.execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?",
                (username,)
            ).fetchone()
        finally:
            connection.close()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("home"))

        flash("Incorrect username or password.", "error")

    return render_template("login.html")


# Logout
@app.route("/logout")
def logout():
    session.clear()
    flash("You have logged out.", "success")
    return redirect(url_for("login"))


# About page
@app.route("/about")
@login_required
def about():
    return render_template("about.html")


# Cybersecurity Awareness
@app.route("/awareness")
@login_required
def awareness():
    return render_template("awareness.html")


# Password Strength Checker
@app.route("/password-checker")
@login_required
def password_checker():
    return render_template("password.html")


# Cybersecurity Quiz
@app.route("/quiz")
@login_required
def quiz():
    return render_template("quiz.html")


# Digital Forensics File Analyzer
@app.route("/forensics", methods=["GET", "POST"])
@login_required
def forensics():
    file_info = None
    error = None

    if request.method == "POST":
        uploaded_file = request.files.get("file")

        if not uploaded_file or not uploaded_file.filename:
            error = "Please select a file first."

        else:
            try:
                content = uploaded_file.read(10 * 1024 * 1024 + 1)

                if len(content) > 10 * 1024 * 1024:
                    error = "File is too large. Maximum size is 10 MB."
                else:
                    file_info = {
                        "filename": uploaded_file.filename,
                        "size": len(content),
                        "sha256": hashlib.sha256(content).hexdigest()
                    }

            except Exception:
                error = "Unable to analyze this file. Please try again."

    return render_template(
        "forensics.html",
        file_info=file_info,
        error=error
    )


# Digital Forensics Investigation Report
@app.route("/report")
@login_required
def report():
    return render_template("report.html")


# File size error
@app.errorhandler(413)
def file_too_large(error):
    return render_template(
        "forensics.html",
        file_info=None,
        error="File is too large. Maximum size is 10 MB."
    ), 413


if __name__ == "__main__":
    init_db()

    Timer(
        1.5,
        lambda: webbrowser.open_new("http://127.0.0.1:5000/login")
    ).start()

    app.run(debug=True, use_reloader=False)
