# app.py — MentorMe Flask entrypoint (Render + Gunicorn friendly)

import os
import logging
from datetime import datetime
from flask import (
    Flask, request, render_template, make_response,
    current_app, redirect, url_for, flash
)
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

# -------------------------------------------------------------------
# App setup
# -------------------------------------------------------------------
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Cookies / session
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")

# Logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("mentorme")

# -------------------------------------------------------------------
# Database
# -------------------------------------------------------------------
db_url = (
    os.environ.get("DATABASE_URL")
    or os.environ.get("SQLALCHEMY_DATABASE_URI")
    or "sqlite:///mentorme.db"
)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
log.info(f"DB: using {db_url.split('://',1)[0]}://***")

# -------------------------------------------------------------------
# Login (Flask-Login setup)
# -------------------------------------------------------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"

from models import User

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------------------------------------------------------
# Inject helpers into Jinja
# -------------------------------------------------------------------
@app.context_processor
def utility_processor():
    def has_endpoint(name):
        return name in current_app.view_functions
    try:
        from app_config import AppConfig
        return dict(
            has_endpoint=has_endpoint,
            config=AppConfig.load_config()
        )
    except Exception:
        return dict(has_endpoint=has_endpoint, config={})

# -------------------------------------------------------------------
# HEAD short-circuit (for Render)
# -------------------------------------------------------------------
@app.before_request
def short_circuit_head_on_root():
    if request.method == "HEAD" and request.path == "/":
        return ("", 200)

# -------------------------------------------------------------------
# Health check
# -------------------------------------------------------------------
@app.route("/healthz", methods=["GET", "HEAD"])
def healthz():
    return ("", 200)

# -------------------------------------------------------------------
# Home
# -------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    try:
        from app_config import AppConfig
        cache_buster = AppConfig.get_cache_buster()
    except Exception:
        cache_buster = int(datetime.utcnow().timestamp())

    html = render_template("index.html", cache_buster=cache_buster)
    resp = make_response(html)
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    resp.headers["Last-Modified"] = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    resp.headers["ETag"] = f"mentorme-{cache_buster}"
    return resp

# -------------------------------------------------------------------
# Auth routes
# -------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        if not email or not password:
            flash("Please enter email and password.", "warning")
            return render_template("login.html"), 400
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        if not username or not email or not password:
            flash("All fields are required.", "warning")
            return render_template("register.html"), 400
        return redirect(url_for("dashboard"))
    return render_template("register.html")

@app.route("/dashboard", methods=["GET"])
def dashboard():
    tpl = os.path.join(app.template_folder or "templates", "dashboard.html")
    if os.path.exists(tpl):
        return render_template("dashboard.html")
    return "Welcome to your dashboard ✨", 200

# -------------------------------------------------------------------
# Import models + auto-create tables
# -------------------------------------------------------------------
with app.app_context():
    try:
        from models import (
            Topic, Quiz, QuizResult, ChecklistProgress,
            SignedNDA, CareerPath, TeenSupport, JobOpportunity,
            UserInterest, Mentor, MentorSpecialty, MentorRecommendation,
            UserMentorMatch, SportsQuizResult, WeeklyDrawingEntry,
            CategoryQuizResult, AIChatHistory, UserBadge, WeeklyDrawing,
            MicroChallenge, UserMicroChallenge, UserSettings,
            UserFeedback, ResourceLibrary, ChatHistory,
            TeenInterest, TeenAccomplishment, RelationshipVideo
        )
        db.create_all()
        log.info("DB tables created/verified.")
    except Exception as e:
        log.error(f"DB init failed: {e}")

# -------------------------------------------------------------------
# Error handler
# -------------------------------------------------------------------
@app.errorhandler(Exception)
def handle_uncaught(e):
    log.exception("Unhandled error")
    return ("Internal Server Error", 500)

# -------------------------------------------------------------------
# Local dev
# -------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
