# app.py — MentorMe Flask entrypoint (Render + Gunicorn friendly)

import os
import logging
from datetime import datetime
from flask import Flask, request, render_template, make_response
from werkzeug.middleware.proxy_fix import ProxyFix

# ---------- Optional extensions ----------
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

# ---------- App base ----------
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

# ---------- Database ----------
db_url = (
    os.environ.get("DATABASE_URL")
    or os.environ.get("SQLALCHEMY_DATABASE_URI")
    or "sqlite:///mentorme.db"
)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
log.info(f"DB: using {db_url.split('://',1)[0]}://***")

# ---------- Login ----------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"

# Tell Flask-Login how to load a user from session
@login_manager.user_loader
def load_user(user_id: str):
    try:
        from models import User
        return db.session.get(User, int(user_id))  # SQLAlchemy 2.0 style
    except Exception as e:
        log.error(f"user_loader error: {e}")
        return None

# ---------- Config injection ----------
@app.context_processor
def inject_app_config():
    try:
        from app_config import AppConfig
        return dict(config=AppConfig.load_config())
    except Exception:
        return dict(config={})

# ---------- HEAD short-circuit for "/" ----------
@app.before_request
def short_circuit_head_on_root():
    if request.method == "HEAD" and request.path == "/":
        return ("", 200)

# ---------- Health check ----------
@app.route("/healthz", methods=["GET", "HEAD"])
def healthz():
    return ("", 200)

# ---------- Home (GET only, guarded, cache-busted) ----------
@app.route("/", methods=["GET"])
def index():
    try:
        from app_config import AppConfig
        cache_buster = AppConfig.get_cache_buster()
    except Exception:
        cache_buster = int(datetime.utcnow().timestamp())

    topics = []
    try:
        from models import Topic
        topics = Topic.query.order_by(Topic.title.asc()).all()
    except Exception as e:
        log.warning(f"Index topics skipped: {e}")

    html = render_template("index.html", topics=topics, cache_buster=cache_buster)

    resp = make_response(html)
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    resp.headers["Last-Modified"] = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    resp.headers["ETag"] = f"mentorme-{cache_buster}"
    return resp

# ---------- Safe DB table creation ----------
with app.app_context():
    try:
        db.create_all()
        log.info("DB tables created/verified.")
    except Exception as e:
        log.error(f"DB init warning: {e}")

# ---------- Global error handler ----------
@app.errorhandler(Exception)
def handle_uncaught(e):
    log.exception("Unhandled error")
    return ("Internal Server Error", 500)

# ---------- Local dev ----------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
