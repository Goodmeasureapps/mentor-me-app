# app.py
import os
import sys
import logging
from datetime import datetime, timedelta

from flask import (
    Flask,
    request,
    render_template,
    make_response,
    current_app,
)

# --- Optional deps (app won't crash if they're missing) ----------------------
try:
    from flask_sqlalchemy import SQLAlchemy
except Exception:
    SQLAlchemy = None  # type: ignore

try:
    from flask_login import LoginManager
except Exception:
    LoginManager = None  # type: ignore

try:
    from flask_wtf.csrf import CSRFProtect
except Exception:
    CSRFProtect = None  # type: ignore

try:
    from sqlalchemy.orm import DeclarativeBase  # SQLAlchemy 2.x style
except Exception:
    DeclarativeBase = object  # fallback so type exists

from werkzeug.middleware.proxy_fix import ProxyFix


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# DB base + instance (optional)
# -----------------------------------------------------------------------------
class Base(DeclarativeBase):  # type: ignore[misc]
    pass


db = SQLAlchemy(model_class=Base) if SQLAlchemy else None  # type: ignore[call-arg]


# -----------------------------------------------------------------------------
# Flask application
# -----------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")

# Let Flask know it’s behind a proxy (Render)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)  # type: ignore[arg-type]


# -----------------------------------------------------------------------------
# Config: database (optional) + cookie/security
# -----------------------------------------------------------------------------
database_url = os.environ.get("DATABASE_URL")
if db and database_url:
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
    }

# Session cookie hardening
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


@app.after_request
def set_security_headers(response):
    # Friendly CSP/headers; adjust as you tighten things up
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return response


# -----------------------------------------------------------------------------
# HEAD short-circuit for Render health checks
# -----------------------------------------------------------------------------
@app.before_request
def _short_circuit_head_checks():
    # Instantly OK HEAD checks to "/" and "/healthz" so templates/db are not touched
    if request.method == "HEAD" and request.path in ("/", "/healthz"):
        return ("", 200)


# -----------------------------------------------------------------------------
# Extensions (only if installed)
# -----------------------------------------------------------------------------
login_manager = None
if db:
    db.init_app(app)

if LoginManager:
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = "login"
    login_manager.login_message_category = "info"

if CSRFProtect:
    # Enable later if you add CSRF tokens to forms
    # CSRFProtect(app)
    pass


# -----------------------------------------------------------------------------
# Health endpoint
# -----------------------------------------------------------------------------
@app.route("/healthz", methods=["GET", "HEAD"])
def healthz():
    return ("", 200)


# -----------------------------------------------------------------------------
# Home (GET only) — guarded
# -----------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    try:
        # Optional: bring in your dynamic config and topics list
        topics = []
        try:
            from app_config import AppConfig  # local import to avoid startup import errors

            # If Topic model exists, load it; otherwise keep empty list
            try:
                from models import Topic  # type: ignore
                topics = Topic.query.order_by(Topic.title.asc()).all()  # type: ignore[attr-defined]
            except Exception:
                topics = []

            cache_buster = getattr(AppConfig, "get_cache_buster", lambda: "")()
        except Exception:
            cache_buster = ""

        html = render_template("index.html", topics=topics, cache_buster=cache_buster)

        resp = make_response(html)
        # No caching on homepage (useful during development and SPA shells)
        resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        resp.headers["Last-Modified"] = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
        resp.headers["ETag"] = f"mentorme-fresh-{int(datetime.utcnow().timestamp())}"
        return resp

    except Exception:
        # Don’t crash the worker on homepage if something is missing
        current_app.logger.exception("index failed")
        return ("MentorMe API is running.", 200)


# -----------------------------------------------------------------------------
# Optional: user loader if using Flask-Login and your models.User exists
# -----------------------------------------------------------------------------
if login_manager:
    @login_manager.user_loader  # type: ignore[misc]
    def load_user(user_id: str):
        try:
            from models import User  # type: ignore
            return User.query.get(int(user_id))  # type: ignore[attr-defined]
        except Exception:
            return None


# -----------------------------------------------------------------------------
# Import routes/models & create tables (won’t crash if they’re absent)
# -----------------------------------------------------------------------------
with app.app_context():
    try:
        # Import your existing routes (they may define additional pages/endpoints)
        try:
            import routes  # noqa: F401
        except Exception:
            pass

        # Create tables only if DB is configured
        if db and database_url:
            try:
                db.create_all()  # type: ignore[attr-defined]
                logger.info("Database tables created successfully")
            except Exception as e:
                # Helpful logs without crashing the app
                msg = str(e)
                if "authentication failed" in msg or "password authentication failed" in msg:
                    logger.error("Database authentication failed - check your DATABASE_URL credentials")
                elif "does not exist" in msg:
                    logger.error("Target database does not exist - ensure the database is created")
                else:
                    logger.exception("DB create_all failed")
        else:
            logger.info("Starting without database connection (no DATABASE_URL)")
    except Exception:
        logger.exception("Startup initialization failed")


# -----------------------------------------------------------------------------
# Global error handler
# -----------------------------------------------------------------------------
@app.errorhandler(Exception)
def handle_uncaught(e):
    logger.exception("Unhandled error")
    return ("Internal Server Error", 500)


# -----------------------------------------------------------------------------
# Local dev entrypoint (Render uses Gunicorn)
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
