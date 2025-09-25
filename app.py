import os
import logging
import sys
from datetime import datetime, timedelta

from flask import Flask, request, render_template, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Env validation
# -----------------------------------------------------------------------------
def validate_environment():
    """Validate that all required environment variables are set for production."""
    required_vars = {
        'SESSION_SECRET': 'Flask session secret key',
        'DATABASE_URL': 'PostgreSQL database connection string'
    }
    missing = [
        f"{var} ({desc})"
        for var, desc in required_vars.items()
        if not os.environ.get(var)
    ]
    if missing and os.environ.get('FLASK_ENV') == 'production':
        logger.error("Missing required environment variables for production:")
        for item in missing:
            logger.error(f"  - {item}")
        logger.error("Please set these variables before deploying to production.")
    return not missing

validate_environment()

# -----------------------------------------------------------------------------
# DB base + app
# -----------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

app = Flask(__name__)

@app.context_processor
def inject_has_endpoint():
    def has_endpoint(name: str) -> bool:
        return name in app.view_functions
    return dict(has_endpoint=has_endpoint)


app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

database_url = os.environ.get("DATABASE_URL", "sqlite:///mentorme.db")
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_recycle": 300, "pool_pre_ping": True}

if database_url.startswith("postgresql://"):
    logger.info("Using PostgreSQL database for production")
elif database_url.startswith("sqlite://"):
    logger.info("Using SQLite database for development")
else:
    logger.warning(f"Unknown database type in DATABASE_URL: {database_url[:20]}...")

# Security config
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 7200  # 2 hours
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

# Security headers
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# Init extensions
db.init_app(app)

# CSRF (left disabled per your comment)
# csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # type: ignore
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# -----------------------------------------------------------------------------
# Health & HEAD handling (no collision with existing `index`)
# -----------------------------------------------------------------------------
@app.route("/healthz", methods=["GET", "HEAD"])
def healthz():
    return ("", 200)

# Render often sends HEAD /. If your app already has GET /, we just short-circuit
# HEAD here to avoid errors without overriding your existing view.
@app.before_request
def _handle_root_head_health():
    if request.method == "HEAD" and request.path == "/":
        return ("", 200)

# -----------------------------------------------------------------------------
# Load models/routes and ensure a fallback root if none exists
# -----------------------------------------------------------------------------
with app.app_context():
    from models import User, Topic, Quiz, QuizResult, ChecklistProgress, SignedNDA
    from routes import *                    # your existing routes (may define "/")
    from app_config import AppConfig

    # If no "/" route exists, register a safe fallback (different endpoint name)
    has_root = any(rule.rule == "/" for rule in app.url_map.iter_rules())
    if not has_root:
        @app.route("/", methods=["GET"])
        def _fallback_index():              # note: different endpoint than "index"
            try:
                return render_template("index.html")
            except Exception:
                return "MentorMe API is running.", 200

    # Create tables with error handling
    try:
        db.create_all()  # type: ignore
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Database connection error: {str(e)}")
        if "could not translate host name" in str(e):
            logger.error("Invalid DATABASE_URL configuration - check your PostgreSQL connection string")
        elif "password authentication failed" in str(e):
            logger.error("Database authentication failed - check your DATABASE_URL credentials")
        elif "database does not exist" in str(e):
            logger.error("Target database does not exist - ensure the database is created")

        if os.environ.get('FLASK_ENV') == 'production':
            logger.error("Application starting without database connection - some features will not work")
        else:
            logger.info("Falling back to development mode - check your database configuration")

# Make config available to templates
@app.context_processor
def inject_app_config():
    from app_config import AppConfig
    return dict(config=AppConfig.load_config())

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Global error handler so unexpected errors don't crash Gunicorn
@app.errorhandler(Exception)
def handle_uncaught(e):
    logger.exception("Unhandled error")
    return "Internal Server Error", 500

# -----------------------------------------------------------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
