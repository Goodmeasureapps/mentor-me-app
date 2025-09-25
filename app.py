import os
import logging
import sys
from datetime import datetime, timedelta

from flask import Flask, request, render_template, make_response, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
# from flask_wtf.csrf import CSRFProtect   # leave disabled for now if desired
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.exceptions import HTTPException

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
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Make a small helper available to templates (avoids current_app usage in Jinja)
@app.context_processor
def inject_has_endpoint():
    def has_endpoint(name: str) -> bool:
        return name in app.view_functions
    return dict(has_endpoint=has_endpoint)

# Database config
database_url = os.environ.get("DATABASE_URL", "sqlite:///mentorme.db")
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_recycle": 300, "pool_pre_ping": True}

if database_url.startswith("postgresql://"):
    logger.
