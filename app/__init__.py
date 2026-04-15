from flask import Flask, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from sqlalchemy import inspect, text
import os

db = SQLAlchemy()
login_manager = LoginManager()


def _ensure_passkey_columns(flask_app):
    """Add passkey-related columns if the DB was created before passkey support."""
    with flask_app.app_context():
        inspector = inspect(db.engine)
        if 'users' not in inspector.get_table_names():
            return

        existing = {col['name'] for col in inspector.get_columns('users')}
        statements = []

        if 'passkey_enabled' not in existing:
            statements.append("ALTER TABLE users ADD COLUMN passkey_enabled BOOLEAN DEFAULT 0")
        if 'passkey_credential_id' not in existing:
            statements.append("ALTER TABLE users ADD COLUMN passkey_credential_id TEXT")
        if 'passkey_public_key' not in existing:
            statements.append("ALTER TABLE users ADD COLUMN passkey_public_key TEXT")
        if 'passkey_sign_count' not in existing:
            statements.append("ALTER TABLE users ADD COLUMN passkey_sign_count INTEGER DEFAULT 0")

        if not statements:
            return

        with db.engine.begin() as connection:
            for statement in statements:
                connection.execute(text(statement))

def create_app():
    flask_app = Flask(__name__)
    
    # Configuration
    flask_app.config['SECRET_KEY'] = 'your-secret-key-change-this'
    base_dir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    flask_app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{base_dir}/mfa_auth.db'
    flask_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Initialize extensions
    db.init_app(flask_app)
    login_manager.init_app(flask_app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    
    # Create database tables
    with flask_app.app_context():
        # Ensure model modules are imported so SQLAlchemy metadata is registered
        from . import models  # noqa: F401
        db.create_all()
        _ensure_passkey_columns(flask_app)
    
    # Register blueprints (use relative import to avoid module/package shadowing)
    from .auth import auth_bp
    flask_app.register_blueprint(auth_bp)
    
    # Root route
    @flask_app.route('/')
    def root():
        return redirect(url_for('auth.index'))
    
    return flask_app
