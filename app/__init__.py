import os
import secrets
from datetime import timedelta
from hmac import compare_digest

from flask import Flask, abort, g, request, session


def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SAMS_SECRET_KEY"),
        SESSION_COOKIE_NAME="sams_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("SAMS_COOKIE_SECURE") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        SESSION_REFRESH_EACH_REQUEST=False,
        MAX_CONTENT_LENGTH=1024 * 1024,
    )
    if not app.config["SECRET_KEY"]:
        if os.environ.get("SAMS_ENV", "development").lower() == "production":
            raise RuntimeError("Set SAMS_SECRET_KEY before starting SAMS in production.")
        app.config["SECRET_KEY"] = secrets.token_hex(32)
        app.logger.warning(
            "SAMS_SECRET_KEY is not set; using a temporary development-only key."
        )
    if os.environ.get("SAMS_ENV", "development").lower() == "production":
        app.config["SESSION_COOKIE_SECURE"] = True

    from pathlib import Path
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    from app.database.database import initialize_database
    initialize_database()

    from app.services.auth import load_current_user

    @app.before_request
    def protect_requests():
        if request.endpoint == "static":
            return

        if not session.get("csrf_token"):
            session["csrf_token"] = secrets.token_urlsafe(32)

        load_current_user()

        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            submitted_token = request.form.get("csrf_token") or request.headers.get(
                "X-CSRF-Token", ""
            )
            expected_token = session.get("csrf_token", "")
            if not submitted_token or not compare_digest(submitted_token, expected_token):
                abort(400, description="The form expired. Refresh the page and try again.")

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if request.endpoint and (
            request.endpoint.startswith("admin.")
            or request.endpoint.startswith("security.")
            or request.endpoint.startswith("student.")
        ):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.context_processor
    def inject_request_context():
        return {
            "csrf_token": lambda: session.get("csrf_token", ""),
            "current_user": getattr(g, "current_user", None),
        }

    from app.routes.main import main_bp
    from app.routes.gate import gate_bp
    from app.routes.admin import admin_bp
    from app.routes.admin_students import admin_students_bp
    from app.routes.admin_security import admin_security_bp
    from app.routes.security import security_bp
    from app.routes.student import student_bp
    from app.routes.registration import registration_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(gate_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(admin_students_bp)
    app.register_blueprint(admin_security_bp)
    app.register_blueprint(security_bp)
    app.register_blueprint(student_bp)
    app.register_blueprint(registration_bp)

    from app.commands import register_commands
    register_commands(app)

    return app
