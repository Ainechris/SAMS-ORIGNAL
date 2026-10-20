
from pathlib import Path

from flask import Flask


def create_app():
    app = Flask(__name__, instance_relative_config=True)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    from app.database.database import initialize_database
    initialize_database()

    from app.routes.main import main_bp
    from app.routes.gate import gate_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(gate_bp)

    return app

from pathlib import Path

from flask import Flask


def create_app():
    app = Flask(__name__, instance_relative_config=True)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    from app.database.database import initialize_database
    initialize_database()

    from app.routes.main import main_bp
    from app.routes.gate import gate_bp
    from app.routes.admin import admin_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(gate_bp)
    app.register_blueprint(admin_bp)

    return app
