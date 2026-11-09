from flask import Blueprint, render_template

from app.database.database import get_connection


main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def home():
    with get_connection() as connection:
        row = connection.execute(
            "SELECT is_open FROM student_registration_settings WHERE id = 1"
        ).fetchone()
    registration_open = bool(row and row["is_open"])
    return render_template("index.html", registration_open=registration_open)



@main_bp.route("/how-it-works")
def how_it_works():
    return render_template("how_it_works.html")
