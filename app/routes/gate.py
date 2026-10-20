
import sqlite3

from flask import Blueprint, render_template, request

from app.database.database import get_connection

gate_bp = Blueprint("gate", __name__)


@gate_bp.route("/gate", methods=["GET", "POST"])
def gate():
    message = ""
    message_type = ""

    if request.method == "POST":
        student_id = request.form.get("student_id", "").strip()

        if not student_id:
            message = "Please enter your student ID."
            message_type = "error"

        else:
            try:
                with get_connection() as connection:
                    student = connection.execute(
                        """
                        SELECT *
                        FROM students
                        WHERE student_id = ?
                        """,
                        (student_id,),
                    ).fetchone()

                    if student is None:
                        message = (
                            "Student ID not found. "
                            "Please check your ID or ask the supervisor."
                        )
                        message_type = "error"

                    else:
                        try:
                            connection.execute(
                                """
                                INSERT INTO attendance (student_id)
                                VALUES (?)
                                """,
                                (student_id,),
                            )

                            message = (
                                f"Welcome, {student['full_name']}! "
                                "Your attendance has been recorded."
                            )
                            message_type = "success"

                        except sqlite3.IntegrityError as error:
                            if "UNIQUE constraint failed" in str(error):
                                message = (
                                    "Your attendance has already been "
                                    "recorded for today."
                                )
                                message_type = "error"
                            else:
                                raise

            except sqlite3.Error:
                message = (
                    "We couldn't process your check-in right now. "
                    "Please ask the gate supervisor for help."
                )
                message_type = "error"

    return render_template(
        "gate.html",
        message=message,
        message_type=message_type,
    )
