import sqlite3

from flask import Blueprint, flash, redirect, render_template, request, url_for

from app.database.database import get_connection
from app.services.auth import audit_event


gate_bp = Blueprint("gate", __name__)


ACTIVE_KIOSK_SESSION_QUERY = """
    SELECT gs.id, gs.session_reference, operator.id AS operator_id
    FROM gate_sessions AS gs
    JOIN gates AS g ON g.id = gs.gate_id
    JOIN gate_stations AS st ON st.id = gs.station_id
    JOIN security_users AS operator ON operator.id = gs.current_operator_id
    WHERE gs.status = 'active'
      AND g.gate_code = 'MAIN' AND g.account_status = 'active'
      AND st.station_code = 'KIOSK-1' AND st.account_status = 'active'
      AND operator.account_status = 'active'
"""


@gate_bp.route("/gate", methods=["GET", "POST"])
def gate():
    if request.method == "POST":
        student_id = request.form.get("student_id", "").strip()[:50]
        if not student_id:
            flash("Enter your student ID to check in.", "error")
            return redirect(url_for("gate.gate"))

        try:
            with get_connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                active_session = connection.execute(ACTIVE_KIOSK_SESSION_QUERY).fetchone()
                if not active_session:
                    flash(
                        "Check-in is currently closed. Please contact the gate supervisor.",
                        "error",
                    )
                    return redirect(url_for("gate.gate"))

                student = connection.execute(
                    "SELECT student_id FROM students WHERE student_id = ? COLLATE NOCASE",
                    (student_id,),
                ).fetchone()
                if not student:
                    audit_event(
                        connection,
                        "security",
                        active_session["operator_id"],
                        "attendance_checkin",
                        "failure",
                        f"session_id={active_session['id']}; reason=unknown_student_id",
                    )
                    flash("Student ID not found. Please check it or ask the gate supervisor.", "error")
                    return redirect(url_for("gate.gate"))

                existing = connection.execute(
                    """
                    SELECT 1 FROM attendance
                    WHERE student_id = ?
                      AND attendance_date = date('now', 'localtime')
                    """,
                    (student["student_id"],),
                ).fetchone()
                if existing:
                    audit_event(
                        connection,
                        "security",
                        active_session["operator_id"],
                        "attendance_checkin",
                        "failure",
                        f"session_id={active_session['id']}; reason=duplicate_checkin",
                    )
                    flash("Your check-in has already been recorded today.", "error")
                    return redirect(url_for("gate.gate"))

                connection.execute(
                    "INSERT INTO attendance (student_id, gate_session_id) VALUES (?, ?)",
                    (student["student_id"], active_session["id"]),
                )
                audit_event(
                    connection,
                    "security",
                    active_session["operator_id"],
                    "attendance_checkin",
                    "success",
                    f"session_id={active_session['id']}",
                )
                flash("Check-in recorded. You’re all set for today.", "success")
        except sqlite3.IntegrityError as error:
            if "attendance.student_id, attendance.attendance_date" in str(error):
                flash("Your check-in has already been recorded today.", "error")
            else:
                flash("We couldn’t complete check-in. Please ask the gate supervisor for help.", "error")
        except sqlite3.Error:
            flash("Check-in is temporarily unavailable. Please ask the gate supervisor for help.", "error")
        return redirect(url_for("gate.gate"))

    try:
        with get_connection() as connection:
            active_session = connection.execute(ACTIVE_KIOSK_SESSION_QUERY).fetchone()
    except sqlite3.Error:
        active_session = None

    return render_template(
        "gate.html",
        gate_open=active_session is not None,
        session_reference=active_session["session_reference"] if active_session else None,
    )
