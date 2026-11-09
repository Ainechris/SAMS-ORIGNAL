import re
import sqlite3

from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from app.database.database import get_connection
from app.services.auth import audit_event, require_role
from app.services.student_portal import create_student_account


registration_bp = Blueprint("registration", __name__)
STUDENT_ID_PATTERN = re.compile(r"^[A-Z0-9-]{1,50}$")


def _registration_is_open(connection):
    row = connection.execute(
        "SELECT is_open FROM student_registration_settings WHERE id = 1"
    ).fetchone()
    return bool(row and row["is_open"])


@registration_bp.route("/register", methods=["GET", "POST"])
def public_registration():
    with get_connection() as connection:
        is_open = _registration_is_open(connection)
        if request.method == "POST":
            if not is_open:
                return render_template("registration/public.html", is_open=False), 403

            # Simple honeypot field to reject basic automated form submissions.
            if request.form.get("website", "").strip():
                return render_template("registration/received.html"), 200

            full_name = request.form.get("full_name", "").strip()
            requested_class = request.form.get("requested_class", "").strip()
            errors = []
            if not full_name or len(full_name) > 120:
                errors.append("Enter the student's full name (up to 120 characters).")
            if not requested_class or len(requested_class) > 80:
                errors.append("Enter the class the student is applying to join (up to 80 characters).")

            if not errors:
                connection.execute(
                    """INSERT INTO student_registration_requests
                       (full_name, requested_class)
                       VALUES (?, ?)""",
                    (full_name, requested_class),
                )
                return render_template("registration/received.html"), 200

            return render_template(
                "registration/public.html",
                is_open=True,
                errors=errors,
                full_name=full_name,
                requested_class=requested_class,
            ), 400

    response = render_template("registration/public.html", is_open=is_open)
    from flask import make_response
    response = make_response(response)
    response.headers["Cache-Control"] = "no-store"
    return response


@registration_bp.route("/admin/registration")
@require_role("admin")
def manage_registration():
    with get_connection() as connection:
        settings = connection.execute(
            "SELECT is_open, updated_at FROM student_registration_settings WHERE id = 1"
        ).fetchone()
        requests = connection.execute(
            """SELECT id, full_name, requested_class, status, submitted_at
               FROM student_registration_requests
               ORDER BY CASE status WHEN 'pending' THEN 0 ELSE 1 END,
                        submitted_at DESC
               LIMIT 200"""
        ).fetchall()
        pending_count = connection.execute(
            "SELECT COUNT(*) FROM student_registration_requests WHERE status = 'pending'"
        ).fetchone()[0]

    return render_template(
        "admin/registration.html",
        settings=settings,
        requests=requests,
        pending_count=pending_count,
        active_page="registration",
        page_title="Student registration",
        page_subtitle="Control public registration and review new-student applications.",
    )


@registration_bp.post("/admin/registration/toggle")
@require_role("admin")
def toggle_registration():
    action = request.form.get("action")
    if action not in {"open", "close"}:
        flash("Choose a valid registration action.", "error")
        return redirect(url_for("registration.manage_registration"))

    is_open = 1 if action == "open" else 0
    with get_connection() as connection:
        connection.execute(
            """UPDATE student_registration_settings
               SET is_open = ?, updated_at = CURRENT_TIMESTAMP, updated_by = ?
               WHERE id = 1""",
            (is_open, g.current_user["id"]),
        )
        audit_event(
            connection, "admin", g.current_user["id"],
            "student_registration_open" if is_open else "student_registration_close",
            "success",
        )

    flash(
        "Public student registration is now open." if is_open
        else "Public student registration has been closed.",
        "success",
    )
    return redirect(url_for("registration.manage_registration"))


@registration_bp.post("/admin/registration/<int:request_id>/approve")
@require_role("admin")
def approve_registration(request_id):
    student_id = request.form.get("student_id", "").strip().upper()
    if not STUDENT_ID_PATTERN.fullmatch(student_id):
        flash("Enter a valid school-assigned student ID (letters, numbers, and hyphens).", "error")
        return redirect(url_for("registration.manage_registration"))

    try:
        with get_connection() as connection:
            application = connection.execute(
                """SELECT id, full_name, requested_class, status
                   FROM student_registration_requests WHERE id = ?""",
                (request_id,),
            ).fetchone()
            if not application:
                flash("That application could not be found.", "error")
                return redirect(url_for("registration.manage_registration"))
            if application["status"] != "pending":
                flash("This application has already been reviewed.", "error")
                return redirect(url_for("registration.manage_registration"))

            cursor = connection.execute(
                """INSERT INTO students (student_id, full_name, class_name)
                   VALUES (?, ?, ?)""",
                (student_id, application["full_name"], application["requested_class"]),
            )
            create_student_account(connection, cursor.lastrowid, student_id)
            connection.execute(
                """UPDATE student_registration_requests
                   SET status = 'approved', reviewed_at = CURRENT_TIMESTAMP,
                       reviewed_by = ?, assigned_student_pk = ?
                   WHERE id = ? AND status = 'pending'""",
                (g.current_user["id"], cursor.lastrowid, request_id),
            )
            audit_event(
                connection, "admin", g.current_user["id"],
                "student_registration_approve", "success",
                f"application_id={request_id}; student_id={student_id}",
            )
        flash(f"Application approved. Student {student_id} was added to SAMS.", "success")
    except sqlite3.IntegrityError:
        flash("That student ID is already in use. Check the ID and try again.", "error")

    return redirect(url_for("registration.manage_registration"))


@registration_bp.post("/admin/registration/<int:request_id>/reject")
@require_role("admin")
def reject_registration(request_id):
    with get_connection() as connection:
        cursor = connection.execute(
            """UPDATE student_registration_requests
               SET status = 'rejected', reviewed_at = CURRENT_TIMESTAMP,
                   reviewed_by = ?
               WHERE id = ? AND status = 'pending'""",
            (g.current_user["id"], request_id),
        )
        if cursor.rowcount:
            audit_event(
                connection, "admin", g.current_user["id"],
                "student_registration_reject", "success",
                f"application_id={request_id}",
            )
            flash("Application marked as rejected.", "success")
        else:
            flash("This pending application could not be found.", "error")
    return redirect(url_for("registration.manage_registration"))
