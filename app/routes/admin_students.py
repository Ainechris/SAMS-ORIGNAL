import math
import re
import sqlite3
from datetime import date

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for

from app.database.database import get_connection
from app.services.auth import audit_event, require_role
from app.services.student_portal import create_student_account, issue_activation_code


admin_students_bp = Blueprint("admin_students", __name__, url_prefix="/admin")
STUDENT_ID_PATTERN = re.compile(r"^[A-Z0-9-]{1,50}$")


def _student_form_values():
    student_id = request.form.get("student_id", "").strip().upper()
    full_name = request.form.get("full_name", "").strip()
    level = request.form.get("level", "").strip().upper()
    trade = request.form.get("trade", "").strip()
    class_name = f"{level} - {trade}" if level and trade else ""
    if not STUDENT_ID_PATTERN.fullmatch(student_id):
        raise ValueError("Student ID may contain letters, numbers, and hyphens (up to 50 characters).")
    if not full_name or len(full_name) > 120:
        raise ValueError("Enter a student name (up to 120 characters).")
    if level not in {"L3", "L4", "L5"}:
        raise ValueError("Choose a valid level: L3, L4, or L5.")
    if trade != "Software Development":
        raise ValueError("Choose Software Development as the trade.")
    return student_id, full_name, class_name, level, trade


@admin_students_bp.route("/students")
@require_role("admin")
def list_students():
    query = request.args.get("q", "").strip()[:100]
    selected_class = request.args.get("class", "").strip()[:80]
    try:
        page = max(int(request.args.get("page", "1")), 1)
    except ValueError:
        page = 1
    per_page = 30

    filters = []
    parameters = []
    if query:
        filters.append("(student_id LIKE ? OR full_name LIKE ?)")
        parameters.extend((f"%{query}%", f"%{query}%"))
    if selected_class:
        filters.append("class_name = ?")
        parameters.append(selected_class)
    where = f"WHERE {' AND '.join(filters)}" if filters else ""

    with get_connection() as connection:
        total = connection.execute(
            f"SELECT COUNT(*) FROM students {where}", parameters
        ).fetchone()[0]
        students = connection.execute(
            f"""SELECT id, student_id, full_name, class_name, created_at
                FROM students {where}
                ORDER BY full_name COLLATE NOCASE, student_id
                LIMIT ? OFFSET ?""",
            (*parameters, per_page, (page - 1) * per_page),
        ).fetchall()
        classes = connection.execute(
            "SELECT DISTINCT class_name FROM students ORDER BY class_name COLLATE NOCASE"
        ).fetchall()

    total_pages = max(math.ceil(total / per_page), 1)
    page = min(page, total_pages)
    return render_template(
        "admin/students.html",
        students=students,
        classes=classes,
        query=query,
        selected_class=selected_class,
        page=page,
        total_pages=total_pages,
        total=total,
        previous_url=(url_for("admin_students.list_students", q=query, page=page - 1, **{"class": selected_class}) if page > 1 else None),
        next_url=(url_for("admin_students.list_students", q=query, page=page + 1, **{"class": selected_class}) if page < total_pages else None),
        active_page="students",
        page_title="Students",
        page_subtitle="Search and maintain registered student records.",
    )


@admin_students_bp.route("/students/new", methods=["GET", "POST"])
@require_role("admin")
def create_student():
    if request.method == "POST":
        try:
            student_id, full_name, class_name, level, trade = _student_form_values()
            with get_connection() as connection:
                cursor = connection.execute(
                    """
                    INSERT INTO students (student_id, full_name, class_name, level, trade)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (student_id, full_name, class_name, level, trade),
                )
                create_student_account(connection, cursor.lastrowid, student_id)
                audit_event(
                    connection, "admin", g.current_user["id"], "student_create", "success",
                    f"student_record_id={cursor.lastrowid}; student_id={student_id}",
                )
            flash(f"Student {student_id} was registered.", "success")
            return redirect(url_for("admin_students.list_students"))
        except ValueError as error:
            flash(str(error), "error")
        except sqlite3.IntegrityError:
            flash("That student ID is already registered.", "error")

    return render_template(
        "admin/student_form.html",
        student=None,
        active_page="students",
        page_title="Register student",
        page_subtitle="Add a student to the existing school register.",
    )


@admin_students_bp.route("/students/<int:student_pk>")
@require_role("admin")
def student_detail(student_pk):
    with get_connection() as connection:
        student = connection.execute(
            """SELECT s.id, s.student_id, s.full_name, s.class_name, s.created_at,
                      a.account_status AS portal_status, a.activated_at
               FROM students AS s LEFT JOIN student_accounts AS a ON a.student_pk = s.id
               WHERE s.id = ?""",
            (student_pk,),
        ).fetchone()
        if not student:
            abort(404)
        attendance = connection.execute("""
            SELECT a.attendance_date, a.check_in_time, a.status,
                   gs.session_reference, st.station_name
            FROM attendance AS a
            LEFT JOIN gate_sessions AS gs ON gs.id = a.gate_session_id
            LEFT JOIN gate_stations AS st ON st.id = gs.station_id
            WHERE a.student_id = ?
            ORDER BY a.attendance_date DESC, a.check_in_time DESC
            LIMIT 100
        """, (student["student_id"],)).fetchall()
    return render_template(
        "admin/student_detail.html",
        student=student,
        attendance=attendance,
        active_page="students",
        page_title="Student record",
        page_subtitle="Registered details and recent attendance history.",
    )


@admin_students_bp.route("/students/<int:student_pk>/edit", methods=["GET", "POST"])
@require_role("admin")
def edit_student(student_pk):
    with get_connection() as connection:
        student = connection.execute(
            "SELECT id, student_id, full_name, class_name, level, trade "
            "FROM students WHERE id = ?",
            (student_pk,),
        ).fetchone()
    if not student:
        abort(404)

    if request.method == "POST":
        try:
            student_id, full_name, class_name, level, trade = _student_form_values()
            with get_connection() as connection:
                connection.execute(
                    """UPDATE student_accounts SET username = ?,
                              updated_at = CURRENT_TIMESTAMP WHERE student_pk = ?""",
                    (student_id, student_pk),
                )
                connection.execute(
                    """
                    UPDATE students SET student_id = ?, full_name = ?, class_name = ?, level = ?, trade = ?
                    WHERE id = ?
                    """,
                    (student_id, full_name, class_name, level, trade, student_pk),
                )
                audit_event(
                    connection, "admin", g.current_user["id"], "student_update", "success",
                    f"student_record_id={student_pk}; student_id={student_id}",
                )
            flash("Student record updated.", "success")
            return redirect(url_for("admin_students.student_detail", student_pk=student_pk))
        except ValueError as error:
            flash(str(error), "error")
        except sqlite3.IntegrityError:
            flash("That student ID is already assigned to another student.", "error")

    return render_template(
        "admin/student_form.html",
        student=student,
        active_page="students",
        page_title="Edit student",
        page_subtitle="Update the registered student details.",
    )


@admin_students_bp.post("/students/<int:student_pk>/portal-code")
@require_role("admin")
def issue_student_portal_code(student_pk):
    with get_connection() as connection:
        student = connection.execute(
            "SELECT student_id, full_name FROM students WHERE id = ?", (student_pk,)
        ).fetchone()
        if not student:
            abort(404)
        try:
            code = issue_activation_code(connection, student_pk)
        except ValueError as error:
            flash(str(error), "error")
            return redirect(url_for("admin_students.student_detail", student_pk=student_pk))
        audit_event(
            connection, "admin", g.current_user["id"],
            "student_activation_code_issue", "success",
            f"student_record_id={student_pk}",
        )

    response = render_template(
        "admin/student_activation_code.html",
        student=student,
        student_pk=student_pk,
        activation_code=code,
        active_page="students",
        page_title="Student activation code",
        page_subtitle="Hand this one-time code directly to the student.",
    )
    from flask import make_response
    response = make_response(response)
    response.headers["Cache-Control"] = "no-store"
    return response


@admin_students_bp.route("/attendance")
@require_role("admin")
def attendance_records():
    selected_date = request.args.get("date", date.today().isoformat()).strip()
    if selected_date:
        try:
            date.fromisoformat(selected_date)
        except ValueError:
            selected_date = date.today().isoformat()
            flash("Choose a valid attendance date.", "error")
    query = request.args.get("q", "").strip()[:100]
    selected_class = request.args.get("class", "").strip()[:80]
    session_reference = request.args.get("session", "").strip()[:40]

    filters = []
    parameters = []
    if selected_date:
        filters.append("a.attendance_date = ?")
        parameters.append(selected_date)
    if query:
        filters.append("(s.student_id LIKE ? OR s.full_name LIKE ?)")
        parameters.extend((f"%{query}%", f"%{query}%"))
    if selected_class:
        filters.append("s.class_name = ?")
        parameters.append(selected_class)
    if session_reference:
        filters.append("gs.session_reference = ?")
        parameters.append(session_reference)
    where = f"WHERE {' AND '.join(filters)}" if filters else ""

    with get_connection() as connection:
        records = connection.execute(
            f"""SELECT a.student_id, s.full_name, s.class_name,
                       a.attendance_date, a.check_in_time, a.status,
                       gs.session_reference, st.station_name
                FROM attendance AS a
                JOIN students AS s ON s.student_id = a.student_id
                LEFT JOIN gate_sessions AS gs ON gs.id = a.gate_session_id
                LEFT JOIN gate_stations AS st ON st.id = gs.station_id
                {where}
                ORDER BY a.attendance_date DESC, a.check_in_time DESC
                LIMIT 200""",
            parameters,
        ).fetchall()
        classes = connection.execute(
            "SELECT DISTINCT class_name FROM students ORDER BY class_name COLLATE NOCASE"
        ).fetchall()
        total = connection.execute(
            f"""SELECT COUNT(*) FROM attendance AS a
                JOIN students AS s ON s.student_id = a.student_id
                LEFT JOIN gate_sessions AS gs ON gs.id = a.gate_session_id
                {where}""",
            parameters,
        ).fetchone()[0]

    return render_template(
        "admin/attendance.html",
        records=records,
        classes=classes,
        selected_date=selected_date,
        query=query,
        selected_class=selected_class,
        session_reference=session_reference,
        total=total,
        active_page="attendance",
        page_title="Attendance records",
        page_subtitle="Search and review recorded student check-ins.",
    )
