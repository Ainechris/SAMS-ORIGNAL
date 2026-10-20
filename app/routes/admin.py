
from flask import Blueprint, render_template

from app.database.database import get_connection

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/")
def dashboard():
    with get_connection() as connection:
        total_students = connection.execute(
            "SELECT COUNT(*) FROM students"
        ).fetchone()[0]

        present_today = connection.execute("""
            SELECT COUNT(DISTINCT student_id)
            FROM attendance
            WHERE attendance_date = date('now', 'localtime')
              AND status = 'Present'
        """).fetchone()[0]

        recent_attendance = connection.execute("""
            SELECT
                s.student_id,
                s.full_name,
                s.class_name,
                a.check_in_time,
                a.status
            FROM attendance AS a
            JOIN students AS s ON s.student_id = a.student_id
            WHERE a.attendance_date = date('now', 'localtime')
            ORDER BY a.check_in_time DESC
            LIMIT 8
        """).fetchall()

    return render_template(
        "admin/dashboard.html",
        total_students=total_students,
        present_today=present_today,
        absent_today=max(total_students - present_today, 0),
        attendance_rate=round(
            present_today / total_students * 100, 1
        ) if total_students else 0,
        recent_attendance=recent_attendance,
    )
