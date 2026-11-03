from datetime import date

from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from app.database.database import get_connection
from app.services.auth import (
    authenticate,
    change_password,
    require_role,
    revoke_current_session,
)
from app.services.gate_sessions import get_active_gate_session


admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()[:100]
        password = request.form.get("password", "")
        if authenticate("admin", username, password):
            return redirect(url_for("admin.dashboard"))
        flash(
            "Sign-in failed. Check your username and password, or contact your administrator.",
            "error",
        )

    return render_template(
        "auth/login.html",
        login_title="Administrator sign in",
        login_role="admin",
    )


@admin_bp.route("/logout", methods=["POST"])
@require_role("admin")
def logout():
    revoke_current_session()
    flash("You have signed out.", "success")
    return redirect(url_for("admin.login"))


@admin_bp.route("/password/change", methods=["GET", "POST"])
@require_role("admin")
def change_own_password():
    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        if new_password != request.form.get("confirm_password", ""):
            flash("The passwords do not match.", "error")
            return render_template("auth/change_password.html", role="admin")
        try:
            change_password(
                "admin",
                g.current_user["id"],
                request.form.get("current_password", ""),
                new_password,
            )
            flash("Your password has been updated.", "success")
            return redirect(url_for("admin.dashboard"))
        except ValueError as error:
            flash(str(error), "error")
    return render_template("auth/change_password.html", role="admin")


@admin_bp.route("/")
@require_role("admin")
def dashboard():
    today = date.today()
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
        current_gate_session = get_active_gate_session(connection)
        recent_gate_sessions = connection.execute("""
            SELECT gs.session_reference, gs.status, gs.started_at, gs.ended_at,
                   g.gate_name, st.station_name,
                   starter.full_name AS started_by_name,
                   current.full_name AS current_operator_name,
                   current.account_status AS current_operator_status,
                   closer.full_name AS closed_by_name
            FROM gate_sessions AS gs
            JOIN gates AS g ON g.id = gs.gate_id
            JOIN gate_stations AS st ON st.id = gs.station_id
            JOIN security_users AS starter ON starter.id = gs.started_by
            JOIN security_users AS current ON current.id = gs.current_operator_id
            LEFT JOIN security_users AS closer ON closer.id = gs.closed_by
            ORDER BY gs.started_at DESC
            LIMIT 5
        """).fetchall()
        gate_station = connection.execute("""
            SELECT g.account_status AS gate_status, st.account_status AS station_status
            FROM gates AS g JOIN gate_stations AS st ON st.gate_id = g.id
            WHERE g.gate_code = 'MAIN' AND st.station_code = 'KIOSK-1'
        """).fetchone()

    rate_ratio = present_today / total_students if total_students else None
    attendance_rate = round(rate_ratio * 100, 1) if rate_ratio is not None else None
    rate_tone = (
        "neutral" if not total_students
        else "excellent" if rate_ratio >= 0.9
        else "moderate" if rate_ratio >= 0.75
        else "attention"
    )
    rate_label = (
        "No data" if not total_students
        else "Excellent" if rate_ratio >= 0.9
        else "Moderate" if rate_ratio >= 0.75
        else "Needs attention"
    )
    operational_alerts = []
    if not current_gate_session:
        operational_alerts.append(
            "No gate session is active. The student kiosk is not accepting check-ins."
        )
    elif current_gate_session["operator_status"] != "active":
        operational_alerts.append(
            "The current operator account is disabled. Kiosk check-ins are paused."
        )
    if not gate_station or gate_station["gate_status"] != "active" or gate_station["station_status"] != "active":
        operational_alerts.append("The Main Gate kiosk is disabled.")

    return render_template(
        "admin/dashboard.html",
        total_students=total_students,
        present_today=present_today,
        attendance_rate=attendance_rate,
        not_checked_in=max(total_students - present_today, 0),
        rate_tone=rate_tone,
        rate_label=rate_label,
        today_iso=today.isoformat(),
        today_label=f"{today:%A}, {today:%B} {today.day}, {today:%Y}",
        recent_attendance=recent_attendance,
        current_gate_session=current_gate_session,
        recent_gate_sessions=recent_gate_sessions,
        operational_alerts=operational_alerts,
        active_page="dashboard",
    )
