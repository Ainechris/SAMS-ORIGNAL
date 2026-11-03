import calendar
import sqlite3
from datetime import date, timedelta

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from werkzeug.security import generate_password_hash

from app.database.database import get_connection
from app.services.auth import audit_event, require_role
from app.services.gate_sessions import get_active_gate_session


admin_security_bp = Blueprint("admin_security", __name__, url_prefix="/admin")


@admin_security_bp.route("/security-users")
@require_role("admin")
def list_security_users():
    with get_connection() as connection:
        users = connection.execute("""
            SELECT u.id, u.staff_id, u.username, u.full_name,
                   u.account_status, u.created_at, u.must_reset_password,
                   CASE WHEN gs.id IS NOT NULL THEN 1 ELSE 0 END AS operating_gate
            FROM security_users AS u
            LEFT JOIN gate_sessions AS gs
              ON gs.current_operator_id = u.id AND gs.status = 'active'
            ORDER BY u.full_name COLLATE NOCASE
        """).fetchall()
    return render_template(
        "admin/security_users.html",
        users=users,
        active_page="security",
        page_title="Security staff",
        page_subtitle="Manage individual gate operator accounts and access.",
    )


@admin_security_bp.route("/security-users/new", methods=["GET", "POST"])
@require_role("admin")
def create_security_user():
    if request.method == "POST":
        staff_id = request.form.get("staff_id", "").strip().upper()[:40]
        username = request.form.get("username", "").strip()[:100]
        full_name = request.form.get("full_name", "").strip()[:120]
        password = request.form.get("temporary_password", "")
        errors = []
        if not staff_id or any(character.isspace() for character in staff_id):
            errors.append("Enter a staff ID without spaces.")
        if not username or len(username) > 100:
            errors.append("Enter a username up to 100 characters long.")
        if not full_name:
            errors.append("Enter the staff member’s full name.")
        if len(password) < 12:
            errors.append("Set a temporary password with at least 12 characters.")
        if errors:
            for message in errors:
                flash(message, "error")
        else:
            try:
                with get_connection() as connection:
                    cursor = connection.execute(
                        """
                        INSERT INTO security_users (
                            staff_id, full_name, username, password_hash,
                            must_reset_password
                        ) VALUES (?, ?, ?, ?, 1)
                        """,
                        (staff_id, full_name, username, generate_password_hash(password)),
                    )
                    audit_event(
                        connection,
                        "admin",
                        g.current_user["id"],
                        "security_user_create",
                        "success",
                        f"security_user_id={cursor.lastrowid}; staff_id={staff_id}",
                    )
                flash(
                    f"Security account created for {staff_id}. Give the temporary password to the staff member securely.",
                    "success",
                )
                return redirect(url_for("admin_security.list_security_users"))
            except sqlite3.IntegrityError:
                flash("That staff ID or username is already in use.", "error")

    return render_template(
        "admin/security_user_form.html",
        active_page="security",
        page_title="Add security staff",
        page_subtitle="Create an individual account for a gate operator.",
    )


@admin_security_bp.route("/security-users/<int:user_id>/status", methods=["POST"])
@require_role("admin")
def change_security_status(user_id):
    requested_status = request.form.get("status")
    if requested_status not in {"active", "disabled"}:
        abort(400)
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        user = connection.execute(
            "SELECT id, staff_id, account_status FROM security_users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if not user:
            abort(404)
        active_session = connection.execute(
            """SELECT id FROM gate_sessions
               WHERE status = 'active' AND current_operator_id = ?""",
            (user_id,),
        ).fetchone()
        if requested_status == "disabled" and active_session:
            flash(
                "This officer currently controls the active gate session. Complete a handover or close the session before disabling the account.",
                "error",
            )
        else:
            connection.execute(
                """UPDATE security_users
                   SET account_status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?""",
                (requested_status, user_id),
            )
            if requested_status == "disabled":
                connection.execute(
                    """UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP
                       WHERE user_type = 'security' AND user_id = ? AND revoked_at IS NULL""",
                    (user_id,),
                )
            audit_event(
                connection,
                "admin",
                g.current_user["id"],
                "security_user_status",
                "success",
                f"security_user_id={user_id}; status={requested_status}",
            )
            flash(f"Security account {user['staff_id']} is now {requested_status}.", "success")
    return redirect(url_for("admin_security.list_security_users"))


@admin_security_bp.route("/security-users/<int:user_id>/reset-password", methods=["GET", "POST"])
@require_role("admin")
def reset_security_password(user_id):
    with get_connection() as connection:
        user = connection.execute(
            "SELECT id, staff_id, full_name FROM security_users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if not user:
            abort(404)

    if request.method == "POST":
        password = request.form.get("temporary_password", "")
        if len(password) < 12:
            flash("Temporary password must be at least 12 characters.", "error")
        else:
            with get_connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                active_session = connection.execute(
                    """SELECT id FROM gate_sessions
                       WHERE status = 'active' AND current_operator_id = ?""",
                    (user_id,),
                ).fetchone()
                if active_session:
                    flash(
                        "The officer controls the active gate session. Complete a handover or close it before resetting their password.",
                        "error",
                    )
                else:
                    connection.execute(
                        """UPDATE security_users
                           SET password_hash = ?, must_reset_password = 1,
                               updated_at = CURRENT_TIMESTAMP
                           WHERE id = ?""",
                        (generate_password_hash(password), user_id),
                    )
                    connection.execute(
                        """UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP
                           WHERE user_type = 'security' AND user_id = ? AND revoked_at IS NULL""",
                        (user_id,),
                    )
                    audit_event(
                        connection,
                        "admin",
                        g.current_user["id"],
                        "security_password_reset",
                        "success",
                        f"security_user_id={user_id}; staff_id={user['staff_id']}",
                    )
                    flash(
                        f"Temporary password set for {user['staff_id']}. The officer must change it before accessing gate operations.",
                        "success",
                    )
                    return redirect(url_for("admin_security.list_security_users"))

    return render_template(
        "admin/security_password_reset.html",
        user=user,
        active_page="security",
        page_title="Reset security password",
        page_subtitle="Set a temporary password that the staff member must change.",
    )


@admin_security_bp.route("/gate-sessions")
@require_role("admin")
def gate_sessions():
    with get_connection() as connection:
        sessions = connection.execute("""
            SELECT gs.id, gs.session_reference, gs.status, gs.started_at,
                   gs.ended_at, g.gate_name, st.station_name,
                   starter.full_name AS started_by_name,
                   operator.full_name AS operator_name,
                   operator.staff_id AS operator_staff_id,
                   operator.account_status AS operator_status,
                   closer.full_name AS security_closer,
                   admin_closer.full_name AS admin_closer,
                   recovery.reason AS recovery_reason,
                   (SELECT COUNT(*) FROM attendance AS a
                    WHERE a.gate_session_id = gs.id) AS checkin_count
            FROM gate_sessions AS gs
            JOIN gates AS g ON g.id = gs.gate_id
            JOIN gate_stations AS st ON st.id = gs.station_id
            JOIN security_users AS starter ON starter.id = gs.started_by
            JOIN security_users AS operator ON operator.id = gs.current_operator_id
            LEFT JOIN security_users AS closer ON closer.id = gs.closed_by
            LEFT JOIN gate_session_admin_closures AS recovery ON recovery.session_id = gs.id
            LEFT JOIN administrators AS admin_closer ON admin_closer.id = recovery.admin_id
            ORDER BY gs.started_at DESC
            LIMIT 200
        """).fetchall()
        handovers = connection.execute("""
            SELECT h.handover_at, h.status, gs.session_reference,
                   outgoing.full_name AS outgoing_name,
                   incoming.full_name AS incoming_name
            FROM gate_handovers AS h
            JOIN gate_sessions AS gs ON gs.id = h.session_id
            JOIN security_users AS outgoing ON outgoing.id = h.outgoing_operator_id
            JOIN security_users AS incoming ON incoming.id = h.incoming_operator_id
            ORDER BY h.handover_at DESC
            LIMIT 200
        """).fetchall()
    return render_template(
        "admin/gate_sessions.html",
        sessions=sessions,
        handovers=handovers,
        active_page="sessions",
        page_title="Gate sessions",
        page_subtitle="Monitor the current gate and review shifts, closures, and handovers.",
    )


@admin_security_bp.route("/gate-sessions/<int:session_id>/force-close", methods=["POST"])
@require_role("admin")
def force_close_session(session_id):
    reason = request.form.get("reason", "").strip()[:500]
    if len(reason) < 15:
        flash("Provide a recovery reason of at least 15 characters.", "error")
        return redirect(url_for("admin_security.gate_sessions"))

    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        active = connection.execute(
            """SELECT id, session_reference, current_operator_id
               FROM gate_sessions WHERE id = ? AND status = 'active'""",
            (session_id,),
        ).fetchone()
        if not active:
            flash("That session is no longer active. Refresh the session list.", "error")
        else:
            connection.execute(
                """UPDATE gate_sessions
                   SET status = 'closed', ended_at = CURRENT_TIMESTAMP, closed_by = ?
                   WHERE id = ? AND status = 'active'""",
                (active["current_operator_id"], session_id),
            )
            connection.execute(
                """INSERT INTO gate_session_admin_closures
                   (session_id, admin_id, session_operator_id, reason)
                   VALUES (?, ?, ?, ?)""",
                (session_id, g.current_user["id"], active["current_operator_id"], reason),
            )
            audit_event(
                connection,
                "admin",
                g.current_user["id"],
                "gate_session_admin_close",
                "success",
                f"session_id={session_id}; operator_id={active['current_operator_id']}; reason={reason}",
            )
            flash(
                f"Session {active['session_reference']} was force-closed. The kiosk is no longer accepting check-ins.",
                "success",
            )
    return redirect(url_for("admin_security.gate_sessions"))


@admin_security_bp.route("/reports")
@require_role("admin")
def reports():
    period = request.args.get("period", "day")
    if period not in {"day", "week", "month"}:
        period = "day"
    try:
        anchor = date.fromisoformat(request.args.get("date", date.today().isoformat()))
    except ValueError:
        anchor = date.today()
        flash("Choose a valid report date.", "error")

    if period == "week":
        start_date = anchor - timedelta(days=6)
        end_date = anchor
    elif period == "month":
        start_date = anchor.replace(day=1)
        end_date = anchor.replace(day=calendar.monthrange(anchor.year, anchor.month)[1])
    else:
        start_date = end_date = anchor

    with get_connection() as connection:
        total_students = connection.execute(
            "SELECT COUNT(*) FROM students"
        ).fetchone()[0]
        daily_rows = connection.execute("""
            SELECT attendance_date,
                   COUNT(CASE WHEN status = 'Present' THEN 1 END) AS present_count,
                   COUNT(*) AS checkin_count
            FROM attendance
            WHERE attendance_date BETWEEN ? AND ?
            GROUP BY attendance_date
            ORDER BY attendance_date
        """, (start_date.isoformat(), end_date.isoformat())).fetchall()
        class_rows = connection.execute("""
            SELECT s.class_name,
                   COUNT(CASE WHEN a.status = 'Present' THEN 1 END) AS present_checkins,
                   COUNT(a.id) AS all_checkins
            FROM students AS s
            LEFT JOIN attendance AS a
              ON a.student_id = s.student_id
             AND a.attendance_date BETWEEN ? AND ?
            GROUP BY s.class_name
            ORDER BY s.class_name COLLATE NOCASE
        """, (start_date.isoformat(), end_date.isoformat())).fetchall()

    total_checkins = sum(row["present_count"] for row in daily_rows)
    recorded_days = len(daily_rows)
    daily_rate = None
    if period == "day" and total_students:
        daily_rate = round(total_checkins / total_students * 100, 1)

    return render_template(
        "admin/reports.html",
        period=period,
        anchor=anchor.isoformat(),
        start_date=start_date.isoformat(),
        end_date=end_date.isoformat(),
        total_students=total_students,
        total_checkins=total_checkins,
        recorded_days=recorded_days,
        daily_rate=daily_rate,
        daily_rows=daily_rows,
        class_rows=class_rows,
        active_page="reports",
        page_title="Reports and analytics",
        page_subtitle="Review attendance patterns from recorded school data.",
    )
