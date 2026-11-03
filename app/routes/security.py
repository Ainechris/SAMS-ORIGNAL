from datetime import datetime, timezone
from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for

from app.database.database import get_connection
from app.services.auth import (
    activate_auth_token,
    authenticate,
    change_password,
    require_role,
    revoke_current_session,
)
from app.services.gate_sessions import (
    GateSessionError,
    active_session_attendance_count,
    close_gate_session,
    get_active_gate_session,
    handover_gate_session,
    start_gate_session,
)


security_bp = Blueprint("security", __name__, url_prefix="/security")


@security_bp.route("/password/change", methods=["GET", "POST"])
@require_role("security")
def change_own_password():
    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        if new_password != request.form.get("confirm_password", ""):
            flash("The passwords do not match.", "error")
            return render_template("auth/change_password.html", role="security")
        try:
            change_password(
                "security",
                g.current_user["id"],
                request.form.get("current_password", ""),
                new_password,
            )
            flash("Your password has been updated.", "success")
            return redirect(url_for("security.dashboard"))
        except ValueError as error:
            flash(str(error), "error")
    return render_template("auth/change_password.html", role="security")


@security_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()[:100]
        password = request.form.get("password", "")
        officer = authenticate("security", username, password)
        if officer:
            return redirect(url_for("security.dashboard"))
        flash(
            "Sign-in failed. Check your staff username and password, or contact an administrator.",
            "error",
        )

    return render_template(
        "auth/login.html",
        login_title="Security staff sign in",
        login_role="security",
    )


@security_bp.route("/logout", methods=["POST"])
@require_role("security")
def logout():
    revoke_current_session()
    flash("You have signed out.", "success")
    return redirect(url_for("security.login"))


@security_bp.route("/dashboard")
@require_role("security")
def dashboard():
    with get_connection() as connection:
        active_session = get_active_gate_session(connection)
        total_students = connection.execute(
            "SELECT COUNT(*) FROM students"
        ).fetchone()[0]
        checkins_today = connection.execute("""
            SELECT COUNT(DISTINCT student_id)
            FROM attendance
            WHERE attendance_date = date('now', 'localtime')
              AND status = 'Present'
        """).fetchone()[0]
        recent_attendance = connection.execute("""
            SELECT s.student_id, s.full_name, s.class_name,
                   a.check_in_time, a.status, gs.session_reference
            FROM attendance AS a
            JOIN students AS s ON s.student_id = a.student_id
            LEFT JOIN gate_sessions AS gs ON gs.id = a.gate_session_id
            WHERE a.attendance_date = date('now', 'localtime')
            ORDER BY a.check_in_time DESC
            LIMIT 8
        """).fetchall()
        station_active = connection.execute("""
            SELECT 1 FROM gates AS g
            JOIN gate_stations AS st ON st.gate_id = g.id
            WHERE g.gate_code = 'MAIN' AND g.account_status = 'active'
              AND st.station_code = 'KIOSK-1' AND st.account_status = 'active'
        """).fetchone() is not None
        session_checkins = (
            active_session_attendance_count(connection, active_session["id"])
            if active_session else 0
        )

    is_current_operator = bool(
        active_session
        and active_session["current_operator_id"] == g.current_user["id"]
    )
    session_started_local = None
    session_duration = None
    if active_session:
        started_at = datetime.strptime(
            active_session["started_at"], "%Y-%m-%d %H:%M:%S"
        ).replace(tzinfo=timezone.utc)
        session_started_local = started_at.astimezone().strftime("%H:%M")
        elapsed_minutes = max(
            int((datetime.now(timezone.utc) - started_at).total_seconds() // 60), 0
        )
        session_duration = f"{elapsed_minutes // 60}h {elapsed_minutes % 60}m"

    return render_template(
        "security/dashboard.html",
        active_session=active_session,
        total_students=total_students,
        checkins_today=checkins_today,
        recent_attendance=recent_attendance,
        station_active=station_active,
        session_checkins=session_checkins,
        is_current_operator=is_current_operator,
        session_started_local=session_started_local,
        session_duration=session_duration,
    )


@security_bp.route("/session/start", methods=["POST"])
@require_role("security")
def session_start():
    try:
        reference = start_gate_session(g.current_user["id"])
        flash(f"Gate session {reference} is now active. The student kiosk is open.", "success")
    except GateSessionError as error:
        flash(str(error), "error")
    return redirect(url_for("security.dashboard"))


@security_bp.route("/session/handover", methods=["GET", "POST"])
@require_role("security")
def session_handover():
    with get_connection() as connection:
        active_session = get_active_gate_session(connection)
    if not active_session or active_session["current_operator_id"] != g.current_user["id"]:
        flash("Only the current operator can hand over the active gate session.", "error")
        return redirect(url_for("security.dashboard"))

    if request.method == "POST":
        if request.form.get("accept_handover") != "yes":
            flash("The incoming officer must explicitly accept the handover.", "error")
        else:
            try:
                reference, new_token = handover_gate_session(
                    g.current_user["id"],
                    request.form.get("incoming_staff", ""),
                    request.form.get("incoming_password", ""),
                    session.get("auth_token"),
                )
                activate_auth_token(new_token)
                flash(f"Handover complete. You are now operating session {reference}.", "success")
                return redirect(url_for("security.dashboard"))
            except GateSessionError as error:
                flash(str(error), "error")

    return render_template("security/handover.html", active_session=active_session)


@security_bp.route("/session/close", methods=["GET", "POST"])
@require_role("security")
def session_close():
    with get_connection() as connection:
        active_session = get_active_gate_session(connection)
    if not active_session or active_session["current_operator_id"] != g.current_user["id"]:
        flash("Only the current operator can close the active gate session.", "error")
        return redirect(url_for("security.dashboard"))

    if request.method == "POST":
        if request.form.get("confirm_close") != "yes":
            flash("Confirm that you want to close the gate session.", "error")
        else:
            try:
                reference = close_gate_session(g.current_user["id"])
                flash(
                    f"Session {reference} is closed. The student kiosk is no longer accepting check-ins.",
                    "success",
                )
                return redirect(url_for("security.dashboard"))
            except GateSessionError as error:
                flash(str(error), "error")

    return render_template("security/close_session.html", active_session=active_session)


@security_bp.route("/session/history")
@require_role("security")
def session_history():
    with get_connection() as connection:
        sessions = connection.execute("""
            SELECT gs.id, gs.session_reference, gs.status, gs.started_at,
                   gs.ended_at, g.gate_name, st.station_name,
                   starter.full_name AS started_by_name,
                   closer.full_name AS closed_by_name,
                   (SELECT COUNT(*) FROM attendance AS a
                    WHERE a.gate_session_id = gs.id) AS checkin_count
            FROM gate_sessions AS gs
            JOIN gates AS g ON g.id = gs.gate_id
            JOIN gate_stations AS st ON st.id = gs.station_id
            JOIN security_users AS starter ON starter.id = gs.started_by
            LEFT JOIN security_users AS closer ON closer.id = gs.closed_by
            ORDER BY gs.started_at DESC
            LIMIT 100
        """).fetchall()
        handovers = connection.execute("""
            SELECT h.session_id, h.handover_at, h.status,
                   h.outgoing_operator_id, h.incoming_operator_id,
                   outgoing.full_name AS outgoing_name,
                   incoming.full_name AS incoming_name,
                   gs.session_reference
            FROM gate_handovers AS h
            JOIN security_users AS outgoing ON outgoing.id = h.outgoing_operator_id
            JOIN security_users AS incoming ON incoming.id = h.incoming_operator_id
            JOIN gate_sessions AS gs ON gs.id = h.session_id
            ORDER BY h.handover_at DESC
            LIMIT 100
        """).fetchall()
    return render_template(
        "security/session_history.html",
        sessions=sessions,
        handovers=handovers,
    )
