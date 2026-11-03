from datetime import date, datetime, timezone

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from app.database.database import get_connection
from app.services.auth import authenticate, change_password, require_role, revoke_current_session


student_bp = Blueprint("student", __name__, url_prefix="/student")


@student_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        student_id = request.form.get("student_id", "").strip().upper()[:50]
        password = request.form.get("password", "")
        user = authenticate("student", student_id, password)
        if user:
            return redirect(url_for("student.dashboard"))
        flash("We couldn’t sign you in. Check your student ID and password, or activate your account first.", "error")
    return render_template("auth/login.html", login_role="student", login_title="Student portal sign in")


@student_bp.route("/activate", methods=["GET", "POST"])
def activate():
    if request.method == "POST":
        student_id = request.form.get("student_id", "").strip().upper()[:50]
        code = request.form.get("activation_code", "").strip().upper()[:40]
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if len(password) < 12:
            flash("Choose a password with at least 12 characters.", "error")
        elif password != confirm:
            flash("The passwords do not match.", "error")
        else:
            result = None
            with get_connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                account = connection.execute(
                    """SELECT a.id, a.activation_code_hash, a.activation_expires_at,
                              a.activation_attempts, a.account_status, s.id AS student_pk
                       FROM student_accounts AS a
                       JOIN students AS s ON s.id = a.student_pk
                       WHERE a.username = ?""",
                    (student_id,),
                ).fetchone()
                valid = bool(
                    account
                    and account["account_status"] == "pending"
                    and account["activation_code_hash"]
                    and account["activation_attempts"] < 10
                    and account["activation_expires_at"]
                    and account["activation_expires_at"] > datetime.now(timezone.utc).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    and check_password_hash(account["activation_code_hash"], code)
                )
                if valid:
                    connection.execute(
                        """UPDATE student_accounts
                           SET password_hash = ?, account_status = 'active',
                               activation_code_hash = NULL, activation_expires_at = NULL,
                               activation_attempts = 0, activated_at = CURRENT_TIMESTAMP,
                               updated_at = CURRENT_TIMESTAMP
                           WHERE id = ? AND account_status = 'pending'""",
                        (generate_password_hash(password), account["id"]),
                    )
                    result = "success"
                    actor_id = account["id"]
                else:
                    if account and account["account_status"] == "pending":
                        connection.execute(
                            """UPDATE student_accounts SET activation_attempts = MIN(activation_attempts + 1, 10),
                                      updated_at = CURRENT_TIMESTAMP WHERE id = ?""",
                            (account["id"],),
                        )
                    result = "failure"
                    actor_id = account["id"] if account else None
                connection.execute(
                    """INSERT INTO audit_logs
                       (actor_type, actor_id, event_type, outcome, details)
                       VALUES ('student', ?, 'student_activation', ?, ?)""",
                    (actor_id, result, "activation_success" if result == "success" else "activation_failed"),
                )
            if result == "success":
                flash("Your account is ready. Sign in with your student ID and new password.", "success")
                return redirect(url_for("student.login"))
            flash("The student ID or activation code is invalid, expired, or locked. Ask an administrator for help.", "error")
    return render_template("student/activate.html")


@student_bp.post("/logout")
@require_role("student")
def logout():
    revoke_current_session()
    flash("You have signed out.", "success")
    return redirect(url_for("student.login"))


@student_bp.route("/dashboard")
@require_role("student")
def dashboard():
    with get_connection() as connection:
        student = connection.execute(
            "SELECT id, student_id, full_name, class_name FROM students WHERE id = ?",
            (g.current_user["student_pk"],),
        ).fetchone()
        if not student:
            abort(404)
        records = connection.execute(
            """SELECT attendance_date, check_in_time, status FROM attendance
               WHERE student_id = ? ORDER BY attendance_date DESC, check_in_time DESC
               LIMIT 100""",
            (student["student_id"],),
        ).fetchall()
        total = connection.execute(
            "SELECT COUNT(*) FROM attendance WHERE student_id = ?",
            (student["student_id"],),
        ).fetchone()[0]
        this_month = connection.execute(
            """SELECT COUNT(*) FROM attendance WHERE student_id = ?
               AND substr(attendance_date, 1, 7) = ?""",
            (student["student_id"], date.today().strftime("%Y-%m")),
        ).fetchone()[0]
    return render_template(
        "student/dashboard.html", student=student, records=records,
        total=total, this_month=this_month,
    )


@student_bp.route("/password/change", methods=["GET", "POST"])
@require_role("student")
def change_own_password():
    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        if new_password != request.form.get("confirm_password", ""):
            flash("The passwords do not match.", "error")
            return render_template("auth/change_password.html", role="student")
        try:
            change_password(
                "student", g.current_user["id"],
                request.form.get("current_password", ""),
                new_password,
            )
            flash("Your password has been updated.", "success")
            return redirect(url_for("student.dashboard"))
        except ValueError as error:
            flash(str(error), "error")
    return render_template("auth/change_password.html", role="student")
