import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import abort, g, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from app.database.database import get_connection


USER_TABLES = {
    "admin": "administrators",
    "security": "security_users",
    "student": "student_accounts",
}
DUMMY_PASSWORD_HASH = generate_password_hash("not-a-real-sams-password")


def audit_event(connection, actor_type, actor_id, event_type, outcome, details=""):
    connection.execute(
        """
        INSERT INTO audit_logs (actor_type, actor_id, event_type, outcome, details)
        VALUES (?, ?, ?, ?, ?)
        """,
        (actor_type, actor_id, event_type, outcome, details[:500]),
    )


def authenticate(user_type, username, password):
    table = USER_TABLES[user_type]
    normalized_username = username.strip()[:100]
    with get_connection() as connection:
        if user_type == "student":
            user = connection.execute(
                """SELECT a.id, a.username, s.full_name, a.password_hash,
                          a.account_status
                   FROM student_accounts AS a
                   JOIN students AS s ON s.id = a.student_pk
                   WHERE a.username = ?""",
                (normalized_username,),
            ).fetchone()
        else:
            user = connection.execute(
                f"""SELECT id, username, full_name, password_hash, account_status
                    FROM {table} WHERE username = ?""",
                (normalized_username,),
            ).fetchone()

        password_matches = check_password_hash(
            user["password_hash"] if user and user["password_hash"] else DUMMY_PASSWORD_HASH,
            password,
        )
        valid = bool(user and user["account_status"] == "active" and password_matches)
        audit_event(
            connection,
            user_type if user else "anonymous",
            user["id"] if user else None,
            "login",
            "success" if valid else "failure",
            f"username={normalized_username}",
        )
    if not valid:
        return None
    revoke_current_session()
    establish_login(user_type, user["id"])
    return {"id": user["id"], "role": user_type, "username": user["username"]}


def establish_login(user_type, user_id):
    with get_connection() as connection:
        raw_token = new_auth_token(connection, user_type, user_id)
    activate_auth_token(raw_token)


def new_auth_token(connection, user_type, user_id):
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=8)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    connection.execute(
        """
        INSERT INTO auth_sessions (token_hash, user_type, user_id, expires_at)
        VALUES (?, ?, ?, ?)
        """,
        (token_hash, user_type, user_id, expires_at),
    )
    return raw_token


def activate_auth_token(raw_token):
    session.clear()
    session.permanent = True
    session["auth_token"] = raw_token
    session["csrf_token"] = secrets.token_urlsafe(32)


def change_password(user_type, user_id, current_password, new_password):
    if len(new_password) < 12:
        raise ValueError("Use a new password with at least 12 characters.")
    if current_password == new_password:
        raise ValueError("Choose a password different from your current password.")

    table = USER_TABLES[user_type]
    failure = None
    raw_token = None
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        user = connection.execute(
            f"SELECT password_hash FROM {table} WHERE id = ? AND account_status = 'active'",
            (user_id,),
        ).fetchone()
        if not user or not check_password_hash(user["password_hash"], current_password):
            audit_event(
                connection,
                user_type,
                user_id,
                "password_change",
                "failure",
                "reason=incorrect_current_password",
            )
            failure = "Current password is incorrect."
        else:
            connection.execute(
                f"""UPDATE {table}
                    SET password_hash = ?, must_reset_password = 0,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?""",
                (generate_password_hash(new_password), user_id),
            )
            connection.execute(
                """UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP
                   WHERE user_type = ? AND user_id = ? AND revoked_at IS NULL""",
                (user_type, user_id),
            )
            raw_token = new_auth_token(connection, user_type, user_id)
            audit_event(connection, user_type, user_id, "password_change", "success")

    if failure:
        raise ValueError(failure)
    activate_auth_token(raw_token)


def revoke_current_session():
    raw_token = session.get("auth_token")
    if raw_token:
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        with get_connection() as connection:
            connection.execute(
                "UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP "
                "WHERE token_hash = ? AND revoked_at IS NULL",
                (token_hash,),
            )
            user = getattr(g, "current_user", None)
            audit_event(
                connection,
                user["role"] if user else "system",
                user["id"] if user else None,
                "logout",
                "success",
            )
    session.clear()


def load_current_user():
    g.current_user = None
    raw_token = session.get("auth_token")
    if not raw_token:
        return

    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    with get_connection() as connection:
        auth = connection.execute(
            """
            SELECT user_type, user_id
            FROM auth_sessions
            WHERE token_hash = ?
              AND revoked_at IS NULL
              AND expires_at > CURRENT_TIMESTAMP
            """,
            (token_hash,),
        ).fetchone()
        if not auth:
            session.clear()
            return

        if auth["user_type"] == "student":
            user = connection.execute(
                """SELECT a.id, a.username, s.full_name, a.account_status,
                          a.must_reset_password, a.student_pk
                   FROM student_accounts AS a
                   JOIN students AS s ON s.id = a.student_pk
                   WHERE a.id = ?""",
                (auth["user_id"],),
            ).fetchone()
        else:
            table = USER_TABLES[auth["user_type"]]
            user = connection.execute(
                f"""SELECT id, username, full_name, account_status, must_reset_password
                    FROM {table} WHERE id = ?""",
                (auth["user_id"],),
            ).fetchone()
        if not user or user["account_status"] != "active":
            connection.execute(
                "UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP "
                "WHERE token_hash = ? AND revoked_at IS NULL",
                (token_hash,),
            )
            session.clear()
            return

        g.current_user = {
            "id": user["id"],
            "username": user["username"],
            "full_name": user["full_name"],
            "role": auth["user_type"],
            "must_reset_password": bool(user["must_reset_password"]),
        }
        if auth["user_type"] == "student":
            g.current_user["student_pk"] = user["student_pk"]


def require_role(role):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = getattr(g, "current_user", None)
            if not user:
                login_endpoint = {
                    "admin": "admin.login",
                    "security": "security.login",
                    "student": "student.login",
                }[role]
                return redirect(url_for(login_endpoint))
            if user["role"] != role:
                abort(403)
            if user["must_reset_password"] and request.endpoint not in {
                f"{role}.change_own_password",
                f"{role}.logout",
            }:
                return redirect(url_for(f"{role}.change_own_password"))
            return view(*args, **kwargs)

        return wrapped

    return decorator
