import secrets
from datetime import datetime, timedelta, timezone

from werkzeug.security import generate_password_hash


def create_student_account(connection, student_pk, student_id):
    """Provision a pending portal account in the student registration transaction."""
    connection.execute(
        """INSERT INTO student_accounts (student_pk, username)
           VALUES (?, ?)""",
        (student_pk, student_id),
    )


def issue_activation_code(connection, student_pk):
    account = connection.execute(
        """SELECT id, account_status FROM student_accounts
           WHERE student_pk = ?""",
        (student_pk,),
    ).fetchone()
    if not account:
        raise ValueError("This student does not have a portal account yet.")
    if account["account_status"] != "pending":
        raise ValueError("This portal account has already been activated.")

    code = secrets.token_hex(6).upper()
    expires = (datetime.now(timezone.utc) + timedelta(days=14)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    connection.execute(
        """UPDATE student_accounts
           SET activation_code_hash = ?, activation_expires_at = ?,
               activation_attempts = 0,
               updated_at = CURRENT_TIMESTAMP
           WHERE id = ?""",
        (generate_password_hash(code), expires, account["id"]),
    )
    return code
