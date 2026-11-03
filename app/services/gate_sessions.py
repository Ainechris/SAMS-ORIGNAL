import hashlib
import secrets

from werkzeug.security import check_password_hash

from app.database.database import get_connection
from app.services.auth import (
    DUMMY_PASSWORD_HASH,
    audit_event,
    new_auth_token,
)


class GateSessionError(Exception):
    pass


ACTIVE_SESSION_QUERY = """
    SELECT
        gs.id,
        gs.session_reference,
        gs.gate_id,
        gs.station_id,
        gs.status,
        gs.started_by,
        gs.current_operator_id,
        gs.started_at,
        gs.ended_at,
        g.gate_name,
        g.account_status AS gate_status,
        st.station_code,
        st.station_name,
        st.account_status AS station_status,
        current.full_name AS current_operator_name,
        current.staff_id AS current_operator_staff_id,
        current.account_status AS operator_status
    FROM gate_sessions AS gs
    JOIN gates AS g ON g.id = gs.gate_id
    JOIN gate_stations AS st ON st.id = gs.station_id
    JOIN security_users AS current ON current.id = gs.current_operator_id
    WHERE gs.gate_id = (SELECT id FROM gates WHERE gate_code = 'MAIN')
      AND gs.status = 'active'
"""


def get_active_gate_session(connection):
    return connection.execute(ACTIVE_SESSION_QUERY).fetchone()


def start_gate_session(operator_id):
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        operator = connection.execute(
            "SELECT id FROM security_users "
            "WHERE id = ? AND account_status = 'active'",
            (operator_id,),
        ).fetchone()
        if not operator:
            raise GateSessionError("Your security account is not active.")

        active = get_active_gate_session(connection)
        if active:
            raise GateSessionError(
                f"An active gate session is already controlled by "
                f"{active['current_operator_name']}."
            )

        station = connection.execute(
            """
            SELECT g.id AS gate_id, st.id AS station_id
            FROM gates AS g
            JOIN gate_stations AS st ON st.gate_id = g.id
            WHERE g.gate_code = 'MAIN'
              AND g.account_status = 'active'
              AND st.station_code = 'KIOSK-1'
              AND st.account_status = 'active'
            """
        ).fetchone()
        if not station:
            raise GateSessionError("The main gate station is disabled. Contact an administrator.")

        reference = "GS-" + secrets.token_hex(6).upper()
        cursor = connection.execute(
            """
            INSERT INTO gate_sessions (
                session_reference, gate_id, station_id, started_by, current_operator_id
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (reference, station["gate_id"], station["station_id"], operator_id, operator_id),
        )
        audit_event(
            connection,
            "security",
            operator_id,
            "gate_session_start",
            "success",
            f"session_id={cursor.lastrowid}; reference={reference}",
        )
        return reference


def close_gate_session(operator_id):
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        active = get_active_gate_session(connection)
        if not active:
            raise GateSessionError("There is no active gate session to close.")
        if active["current_operator_id"] != operator_id:
            raise GateSessionError(
                "Only the current gate operator can close this session."
            )

        cursor = connection.execute(
            """
            UPDATE gate_sessions
            SET status = 'closed', ended_at = CURRENT_TIMESTAMP, closed_by = ?
            WHERE id = ? AND current_operator_id = ? AND status = 'active'
            """,
            (operator_id, active["id"], operator_id),
        )
        if cursor.rowcount != 1:
            raise GateSessionError("The gate session changed before it could be closed. Refresh and try again.")
        audit_event(
            connection,
            "security",
            operator_id,
            "gate_session_close",
            "success",
            f"session_id={active['id']}; reference={active['session_reference']}",
        )
        return active["session_reference"]


def handover_gate_session(
    outgoing_operator_id,
    incoming_identifier,
    incoming_password,
    current_auth_token,
):
    incoming_identifier = incoming_identifier.strip()[:100]
    failure = None
    new_token = None
    active = None

    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        active = get_active_gate_session(connection)
        if not active:
            failure = "There is no active gate session to hand over."
        elif active["current_operator_id"] != outgoing_operator_id:
            failure = "Only the current gate operator can hand over this session."

        incoming = None
        if not failure:
            incoming = connection.execute(
                """
                SELECT id, username, password_hash, account_status, must_reset_password
                FROM security_users
                WHERE username = ? COLLATE NOCASE
                """,
                (incoming_identifier,),
            ).fetchone()
            if not incoming:
                incoming = connection.execute(
                    """
                    SELECT id, username, password_hash, account_status, must_reset_password
                    FROM security_users
                    WHERE staff_id = ? COLLATE NOCASE
                    """,
                    (incoming_identifier,),
                ).fetchone()

            password_matches = check_password_hash(
                incoming["password_hash"] if incoming else DUMMY_PASSWORD_HASH,
                incoming_password,
            )
            if (
                not incoming
                or incoming["account_status"] != "active"
                or incoming["must_reset_password"]
                or not password_matches
                or incoming["id"] == outgoing_operator_id
            ):
                failure = "The incoming officer could not be authenticated. Check the staff ID and password, and make sure any temporary password has been changed before handover."

        if failure:
            audit_event(
                connection,
                "security",
                outgoing_operator_id,
                "gate_handover",
                "failure",
                f"session_id={active['id'] if active else 'none'}; reason={failure}",
            )
        else:
            cursor = connection.execute(
                """
                UPDATE gate_sessions
                SET current_operator_id = ?
                WHERE id = ? AND current_operator_id = ? AND status = 'active'
                """,
                (incoming["id"], active["id"], outgoing_operator_id),
            )
            if cursor.rowcount != 1:
                failure = "The session changed before handover completed. Refresh and try again."
                audit_event(
                    connection,
                    "security",
                    outgoing_operator_id,
                    "gate_handover",
                    "failure",
                    f"session_id={active['id']}; reason=session_changed",
                )
            else:
                connection.execute(
                    """
                    INSERT INTO gate_handovers (
                        session_id, outgoing_operator_id, incoming_operator_id
                    ) VALUES (?, ?, ?)
                    """,
                    (active["id"], outgoing_operator_id, incoming["id"]),
                )
                if current_auth_token:
                    token_hash = hashlib.sha256(current_auth_token.encode("utf-8")).hexdigest()
                    connection.execute(
                        "UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP "
                        "WHERE token_hash = ? AND revoked_at IS NULL",
                        (token_hash,),
                    )
                new_token = new_auth_token(connection, "security", incoming["id"])
                audit_event(
                    connection,
                    "security",
                    outgoing_operator_id,
                    "gate_handover",
                    "success",
                    f"session_id={active['id']}; incoming_user_id={incoming['id']}",
                )
                audit_event(
                    connection,
                    "security",
                    incoming["id"],
                    "handover_accepted",
                    "success",
                    f"session_id={active['id']}; outgoing_user_id={outgoing_operator_id}",
                )

    if failure:
        raise GateSessionError(failure)
    return active["session_reference"], new_token


def active_session_attendance_count(connection, session_id):
    return connection.execute(
        "SELECT COUNT(*) FROM attendance WHERE gate_session_id = ?",
        (session_id,),
    ).fetchone()[0]
