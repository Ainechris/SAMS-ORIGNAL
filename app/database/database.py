import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


DATABASE_PATH = Path(__file__).resolve().parents[2] / "instance" / "sams.db"
SCHEMA_VERSION = 5


@contextmanager
def get_connection():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 15000")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _table_exists(connection, table_name):
    return connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone() is not None


def _backup_before_migration(connection):
    """Create a consistent SQLite backup before applying schema changes."""
    backup_time = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup_path = DATABASE_PATH.with_name(f"sams.db.backup-{backup_time}")
    backup_connection = sqlite3.connect(backup_path)
    try:
        connection.backup(backup_connection)
    finally:
        backup_connection.close()
    return backup_path


def _apply_initial_schema(connection):
    connection.execute("""
        CREATE TABLE IF NOT EXISTS administrators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL COLLATE NOCASE UNIQUE,
            full_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            account_status TEXT NOT NULL DEFAULT 'active'
                CHECK (account_status IN ('active', 'disabled')),
            must_reset_password INTEGER NOT NULL DEFAULT 0
                CHECK (must_reset_password IN (0, 1)),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS security_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            staff_id TEXT NOT NULL COLLATE NOCASE UNIQUE,
            full_name TEXT NOT NULL,
            username TEXT NOT NULL COLLATE NOCASE UNIQUE,
            password_hash TEXT NOT NULL,
            account_status TEXT NOT NULL DEFAULT 'active'
                CHECK (account_status IN ('active', 'disabled')),
            must_reset_password INTEGER NOT NULL DEFAULT 0
                CHECK (must_reset_password IN (0, 1)),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS gates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            gate_code TEXT NOT NULL COLLATE NOCASE UNIQUE,
            gate_name TEXT NOT NULL,
            account_status TEXT NOT NULL DEFAULT 'active'
                CHECK (account_status IN ('active', 'disabled')),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS gate_stations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            gate_id INTEGER NOT NULL,
            station_code TEXT NOT NULL COLLATE NOCASE UNIQUE,
            station_name TEXT NOT NULL,
            account_status TEXT NOT NULL DEFAULT 'active'
                CHECK (account_status IN ('active', 'disabled')),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (id, gate_id),
            FOREIGN KEY (gate_id) REFERENCES gates(id)
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS gate_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_reference TEXT NOT NULL UNIQUE,
            gate_id INTEGER NOT NULL,
            station_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'closed')),
            started_by INTEGER NOT NULL,
            current_operator_id INTEGER NOT NULL,
            started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            ended_at TEXT,
            closed_by INTEGER,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CHECK (
                (status = 'active' AND ended_at IS NULL AND closed_by IS NULL)
                OR
                (status = 'closed' AND ended_at IS NOT NULL AND closed_by IS NOT NULL)
            ),
            FOREIGN KEY (gate_id) REFERENCES gates(id),
            FOREIGN KEY (station_id, gate_id)
                REFERENCES gate_stations(id, gate_id),
            FOREIGN KEY (started_by) REFERENCES security_users(id),
            FOREIGN KEY (current_operator_id) REFERENCES security_users(id),
            FOREIGN KEY (closed_by) REFERENCES security_users(id)
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS gate_handovers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            outgoing_operator_id INTEGER NOT NULL,
            incoming_operator_id INTEGER NOT NULL,
            handover_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            status TEXT NOT NULL DEFAULT 'accepted'
                CHECK (status IN ('accepted')),
            FOREIGN KEY (session_id) REFERENCES gate_sessions(id),
            FOREIGN KEY (outgoing_operator_id) REFERENCES security_users(id),
            FOREIGN KEY (incoming_operator_id) REFERENCES security_users(id),
            CHECK (outgoing_operator_id != incoming_operator_id)
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS auth_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash TEXT NOT NULL UNIQUE,
            user_type TEXT NOT NULL CHECK (user_type IN ('admin', 'security')),
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT NOT NULL,
            revoked_at TEXT
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_type TEXT NOT NULL
                CHECK (actor_type IN ('admin', 'security', 'system', 'anonymous')),
            actor_id INTEGER,
            event_type TEXT NOT NULL,
            outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
            details TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_gate_sessions_history
        ON gate_sessions(gate_id, started_at DESC)
    """)
    connection.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_gate_sessions_one_active_per_gate
        ON gate_sessions(gate_id) WHERE status = 'active'
    """)
    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_gate_handovers_session
        ON gate_handovers(session_id, handover_at DESC)
    """)
    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_logs_created
        ON audit_logs(created_at DESC)
    """)
    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_auth_sessions_user
        ON auth_sessions(user_type, user_id, expires_at)
    """)

    attendance_columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(attendance)")
    }
    if "gate_session_id" not in attendance_columns:
        connection.execute("""
            ALTER TABLE attendance
            ADD COLUMN gate_session_id INTEGER
                REFERENCES gate_sessions(id)
        """)
    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_attendance_gate_session
        ON attendance(gate_session_id)
    """)

    connection.execute("""
        INSERT INTO gates (gate_code, gate_name)
        VALUES ('MAIN', 'Main Gate')
        ON CONFLICT(gate_code) DO NOTHING
    """)
    gate = connection.execute(
        "SELECT id FROM gates WHERE gate_code = 'MAIN'"
    ).fetchone()
    connection.execute("""
        INSERT INTO gate_stations (gate_id, station_code, station_name)
        VALUES (?, 'KIOSK-1', 'Main Gate Kiosk')
        ON CONFLICT(station_code) DO NOTHING
    """, (gate["id"],))


def _apply_admin_recovery_schema(connection):
    connection.execute("""
        CREATE TABLE IF NOT EXISTS gate_session_admin_closures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL UNIQUE,
            admin_id INTEGER NOT NULL,
            session_operator_id INTEGER NOT NULL,
            reason TEXT NOT NULL,
            closed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (session_id) REFERENCES gate_sessions(id),
            FOREIGN KEY (admin_id) REFERENCES administrators(id),
            FOREIGN KEY (session_operator_id) REFERENCES security_users(id)
        )
    """)
    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_admin_session_closures_admin
        ON gate_session_admin_closures(admin_id, closed_at DESC)
    """)


def _apply_student_portal_schema(connection):
    # The stable numeric student row key survives changes to a student's public ID.
    connection.execute("""
        CREATE TABLE IF NOT EXISTS student_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_pk INTEGER NOT NULL UNIQUE,
            username TEXT NOT NULL COLLATE NOCASE UNIQUE,
            password_hash TEXT,
            activation_code_hash TEXT,
            activation_expires_at TEXT,
            activation_attempts INTEGER NOT NULL DEFAULT 0,
            account_status TEXT NOT NULL DEFAULT 'pending'
                CHECK (account_status IN ('pending', 'active', 'disabled')),
            must_reset_password INTEGER NOT NULL DEFAULT 0
                CHECK (must_reset_password IN (0, 1)),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            activated_at TEXT,
            FOREIGN KEY (student_pk) REFERENCES students(id) ON DELETE CASCADE,
            CHECK (
                (account_status = 'pending' AND password_hash IS NULL)
                OR (account_status IN ('active', 'disabled') AND password_hash IS NOT NULL)
            )
        )
    """)
    connection.execute("""
        INSERT OR IGNORE INTO student_accounts (student_pk, username)
        SELECT id, student_id FROM students
    """)
    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_student_accounts_activation
        ON student_accounts(account_status, activation_expires_at)
    """)

    # Extend the accepted role values while preserving every existing session and audit row.
    connection.execute("""
        CREATE TABLE auth_sessions_v3 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash TEXT NOT NULL UNIQUE,
            user_type TEXT NOT NULL CHECK (user_type IN ('admin', 'security', 'student')),
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT NOT NULL,
            revoked_at TEXT
        )
    """)
    connection.execute("""
        INSERT INTO auth_sessions_v3
        SELECT id, token_hash, user_type, user_id, created_at, expires_at, revoked_at
        FROM auth_sessions
    """)
    connection.execute("DROP TABLE auth_sessions")
    connection.execute("ALTER TABLE auth_sessions_v3 RENAME TO auth_sessions")
    connection.execute("""
        CREATE INDEX idx_auth_sessions_user
        ON auth_sessions(user_type, user_id, expires_at)
    """)

    connection.execute("""
        CREATE TABLE audit_logs_v3 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_type TEXT NOT NULL
                CHECK (actor_type IN ('admin', 'security', 'student', 'system', 'anonymous')),
            actor_id INTEGER,
            event_type TEXT NOT NULL,
            outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
            details TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    connection.execute("""
        INSERT INTO audit_logs_v3
        SELECT id, actor_type, actor_id, event_type, outcome, details, created_at
        FROM audit_logs
    """)
    connection.execute("DROP TABLE audit_logs")
    connection.execute("ALTER TABLE audit_logs_v3 RENAME TO audit_logs")
    connection.execute("""
        CREATE INDEX idx_audit_logs_created ON audit_logs(created_at DESC)
    """)



def _apply_student_registration_schema(connection):
    connection.execute("""
        CREATE TABLE IF NOT EXISTS student_registration_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            is_open INTEGER NOT NULL DEFAULT 0 CHECK (is_open IN (0, 1)),
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_by INTEGER,
            FOREIGN KEY (updated_by) REFERENCES administrators(id)
        )
    """)
    connection.execute("""
        INSERT OR IGNORE INTO student_registration_settings (id, is_open)
        VALUES (1, 0)
    """)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS student_registration_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            requested_class TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'approved', 'rejected')),
            submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            reviewed_at TEXT,
            reviewed_by INTEGER,
            assigned_student_pk INTEGER,
            FOREIGN KEY (reviewed_by) REFERENCES administrators(id),
            FOREIGN KEY (assigned_student_pk) REFERENCES students(id)
        )
    """)
    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_student_registration_status
        ON student_registration_requests(status, submitted_at DESC)
    """)



def _apply_student_level_trade_schema(connection):
    student_columns = {row["name"] for row in connection.execute("PRAGMA table_info(students)")}
    if "level" not in student_columns:
        connection.execute("ALTER TABLE students ADD COLUMN level TEXT")
    if "trade" not in student_columns:
        connection.execute("ALTER TABLE students ADD COLUMN trade TEXT")

    request_columns = {row["name"] for row in connection.execute("PRAGMA table_info(student_registration_requests)")}
    if "requested_level" not in request_columns:
        connection.execute("ALTER TABLE student_registration_requests ADD COLUMN requested_level TEXT")
    if "requested_trade" not in request_columns:
        connection.execute("ALTER TABLE student_registration_requests ADD COLUMN requested_trade TEXT")

    # Preserve old records and identify the level/trade where the old class text allows it.
    connection.execute("""
        UPDATE students
        SET level = UPPER(SUBSTR(TRIM(class_name), 1, 2)),
            trade = 'Software Development'
        WHERE level IS NULL
          AND UPPER(TRIM(class_name)) GLOB 'L[345]*'
          AND UPPER(class_name) LIKE '%SWD%'
    """)
    connection.execute("""
        UPDATE student_registration_requests
        SET requested_level = UPPER(SUBSTR(TRIM(requested_class), 1, 2)),
            requested_trade = 'Software Development'
        WHERE requested_level IS NULL
          AND UPPER(TRIM(requested_class)) GLOB 'L[345]*'
          AND UPPER(requested_class) LIKE '%SWD%'
    """)


def initialize_database():
    with get_connection() as connection:
        if not _table_exists(connection, "students"):
            connection.execute("""
                CREATE TABLE students (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    student_id TEXT NOT NULL UNIQUE,
                    full_name TEXT NOT NULL,
                    class_name TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
        if not _table_exists(connection, "attendance"):
            connection.execute("""
                CREATE TABLE attendance (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    student_id TEXT NOT NULL,
                    attendance_date TEXT NOT NULL DEFAULT (date('now', 'localtime')),
                    check_in_time TEXT NOT NULL DEFAULT (time('now', 'localtime')),
                    status TEXT NOT NULL DEFAULT 'Present',
                    FOREIGN KEY (student_id) REFERENCES students(student_id),
                    UNIQUE (student_id, attendance_date)
                )
            """)

        if not _table_exists(connection, "schema_migrations"):
            has_existing_data = connection.execute(
                "SELECT EXISTS(SELECT 1 FROM students) "
                "OR EXISTS(SELECT 1 FROM attendance)"
            ).fetchone()[0]
            if has_existing_data:
                _backup_before_migration(connection)
            connection.execute("""
                CREATE TABLE schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)

        applied = connection.execute(
            "SELECT MAX(version) FROM schema_migrations"
        ).fetchone()[0] or 0
        while applied < SCHEMA_VERSION:
            next_version = applied + 1
            if next_version > 1:
                _backup_before_migration(connection)
            connection.execute("BEGIN IMMEDIATE")
            if next_version == 1:
                _apply_initial_schema(connection)
            elif next_version == 2:
                _apply_admin_recovery_schema(connection)
            elif next_version == 3:
                _apply_student_portal_schema(connection)
            elif next_version == 4:
                _apply_student_registration_schema(connection)
            connection.execute(
                "INSERT INTO schema_migrations (version) VALUES (?)",
                (next_version,),
            )
            connection.commit()
            applied = next_version


if __name__ == "__main__":
    initialize_database()
    print(f"SAMS database initialized at: {DATABASE_PATH}")
