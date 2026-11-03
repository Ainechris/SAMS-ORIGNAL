import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from werkzeug.security import generate_password_hash

from app import create_app
from app.database import database


class AdminWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(
            prefix="sams-admin-test-", dir=Path(__file__).parent
        )
        self.database_path = Path(self.temp_dir.name) / "test.db"
        self.database_patch = patch.object(database, "DATABASE_PATH", self.database_path)
        self.database_patch.start()
        database.initialize_database()
        with database.get_connection() as connection:
            connection.execute(
                """
                INSERT INTO administrators (username, full_name, password_hash)
                VALUES (?, ?, ?)
                """,
                ("admin", "School Admin", generate_password_hash("admin-password-123")),
            )
            connection.execute(
                """
                INSERT INTO security_users (staff_id, username, full_name, password_hash)
                VALUES (?, ?, ?, ?)
                """,
                ("SEC-001", "operator", "Gate Operator", generate_password_hash("operator-password-123")),
            )
            connection.execute(
                "INSERT INTO students (student_id, full_name, class_name) VALUES (?, ?, ?)",
                ("SAMS001", "Test Student", "Class 1"),
            )

        with patch.dict("os.environ", {"SAMS_SECRET_KEY": "admin-tests-only"}):
            self.app = create_app()
        self.app.config.update(TESTING=True)
        self.admin_client = self.app.test_client()
        self.security_client = self.app.test_client()
        token = self.csrf_token(self.admin_client, "/admin/login")
        self.admin_client.post(
            "/admin/login",
            data={"csrf_token": token, "username": "admin", "password": "admin-password-123"},
        )

    def tearDown(self):
        self.database_patch.stop()
        self.temp_dir.cleanup()

    def csrf_token(self, client, path):
        client.get(path)
        with client.session_transaction() as browser_session:
            return browser_session["csrf_token"]

    def test_administrator_pages_render_from_real_database(self):
        for path in (
            "/admin/",
            "/admin/students",
            "/admin/students/new",
            "/admin/students/1",
            "/admin/students/1/edit",
            "/admin/attendance",
            "/admin/security-users",
            "/admin/security-users/new",
            "/admin/gate-sessions",
            "/admin/reports",
        ):
            with self.subTest(path=path):
                self.assertEqual(self.admin_client.get(path).status_code, 200)

    def test_student_create_edit_search_and_attendance_filter(self):
        token = self.csrf_token(self.admin_client, "/admin/students/new")
        response = self.admin_client.post(
            "/admin/students/new",
            data={
                "csrf_token": token,
                "student_id": "sams002",
                "full_name": "Second Student",
                "class_name": "Class 2",
            },
        )
        self.assertEqual(response.status_code, 302)
        with database.get_connection() as connection:
            student = connection.execute(
                "SELECT id, student_id FROM students WHERE student_id = 'SAMS002'"
            ).fetchone()
        self.assertIsNotNone(student)

        token = self.csrf_token(self.admin_client, f"/admin/students/{student['id']}/edit")
        response = self.admin_client.post(
            f"/admin/students/{student['id']}/edit",
            data={
                "csrf_token": token,
                "student_id": "SAMS002",
                "full_name": "Second Student Updated",
                "class_name": "Class 2",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            self.admin_client.get("/admin/students?q=Second").status_code,
            200,
        )
        self.assertEqual(
            self.admin_client.get("/admin/attendance?date=not-a-date").status_code,
            200,
        )

    def test_temporary_security_password_must_be_changed(self):
        token = self.csrf_token(self.admin_client, "/admin/security-users/new")
        response = self.admin_client.post(
            "/admin/security-users/new",
            data={
                "csrf_token": token,
                "staff_id": "SEC-002",
                "username": "new-operator",
                "full_name": "New Operator",
                "temporary_password": "temporary-password-123",
            },
        )
        self.assertEqual(response.status_code, 302)

        token = self.csrf_token(self.security_client, "/security/login")
        response = self.security_client.post(
            "/security/login",
            data={
                "csrf_token": token,
                "username": "new-operator",
                "password": "temporary-password-123",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            self.security_client.get("/security/dashboard").location,
            "/security/password/change",
        )

        token = self.csrf_token(self.security_client, "/security/password/change")
        response = self.security_client.post(
            "/security/password/change",
            data={
                "csrf_token": token,
                "current_password": "temporary-password-123",
                "new_password": "permanent-password-456",
                "confirm_password": "permanent-password-456",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.security_client.get("/security/dashboard").status_code, 200)

    def test_admin_recovery_closes_session_with_reason_and_preserves_checkins(self):
        with database.get_connection() as connection:
            gate = connection.execute("SELECT id FROM gates WHERE gate_code = 'MAIN'").fetchone()
            station = connection.execute("SELECT id FROM gate_stations WHERE station_code = 'KIOSK-1'").fetchone()
            session_cursor = connection.execute(
                """
                INSERT INTO gate_sessions (
                    session_reference, gate_id, station_id, started_by, current_operator_id
                ) VALUES ('GS-RECOVERY', ?, ?, 1, 1)
                """,
                (gate["id"], station["id"]),
            )
            session_id = session_cursor.lastrowid
            connection.execute(
                "INSERT INTO attendance (student_id, gate_session_id) VALUES ('SAMS001', ?)",
                (session_id,),
            )

        token = self.csrf_token(self.admin_client, "/admin/gate-sessions")
        response = self.admin_client.post(
            f"/admin/gate-sessions/{session_id}/force-close",
            data={"csrf_token": token, "reason": "The operator workstation was unavailable."},
        )
        self.assertEqual(response.status_code, 302)
        with database.get_connection() as connection:
            closed = connection.execute(
                "SELECT status FROM gate_sessions WHERE id = ?", (session_id,)
            ).fetchone()
            recovery = connection.execute(
                "SELECT admin_id, reason FROM gate_session_admin_closures WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            attendance_count = connection.execute(
                "SELECT COUNT(*) FROM attendance WHERE gate_session_id = ?", (session_id,)
            ).fetchone()[0]
        self.assertEqual(closed["status"], "closed")
        self.assertEqual(recovery["admin_id"], 1)
        self.assertEqual(attendance_count, 1)


if __name__ == "__main__":
    unittest.main()
