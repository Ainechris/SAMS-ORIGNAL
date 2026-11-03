import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from werkzeug.security import generate_password_hash

from app import create_app
from app.database import database


class GateSessionWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(
            prefix="sams-gate-test-", dir=Path(__file__).parent
        )
        self.database_path = Path(self.temp_dir.name) / "test.db"
        self.database_patch = patch.object(database, "DATABASE_PATH", self.database_path)
        self.database_patch.start()
        database.initialize_database()
        with database.get_connection() as connection:
            connection.execute(
                "INSERT INTO students (student_id, full_name, class_name) VALUES (?, ?, ?)",
                ("SAMS001", "Test Student", "Class 1"),
            )
            for staff_id, username, name, password in (
                ("SEC-001", "officer-a", "Officer A", "officer-a-password"),
                ("SEC-002", "officer-b", "Officer B", "officer-b-password"),
            ):
                connection.execute(
                    """
                    INSERT INTO security_users (staff_id, username, full_name, password_hash)
                    VALUES (?, ?, ?, ?)
                    """,
                    (staff_id, username, name, generate_password_hash(password)),
                )

        with patch.dict("os.environ", {"SAMS_SECRET_KEY": "gate-tests-only"}):
            self.app = create_app()
        self.app.config.update(TESTING=True)
        self.client = self.app.test_client()

    def tearDown(self):
        self.database_patch.stop()
        self.temp_dir.cleanup()

    def csrf_token(self, path):
        self.client.get(path)
        with self.client.session_transaction() as browser_session:
            return browser_session["csrf_token"]

    def sign_in(self, username, password):
        token = self.csrf_token("/security/login")
        return self.client.post(
            "/security/login",
            data={"csrf_token": token, "username": username, "password": password},
        )

    def test_kiosk_blocks_checkins_until_a_session_starts(self):
        page = self.client.get("/gate")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"currently closed", page.data)
        self.assertNotIn(b'name="student_id"', page.data)

        token = self.csrf_token("/gate")
        response = self.client.post(
            "/gate", data={"csrf_token": token, "student_id": "SAMS001"}
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get("/gate").status_code, 200)
        with database.get_connection() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM attendance").fetchone()[0], 0)

    def test_start_checkin_duplicate_and_close_flow(self):
        self.assertEqual(self.sign_in("officer-a", "officer-a-password").status_code, 302)
        token = self.csrf_token("/security/dashboard")
        response = self.client.post(
            "/security/session/start", data={"csrf_token": token}
        )
        self.assertEqual(response.status_code, 302)
        dashboard = self.client.get("/security/dashboard")
        self.assertIn(b"Active", dashboard.data)
        self.assertIn(b"Officer A", dashboard.data)

        token = self.csrf_token("/gate")
        response = self.client.post(
            "/gate", data={"csrf_token": token, "student_id": "SAMS001"}
        )
        self.assertEqual(response.status_code, 302)
        page = self.client.get("/gate")
        self.assertIn(b"Check-in recorded", page.data)
        self.assertIn(b'name="student_id"', page.data)

        token = self.csrf_token("/gate")
        self.client.post("/gate", data={"csrf_token": token, "student_id": "SAMS001"})
        page = self.client.get("/gate")
        self.assertIn(b"already been recorded today", page.data)

        token = self.csrf_token("/gate")
        self.client.post("/gate", data={"csrf_token": token, "student_id": "UNKNOWN"})
        self.assertIn(b"Student ID not found", self.client.get("/gate").data)

        with database.get_connection() as connection:
            attendance = connection.execute(
                "SELECT gate_session_id FROM attendance"
            ).fetchone()
            self.assertIsNotNone(attendance["gate_session_id"])
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM attendance").fetchone()[0], 1)
            session_id = attendance["gate_session_id"]

        close_page = self.client.get("/security/session/close")
        self.assertEqual(close_page.status_code, 200)
        token = self.csrf_token("/security/session/close")
        response = self.client.post(
            "/security/session/close",
            data={"csrf_token": token, "confirm_close": "yes"},
        )
        self.assertEqual(response.status_code, 302)
        with database.get_connection() as connection:
            closed = connection.execute(
                "SELECT status, closed_by, ended_at FROM gate_sessions WHERE id = ?",
                (session_id,),
            ).fetchone()
            self.assertEqual(closed["status"], "closed")
            self.assertIsNotNone(closed["closed_by"])
            self.assertIsNotNone(closed["ended_at"])

        token = self.csrf_token("/gate")
        self.client.post("/gate", data={"csrf_token": token, "student_id": "SAMS001"})
        self.assertIn(b"currently closed", self.client.get("/gate").data)

    def test_handover_requires_incoming_auth_and_rotates_operator_session(self):
        self.sign_in("officer-a", "officer-a-password")
        token = self.csrf_token("/security/dashboard")
        self.client.post("/security/session/start", data={"csrf_token": token})
        with self.client.session_transaction() as browser_session:
            outgoing_token = browser_session["auth_token"]

        token = self.csrf_token("/security/session/handover")
        response = self.client.post(
            "/security/session/handover",
            data={
                "csrf_token": token,
                "incoming_staff": "SEC-002",
                "incoming_password": "wrong-password",
                "accept_handover": "yes",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"could not be authenticated", response.data)
        with database.get_connection() as connection:
            session_row = connection.execute(
                "SELECT current_operator_id FROM gate_sessions WHERE status = 'active'"
            ).fetchone()
            self.assertEqual(session_row["current_operator_id"], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM gate_handovers").fetchone()[0], 0)

        token = self.csrf_token("/security/session/handover")
        response = self.client.post(
            "/security/session/handover",
            data={
                "csrf_token": token,
                "incoming_staff": "SEC-002",
                "incoming_password": "officer-b-password",
                "accept_handover": "yes",
            },
        )
        self.assertEqual(response.status_code, 302)
        dashboard = self.client.get("/security/dashboard")
        self.assertIn(b"Officer B", dashboard.data)
        self.assertNotIn(b"Officer A</strong>", dashboard.data)

        with database.get_connection() as connection:
            current = connection.execute(
                "SELECT current_operator_id, session_reference FROM gate_sessions WHERE status = 'active'"
            ).fetchone()
            self.assertEqual(current["current_operator_id"], 2)
            self.assertTrue(current["session_reference"].startswith("GS-"))
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM gate_handovers").fetchone()[0], 1)
            revoked = connection.execute(
                "SELECT revoked_at FROM auth_sessions WHERE token_hash = ?",
                (hashlib.sha256(outgoing_token.encode()).hexdigest(),),
            ).fetchone()
            self.assertIsNotNone(revoked["revoked_at"])

    def test_only_one_active_session_can_exist(self):
        self.sign_in("officer-a", "officer-a-password")
        token = self.csrf_token("/security/dashboard")
        self.client.post("/security/session/start", data={"csrf_token": token})
        token = self.csrf_token("/security/dashboard")
        self.client.post("/security/logout", data={"csrf_token": token})
        self.sign_in("officer-b", "officer-b-password")
        token = self.csrf_token("/security/dashboard")
        response = self.client.post("/security/session/start", data={"csrf_token": token})
        self.assertEqual(response.status_code, 302)
        dashboard = self.client.get("/security/dashboard")
        self.assertIn(b"already controlled by Officer A", dashboard.data)
        with database.get_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM gate_sessions WHERE status = 'active'"
                ).fetchone()[0],
                1,
            )


if __name__ == "__main__":
    unittest.main()
