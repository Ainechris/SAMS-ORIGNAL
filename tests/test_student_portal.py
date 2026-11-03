import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import create_app
from app.database import database
from werkzeug.security import generate_password_hash


class StudentPortalTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(
            prefix="sams-student-test-", dir=Path(__file__).parent
        )
        self.database_path = Path(self.temp_dir.name) / "test.db"
        self.database_patch = patch.object(database, "DATABASE_PATH", self.database_path)
        self.database_patch.start()
        database.initialize_database()
        with database.get_connection() as connection:
            connection.execute(
                """INSERT INTO administrators (username, full_name, password_hash)
                   VALUES (?, ?, ?)""",
                ("admin", "School Admin", generate_password_hash("admin-password-123")),
            )
        with patch.dict("os.environ", {"SAMS_SECRET_KEY": "student-tests-only"}):
            self.app = create_app()
        self.app.config.update(TESTING=True)
        self.admin = self.app.test_client()
        self.student = self.app.test_client()
        token = self.csrf_token(self.admin, "/admin/login")
        self.admin.post(
            "/admin/login",
            data={"csrf_token": token, "username": "admin", "password": "admin-password-123"},
        )

    def tearDown(self):
        self.database_patch.stop()
        self.temp_dir.cleanup()

    @staticmethod
    def csrf_token(client, path):
        client.get(path)
        with client.session_transaction() as browser_session:
            return browser_session["csrf_token"]

    def test_admin_provisions_private_code_then_student_activates_and_sees_own_records(self):
        token = self.csrf_token(self.admin, "/admin/students/new")
        response = self.admin.post(
            "/admin/students/new",
            data={"csrf_token": token, "student_id": "SAMS201", "full_name": "Portal Student", "class_name": "Class 2"},
        )
        self.assertEqual(response.status_code, 302)
        with database.get_connection() as connection:
            student = connection.execute(
                "SELECT id FROM students WHERE student_id = 'SAMS201'"
            ).fetchone()
            account = connection.execute(
                "SELECT account_status FROM student_accounts WHERE username = 'SAMS201'"
            ).fetchone()
        self.assertEqual(account["account_status"], "pending")

        token = self.csrf_token(self.admin, f"/admin/students/{student['id']}")
        response = self.admin.post(
            f"/admin/students/{student['id']}/portal-code",
            data={"csrf_token": token},
        )
        self.assertEqual(response.status_code, 200)
        code = re.search(r"<output class=\"activation-code\">([A-F0-9]+)</output>", response.get_data(as_text=True)).group(1)

        token = self.csrf_token(self.student, "/student/activate")
        response = self.student.post(
            "/student/activate",
            data={"csrf_token": token, "student_id": "SAMS201", "activation_code": code,
                  "password": "student-password-123", "confirm_password": "student-password-123"},
        )
        self.assertEqual(response.status_code, 302)
        with database.get_connection() as connection:
            connection.execute(
                """INSERT INTO attendance (student_id, attendance_date, check_in_time)
                   VALUES ('SAMS201', '2026-11-03', '08:02:00')"""
            )
            connection.execute(
                """INSERT INTO students (student_id, full_name, class_name)
                   VALUES ('SAMS202', 'Another Student', 'Class 2')"""
            )
            connection.execute(
                """INSERT INTO attendance (student_id, attendance_date, check_in_time)
                   VALUES ('SAMS202', '2026-11-03', '08:04:00')"""
            )

        token = self.csrf_token(self.student, "/student/login")
        response = self.student.post(
            "/student/login",
            data={"csrf_token": token, "student_id": "SAMS201", "password": "student-password-123"},
        )
        self.assertEqual(response.status_code, 302)
        response = self.student.get("/student/dashboard")
        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn("2026-11-03", body)
        self.assertNotIn("SAMS202", body)

        token = self.csrf_token(self.student, "/student/dashboard")
        self.student.post("/student/logout", data={"csrf_token": token})
        self.assertEqual(self.student.get("/student/dashboard").status_code, 302)

    def test_activation_code_expires_after_use_and_passwords_are_not_plaintext(self):
        with database.get_connection() as connection:
            connection.execute(
                "INSERT INTO students (student_id, full_name, class_name) VALUES ('SAMS301', 'Pending Student', 'Class 3')"
            )
            student = connection.execute("SELECT id FROM students WHERE student_id = 'SAMS301'").fetchone()
            from app.services.student_portal import create_student_account, issue_activation_code
            create_student_account(connection, student["id"], "SAMS301")
            code = issue_activation_code(connection, student["id"])

        token = self.csrf_token(self.student, "/student/activate")
        data = {"csrf_token": token, "student_id": "SAMS301", "activation_code": code,
                "password": "student-password-456", "confirm_password": "student-password-456"}
        self.assertEqual(self.student.post("/student/activate", data=data).status_code, 302)
        response = self.student.post("/student/activate", data=data)
        self.assertEqual(response.status_code, 200)
        self.assertIn("invalid, expired, or locked", response.get_data(as_text=True))
        with database.get_connection() as connection:
            account = connection.execute(
                "SELECT password_hash, activation_code_hash FROM student_accounts WHERE username = 'SAMS301'"
            ).fetchone()
        self.assertNotEqual(account["password_hash"], "student-password-456")
        self.assertIsNone(account["activation_code_hash"])
