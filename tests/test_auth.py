import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from werkzeug.security import generate_password_hash

from app import create_app
from app.database import database


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(
            prefix="sams-auth-test-", dir=Path(__file__).parent
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
                ("principal", "School Principal", generate_password_hash("admin-password-123")),
            )
            connection.execute(
                """
                INSERT INTO security_users (staff_id, username, full_name, password_hash)
                VALUES (?, ?, ?, ?)
                """,
                ("SEC-001", "officer", "Gate Officer", generate_password_hash("security-password-123")),
            )
            connection.execute(
                """
                INSERT INTO security_users (
                    staff_id, username, full_name, password_hash, account_status
                ) VALUES (?, ?, ?, ?, 'disabled')
                """,
                ("SEC-002", "inactive", "Inactive Officer", generate_password_hash("disabled-password-123")),
            )

        self.app = create_app()
        self.app.config.update(TESTING=True, SECRET_KEY="test-only-secret")
        self.client = self.app.test_client()

    def tearDown(self):
        self.database_patch.stop()
        self.temp_dir.cleanup()

    def csrf_token(self, path):
        self.client.get(path)
        with self.client.session_transaction() as browser_session:
            return browser_session["csrf_token"]

    def test_workspace_redirects_require_sign_in(self):
        self.assertEqual(self.client.get("/admin/").status_code, 302)
        self.assertEqual(self.client.get("/admin/").location, "/admin/login")
        self.assertEqual(self.client.get("/security/dashboard").status_code, 302)
        self.assertEqual(self.client.get("/security/dashboard").location, "/security/login")

    def test_admin_and_security_accounts_are_separate_roles(self):
        admin_token = self.csrf_token("/admin/login")
        response = self.client.post(
            "/admin/login",
            data={
                "csrf_token": admin_token,
                "username": "principal",
                "password": "admin-password-123",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/admin/")
        self.assertEqual(self.client.get("/admin/").status_code, 200)
        self.assertEqual(self.client.get("/security/dashboard").status_code, 403)

        logout_token = self.csrf_token("/admin/")
        self.client.post("/admin/logout", data={"csrf_token": logout_token})
        self.assertEqual(self.client.get("/admin/").status_code, 302)

        security_token = self.csrf_token("/security/login")
        response = self.client.post(
            "/security/login",
            data={
                "csrf_token": security_token,
                "username": "officer",
                "password": "security-password-123",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/security/dashboard")
        self.assertEqual(self.client.get("/security/dashboard").status_code, 200)
        self.assertEqual(self.client.get("/admin/").status_code, 403)

    def test_invalid_and_disabled_security_accounts_are_rejected(self):
        token = self.csrf_token("/security/login")
        for username, password in (
            ("officer", "wrong-password"),
            ("inactive", "disabled-password-123"),
        ):
            response = self.client.post(
                "/security/login",
                data={"csrf_token": token, "username": username, "password": password},
            )
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"Sign-in failed", response.data)
            self.assertEqual(self.client.get("/security/dashboard").status_code, 302)

        with database.get_connection() as connection:
            audit = connection.execute(
                "SELECT details FROM audit_logs WHERE event_type = 'login'"
            ).fetchall()
        self.assertTrue(audit)
        self.assertNotIn(
            "security-password-123",
            " ".join(row["details"] for row in audit),
        )

    def test_post_without_csrf_token_is_rejected(self):
        self.assertEqual(self.client.post("/security/login", data={}).status_code, 400)


if __name__ == "__main__":
    unittest.main()
