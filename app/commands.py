import click
from werkzeug.security import generate_password_hash

from app.database.database import get_connection
from app.services.auth import audit_event


def register_commands(app):
    @app.cli.command("create-admin")
    @click.option("--username", prompt=True, help="Administrator sign-in name.")
    @click.option("--name", "full_name", prompt=True, help="Administrator's name.")
    def create_admin(username, full_name):
        """Create the initial administrator without a hardcoded password."""
        username = username.strip()
        full_name = full_name.strip()
        if not username or len(username) > 100:
            raise click.ClickException("Username must contain 1 to 100 characters.")
        if not full_name or len(full_name) > 120:
            raise click.ClickException("Name must contain 1 to 120 characters.")

        password = click.prompt(
            "Password (at least 12 characters)",
            hide_input=True,
            confirmation_prompt=True,
        )
        if len(password) < 12:
            raise click.ClickException("Password must be at least 12 characters.")

        with get_connection() as connection:
            if connection.execute("SELECT 1 FROM administrators LIMIT 1").fetchone():
                raise click.ClickException(
                    "An administrator already exists. Create additional accounts "
                    "from the administrator workspace."
                )
            cursor = connection.execute(
                """
                INSERT INTO administrators (username, full_name, password_hash)
                VALUES (?, ?, ?)
                """,
                (username, full_name, generate_password_hash(password)),
            )
            audit_event(
                connection,
                "system",
                None,
                "administrator_bootstrap",
                "success",
                f"administrator_id={cursor.lastrowid}",
            )

        click.echo(f"Administrator '{username}' created. Keep the password private.")
