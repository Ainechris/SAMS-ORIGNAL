"""Compatibility exports for the canonical application database module."""

from app.database.database import DATABASE_PATH, get_connection, initialize_database

__all__ = ["DATABASE_PATH", "get_connection", "initialize_database"]
