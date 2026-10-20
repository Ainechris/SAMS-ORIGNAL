
import sqlite3
from pathlib import Path


DATABASE_PATH = Path(__file__).resolve().parents[2] / "instance" / "sams.db"



def get_connection():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id TEXT NOT NULL UNIQUE,
                full_name TEXT NOT NULL,
                class_name TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS attendance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id TEXT NOT NULL,
                attendance_date TEXT NOT NULL DEFAULT (date('now', 'localtime')),
                check_in_time TEXT NOT NULL DEFAULT (time('now', 'localtime')),
                status TEXT NOT NULL DEFAULT 'Present',
                FOREIGN KEY (student_id)
                    REFERENCES students(student_id),
                UNIQUE (student_id, attendance_date)
            )
        """)


if __name__ == "__main__":
    initialize_database()
    print(f"SAMS database initialized at: {DATABASE_PATH}")
