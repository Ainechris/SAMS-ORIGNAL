
from flask import Flask, render_template, request
from database import get_connection, initialize_database

app = Flask(__name__)
initialize_database()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/gate", methods=["GET", "POST"])
def gate():
    message = ""
    message_type = ""

    if request.method == "POST":
        student_id = request.form.get("student_id", "").strip()

        if not student_id:
            message = "Please enter your student ID."
            message_type = "error"
        else:
            with get_connection() as connection:
                student = connection.execute(
                    "SELECT * FROM students WHERE student_id = ?",
                    (student_id,)
                ).fetchone()

                if student is None:
                    message = "Student ID not found. Please contact the school office."
                    message_type = "error"
                else:
                    try:
                        connection.execute(
                            """INSERT INTO attendance (student_id)
                               VALUES (?)""",
                            (student_id,)
                        )
                        message = f"Welcome, {student['full_name']}! Your attendance is recorded."
                        message_type = "success"
                    except Exception as error:
                        if "UNIQUE constraint failed" in str(error):
                            message = "Your attendance has already been recorded today."
                            message_type = "error"
                        else:
                            raise

    return render_template(
        "gate.html",
        message=message,
        message_type=message_type
    )


if __name__ == "__main__":
    app.run(debug=True)
