
from app import create_app
import webbrowser
from threading import Timer

app = create_app()


def open_browser():
    webbrowser.open("http://127.0.0.1:5000/gate")


if __name__ == "__main__":
    Timer(1.5, open_browser).start()
    app.run(debug=True)
