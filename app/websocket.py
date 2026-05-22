"""WebSocket registration.

Extracted from the app factory. flask-sock upgrades HTTP → WS for the live CLI
terminal at ``/terminal/ws``.
"""


def register_websocket(app):
    from flask_sock import Sock
    from routes.terminal import terminal_ws

    sock = Sock(app)
    sock.route("/terminal/ws")(terminal_ws)
    return sock
