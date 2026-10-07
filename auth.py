"""Auth bersama — dipakai app.py & filemanager.py."""
import os


def current_pass():
    """Password aktif: baca ulang .monitor.env agar ganti password via UI
    berlaku langsung tanpa restart."""
    env_file = os.environ.get(
        "MONITOR_ENV",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), ".monitor.env"))
    try:
        with open(env_file) as f:
            for line in f:
                if line.startswith("MONITOR_PASS="):
                    return line.split("=", 1)[1].strip()
    except Exception:
        pass
    return os.environ.get("MONITOR_PASS", "admin123")


def current_user():
    return os.environ.get("MONITOR_USER", "admin")


def check_auth():
    from flask import request
    auth = request.authorization
    return auth and auth.username == current_user() \
        and auth.password == current_pass()
