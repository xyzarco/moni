"""Auth bersama — dipakai app.py & filemanager.py."""
import os


def check_auth():
    from flask import request
    auth = request.authorization
    return auth and auth.username == os.environ.get("MONITOR_USER", "admin") \
        and auth.password == os.environ.get("MONITOR_PASS", "admin123")
