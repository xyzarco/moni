"""noVNC: serve file statis + bridge WebSocket browser langsung ke VNC TCP (localhost:5901).

Tidak butuh websockify sama sekali: frame binary WS = byte stream RFB mentah.
(noVNC memanggil path /novnc/websockify dengan param ?path=... — kita abaikan query.)
"""
import socket
import threading

from flask import request, Blueprint, Response, send_from_directory
from auth import check_auth

vnc_bp = Blueprint("novnc", __name__)

NOVNC_DIR = "/usr/share/novnc"
VNC_HOST = "127.0.0.1"
VNC_PORT = 5901


@vnc_bp.route("/novnc/<path:path>", strict_slashes=False)
def novnc_static(path):
    if not check_auth():
        return Response("Auth required", 401, {"WWW-Authenticate": "Basic realm=ServerMonitor"})
    return send_from_directory(NOVNC_DIR, path)


@vnc_bp.route("/novnc", strict_slashes=False)
def novnc_index():
    """/novnc -> serve vnc.html langsung."""
    if not check_auth():
        return Response("Auth required", 401, {"WWW-Authenticate": "Basic realm=ServerMonitor"})
    return send_from_directory(NOVNC_DIR, "vnc.html")


def bridge(ws):
    """Pipe dua arah: WS browser <-> TCP VNC. WebSocket send/receive binary saja."""
    import sys
    try:
        sock = socket.create_connection((VNC_HOST, VNC_PORT), timeout=10)
        sock.settimeout(None)
    except Exception as e:
        try: ws.send(f"VNC backend tidak tersedia: {e}")
        except Exception: pass
        return

    def pump_down():
        # VNC -> browser
        try:
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                ws.send(data)
        except Exception:
            import traceback
            print("novnc pump_down err:\n" + traceback.format_exc(), file=sys.stderr, flush=True)
        finally:
            try: ws.close()
            except Exception: pass

    threading.Thread(target=pump_down, daemon=True).start()
    try:
        while True:
            data = ws.receive()
            if data is None:
                break
            if isinstance(data, str):
                data = data.encode("utf-8")
            sock.sendall(data)
    except Exception:
        import traceback
        print("novnc bridge up err:\n" + traceback.format_exc(), file=sys.stderr, flush=True)
    finally:
        try: sock.close()
        except Exception: pass
