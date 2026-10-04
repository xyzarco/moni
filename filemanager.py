"""File Manager API — browse, read, create, delete files & folders (Blueprint)."""
import os, shutil, mimetypes, base64
from flask import request, Blueprint, send_file, jsonify
from auth import check_auth

fm_bp = Blueprint("filemanager", __name__)

SAFE_BASE = os.environ.get("FM_ROOT", "/")


def _real(path):
    """Resolve path & pastikan di dalam SAFE_BASE."""
    p = os.path.realpath(os.path.abspath(path))
    if not (p == SAFE_BASE or p.startswith(SAFE_BASE.rstrip("/") + "/")):
        raise PermissionError("outside allowed root")
    return p


@fm_bp.route("/api/fs/list")
def fs_list():
    if not check_auth(): return jsonify({"error": "unauthorized"}), 401
    path = request.args.get("path", "/")
    try:
        p = _real(path)
        if not os.path.isdir(p): return jsonify({"error": "not a directory"}), 400
        items = []
        for name in sorted(os.listdir(p), key=str.lower):
            if name.startswith("."): continue
            full = os.path.join(p, name)
            try:
                st = os.stat(full, follow_symlinks=False)
                is_dir = os.path.isdir(full)
                items.append({"name": name, "dir": is_dir, "size": 0 if is_dir else st.st_size,
                              "mtime": int(st.st_mtime)})
            except OSError:
                continue
        dirs = [i for i in items if i["dir"]]
        files = [i for i in items if not i["dir"]]
        return {"path": p, "items": dirs + files}
    except PermissionError as e:
        return jsonify({"error": str(e)}), 403
    except OSError as e:
        return jsonify({"error": e.strerror}), 400


@fm_bp.route("/api/fs/read")
def fs_read():
    if not check_auth(): return jsonify({"error": "unauthorized"}), 401
    try:
        p = _real(request.args.get("path", ""))
        if os.path.isdir(p): return jsonify({"error": "is a directory"}), 400
        size = os.path.getsize(p)
        if size > 2 * 1024 * 1024:
            return jsonify({"error": "file too large (>2MB) — pakai Download"}), 400
        mime = mimetypes.guess_type(p)[0] or ""
        if mime.startswith(("image/",)):
            return jsonify({"kind": "image", "mime": mime})
        raw = open(p, "rb").read()
        try: text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return jsonify({"error": "binary file — pakai Download"}), 400
        return jsonify({"kind": "text", "content": text, "size": size})
    except PermissionError as e:
        return jsonify({"error": str(e)}), 403
    except OSError as e:
        return jsonify({"error": e.strerror}), 400


@fm_bp.route("/api/fs/download")
def fs_download():
    if not check_auth(): return jsonify({"error": "unauthorized"}), 401
    try:
        p = _real(request.args.get("path", ""))
        if os.path.isdir(p):
            mem = shutil.make_archive("/tmp/fm_dl", "zip", p)
            return send_file(mem, as_attachment=True, download_name=os.path.basename(p) + ".zip")
        return send_file(p, as_attachment=True)
    except (PermissionError, OSError) as e:
        return jsonify({"error": str(e)}), 400


@fm_bp.route("/api/fs/image")
def fs_image():
    if not check_auth(): return jsonify({"error": "unauthorized"}), 401
    try:
        p = _real(request.args.get("path", ""))
        return send_file(p)
    except (PermissionError, OSError) as e:
        return jsonify({"error": str(e)}), 400


@fm_bp.route("/api/fs/write", methods=["POST"])
def fs_write():
    if not check_auth(): return jsonify({"error": "unauthorized"}), 401
    d = request.get_json(force=True)
    try:
        p = _real(d.get("path", ""))
        os.makedirs(os.path.dirname(p) or "/", exist_ok=True)
        mode = "wb" if d.get("b64") else "w"
        with open(p, mode) as f:
            f.write(base64.b64decode(d["content"]) if d.get("b64") else d["content"])
        return {"ok": True}
    except PermissionError as e:
        return jsonify({"error": str(e)}), 403
    except OSError as e:
        return jsonify({"error": e.strerror}), 400


@fm_bp.route("/api/fs/mkdir", methods=["POST"])
def fs_mkdir():
    if not check_auth(): return jsonify({"error": "unauthorized"}), 401
    d = request.get_json(force=True)
    try:
        os.makedirs(_real(d["path"]), exist_ok=False)
        return {"ok": True}
    except FileExistsError:
        return jsonify({"error": "sudah ada"}), 400
    except (PermissionError, OSError) as e:
        return jsonify({"error": str(e)}), 400


@fm_bp.route("/api/fs/rename", methods=["POST"])
def fs_rename():
    if not check_auth(): return jsonify({"error": "unauthorized"}), 401
    d = request.get_json(force=True)
    try:
        os.rename(_real(d["src"]), _real(d["dst"]))
        return {"ok": True}
    except (PermissionError, OSError) as e:
        return jsonify({"error": str(e)}), 400


@fm_bp.route("/api/fs/delete", methods=["POST"])
def fs_delete():
    if not check_auth(): return jsonify({"error": "unauthorized"}), 401
    d = request.get_json(force=True)
    try:
        p = _real(d["path"])
        if p == "/" or p == SAFE_BASE:
            return jsonify({"error": "dilarang hapus root"}), 400
        if os.path.isdir(p) and not os.path.islink(p):
            shutil.rmtree(p)
        else:
            os.remove(p)
        return {"ok": True}
    except (PermissionError, OSError) as e:
        return jsonify({"error": str(e)}), 400
