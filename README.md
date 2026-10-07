# Moni — Web Server Monitor

Web app all-in-one untuk monitoring server Linux: dashboard real-time, file manager, Web SSH (terminal di browser), dan remote desktop LXQt via noVNC — semuanya dalam satu dashboard bertab dengan satu login.

![tabs](https://img.shields.io/badge/tabs-5-blue) ![python](https://img.shields.io/badge/python-3.9%2B-green) ![license](https://img.shields.io/badge/license-MIT-lightgrey) ![framework](https://img.shields.io/badge/framework-Flask-red)

## Features

| Tab | Fungsi |
|---|---|
| **Monitoring** | CPU, RAM, disk, network, load average, suhu, daftar proses — update real-time (interval bisa diatur 2–30 detik) |
| **File Manager** | Browse, upload, download, edit, rename, mkdir, delete file/folder (guard path traversal) |
| **Web SSH** | Terminal interaktif di browser (Paramiko + xterm.js), auto-resize, scrollback 2000 |
| **Desktop** | Remote desktop LXQt via noVNC, auto-scale, fullscreen, tombol Start/Stop untuk hemat resource |
| **Settings** | Ganti password login (berlaku langsung tanpa restart), tema System/Dark/Light, interval polling, VNC autostart |

- **Auth tunggal** — basic-auth untuk semua HTTP + session token (kedaluwarsa 1 jam) untuk WebSocket
- **SSH key-based** — Web SSH memakai SSH key lokal, bukan password
- **VNC localhost-only** — remote desktop tidak pernah terekspos langsung; semua lewat proxy Flask yang ter-auth
- **Theme switch** — System/Dark/Light, preferensi di localStorage + `settings.json`

## Architecture

```
Browser ──HTTP──> Flask :8080
             ├── /              → dashboard UI (ui.html, embedded)
             ├── /api/stats     → psutil metrics
             ├── /api/fs/*      → file manager (filemanager.py)
             ├── /api/settings  → preferensi (settings.json)
             ├── /api/password  → ganti password (tulis .monitor.env)
             ├── /api/vnc       → status + start/stop VNC
             ├── /api/session   → basic-auth → token WS (1 jam)
             ├── /ws/ssh        → WebSocket → Paramiko SSH
             ├── /novnc/*       → static noVNC (novncproxy.py)
             └── /novnc/websockify → WS bridge TCP → VNC :5901 (localhost)

VNC :5901 (Xtigervnc, SecurityTypes None, localhost-only)
  └── LXQt session (~/.vnc/xstartup-lxqt)
```

## Requirements

- Linux (diuji di Ubuntu 24.04) + Python 3.9+
- OpenSSH server berjalan
- (Opsional, untuk tab Desktop) LXQt + TigerVNC + noVNC

## Install

```bash
git clone https://github.com/xyzarco/moni.git
cd moni
python3 -m venv venv
venv/bin/pip install -r requirements.txt
```

Buat kredensial dashboard:

```bash
cat > .monitor.env <<EOF
MONITOR_USER=admin
MONITOR_PASS=passwordKamuYangKuat
SSH_HOST=127.0.0.1
SSH_PORT=22
SSH_USER=$USER
EOF
chmod 600 .monitor.env
```

| Variabel | Arti |
|---|---|
| `MONITOR_USER` / `MONITOR_PASS` | login dashboard |
| `SSH_HOST` / `SSH_PORT` | target SSH untuk Web SSH |
| `SSH_USER` | user Linux untuk sesi SSH |
| `SSH_KEY` | (opsional) path SSH key, default `~/.ssh/id_ed25519` |

Siapkan SSH key (untuk Web SSH):

```bash
[ -f ~/.ssh/id_ed25519 ] || ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519
cat ~/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

## Usage

```bash
venv/bin/python app.py
# buka http://localhost:8080
```

### (Opsional) Desktop Remote — tab noVNC

```bash
sudo apt install -y tigervnc-standalone-server novnc lxqt-core  # sesuaikan meta-paket LXQt
```

Buat `~/.vnc/xstartup-lxqt`:

```bash
#!/bin/bash
unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS
export XDG_CURRENT_DESKTOP=LXQt
exec startlxqt
```

Buat `~/.vnc/start-desktop.sh` (perhatikan `unset TMPDIR` — tanpa itu TigerVNC membuat password acak di `$TMPDIR`):

```bash
#!/bin/bash
unset TMPDIR
vncserver -kill :1 2>/dev/null; sleep 1
vncserver :1 -geometry 1280x800 -depth 24 -localhost yes \
  -SecurityTypes None \
  -PasswordFile "$HOME/.vnc/passwd" \
  -xstartup "$HOME/.vnc/xstartup-lxqt"
echo "VNC :1 siap"
```

```bash
chmod +x ~/.vnc/xstartup-lxqt ~/.vnc/start-desktop.sh
~/.vnc/start-desktop.sh
```

> `SecurityTypes None` aman di sini karena VNC hanya listen di localhost dan auth tetap ditangani dashboard. Jika ingin double-layer, hapus flag tersebut dan set password dengan `vncpasswd`.

### Deploy via tunnel publik

Contoh dengan Cloudflare quick tunnel (tanpa konfigurasi):

```bash
cloudflared tunnel --url http://127.0.0.1:8080
```

Atau tunnel bernama permanen:

```bash
sudo cloudflared service install <TOKEN>
# lalu set Public Hostname → HTTP localhost:8080 di Zero Trust dashboard
```

⚠️ Selalu pastikan endpoint yang terekspos publik terlindungi `MONITOR_PASS` yang kuat.

## Project Structure

```
moni/
├── app.py           # Flask utama + WebSocket SSH + embed UI + WS bridge noVNC + Settings API
├── auth.py          # helper check_auth + current_pass (dipakai bersama)
├── filemanager.py   # Blueprint /api/fs/*
├── novncproxy.py    # Blueprint /novnc/* (static + WS bridge TCP → VNC)
├── ui.html          # sumber UI (di-embed ke app.py saat build)
├── requirements.txt
└── .gitignore
```

## Security

- Kredensial via `.monitor.env` (chmod 600, jangan pernah di-commit)
- Path traversal diblok di file manager
- WebSocket token kedaluwarsa 1 jam, token invalid ditolak sebelum login SSH
- Ganti password lewat UI berlaku langsung — ditulis atomik ke `.monitor.env`
- Untuk produksi: taruh di balik reverse proxy (nginx/caddy) dengan HTTPS

## License

MIT
