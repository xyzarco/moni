#!/usr/bin/env python3
"""Server Monitor + Web SSH — dashboard monitoring & terminal SSH di browser."""
import json, os, socket, time, getpass
import psutil
from flask import Flask, Response, request
from flask_sock import Sock
import paramiko


app = Flask(__name__)
sock = Sock(app)

def _load_env_file(path=None):
    """Muat .monitor.env (OP=VALUE per baris) — dipakai otomatis saat start."""
    path = path or os.path.join(os.path.dirname(os.path.abspath(__file__)), ".monitor.env")
    if os.path.isfile(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())


_load_env_file()

APP_USER = os.environ.get("MONITOR_USER", "admin")
APP_PASS = os.environ.get("MONITOR_PASS", "admin123")
SSH_HOST = os.environ.get("SSH_HOST", "127.0.0.1")
SSH_PORT = int(os.environ.get("SSH_PORT", "22"))
SSH_USER = os.environ.get("SSH_USER", getpass.getuser())
PORT = int(os.environ.get("PORT", "8080"))


def check_auth():
    auth = request.authorization
    return auth and auth.username == APP_USER and auth.password == APP_PASS


# ---- Session token auth (untuk WebSocket, yang tidak memicu prompt browser) ----
import secrets
SESSION_TOKENS = set()


@app.route("/api/session", methods=["POST"])
def new_session():
    """Tukar basic-auth yang valid menjadi token sesi sekali-pakai."""
    if not check_auth():
        return Response("Auth required", 401, {"WWW-Authenticate": "Basic realm=ServerMonitor"})
    tok = secrets.token_urlsafe(24)
    SESSION_TOKENS.add(tok)
    return {"token": tok}


def ws_authorized():
    """Auth untuk WebSocket: token sesi via query ?t=, atau basic-auth."""
    if check_auth():
        return True
    tok = request.args.get("t", "")
    return tok in SESSION_TOKENS


from filemanager import fm_bp  # noqa: E402 — register /api/fs/* routes
app.register_blueprint(fm_bp)
from novncproxy import vnc_bp, bridge  # noqa: E402 — register /novnc/* static + WS bridge
app.register_blueprint(vnc_bp)

# noVNC meminta subprotocol "binary"; simple-websocket harus meng-echo-nya
# di handshake, kalau tidak browser menutup koneksi (onerror).
app.config["SOCK_SERVER_OPTIONS"] = {"subprotocols": ["binary"]}


@sock.route("/novnc/websockify")
def novnc_ws(ws):
    """WebSocket noVNC — auth token/basic dulu, lalu bridge ke websockify."""
    if not ws_authorized():
        try: ws.send("AUTH_REQUIRED")
        except Exception: pass
        return
    bridge(ws)


# simple-websocket default tidak meng-echo subprotocol yang diminta browser;
# noVNC menutup koneksi kalau "binary" tidak dikonfirmasi. Monkeypatch:
import simple_websocket.ws as _sw_ws
import simple_websocket as _sw
from simple_websocket import Server as _WServer


class _SubprotocolServer(_WServer):
    def choose_subprotocol(self, request):
        # request.subprotocols sudah di-parse oleh simple-websocket dari header
        if getattr(request, "subprotocols", None):
            return request.subprotocols[0]
        return None


# flask_sock melakukan `from simple_websocket import Server` — ganti symbol di kedua modul
_sw.Server = _SubprotocolServer
_sw_ws.Server = _SubprotocolServer
import flask_sock as _fsock
_fsock.Server = _SubprotocolServer


@app.route("/")
def index():
    if not check_auth():
        return Response("Auth required", 401, {"WWW-Authenticate": "Basic realm=ServerMonitor"})
    return INDEX_HTML


@app.route("/api/stats")
def stats():
    if not check_auth():
        return {"error": "unauthorized"}, 401
    cpu = psutil.cpu_percent(interval=0.3)
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage("/")
    net = psutil.net_io_counters()
    load1, load5, load15 = os.getloadavg()
    procs = sorted(psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]),
                   key=lambda p: (p.info["cpu_percent"] or 0), reverse=True)[:8]
    try:
        temps = psutil.sensors_temperatures() if hasattr(psutil, "sensors_temperatures") else {}
        temp = next((t.current for v in temps.values() for t in v), None)
    except Exception:
        temp = None
    boot = psutil.boot_time()
    return {
        "hostname": socket.gethostname(),
        "uptime_h": round((time.time() - boot) / 3600, 1),
        "cpu": cpu, "load": [round(load1, 2), round(load5, 2), round(load15, 2)],
        "mem": {"used": mem.used, "total": mem.total, "pct": mem.percent},
        "swap": {"used": swap.used, "total": swap.total, "pct": swap.percent},
        "disk": {"used": disk.used, "total": disk.total, "pct": disk.percent},
        "net": {"sent": net.bytes_sent, "recv": net.bytes_recv},
        "temp": temp,
        "top": [{"pid": p.info["pid"], "name": p.info["name"],
                 "cpu": p.info["cpu_percent"] or 0, "mem": round(p.info["memory_percent"] or 0, 1)}
                for p in procs],
    }


@sock.route("/ws/ssh")
def ssh_ws(ws):
    if not ws_authorized():
        # Kirim penanda jelas sebelum tutup, supaya UI tahu ini masalah login
        try: ws.send("[AUTH_FAILED] Sesi tidak sah — refresh halaman dan login ulang.\r\n")
        except Exception: pass
        return
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(SSH_HOST, port=SSH_PORT, username=SSH_USER,
                       pkey=paramiko.Ed25519Key.from_private_key_file(
                           os.path.expanduser(os.environ.get("SSH_KEY", "~/.ssh/id_ed25519"))),
                       timeout=8)
    except Exception as e:
        ws.send(f"\r\n[SSH connect failed: {e}]\r\n")
        return
    transport = client.get_transport()
    chan = transport.open_session()
    chan.get_pty(term="xterm-256color", width=120, height=32)
    chan.invoke_shell()
    import threading

    def reader():
        while True:
            if chan.recv_ready():
                ws.send(chan.recv(4096).decode("utf-8", "replace"))
            if chan.exit_status_ready() or not transport.is_active():
                break
            time.sleep(0.05)
        try: ws.send("\r\n[session closed]\r\n")
        except Exception: pass

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    while True:
        try:
            data = ws.receive(timeout=1)
        except Exception:
            break
        if data is None:
            continue
        msg = json.loads(data) if data.startswith("{") else {"d": data}
        if "r" in msg:  # resize
            chan.resize_pty(width=msg["r"]["c"], height=msg["r"]["r"])
        elif "d" in msg:
            chan.send(msg["d"])
    chan.close(); client.close()


import traceback


# route /ws/ssh kedua (wrapper logging) dihapus — satu route saja, jangan dobel.


INDEX_HTML = r"""<!doctype html>
<html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Server Monitor</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;600&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
:root{--bg:#0a0d10;--panel:#12171c;--line:#202830;--txt:#d7dfe6;--dim:#7c8a95;--ac:#9dce6a;--warn:#e0b34c;--err:#e06c5c;--acdim:#3a4a30}
*{box-sizing:border-box;margin:0}
html{-webkit-text-size-adjust:100%}
body{background:var(--bg);color:var(--txt);font:14px/1.5 "JetBrains Mono",ui-monospace,Menlo,monospace;padding:20px 20px 40px;max-width:1080px;margin:0 auto}
h1{font-family:"Space Grotesk",sans-serif;font-size:20px;font-weight:600;letter-spacing:-.01em;display:flex;align-items:center;gap:10px;margin-bottom:6px}
h1 .mark{color:var(--ac)}
.statusline{display:flex;align-items:center;gap:8px;color:var(--dim);font-size:12px;margin-bottom:18px}
.pill{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);border-radius:99px;padding:2px 10px;font-size:11px}
.pill i{width:7px;height:7px;border-radius:50%;background:var(--ac);display:inline-block}
.pill.err i{background:var(--err)}.pill.warn i{background:var(--warn)}
.tabs{display:flex;gap:8px;margin-bottom:16px;border-bottom:1px solid var(--line)}
.tab{background:none;border:none;border-bottom:2px solid transparent;color:var(--dim);padding:10px 4px;margin-bottom:-1px;cursor:pointer;font:inherit;font-size:13px}
.tab:hover{color:var(--txt)}
.tab.on{color:var(--txt);border-bottom-color:var(--ac)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px;margin-bottom:14px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}
.panel h3{font-size:11px;text-transform:uppercase;color:var(--dim);letter-spacing:.1em;margin-bottom:10px}
.big{font-size:30px;font-weight:700;font-variant-numeric:tabular-nums;letter-spacing:-.02em}
.unit{font-size:14px;color:var(--dim);font-weight:400;margin-left:2px}
.bar{height:6px;background:var(--line);border-radius:3px;margin-top:10px;overflow:hidden}
.bar i{display:block;height:100%;background:var(--ac);width:0;transition:width .6s ease}
.sub{color:var(--dim);font-size:12px;margin-top:8px}
.spark{margin-top:10px;display:block;width:100%;height:34px}
table{width:100%;border-collapse:collapse;font-size:12.5px}
td,th{padding:8px 8px;text-align:left;border-bottom:1px solid var(--line)}
tbody tr:last-child td{border-bottom:none}
th{color:var(--dim);font-weight:400;text-transform:uppercase;font-size:10px;letter-spacing:.08em}
td.num{text-align:right;font-variant-numeric:tabular-nums}
th.num{text-align:right}
#term{height:440px;border-radius:10px;overflow:hidden;border:1px solid var(--line);background:#0b0e11;padding:8px}
#term .xterm,#term .xterm .xterm-viewport{height:100%!important}
#term .xterm-screen{height:auto!important}
.hidden{display:none}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
.tab:focus-visible,.tab:focus-visible{outline:2px solid var(--ac);outline-offset:2px}
@media(max-width:640px){#term{height:320px}body{padding:12px 12px 32px}.big{font-size:24px}}
.btn{background:var(--panel);border:1px solid var(--line);color:var(--txt);padding:7px 12px;border-radius:6px;cursor:pointer;font:inherit;font-size:12px;white-space:nowrap}
.btn:hover{border-color:var(--ac);color:var(--ac)}
.btn.danger:hover{border-color:var(--err);color:var(--err)}
.fmbar{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px;align-items:center}
.fmpath{flex:1;min-width:180px;background:var(--panel);border:1px solid var(--line);color:var(--txt);padding:7px 10px;border-radius:6px;font:inherit;font-size:12px}
.fmtext{width:100%;height:420px;background:var(--panel);border:1px solid var(--line);color:var(--txt);padding:12px;border-radius:8px;font:13px/1.6 "JetBrains Mono",monospace;resize:vertical}
.fmname{color:var(--txt);cursor:pointer;background:none;border:none;font:inherit;font-size:12.5px;text-align:left;padding:0}
.fmname:hover{color:var(--ac);text-decoration:underline}
.fmact{display:flex;gap:4px;justify-content:flex-end}
</style></head><body>
<h1><span class="mark">▸</span><span id="hn">Server</span><span style="color:var(--dim);font-weight:400">Monitor</span></h1>
<div class="statusline">
  <span class="pill" id="live"><i></i>live</span>
  <span id="clock"></span>
</div>
<div class="tabs" role="tablist">
  <button class="tab on" data-t="dash" role="tab">Monitoring</button>
  <button class="tab" data-t="files" role="tab">File Manager</button>
  <button class="tab" data-t="ssh" role="tab">Web SSH</button>
  <button class="tab" data-t="desktop" role="tab">Desktop</button>
</div>
<div id="dash" role="tabpanel">
  <div class="grid">
    <div class="panel"><h3>CPU</h3><div class="big"><span id="cpu">–</span><span class="unit">%</span></div><div class="bar"><i id="cpuB"></i></div><canvas class="spark" id="cpuSpark"></canvas><div class="sub" id="load"></div></div>
    <div class="panel"><h3>Memory</h3><div class="big"><span id="mem">–</span><span class="unit">%</span></div><div class="bar"><i id="memB"></i></div><div class="sub" id="memS"></div></div>
    <div class="panel"><h3>Disk /</h3><div class="big"><span id="disk">–</span><span class="unit">%</span></div><div class="bar"><i id="diskB"></i></div><div class="sub" id="diskS"></div></div>
    <div class="panel"><h3>Uptime</h3><div class="big"><span id="up">–</span><span class="unit">jam</span></div><div class="sub" id="temp"></div><div class="sub" id="swap"></div></div>
    <div class="panel"><h3>Network total</h3><div class="big"><span id="net">–</span><span class="unit">↓</span></div><div class="sub" id="nets"></div></div>
  </div>
  <div class="panel"><h3>Proses teratas · CPU</h3><table><thead><tr><th>PID</th><th>Nama</th><th class="num">CPU %</th><th class="num">MEM %</th></tr></thead><tbody id="top"></tbody></table></div>
</div>
<div id="files" class="hidden" role="tabpanel">
  <div class="fmbar">
    <button class="btn" id="fmUp">↑ Naik</button>
    <input id="fmPath" class="fmpath" spellcheck="false" placeholder="/path/ke/folder">
    <button class="btn" id="fmGo">Buka</button>
    <button class="btn" id="fmNewFile">+ File</button>
    <button class="btn" id="fmNewDir">+ Folder</button>
    <button class="btn" id="fmUpload">⤒ Upload</button>
    <input type="file" id="fmFile" class="hidden" multiple>
  </div>
  <div id="fmMsg" class="sub" style="min-height:18px"></div>
  <div class="panel"><table><thead><tr><th style="width:40%">Nama</th><th>Ukuran</th><th>Diubah</th><th style="width:170px"></th></tr></thead><tbody id="fmList"></tbody></table></div>
</div>
<div id="fmEditor" class="hidden">
  <div class="fmbar">
    <span id="fmEdPath" class="sub" style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"></span>
    <button class="btn" id="fmSave">💾 Simpan</button>
    <button class="btn" id="fmClose">Tutup</button>
  </div>
  <textarea id="fmText" class="fmtext" spellcheck="false"></textarea>
</div>
<div id="ssh" class="hidden" role="tabpanel">
  <div id="term"></div>
</div>
<div id="desktop" class="hidden" role="tabpanel">
  <div class="fmbar">
    <span class="sub" style="flex:1">Desktop LXQt via noVNC — password VNC: sama dengan login dashboard</span>
    <button class="btn" id="vncFull">Layar penuh ⛶</button>
  </div>
  <iframe id="vncFrame" src="about:blank" style="width:100%;height:640px;border:1px solid var(--line);border-radius:10px;background:#0b0e11"></iframe>
</div>
<script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.min.css">
<script>
const fmt=b=>b>1073741824?(b/1073741824).toFixed(1)+' GB':(b/1048576).toFixed(0)+' MB';
const $=id=>document.getElementById(id);
const col=(p,el)=>{el.style.width=p+'%';el.style.background=p>85?'var(--err)':p>60?'var(--warn)':'var(--ac)'};
const hist=[];
function spark(){
  const c=$('cpuSpark');const w=c.clientWidth,h=34;c.width=w*2;c.height=h*2;
  const g=c.getContext('2d');g.scale(2,2);g.clearRect(0,0,w,h);
  if(hist.length<2)return;
  g.beginPath();
  hist.forEach((v,i)=>{const x=i/(hist.length-1)*w,y=h-2-(v/100)*(h-6);i?g.lineTo(x,y):g.moveTo(x,y)});
  g.strokeStyle='#9dce6a';g.lineWidth=1.5;g.stroke();
  g.lineTo(w,h);g.lineTo(0,h);g.closePath();
  g.fillStyle='rgba(157,206,106,.12)';g.fill();
}
async function poll(){
  try{
    const s=await (await fetch('/api/stats')).json();
    $('hn').textContent=s.hostname;
    $('cpu').textContent=s.cpu;col(s.cpu,$('cpuB'));
    hist.push(s.cpu);if(hist.length>60)hist.shift();spark();
    $('load').textContent='load '+s.load.join(' / ');
    $('mem').textContent=s.mem.pct;col(s.mem.pct,$('memB'));
    $('memS').textContent=fmt(s.mem.used)+' / '+fmt(s.mem.total);
    $('disk').textContent=s.disk.pct;col(s.disk.pct,$('diskB'));
    $('diskS').textContent=fmt(s.disk.used)+' / '+fmt(s.disk.total);
    $('up').textContent=s.uptime_h;
    $('temp').textContent=s.temp?s.temp.toFixed(0)+'°C':'';
    $('swap').textContent='swap '+s.swap.pct+'%';
    $('net').textContent='↓ '+fmt(s.net.recv);
    $('nets').textContent='↑ '+fmt(s.net.sent);
    $('top').innerHTML=s.top.map(p=>`<tr><td>${p.pid}</td><td>${p.name}</td><td class="num">${p.cpu}</td><td class="num">${p.mem}</td></tr>`).join('');
    const p=s.cpu>85||s.disk.pct>90?'err':s.cpu>60?'warn':'';
    $('live').className='pill '+p;
    $('clock').textContent=new Date().toLocaleTimeString('id-ID');
  }catch(e){$('live').className='pill err';$('clock').textContent='koneksi terputus'}
}
setInterval(poll,3000);poll();

document.querySelectorAll('.tab').forEach(t=>t.onclick=()=>{
  document.querySelectorAll('.tab').forEach(x=>{x.classList.remove('on');x.setAttribute('aria-selected','false')});
  t.classList.add('on');t.setAttribute('aria-selected','true');
  ['dash','files','ssh','desktop'].forEach(id=>document.getElementById(id).classList.toggle('hidden',t.dataset.t!==id));
  document.getElementById('fmEditor').classList.add('hidden');
  if(t.dataset.t==='files'&&!window._fmInit){window._fmInit=1;initFM();}
  if(t.dataset.t==='ssh'&&!window._sshInit){window._sshInit=1;initSSH();}
  if(t.dataset.t==='desktop'&&!window._vncInit){window._vncInit=1;
    const f=document.getElementById('vncFrame');
    const load=(q)=>{f.src='/novnc/vnc.html?path=/novnc/websockify'+q+'&autoconnect=1&resize=scale';};
    fetch('/api/session',{method:'POST'}).then(r=>r.ok?r.json():null)
      .then(j=>load(j?'%3Ft%3D'+encodeURIComponent(j.token):''))
      .catch(()=>load(''));
    document.getElementById('vncFull').onclick=()=>f.requestFullscreen&&f.requestFullscreen();
  }
});

/* ===== File Manager ===== */
let fmCur='/';
const fmE=async(p,opt)=>{const r=await fetch(p,opt);const j=await r.json().catch(()=>({error:'gagal'}));if(!r.ok||j.error){fmMsg(j.error||'error '+r.status);throw j}return j};
const fmMsg=m=>{document.getElementById('fmMsg').textContent=m||''};
function fmFmtSize(b){if(b===0)return'0 B';const u=['B','KB','MB','GB','TB'];let i=0;while(b>=1024&&i<4){b/=1024;i++}return b.toFixed(b<10&&i>0?1:0)+' '+u[i]}
function fmFmtTime(t){return new Date(t*1000).toLocaleString('id-ID',{day:'2-digit',month:'short',year:'2-digit',hour:'2-digit',minute:'2-digit'})}
async function fmLoad(path){
  try{
    const j=await fmE('/api/fs/list?path='+encodeURIComponent(path||'/'));
    fmCur=j.path;fmPath.value=j.path;fmMsg('');
    const rows=j.items.map(it=>{
      const icon=it.dir?'📁':'📄';
      return `<tr>
        <td><button class="fmname" data-p="${it.dir?1:0}" data-n="${encodeURIComponent(it.name)}">${icon} ${it.name}</button></td>
        <td>${it.dir?'—':fmFmtSize(it.size)}</td>
        <td class="sub">${fmFmtTime(it.mtime)}</td>
        <td><div class="fmact">
          ${!it.dir?'<button class="btn" data-act="view" data-n="'+encodeURIComponent(it.name)+'">Lihat</button>':''}
          <button class="btn" data-act="ren" data-n="${encodeURIComponent(it.name)}">Rename</button>
          <button class="btn danger" data-act="del" data-n="${encodeURIComponent(it.name)}">Hapus</button>
        </div></td></tr>`;
    }).join('');
    document.getElementById('fmList').innerHTML=rows||'<tr><td colspan="4" class="sub">folder kosong</td></tr>';
  }catch(e){}
}
async function fmView(name){
  const p=(fmCur==='/'?'':fmCur)+'/'+name;
  try{
    const j=await fmE('/api/fs/read?path='+encodeURIComponent(p));
    if(j.kind==='image'){
      document.getElementById('fmEdPath').textContent=p;
      document.getElementById('fmText').value='[gambar] preview: '+location.origin+'/api/fs/image?path='+encodeURIComponent(p);
      document.getElementById('fmSave').disabled=true;
    }else{
      document.getElementById('fmText').value=j.content;
      document.getElementById('fmSave').disabled=false;
    }
    document.getElementById('fmEdPath').textContent=p;
    document.getElementById('fmEditor').classList.remove('hidden');
    window.scrollTo(0,0);
  }catch(e){}
}
function initFM(){
  fmLoad('/');
  const $=id=>document.getElementById(id);
  $('fmGo').onclick=()=>fmLoad($('fmPath').value);
  $('fmPath').onkeydown=e=>{if(e.key==='Enter')fmLoad($('fmPath').value)};
  $('fmUp').onclick=()=>fmLoad(fmCur.replace(/\/[^/]*$/,'')||'/');
  $('fmNewFile').onclick=async()=>{
    const n=prompt('Nama file baru:');if(!n)return;
    await fmE('/api/fs/write',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:fmCur+'/'+n,content:''})});
    fmLoad(fmCur);
  };
  $('fmNewDir').onclick=async()=>{
    const n=prompt('Nama folder baru:');if(!n)return;
    await fmE('/api/fs/mkdir',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:fmCur+'/'+n})});
    fmLoad(fmCur);
  };
  $('fmUpload').onclick=()=>$('fmFile').click();
  $('fmFile').onchange=async()=>{
    for(const f of $('fmFile').files){
      const b64=await new Promise(res=>{const r=new FileReader();r.onload=()=>res(r.result.split(',')[1]);r.readAsDataURL(f)});
      await fmE('/api/fs/write',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:fmCur+'/'+f.name,content:b64,b64:true})});
    }
    $('fmFile').value='';fmLoad(fmCur);
  };
  $('fmSave').onclick=async()=>{
    const p=$('fmEdPath').textContent;
    await fmE('/api/fs/write',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:p,content:$('fmText').value})});
    fmMsg('tersimpan ✓');setTimeout(fmMsg,1500);
  };
  $('fmClose').onclick=()=>{document.getElementById('fmEditor').classList.add('hidden');fmLoad(fmCur)};
  document.getElementById('fmList').addEventListener('click',async e=>{
    const name=e.target.dataset.n;if(!name)return;
    const act=e.target.dataset.act;
    if(e.target.classList.contains('fmname')){
      if(e.target.dataset.p==='1')fmLoad(fmCur+'/'+name);
      else fmView(name);
      return;
    }
    if(act==='view')fmView(name);
    if(act==='ren'){
      const nn=prompt('Nama baru:',decodeURIComponent(name));if(!nn||nn===name)return;
      await fmE('/api/fs/rename',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({src:fmCur+'/'+name,dst:fmCur+'/'+nn})});
      fmLoad(fmCur);
    }
    if(act==='del'){
      if(!confirm('Hapus '+decodeURIComponent(name)+'?'))return;
      await fmE('/api/fs/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:fmCur+'/'+name})});
      fmLoad(fmCur);
    }
  });
}
async function initSSH(){
  const term=new Terminal({cursorBlink:true,fontFamily:'JetBrains Mono,Menlo,monospace',fontSize:14,theme:{background:'#0b0e11'},scrollback:2000});
  term.open(document.getElementById('term'));
  // fit terminal ke tinggi container (biar baris bawah tidak terpotong)
  const fit=()=>{try{
    const el=document.getElementById('term');
    const availH=el.clientHeight-16, availW=el.clientWidth-16;
    const lh=Math.ceil(14*1.4), cw=Math.ceil(term._core._renderService.dimensions.css.cell.width)||8;
    term.resize(Math.max(20,Math.floor(availW/cw)), Math.max(8,Math.floor(availH/lh)));
  }catch(e){}};
  fit();
  window.addEventListener('resize',()=>{fit();try{ws.readyState===1&&ws.send(JSON.stringify({r:{c:term.cols,r:term.rows}}))}catch(e){}});
  term.writeln('Menghubungkan…');
  let token='';
  try{
    const r=await fetch('/api/session',{method:'POST',cache:'no-store'});
    if(r.status===401){
      // basic auth invalid → paksa browser minta kredensial, lalu coba lagi
      await fetch('/api/stats?reauth='+Date.now(),{cache:'no-store'});
      const r2=await fetch('/api/session',{method:'POST',cache:'no-store'});
      token=(await r2.json()).token||'';
    }else{
      token=(await r.json()).token||'';
    }
  }catch(e){}
  if(!token){term.writeln('[AUTH_FAILED] Gagal otorisasi — refresh halaman.');return;}
  const proto=(location.protocol==='https:')?'wss://':'ws://';
  const ws=new WebSocket(proto+location.host+'/ws/ssh?t='+encodeURIComponent(token));
  ws.onopen=()=>{term.clear();term.focus()};
  // kirim ukuran pty setelah open & setelah connect agar sesuai
  setTimeout(()=>{try{ws.readyState===1&&ws.send(JSON.stringify({r:{c:term.cols,r:term.rows}}))}catch(e){}},300);
  ws.onmessage=e=>{
    term.write(e.data);
    if(e.data.includes('[AUTH_FAILED]')){
      term.writeln('\r\n[Kredensial ditolak — refresh halaman & login ulang]');
    }
  };
  term.onData(d=>ws.send(JSON.stringify({d})));
  new ResizeObserver(()=>{fit();try{ws.readyState===1&&ws.send(JSON.stringify({r:{c:term.cols,r:term.rows}}))}catch(e){}}).observe(document.getElementById('term'));
}
</script></body></html>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
