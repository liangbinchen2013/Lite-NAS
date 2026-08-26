import os
import hashlib
import secrets
import time
import re
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse, unquote
import mimetypes


def parse_multipart(content_type, body):
    boundary = None
    m = re.search(r'boundary=(.+)', content_type)
    if m:
        boundary = m.group(1).strip()
    if not boundary:
        return None, None

    boundary_bytes = boundary.encode()
    parts = body.split(b'--' + boundary_bytes)
    filename = None
    file_data = None

    for part in parts:
        if b'Content-Disposition' not in part:
            continue
        header_end = part.find(b'\r\n\r\n')
        if header_end == -1:
            continue
        headers_raw = part[:header_end].decode('utf-8', errors='replace')
        data = part[header_end + 4:]
        if data.endswith(b'\r\n'):
            data = data[:-2]

        name_match = re.search(r'name="([^"]+)"', headers_raw)
        fname_match = re.search(r'filename="([^"]+)"', headers_raw)
        if fname_match and name_match and name_match.group(1) == 'file':
            filename = fname_match.group(1)
            file_data = data
            break

    return filename, file_data


HOST = "127.0.0.1"
PORT = 8888
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STORAGE_DIR = os.path.join(BASE_DIR, "storage")
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")

sessions = {}


def load_config():
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"username": "", "password": ""}


def md5_hash(password):
    return hashlib.md5(password.encode()).hexdigest()


def verify_user(username, password):
    config = load_config()
    return (username == config["username"] and 
            md5_hash(password) == config["password"])


def create_session_token(username):
    token = secrets.token_hex(32)
    sessions[token] = {"username": username, "time": time.time()}
    return token


def is_valid_session(token):
    if token and token in sessions:
        if time.time() - sessions[token]["time"] < 86400:
            sessions[token]["time"] = time.time()
            return True, sessions[token]["username"]
        else:
            del sessions[token]
    return False, None


def generate_session_cookie(token):
    return f"session={token}; Path=/; HttpOnly; SameSite=Strict"


def get_dir_size(path):
    total = 0
    if os.path.exists(path):
        for dirpath, dirnames, filenames in os.walk(path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                if os.path.isfile(fp):
                    total += os.path.getsize(fp)
    return total


def format_size(size):
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    elif size < 1024 * 1024 * 1024:
        return f"{size / (1024*1024):.1f} MB"
    else:
        return f"{size / (1024*1024*1024):.1f} GB"


LOGIN_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Lite-NAS - Login</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #e2e8f0; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
.login-box { background: #1e293b; border-radius: 16px; padding: 48px 40px; width: 380px; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5); }
h1 { font-size: 24px; margin-bottom: 8px; color: #f8fafc; }
.subtitle { color: #94a3b8; margin-bottom: 32px; font-size: 14px; }
.form-group { margin-bottom: 20px; }
label { display: block; margin-bottom: 6px; font-size: 14px; color: #cbd5e1; }
input[type="text"], input[type="password"] { width: 100%; padding: 12px 16px; background: #0f172a; border: 1px solid #334155; border-radius: 8px; color: #f8fafc; font-size: 16px; outline: none; transition: border-color 0.2s; }
input[type="text"]:focus, input[type="password"]:focus { border-color: #3b82f6; }
button { width: 100%; padding: 12px; background: #3b82f6; color: white; border: none; border-radius: 8px; font-size: 16px; cursor: pointer; transition: background 0.2s; }
button:hover { background: #2563eb; }
.error { color: #f87171; margin-bottom: 16px; font-size: 14px; text-align: center; }
</style>
</head>
<body>
<div class="login-box">
  <h1>Lite-NAS</h1>
  <p class="subtitle">请输入用户名和密码以访问文件管理</p>
  <form method="POST" action="/login">
    <div class="form-group">
      <label for="username">用户名</label>
      <input type="text" id="username" name="username" placeholder="请输入用户名" autofocus>
    </div>
    <div class="form-group">
      <label for="password">密码</label>
      <input type="password" id="password" name="password" placeholder="请输入密码">
    </div>
    <button type="submit">登录</button>
  </form>
</div>
</body>
</html>"""


def get_file_list_html(username):
    files = []
    if os.path.exists(STORAGE_DIR):
        for f in sorted(os.listdir(STORAGE_DIR)):
            fp = os.path.join(STORAGE_DIR, f)
            if os.path.isfile(fp):
                size = os.path.getsize(fp)
                mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(fp)))
                files.append((f, format_size(size), mtime))

    total_size = get_dir_size(STORAGE_DIR)
    file_count = len(files)

    file_rows = ""
    for name, size, mtime in files:
        encoded_name = name.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        file_rows += f"""
        <tr>
          <td class="name-cell">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
            <a href="/download/{unquote(name)}" class="file-link">{encoded_name}</a>
          </td>
          <td>{size}</td>
          <td>{mtime}</td>
          <td class="action-cell">
            <a href="/download/{unquote(name)}" class="btn btn-download" title="下载">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            </a>
            <form method="POST" action="/delete" style="display:inline" onsubmit="return confirm('确定删除 {encoded_name} 吗？')">
              <input type="hidden" name="filename" value="{unquote(name)}">
              <button type="submit" class="btn btn-delete" title="删除">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
              </button>
            </form>
          </td>
        </tr>"""

    if not files:
        file_rows = '<tr><td colspan="4" class="empty">暂无文件，请上传</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Lite-NAS</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }}
.container {{ max-width: 960px; margin: 0 auto; padding: 32px 24px; }}
header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 32px; }}
.header-left {{ display: flex; align-items: center; gap: 16px; }}
header h1 {{ font-size: 28px; color: #f8fafc; }}
.user-info {{ color: #94a3b8; font-size: 14px; padding: 6px 12px; background: #0f172a; border-radius: 6px; }}
.logout {{ color: #94a3b8; text-decoration: none; font-size: 14px; padding: 8px 16px; border: 1px solid #334155; border-radius: 8px; transition: all 0.2s; }}
.logout:hover {{ color: #f8fafc; border-color: #64748b; }}
.storage-card {{ background: #1e293b; border-radius: 12px; padding: 20px 24px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; }}
.storage-label {{ color: #94a3b8; font-size: 14px; }}
.storage-value {{ color: #f8fafc; font-size: 24px; font-weight: 600; }}
.upload-zone {{ background: #1e293b; border: 2px dashed #334155; border-radius: 12px; padding: 40px; text-align: center; margin-bottom: 24px; transition: all 0.2s; cursor: pointer; }}
.upload-zone:hover, .upload-zone.dragover {{ border-color: #3b82f6; background: #1e293b; }}
.upload-zone p {{ color: #94a3b8; margin-top: 12px; font-size: 14px; }}
.upload-icon {{ color: #64748b; }}
input[type="file"] {{ display: none; }}
.upload-btn {{ display: inline-block; padding: 10px 24px; background: #3b82f6; color: white; border: none; border-radius: 8px; font-size: 14px; cursor: pointer; margin-top: 16px; transition: background 0.2s; }}
.upload-btn:hover {{ background: #2563eb; }}
.file-table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 12px; overflow: hidden; }}
.file-table th {{ text-align: left; padding: 14px 20px; background: #1e293b; color: #94a3b8; font-weight: 500; font-size: 13px; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid #334155; }}
.file-table td {{ padding: 12px 20px; border-bottom: 1px solid #1e293b; font-size: 14px; }}
.file-table tr:hover td {{ background: #253348; }}
.file-table tr:last-child td {{ border-bottom: none; }}
.name-cell {{ display: flex; align-items: center; gap: 10px; }}
.file-link {{ color: #e2e8f0; text-decoration: none; transition: color 0.2s; }}
.file-link:hover {{ color: #60a5fa; }}
.empty {{ color: #64748b; text-align: center; padding: 40px 20px !important; }}
.action-cell {{ width: 80px; text-align: right; }}
.action-cell form {{ display: inline; }}
.btn {{ display: inline-flex; align-items: center; justify-content: center; width: 32px; height: 32px; border: none; border-radius: 6px; background: transparent; cursor: pointer; transition: all 0.2s; }}
.btn-download {{ color: #94a3b8; }}
.btn-download:hover {{ color: #3b82f6; background: rgba(59,130,246,0.1); }}
.btn-delete {{ color: #94a3b8; }}
.btn-delete:hover {{ color: #f87171; background: rgba(248,113,113,0.1); }}
.progress-bar {{ display: none; height: 4px; background: #334155; border-radius: 2px; margin-top: 16px; overflow: hidden; }}
.progress-bar .fill {{ height: 100%; background: #3b82f6; border-radius: 2px; transition: width 0.3s; width: 0%; }}
.toast {{ position: fixed; top: 24px; right: 24px; padding: 12px 20px; border-radius: 8px; font-size: 14px; z-index: 1000; opacity: 0; transform: translateY(-10px); transition: all 0.3s; }}
.toast.show {{ opacity: 1; transform: translateY(0); }}
.toast.success {{ background: #065f46; color: #6ee7b7; border: 1px solid #059669; }}
.toast.error {{ background: #7f1d1d; color: #fca5a5; border: 1px solid #dc2626; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="header-left">
      <h1>Lite-NAS</h1>
      <span class="user-info">{username}</span>
    </div>
    <a href="/logout" class="logout">退出登录</a>
  </header>

  <div class="storage-card">
    <span class="storage-label">已使用空间</span>
    <span class="storage-value">{format_size(total_size)}</span>
  </div>

  <div class="upload-zone" id="uploadZone">
    <svg class="upload-icon" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
    <p>拖拽文件到此处，或点击选择文件</p>
    <input type="file" id="fileInput" multiple>
    <button class="upload-btn" onclick="document.getElementById('fileInput').click()">选择文件</button>
    <div class="progress-bar" id="progressBar"><div class="fill" id="progressFill"></div></div>
  </div>

  <table class="file-table">
    <thead>
      <tr><th>文件名</th><th>大小</th><th>修改时间</th><th style="text-align:right">操作</th></tr>
    </thead>
    <tbody>{file_rows}</tbody>
  </table>
</div>

<div class="toast" id="toast"></div>

<script>
const zone = document.getElementById('uploadZone');
const input = document.getElementById('fileInput');
const bar = document.getElementById('progressBar');
const fill = document.getElementById('progressFill');

function showToast(msg, type) {{
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast ' + type + ' show';
  setTimeout(() => t.className = 'toast', 3000);
}}

function uploadFile(file) {{
  const fd = new FormData();
  fd.append('file', file);
  const xhr = new XMLHttpRequest();
  bar.style.display = 'block';
  fill.style.width = '0%';
  xhr.upload.onprogress = e => {{ if (e.lengthComputable) fill.style.width = (e.loaded / e.total * 100) + '%'; }};
  xhr.onload = () => {{
    bar.style.display = 'none';
    if (xhr.status === 200) {{ showToast(file.name + ' 上传成功', 'success'); setTimeout(() => location.reload(), 500); }}
    else {{ showToast('上传失败: ' + xhr.responseText, 'error'); }}
  }};
  xhr.onerror = () => {{ bar.style.display = 'none'; showToast('上传出错', 'error'); }};
  xhr.open('POST', '/upload');
  xhr.send(fd);
}}

input.addEventListener('change', () => {{ for (const f of input.files) uploadFile(f); input.value = ''; }});
zone.addEventListener('dragover', e => {{ e.preventDefault(); zone.classList.add('dragover'); }});
zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
zone.addEventListener('drop', e => {{ e.preventDefault(); zone.classList.remove('dragover'); for (const f of e.dataTransfer.files) uploadFile(f); }});
</script>
</body>
</html>"""


class NASHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def send_html(self, html, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def send_redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def send_text(self, text, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(text.encode("utf-8"))

    def get_cookie(self, name):
        cookie_header = self.headers.get("Cookie", "")
        for part in cookie_header.split(";"):
            part = part.strip()
            if part.startswith(f"{name}="):
                return part[len(name) + 1:]
        return None

    def is_authenticated(self):
        token = self.get_cookie("session")
        valid, username = is_valid_session(token)
        return valid, username

    def handle_login(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")
        params = parse_qs(body)
        username = params.get("username", [""])[0]
        password = params.get("password", [""])[0]

        if verify_user(username, password):
            token = create_session_token(username)
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", generate_session_cookie(token))
            self.end_headers()
        else:
            error_html = LOGIN_HTML.replace("</form>", '<p class="error">用户名或密码错误</p></form>')
            if username:
                error_html = error_html.replace('value=""', f'value="{username}"')
            self.send_html(error_html, 401)

    def handle_upload(self):
        valid, username = self.is_authenticated()
        if not valid:
            self.send_redirect("/login")
            return

        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            self.send_text("Bad request", 400)
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        filename, file_data = parse_multipart(content_type, body)
        if filename and file_data:
            os.makedirs(STORAGE_DIR, exist_ok=True)
            filename = os.path.basename(filename)
            filepath = os.path.join(STORAGE_DIR, filename)
            with open(filepath, "wb") as f:
                f.write(file_data)
            self.send_text("OK")
        else:
            self.send_text("No file", 400)

    def handle_download(self, filename):
        valid, username = self.is_authenticated()
        if not valid:
            self.send_redirect("/login")
            return

        filepath = os.path.join(STORAGE_DIR, filename)
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            self.send_text("File not found", 404)
            return

        mime, _ = mimetypes.guess_type(filename)
        if mime is None:
            mime = "application/octet-stream"

        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(os.path.getsize(filepath)))
        self.end_headers()

        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)

    def handle_delete(self, filename):
        valid, username = self.is_authenticated()
        if not valid:
            self.send_redirect("/login")
            return

        filepath = os.path.join(STORAGE_DIR, filename)
        if os.path.exists(filepath) and os.path.isfile(filepath):
            os.remove(filepath)

        self.send_response(302)
        self.send_header("Location", "/")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/":
            valid, username = self.is_authenticated()
            if not valid:
                self.send_redirect("/login")
                return
            self.send_html(get_file_list_html(username))
        elif path == "/login":
            valid, username = self.is_authenticated()
            if valid:
                self.send_redirect("/")
                return
            self.send_html(LOGIN_HTML)
        elif path == "/logout":
            token = self.get_cookie("session")
            if token and token in sessions:
                del sessions[token]
            self.send_response(302)
            self.send_header("Location", "/login")
            self.send_header("Set-Cookie", "session=; Path=/; Max-Age=0")
            self.end_headers()
        elif path.startswith("/download/"):
            filename = unquote(path[len("/download/"):])
            self.handle_download(filename)
        else:
            self.send_text("Not found", 404)

    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/login":
            self.handle_login()
        elif path == "/upload":
            self.handle_upload()
        elif path == "/delete":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            params = parse_qs(body)
            filename = params.get("filename", [""])[0]
            self.handle_delete(filename)
        else:
            self.send_text("Not found", 404)


def main():
    os.makedirs(STORAGE_DIR, exist_ok=True)

    server = HTTPServer((HOST, PORT), NASHandler)
    print(f"Lite-NAS server running at http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        server.server_close()


if __name__ == "__main__":
    main()
