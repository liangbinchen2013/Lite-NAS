import os
import hashlib
import secrets
import time
import re
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse, unquote, quote
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
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

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


def load_template(name):
    path = os.path.join(TEMPLATES_DIR, f"{name}.html")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


LOGIN_HTML = ""


def get_file_ext_type(name):
    ext = os.path.splitext(name)[1].lower()
    type_map = {
        ".cpp": ("cpp", "C++ Source File"),
        ".c": ("c", "C Source File"),
        ".h": ("h", "Header File"),
        ".py": ("py", "Python File"),
        ".js": ("js", "JavaScript File"),
        ".html": ("html", "HTML File"),
        ".css": ("css", "CSS File"),
        ".json": ("json", "JSON File"),
        ".txt": ("txt", "Text File"),
        ".md": ("md", "Markdown File"),
        ".exe": ("exe", "Application"),
        ".msi": ("msi", "Installer"),
        ".zip": ("zip", "ZIP Archive"),
        ".rar": ("rar", "RAR Archive"),
        ".7z": ("7z", "7-Zip Archive"),
        ".jpg": ("jpg", "JPEG Image"),
        ".jpeg": ("jpeg", "JPEG Image"),
        ".png": ("png", "PNG Image"),
        ".gif": ("gif", "GIF Image"),
        ".bmp": ("bmp", "Bitmap Image"),
        ".mp3": ("mp3", "MP3 Audio"),
        ".mp4": ("mp4", "MP4 Video"),
        ".avi": ("avi", "AVI Video"),
        ".mkv": ("mkv", "MKV Video"),
        ".doc": ("doc", "Word Document"),
        ".docx": ("docx", "Word Document"),
        ".xls": ("xls", "Excel Spreadsheet"),
        ".xlsx": ("xlsx", "Excel Spreadsheet"),
        ".ppt": ("ppt", "PowerPoint Presentation"),
        ".pptx": ("pptx", "PowerPoint Presentation"),
        ".pdf": ("pdf", "PDF Document"),
        ".in": ("in", "IN File"),
        ".out": ("out", "OUT File"),
        ".log": ("log", "Log File"),
        ".xml": ("xml", "XML File"),
        ".yaml": ("yaml", "YAML File"),
        ".yml": ("yml", "YAML File"),
        ".toml": ("toml", "TOML File"),
        ".sh": ("sh", "Shell Script"),
        ".bat": ("bat", "Batch File"),
        ".cmd": ("cmd", "Command File"),
        ".java": ("java", "Java File"),
        ".rs": ("rs", "Rust File"),
        ".go": ("go", "Go File"),
        ".ts": ("ts", "TypeScript File"),
        ".tsx": ("tsx", "TypeScript React File"),
        ".jsx": ("jsx", "React File"),
        ".vue": ("vue", "Vue File"),
        ".sql": ("sql", "SQL File"),
        ".csv": ("csv", "CSV File"),
    }
    if ext in type_map:
        return type_map[ext]
    return ("file", ext.upper().lstrip(".") + " File" if ext else "File")


def get_file_list_html(username):
    files = []
    if os.path.exists(STORAGE_DIR):
        for f in sorted(os.listdir(STORAGE_DIR)):
            fp = os.path.join(STORAGE_DIR, f)
            if os.path.isfile(fp):
                size = os.path.getsize(fp)
                mtime = os.path.getmtime(fp)
                date_str = time.strftime("%Y/%m/%d %H:%M", time.localtime(mtime))
                _, type_name = get_file_ext_type(f)
                files.append((f, format_size(size), date_str, type_name))

    total_size = get_dir_size(STORAGE_DIR)

    file_rows = ""
    for name, size, date, type_name in files:
        encoded_name = name.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        url_name = quote(name)
        file_rows += f"""
        <tr>
          <td><a href="/download/{url_name}" class="file-link">{encoded_name}</a></td>
          <td>{date}</td>
          <td>{type_name}</td>
          <td>{size}</td>
          <td class="action-cell">
            <a href="/download/{url_name}" class="btn btn-download" title="下载">下载</a>
            <form method="POST" action="/delete" style="display:inline" onsubmit="return confirm('确定删除 {encoded_name} 吗？')">
              <input type="hidden" name="filename" value="{url_name}">
              <button type="submit" class="btn btn-delete" title="删除">删除</button>
            </form>
          </td>
        </tr>"""

    if not files:
        file_rows = '<tr><td colspan="5" class="empty">暂无文件，请上传</td></tr>'

    html = load_template("index")
    return html.replace("{{username}}", username).replace("{{storage}}", format_size(total_size)).replace("{{file_rows}}", file_rows)


class NASHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def handle(self):
        try:
            super().handle()
        except ConnectionAbortedError:
            pass
        except BrokenPipeError:
            pass
        except Exception:
            pass

    def send_html(self, html, status=200):
        try:
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))
        except (ConnectionAbortedError, BrokenPipeError):
            pass

    def send_redirect(self, location):
        try:
            self.send_response(302)
            self.send_header("Location", location)
            self.end_headers()
        except (ConnectionAbortedError, BrokenPipeError):
            pass

    def send_text(self, text, status=200):
        try:
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(text.encode("utf-8"))
        except (ConnectionAbortedError, BrokenPipeError):
            pass

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
            login_html = load_template("login")
            error_html = login_html.replace("</form>", '<p class="error">用户名或密码错误</p></form>')
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

        try:
            mime, _ = mimetypes.guess_type(filename)
            if mime is None:
                mime = "application/octet-stream"

            encoded_filename = quote(filename)
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{encoded_filename}")
            self.send_header("Content-Length", str(os.path.getsize(filepath)))
            self.end_headers()

            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
        except (ConnectionAbortedError, BrokenPipeError):
            pass
        except Exception as e:
            print(f"Download error: {e}")

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
            self.send_html(load_template("login"))
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
