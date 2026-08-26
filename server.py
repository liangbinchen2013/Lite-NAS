import os
import hashlib
import secrets
import time
import re
import json
import shutil
from http.server import BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from http.server import HTTPServer
from urllib.parse import parse_qs, urlparse, unquote, quote
import mimetypes


CHUNK_SIZE = 65536


class LengthLimitedReader:
    def __init__(self, rfile, limit):
        self._rfile = rfile
        self._remaining = limit

    def read(self, n=-1):
        if self._remaining <= 0:
            return b''
        to_read = n if n > 0 else self._remaining
        to_read = min(to_read, self._remaining)
        chunk = self._rfile.read(to_read)
        self._remaining -= len(chunk)
        return chunk


def parse_multipart_streaming(limited_reader, boundary, target_dir):
    delimiter = b'\r\n--' + boundary.encode()
    delim_len = len(delimiter)
    buf = b''

    def read_bytes(n):
        nonlocal buf
        while len(buf) < n:
            chunk = limited_reader.read(min(CHUNK_SIZE, n - len(buf)))
            if not chunk:
                break
            buf += chunk
        result = buf[:n]
        buf = buf[n:]
        return result

    def read_until(marker):
        nonlocal buf
        while True:
            pos = buf.find(marker)
            if pos >= 0:
                result = buf[:pos + len(marker)]
                buf = buf[pos + len(marker):]
                return result
            chunk = limited_reader.read(CHUNK_SIZE)
            if not chunk:
                result = buf
                buf = b''
                return result
            buf += chunk

    initial = b'--' + boundary.encode() + b'\r\n'
    got = read_bytes(len(initial))
    if got != initial:
        return []

    files = []

    while True:
        header_data = read_until(b'\r\n\r\n')
        headers_raw = header_data[:-4].decode('utf-8', errors='replace')

        fname_match = re.search(r'filename="([^"]*)"', headers_raw)
        if not fname_match or not fname_match.group(1):
            pos = buf.find(delimiter)
            if pos >= 0:
                buf = buf[pos + delim_len:]
            else:
                while True:
                    chunk = limited_reader.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    buf += chunk
                    pos = buf.find(delimiter)
                    if pos >= 0:
                        buf = buf[pos + delim_len:]
                        break
            next_2 = read_bytes(2)
            if next_2 == b'--':
                read_bytes(2)
            break

        full_name = fname_match.group(1)

        safe_parts = []
        rejected = False
        for part in full_name.replace('\\', '/').split('/'):
            if not part or part == '.':
                continue
            if part == '..':
                rejected = True
                break
            safe_parts.append(part)

        if rejected or not safe_parts:
            while True:
                pos = buf.find(delimiter)
                if pos >= 0:
                    buf = buf[pos + delim_len:]
                    break
                chunk = limited_reader.read(CHUNK_SIZE)
                if not chunk:
                    break
                buf += chunk
            next_2 = read_bytes(2)
            if next_2 == b'--':
                read_bytes(2)
                break
            continue

        target_file = os.path.join(target_dir, *safe_parts)
        os.makedirs(os.path.dirname(target_file), exist_ok=True)
        total = 0

        with open(target_file, 'wb') as f:
            while True:
                pos = buf.find(delimiter)
                if pos >= 0:
                    data = buf[:pos]
                    if data.endswith(b'\r\n'):
                        data = data[:-2]
                    f.write(data)
                    total += len(data)
                    buf = buf[pos + delim_len:]
                    break

                write_up_to = max(0, len(buf) - delim_len)
                if write_up_to > 0:
                    f.write(buf[:write_up_to])
                    total += write_up_to
                    buf = buf[write_up_to:]

                chunk = limited_reader.read(CHUNK_SIZE)
                if not chunk:
                    data = buf
                    if data.endswith(b'\r\n'):
                        data = data[:-2]
                    f.write(data)
                    total += len(data)
                    buf = b''
                    break
                buf += chunk

        files.append(full_name)


        next_2 = read_bytes(2)
        if next_2 == b'--':
            read_bytes(2)
            break

    return files


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


def safe_path(rel_path):
    rel_path = rel_path.strip("/")
    if not rel_path:
        return STORAGE_DIR
    parts = [p for p in rel_path.split("/") if p and p != "." and p != ".."]
    fp = os.path.join(STORAGE_DIR, *parts) if parts else STORAGE_DIR
    real_storage = os.path.realpath(STORAGE_DIR)
    real_fp = os.path.realpath(fp)
    if not real_fp.startswith(real_storage):
        return None
    return fp


def get_file_ext_type(name):
    ext = os.path.splitext(name)[1].lower()
    type_map = {
        ".cpp": "C++ Source File", ".c": "C Source File", ".h": "Header File",
        ".py": "Python File", ".js": "JavaScript File", ".html": "HTML File",
        ".css": "CSS File", ".json": "JSON File", ".txt": "Text File",
        ".md": "Markdown File", ".exe": "Application", ".msi": "Installer",
        ".zip": "ZIP Archive", ".rar": "RAR Archive", ".7z": "7-Zip Archive",
        ".jpg": "JPEG Image", ".jpeg": "JPEG Image", ".png": "PNG Image",
        ".gif": "GIF Image", ".bmp": "Bitmap Image", ".mp3": "MP3 Audio",
        ".mp4": "MP4 Video", ".avi": "AVI Video", ".mkv": "MKV Video",
        ".doc": "Word Document", ".docx": "Word Document",
        ".xls": "Excel Spreadsheet", ".xlsx": "Excel Spreadsheet",
        ".ppt": "PowerPoint", ".pptx": "PowerPoint", ".pdf": "PDF Document",
        ".in": "IN File", ".out": "OUT File", ".log": "Log File",
        ".xml": "XML File", ".yaml": "YAML File", ".yml": "YAML File",
        ".toml": "TOML File", ".sh": "Shell Script", ".bat": "Batch File",
        ".java": "Java File", ".rs": "Rust File", ".go": "Go File",
        ".ts": "TypeScript File", ".sql": "SQL File", ".csv": "CSV File",
    }
    return type_map.get(ext, ext.upper().lstrip(".") + " File" if ext else "File")


def build_breadcrumb(rel_path):
    parts = [p for p in rel_path.strip("/").split("/") if p]
    crumbs = [{"name": "根目录", "path": ""}]
    acc = ""
    for p in parts:
        acc = acc + "/" + p if acc else p
        crumbs.append({"name": p, "path": acc})
    return crumbs


def get_file_list_html(username, rel_path=""):
    current_dir = safe_path(rel_path)
    if not current_dir or not os.path.isdir(current_dir):
        return None

    dirs = []
    files = []
    if os.path.exists(current_dir):
        for f in os.listdir(current_dir):
            fp = os.path.join(current_dir, f)
            if os.path.isdir(fp):
                dirs.append({"name": f, "is_dir": True, "size": get_dir_size(fp),
                             "mtime": os.path.getmtime(fp), "type": "文件夹"})
            else:
                size = os.path.getsize(fp)
                type_name = get_file_ext_type(f)
                files.append({"name": f, "is_dir": False, "size": size,
                              "mtime": os.path.getmtime(fp), "type": type_name})
    dirs.sort(key=lambda x: x["name"].lower())
    files.sort(key=lambda x: x["name"].lower())
    items = dirs + files

    total_size = get_dir_size(STORAGE_DIR)
    breadcrumb = build_breadcrumb(rel_path)

    file_rows = ""
    for item in items:
        encoded_name = item["name"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        url_name = quote(item["name"])
        date_str = time.strftime("%Y/%m/%d %H:%M", time.localtime(item["mtime"]))

        if item["is_dir"]:
            child_path = rel_path + "/" + item["name"] if rel_path else item["name"]
            url_child = quote(child_path, safe="")
            file_rows += f"""
        <tr>
          <td><a href="/folder/{url_child}" class="file-link folder-link">{encoded_name}</a></td>
          <td>{date_str}</td>
          <td>文件夹</td>
          <td>-</td>
          <td class="action-cell">
            <form method="POST" action="/delete" style="display:inline" onsubmit="return confirm('确定删除文件夹 {encoded_name} 及其所有内容吗？')">
              <input type="hidden" name="filename" value="{quote(item['name'])}">
              <input type="hidden" name="is_dir" value="1">
              <input type="hidden" name="current_path" value="{quote(rel_path, safe='')}">
              <button type="submit" class="btn btn-delete" title="删除">删除</button>
            </form>
          </td>
        </tr>"""
        else:
            file_path = rel_path + "/" + item["name"] if rel_path else item["name"]
            url_file = quote(file_path, safe="")
            file_rows += f"""
        <tr>
          <td><a href="/download/{url_file}" class="file-link">{encoded_name}</a></td>
          <td>{date_str}</td>
          <td>{item['type']}</td>
          <td>{format_size(item['size'])}</td>
          <td class="action-cell">
            <a href="/download/{url_file}" class="btn btn-download" title="下载">下载</a>
            <form method="POST" action="/delete" style="display:inline" onsubmit="return confirm('确定删除 {encoded_name} 吗？')">
              <input type="hidden" name="filename" value="{quote(item['name'])}">
              <input type="hidden" name="is_dir" value="0">
              <input type="hidden" name="current_path" value="{quote(rel_path, safe='')}">
              <button type="submit" class="btn btn-delete" title="删除">删除</button>
            </form>
          </td>
        </tr>"""

    if not items:
        file_rows = '<tr><td colspan="5" class="empty">此文件夹为空</td></tr>'

    breadcrumb_html = ""
    for i, crumb in enumerate(breadcrumb):
        if i > 0:
            breadcrumb_html += '<span class="sep">/</span>'
        if crumb["path"]:
            url_crumb = quote(crumb["path"], safe="")
            breadcrumb_html += f'<a href="/folder/{url_crumb}" class="crumb-link">{crumb["name"]}</a>'
        else:
            breadcrumb_html += f'<a href="/" class="crumb-link">{crumb["name"]}</a>'

    html = load_template("index")
    return (html.replace("{{username}}", username)
                .replace("{{storage}}", format_size(total_size))
                .replace("{{file_rows}}", file_rows)
                .replace("{{breadcrumb}}", breadcrumb_html)
                .replace("{{current_path}}", quote(rel_path, safe="")))


class NASHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def handle(self):
        try:
            self.close_connection = True
            self.handle_one_request()
        except (ConnectionAbortedError, BrokenPipeError):
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
        return is_valid_session(token)

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

        m = re.search(r'boundary=([^\s;]+)', content_type)
        if not m:
            self.send_text("No boundary", 400)
            return
        boundary = m.group(1).strip().strip('"')

        length = int(self.headers.get("Content-Length", 0))
        raw_path = self.headers.get("X-Current-Path", "")
        current_path = unquote(raw_path) if raw_path else ""
        target_dir = safe_path(current_path)
        if not target_dir:
            self.send_text("Invalid path", 400)
            return
        os.makedirs(target_dir, exist_ok=True)

        try:
            limited = LengthLimitedReader(self.rfile, length)
            files = parse_multipart_streaming(limited, boundary, target_dir)
            if not files:
                self.send_text("No file", 400)
                return
            self.send_text("OK")
        except Exception:
            self.send_text("Upload error", 500)

    def handle_download(self, filename):
        valid, username = self.is_authenticated()
        if not valid:
            self.send_redirect("/login")
            return

        filepath = safe_path(filename)
        if not filepath or not os.path.exists(filepath) or not os.path.isfile(filepath):
            self.send_text("File not found", 404)
            return

        try:
            mime, _ = mimetypes.guess_type(filepath)
            if mime is None:
                mime = "application/octet-stream"

            basename = os.path.basename(filepath)
            encoded_filename = quote(basename)
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

    def handle_delete(self):
        valid, username = self.is_authenticated()
        if not valid:
            self.send_redirect("/login")
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")
        params = parse_qs(body)
        name = params.get("filename", [""])[0]
        is_dir = params.get("is_dir", ["0"])[0] == "1"
        current_path = unquote(params.get("current_path", [""])[0])

        if not name:
            self.send_redirect(f"/folder/{quote(current_path, safe='')}" if current_path else "/")
            return

        target = safe_path(current_path + "/" + name if current_path else name)
        if target and os.path.exists(target):
            if is_dir:
                shutil.rmtree(target, ignore_errors=True)
            else:
                try:
                    os.remove(target)
                except IsADirectoryError:
                    shutil.rmtree(target, ignore_errors=True)

        redir = f"/folder/{quote(current_path, safe='')}" if current_path else "/"
        self.send_response(302)
        self.send_header("Location", redir)
        self.end_headers()

    def handle_mkdir(self):
        valid, username = self.is_authenticated()
        if not valid:
            self.send_redirect("/login")
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")
        params = parse_qs(body)
        folder_name = params.get("folder_name", [""])[0].strip()
        current_path = unquote(params.get("current_path", [""])[0])

        if folder_name and not "/" in folder_name and not "\\" in folder_name:
            target = safe_path(current_path + "/" + folder_name if current_path else folder_name)
            if target:
                os.makedirs(target, exist_ok=True)

        redir = f"/folder/{quote(current_path, safe='')}" if current_path else "/"
        self.send_response(302)
        self.send_header("Location", redir)
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/":
            valid, username = self.is_authenticated()
            if not valid:
                self.send_redirect("/login")
                return
            self.send_html(get_file_list_html(username))
        elif path.startswith("/folder/"):
            valid, username = self.is_authenticated()
            if not valid:
                self.send_redirect("/login")
                return
            rel_path = unquote(path[len("/folder/"):])
            html = get_file_list_html(username, rel_path)
            if html is None:
                self.send_redirect("/")
                return
            self.send_html(html)
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
            self.handle_delete()
        elif path == "/mkdir":
            self.handle_mkdir()
        else:
            self.send_text("Not found", 404)


def main():
    os.makedirs(STORAGE_DIR, exist_ok=True)

    class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True

    server = ThreadedHTTPServer((HOST, PORT), NASHandler)
    print(f"Lite-NAS server running at http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        server.server_close()


if __name__ == "__main__":
    main()
