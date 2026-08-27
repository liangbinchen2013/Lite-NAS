import os
import hashlib
import secrets
import time
import re
import json
import shutil
import zipfile
import tarfile
import io
import threading
import uuid
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

login_failures = {}

zip_tasks = {}
ZIP_TASKS_DIR = os.path.join(BASE_DIR, ".zip_tasks")


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


def count_files_and_size(file_list):
    count = 0
    total = 0
    for item in file_list:
        fp = safe_path(item)
        if not fp or not os.path.exists(fp):
            continue
        if os.path.isfile(fp):
            count += 1
            total += os.path.getsize(fp)
        elif os.path.isdir(fp):
            for dirpath, dirnames, filenames in os.walk(fp):
                for f in filenames:
                    fpath = os.path.join(dirpath, f)
                    if os.path.isfile(fpath):
                        count += 1
                        total += os.path.getsize(fpath)
    return count, total


def zip_create_task(file_list, compression_level, compresslevel=None, archive_type="zip"):
    task_id = str(uuid.uuid4())[:8]
    os.makedirs(ZIP_TASKS_DIR, exist_ok=True)

    def run_archive():
        task = zip_tasks[task_id]
        try:
            if archive_type == "tar":
                out_path = os.path.join(ZIP_TASKS_DIR, f"{task_id}.tar")
                with tarfile.open(out_path, 'w') as tf:
                    for item in file_list:
                        fp = safe_path(item)
                        if not fp or not os.path.exists(fp):
                            continue
                        if os.path.isfile(fp):
                            arcname = os.path.basename(item)
                            tf.add(fp, arcname=arcname)
                            task["done"] += 1
                        elif os.path.isdir(fp):
                            base_name = os.path.basename(item)
                            for dirpath, dirnames, filenames in os.walk(fp):
                                for f in filenames:
                                    fpath = os.path.join(dirpath, f)
                                    if os.path.isfile(fpath):
                                        arcname = os.path.join(base_name, os.path.relpath(fpath, fp))
                                        tf.add(fpath, arcname=arcname)
                                        task["done"] += 1
            else:
                out_path = os.path.join(ZIP_TASKS_DIR, f"{task_id}.zip")
                kwargs = {'compression': compression_level}
                if compresslevel is not None and compression_level == zipfile.ZIP_DEFLATED:
                    kwargs['compresslevel'] = compresslevel
                with zipfile.ZipFile(out_path, 'w', **kwargs) as zf:
                    for item in file_list:
                        fp = safe_path(item)
                        if not fp or not os.path.exists(fp):
                            continue
                        if os.path.isfile(fp):
                            arcname = os.path.basename(item)
                            zf.write(fp, arcname)
                            task["done"] += 1
                        elif os.path.isdir(fp):
                            base_name = os.path.basename(item)
                            for dirpath, dirnames, filenames in os.walk(fp):
                                for f in filenames:
                                    fpath = os.path.join(dirpath, f)
                                    if os.path.isfile(fpath):
                                        arcname = os.path.join(base_name, os.path.relpath(fpath, fp))
                                        zf.write(fpath, arcname)
                                        task["done"] += 1
            task["status"] = "done"
            task["out_path"] = out_path
            task["archive_type"] = archive_type
        except Exception as e:
            task["status"] = "error"
            task["error"] = str(e)

    total_files, _ = count_files_and_size(file_list)
    zip_tasks[task_id] = {
        "status": "compressing",
        "total": total_files,
        "done": 0,
        "out_path": None,
        "archive_type": archive_type,
        "error": None,
        "time": time.time()
    }
    t = threading.Thread(target=run_archive, daemon=True)
    t.start()
    return task_id


def zip_get_progress(task_id):
    task = zip_tasks.get(task_id)
    if not task:
        return None
    if time.time() - task["time"] > 600:
        del zip_tasks[task_id]
        return None
    return task


def zip_cleanup():
    now = time.time()
    expired = [k for k, v in zip_tasks.items() if now - v["time"] > 600]
    for k in expired:
        task = zip_tasks.pop(k, None)
        if task and task.get("out_path") and os.path.exists(task["out_path"]):
            try:
                os.remove(task["out_path"])
            except OSError:
                pass


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
        item_path = rel_path + "/" + item["name"] if rel_path else item["name"]
        item_path_encoded = quote(item_path, safe="")

        if item["is_dir"]:
            child_path = rel_path + "/" + item["name"] if rel_path else item["name"]
            url_child = quote(child_path, safe="")
            file_rows += f"""
        <tr data-path="{item_path_encoded}" data-is-dir="1"
            ondragover="onDragOver(event)" ondragleave="onDragLeave(event)" ondrop="onDrop(event)">
          <td><input type="checkbox" class="file-check" value="{item_path_encoded}"></td>
          <td><a href="/folder/{url_child}" class="file-link folder-link">{encoded_name}</a></td>
          <td>{date_str}</td>
          <td>文件夹</td>
          <td>-</td>
          <td class="action-cell">
            <button class="btn btn-move" onclick="showMoveForItem('{item_path_encoded}')">移动</button>
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
        <tr draggable="true" data-path="{item_path_encoded}"
            ondragstart="onDragStart(event)" ondragend="onDragEnd(event)">
          <td><input type="checkbox" class="file-check" value="{item_path_encoded}"></td>
          <td><a href="/download/{url_file}" class="file-link">{encoded_name}</a></td>
          <td>{date_str}</td>
          <td>{item['type']}</td>
          <td>{format_size(item['size'])}</td>
          <td class="action-cell">
            <button class="btn btn-move" onclick="showMoveForItem('{item_path_encoded}')">移动</button>
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
        file_rows = '<tr><td colspan="6" class="empty">此文件夹为空</td></tr>'

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

    def get_client_ip(self):
        cf_ip = self.headers.get("CF-Connecting-IP", "").strip()
        if cf_ip:
            ip = cf_ip.split(",")[0].strip()
            if ip:
                return ip
        return self.client_address[0]

    def is_suspicious_ip(self, ip):
        suspicious = {"127.0.0.1", "::1", "0.0.0.0", "localhost"}
        if ip in suspicious:
            return True
        if ip.startswith("::ffff:127.") or ip.startswith("::ffff:0:"):
            return True
        return False

    def handle_login(self):
        client_ip = self.get_client_ip()
        config = load_config()
        debug = config.get("debug", False)
        rate_limit_interval = config.get("rate_limit_interval", 60)

        if not debug and self.is_suspicious_ip(client_ip):
            login_html = load_template("login")
            error_html = login_html.replace("</form>", '<p class="error">环境异常，拒绝访问</p></form>')
            self.send_html(error_html, 403)
            return

        now = time.time()
        last_fail = login_failures.get(client_ip)
        if last_fail and (now - last_fail) < rate_limit_interval:
            remaining = int(rate_limit_interval - (now - last_fail))
            login_html = load_template("login")
            error_html = login_html.replace("</form>", f'<p class="error">登录尝试过于频繁，请{remaining}s后重试</p></form>')
            self.send_html(error_html, 429)
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")
        params = parse_qs(body)
        username = params.get("username", [""])[0]
        password = params.get("password", [""])[0]

        if verify_user(username, password):
            login_failures.pop(client_ip, None)
            token = create_session_token(username)
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", generate_session_cookie(token))
            self.end_headers()
        else:
            login_failures[client_ip] = time.time()
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
        name = unquote(params.get("filename", [""])[0])
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
        folder_name = unquote(params.get("folder_name", [""])[0]).strip()
        current_path = unquote(params.get("current_path", [""])[0])

        if folder_name and not "/" in folder_name and not "\\" in folder_name:
            target = safe_path(current_path + "/" + folder_name if current_path else folder_name)
            if target:
                os.makedirs(target, exist_ok=True)

        redir = f"/folder/{quote(current_path, safe='')}" if current_path else "/"
        self.send_response(302)
        self.send_header("Location", redir)
        self.end_headers()

    def handle_zip_start(self):
        valid, username = self.is_authenticated()
        if not valid:
            self.send_text("Unauthorized", 401)
            return

        zip_cleanup()

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")
        params = parse_qs(body)
        file_list_str = params.get("files", [""])[0]
        compression = params.get("compression", ["none"])[0]

        if not file_list_str:
            self.send_text("No files", 400)
            return

        file_list = [unquote(f) for f in file_list_str.split(",") if f]
        if not file_list:
            self.send_text("No files", 400)
            return

        comp_map = {
            "none": zipfile.ZIP_STORED,
            "fast": zipfile.ZIP_DEFLATED,
            "best": zipfile.ZIP_DEFLATED
        }
        comp_level = comp_map.get(compression, zipfile.ZIP_STORED)

        if compression == "best":
            task_id = zip_create_task(file_list, zipfile.ZIP_DEFLATED, compresslevel=9, archive_type="zip")
        elif compression == "fast":
            task_id = zip_create_task(file_list, zipfile.ZIP_DEFLATED, compresslevel=6, archive_type="zip")
        else:
            task_id = zip_create_task(file_list, None, archive_type="tar")

        self.send_text(task_id)

    def handle_zip_progress(self):
        valid, username = self.is_authenticated()
        if not valid:
            self.send_text("Unauthorized", 401)
            return

        query = urlparse(self.path).query
        params = parse_qs(query)
        task_id = params.get("task_id", [""])[0]

        if not task_id:
            self.send_text("No task_id", 400)
            return

        task = zip_get_progress(task_id)
        if not task:
            self.send_text(json.dumps({"status": "not_found"}), 200)
            return

        result = {
            "status": task["status"],
            "total": task["total"],
            "done": task["done"]
        }
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(result).encode("utf-8"))

    def handle_zip_download(self):
        valid, username = self.is_authenticated()
        if not valid:
            self.send_redirect("/login")
            return

        query = urlparse(self.path).query
        params = parse_qs(query)
        task_id = params.get("task_id", [""])[0]

        if not task_id:
            self.send_text("No task_id", 400)
            return

        task = zip_get_progress(task_id)
        if not task or task["status"] != "done":
            self.send_text("Not ready", 400)
            return

        out_path = task["out_path"]
        if not out_path or not os.path.exists(out_path):
            self.send_text("File not found", 404)
            return

        try:
            file_size = os.path.getsize(out_path)
            archive_type = task.get("archive_type", "zip")
            if archive_type == "tar":
                content_type = "application/x-tar"
                filename = "download.tar"
            else:
                content_type = "application/zip"
                filename = "download.zip"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(file_size))
            self.end_headers()

            with open(out_path, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
        except (ConnectionAbortedError, BrokenPipeError):
            pass
        except Exception as e:
            print(f"Archive download error: {e}")

        try:
            os.remove(out_path)
        except OSError:
            pass
        zip_tasks.pop(task_id, None)

    def handle_api_folders(self):
        valid, username = self.is_authenticated()
        if not valid:
            self.send_text("Unauthorized", 401)
            return

        folders = [""]
        for dirpath, dirnames, filenames in os.walk(STORAGE_DIR):
            dirnames.sort()
            rel = os.path.relpath(dirpath, STORAGE_DIR)
            if rel == ".":
                continue
            folders.append(rel.replace("\\", "/"))

        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(folders).encode("utf-8"))

    def handle_move(self):
        valid, username = self.is_authenticated()
        if not valid:
            self.send_text("Unauthorized", 401)
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")
        params = parse_qs(body)
        source_str = params.get("source", [""])[0]
        target_dir = params.get("target_dir", [""])[0]

        if not source_str or not target_dir:
            self.send_text("Missing parameters", 400)
            return

        sources = [unquote(s) for s in source_str.split("\n") if s.strip()]

        target_abs = safe_path(unquote(target_dir))
        if not target_abs or not os.path.isdir(target_abs):
            self.send_text("Invalid target", 400)
            return

        moved = 0
        for source in sources:
            source_abs = safe_path(source)
            if not source_abs or not os.path.exists(source_abs):
                continue

            real_source = os.path.realpath(source_abs)
            real_target = os.path.realpath(target_abs)
            if real_target.startswith(real_source + os.sep) or real_target == real_source:
                continue

            dest = os.path.join(target_abs, os.path.basename(source_abs))

            if os.path.exists(dest):
                base = os.path.basename(source_abs)
                name, ext = os.path.splitext(base)
                counter = 1
                while os.path.exists(dest):
                    new_name = f"{name} ({counter}){ext}" if ext else f"{name} ({counter})"
                    dest = os.path.join(target_abs, new_name)
                    counter += 1

            try:
                shutil.move(source_abs, dest)
                moved += 1
            except Exception:
                continue

        if moved > 0:
            self.send_text("OK")
        else:
            self.send_text("No files moved", 400)

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
        elif path == "/zip-progress":
            self.handle_zip_progress()
        elif path == "/zip-download":
            self.handle_zip_download()
        elif path == "/api/folders":
            self.handle_api_folders()
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
        elif path == "/zip-start":
            self.handle_zip_start()
        elif path == "/move":
            self.handle_move()
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
