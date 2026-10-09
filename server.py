import os
import hashlib
import hmac
import secrets
import time
import re
import json
import shutil
import logging
import zipfile
import tarfile
import io
import ipaddress
import threading
import uuid
from logging.handlers import RotatingFileHandler
from http.server import BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from http.server import HTTPServer
from urllib.parse import parse_qs, urlparse, unquote, quote
from html import escape as html_escape
import mimetypes


CHUNK_SIZE = 65536
MAX_FORM_BODY = 65536


def read_form_body(handler):
    length = handler.headers.get("Content-Length", "").strip()
    if not length.isdigit() or int(length) > MAX_FORM_BODY:
        return None
    return handler.rfile.read(int(length)).decode("utf-8", errors="replace")


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


def unique_path(path):
    if not os.path.exists(path):
        return path, None
    directory, base = os.path.split(path)
    stem, ext = os.path.splitext(base)
    counter = 1
    while True:
        candidate = os.path.join(directory, f"{stem} ({counter}){ext}" if ext else f"{stem} ({counter})")
        if not os.path.exists(candidate):
            return candidate, os.path.basename(candidate)
        counter += 1


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
        return [], [], []

    files = []
    renamed = []
    truncated = []

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
        target_file, renamed_name = unique_path(target_file)
        if renamed_name:
            renamed.append(f"{full_name} → {'/'.join(safe_parts[:-1] + [renamed_name])}")
        total = 0
        f = open(target_file, 'wb')
        completed = False
        try:
            while True:
                pos = buf.find(delimiter)
                if pos >= 0:
                    data = buf[:pos]
                    if data.endswith(b'\r\n'):
                        data = data[:-2]
                    f.write(data)
                    total += len(data)
                    buf = buf[pos + delim_len:]
                    completed = True
                    break

                write_up_to = max(0, len(buf) - delim_len)
                if write_up_to > 0:
                    f.write(buf[:write_up_to])
                    total += write_up_to
                    buf = buf[write_up_to:]

                chunk = limited_reader.read(CHUNK_SIZE)
                if not chunk:
                    break
                buf += chunk
        finally:
            f.close()
            if not completed:
                try:
                    os.remove(target_file)
                except OSError:
                    pass
                truncated.append(full_name)

        if not completed:
            break

        files.append(full_name)

        next_2 = read_bytes(2)
        if next_2 == b'--':
            read_bytes(2)
            break

    return files, renamed, truncated


HOST = "0.0.0.0"
PORT = 8888
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STORAGE_DIR = os.path.join(BASE_DIR, "storage")
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
AUDIT_LOG_FILE = os.path.join(BASE_DIR, "nas.log")

audit_log = logging.getLogger("lite-nas")


def setup_audit_log():
    handler = RotatingFileHandler(AUDIT_LOG_FILE, maxBytes=2 * 1024 * 1024,
                                  backupCount=2, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(message)s", "%Y-%m-%d %H:%M:%S"))
    audit_log.addHandler(handler)
    audit_log.setLevel(logging.INFO)
    audit_log.propagate = False


def one_line(value, limit=200):
    # 文件名/用户名可能带换行，不处理会被用来伪造审计日志行
    return str(value).replace("\r", " ").replace("\n", " ")[:limit]

sessions = {}

login_failures = {}

SESSION_IDLE_TIMEOUT = 86400
SESSION_ABSOLUTE_TIMEOUT = 7 * 86400
STATE_SWEEP_INTERVAL = 600

zip_tasks = {}
ZIP_TASKS_DIR = os.path.join(BASE_DIR, ".zip_tasks")
ZIP_TASK_TTL = 600
MAX_ZIP_TASKS = 4


DEFAULT_CONFIG = {"username": "", "password": "", "nas_name": "Lite-NAS"}


def load_config():
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            config = json.load(f)
    except (OSError, ValueError):
        # 文件缺失/无权限/JSON 损坏都退回空配置，不能让登录与列表请求抛异常
        return dict(DEFAULT_CONFIG)
    if not isinstance(config, dict):
        return dict(DEFAULT_CONFIG)
    return config


PBKDF2_ITERATIONS = 210000


def hash_password(password, iterations=PBKDF2_ITERATIONS):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def md5_hash(password):
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(password, stored):
    if not isinstance(stored, str) or not stored:
        return False
    if stored.startswith("pbkdf2_sha256$"):
        try:
            _, iterations, salt_hex, hash_hex = stored.split("$")
            digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                         bytes.fromhex(salt_hex), int(iterations))
        except ValueError:
            return False
        return hmac.compare_digest(digest.hex(), hash_hex)
    return hmac.compare_digest(md5_hash(password), stored)


def save_config(config):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except OSError:
        pass


def verify_user(username, password):
    config = load_config()
    stored = config.get("password", "")
    if not (username == config.get("username") and verify_password(password, stored)):
        return False
    if not stored.startswith("pbkdf2_sha256$"):
        # 旧版 config 存的是无盐 MD5，借这次成功的明文口令就地升级
        config["password"] = hash_password(password)
        save_config(config)
    return True


def session_expired(session, now):
    return (now - session["time"] > SESSION_IDLE_TIMEOUT
            or now - session["created"] > SESSION_ABSOLUTE_TIMEOUT)


def create_session_token(username):
    token = secrets.token_hex(32)
    now = time.time()
    sessions[token] = {"username": username, "time": now, "created": now}
    return token


def is_valid_session(token):
    session = sessions.get(token) if token else None
    if not session:
        return False, None
    now = time.time()
    if session_expired(session, now):
        sessions.pop(token, None)
        return False, None
    session["time"] = now
    return True, session["username"]


def sweep_stale_state():
    now = time.time()
    rate_interval = load_config().get("rate_limit_interval", 60)
    for token in [t for t, s in sessions.items() if session_expired(s, now)]:
        sessions.pop(token, None)
    for ip in [i for i, failed_at in login_failures.items() if now - failed_at > rate_interval]:
        login_failures.pop(ip, None)
    zip_sweep()


def state_janitor():
    while True:
        time.sleep(STATE_SWEEP_INTERVAL)
        try:
            sweep_stale_state()
        except Exception:
            # 配置读取等偶发异常不能让回收线程停摆
            pass


def generate_session_cookie(token, secure):
    flags = "Path=/; HttpOnly; SameSite=Strict"
    if secure:
        flags += "; Secure"
    return f"session={token}; {flags}"


def get_total_size(root):
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            try:
                if os.path.isfile(fp):
                    total += os.path.getsize(fp)
            except OSError:
                continue
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


def esc(value):
    return html_escape(str(value), quote=True)


def render_login_page(error=None):
    nas_name = esc(load_config().get("nas_name", "Lite-NAS"))
    html = load_template("login").replace("{{nas_name}}", nas_name)
    if error:
        html = html.replace("</form>", f'<p class="error">{error}</p></form>')
    return html


def safe_path(rel_path):
    rel_path = rel_path.strip("/")
    if not rel_path:
        return STORAGE_DIR
    parts = [p for p in rel_path.split("/") if p and p != "." and p != ".."]
    fp = os.path.join(STORAGE_DIR, *parts) if parts else STORAGE_DIR
    real_storage = os.path.realpath(STORAGE_DIR)
    real_fp = os.path.realpath(fp)
    if real_fp != real_storage and not real_fp.startswith(real_storage + os.sep):
        return None
    return fp


def parse_ip(value):
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr


def is_loopback_addr(ip):
    addr = parse_ip(ip)
    return bool(addr) and addr.is_loopback


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
        out_path = None
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
            if task_id not in zip_tasks:
                # 压缩期间任务已被回收（如超过 TTL），归档不能再留在盘上
                remove_quietly(out_path)
        except Exception as e:
            task["status"] = "error"
            task["error"] = str(e)
            if task_id not in zip_tasks:
                remove_quietly(out_path)

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


def remove_quietly(path):
    if not path:
        return
    try:
        os.remove(path)
    except OSError:
        pass


def zip_drop_task(task_id):
    task = zip_tasks.pop(task_id, None)
    if task:
        remove_quietly(task.get("out_path"))


def zip_sweep():
    now = time.time()
    for task_id in [k for k, v in zip_tasks.items() if now - v["time"] > ZIP_TASK_TTL]:
        zip_drop_task(task_id)


def zip_get_progress(task_id):
    task = zip_tasks.get(task_id)
    if not task:
        return None
    if time.time() - task["time"] > ZIP_TASK_TTL:
        zip_drop_task(task_id)
        return None
    return task


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
                dirs.append({"name": f, "is_dir": True,
                             "mtime": os.path.getmtime(fp), "type": "文件夹"})
            else:
                size = os.path.getsize(fp)
                type_name = get_file_ext_type(f)
                files.append({"name": f, "is_dir": False, "size": size,
                              "mtime": os.path.getmtime(fp), "type": type_name})
    dirs.sort(key=lambda x: x["name"].lower())
    files.sort(key=lambda x: x["name"].lower())
    items = dirs + files

    total_size = get_total_size(STORAGE_DIR)
    breadcrumb = build_breadcrumb(rel_path)

    file_rows = ""
    for item in items:
        encoded_name = esc(item["name"])
        encoded_type = esc(item["type"])
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
            <form method="POST" action="/delete" style="display:inline" data-name="{encoded_name}" data-kind="文件夹" onsubmit="return confirmDelete(this)">
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
          <td>{encoded_type}</td>
          <td>{format_size(item['size'])}</td>
          <td class="action-cell">
            <button class="btn btn-move" onclick="showMoveForItem('{item_path_encoded}')">移动</button>
            <a href="/download/{url_file}" class="btn btn-download" title="下载">下载</a>
            <form method="POST" action="/delete" style="display:inline" data-name="{encoded_name}" data-kind="" onsubmit="return confirmDelete(this)">
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
        name = esc(crumb["name"])
        if crumb["path"]:
            url_crumb = quote(crumb["path"], safe="")
            breadcrumb_html += f'<a href="/folder/{url_crumb}" class="crumb-link">{name}</a>'
        else:
            breadcrumb_html += f'<a href="/" class="crumb-link">{name}</a>'

    html = load_template("index")
    config = load_config()
    nas_name = config.get("nas_name", "Lite-NAS")
    return (html.replace("{{username}}", esc(username))
                .replace("{{nas_name}}", esc(nas_name))
                .replace("{{storage}}", format_size(total_size))
                .replace("{{file_rows}}", file_rows)
                .replace("{{breadcrumb}}", breadcrumb_html)
                .replace("{{current_path}}", quote(rel_path, safe="")))


MAX_CONCURRENT_CONNECTIONS = 64
connection_slots = threading.BoundedSemaphore(MAX_CONCURRENT_CONNECTIONS)

# 页面脚本与样式都是内联的，因此必须放行 'unsafe-inline'；
# 其余来源一律禁止，可挡住被注入标签后拉外部脚本、劫持表单和嵌框。
SECURITY_HEADERS = (
    ("Content-Security-Policy",
     "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; "
     "img-src 'self' data:; connect-src 'self'; form-action 'self'; "
     "frame-ancestors 'none'; base-uri 'none'; object-src 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "same-origin"),
)


class NASHandler(BaseHTTPRequestHandler):
    timeout = 30

    def log_message(self, format, *args):
        pass

    def version_string(self):
        return "Lite-NAS"

    def end_headers(self):
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)
        BaseHTTPRequestHandler.end_headers(self)

    def handle(self):
        if not connection_slots.acquire(blocking=False):
            return
        try:
            self.close_connection = True
            self.handle_one_request()
        except (ConnectionAbortedError, BrokenPipeError):
            pass
        except Exception:
            pass
        finally:
            connection_slots.release()

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
        peer = self.client_address[0]
        # 代理头仅在 TCP 对端确为本机回环（CF Tunnel/Nginx 同机）时可信，否则客户端可自造 IP 绕过限流
        if is_loopback_addr(peer):
            for value in self.headers.get("CF-Connecting-IP", "").split(","):
                value = value.strip()
                if parse_ip(value):
                    return value
        return peer

    def is_suspicious_ip(self, ip):
        return ip in ("0.0.0.0", "localhost") or is_loopback_addr(ip)

    def is_https_origin(self):
        # 只有同机反代（隧道）声明的 X-Forwarded-Proto 才可信，理由同 CF-Connecting-IP
        if not is_loopback_addr(self.client_address[0]):
            return False
        proto = self.headers.get("X-Forwarded-Proto", "").split(",")[0].strip().lower()
        return proto == "https"

    def handle_login(self):
        client_ip = self.get_client_ip()
        config = load_config()
        debug = config.get("debug", False)
        rate_limit_interval = config.get("rate_limit_interval", 60)

        if not debug and self.is_suspicious_ip(client_ip):
            audit_log.warning("login blocked (loopback, debug off) ip=%s", client_ip)
            self.send_html(render_login_page("环境异常，拒绝访问"), 403)
            return

        now = time.time()
        last_fail = login_failures.get(client_ip)
        if last_fail and (now - last_fail) < rate_limit_interval:
            remaining = int(rate_limit_interval - (now - last_fail))
            audit_log.warning("login rate limited ip=%s retry_in=%ss", client_ip, remaining)
            self.send_html(render_login_page(f"登录尝试过于频繁，请{remaining}s后重试"), 429)
            return

        body = read_form_body(self)
        if body is None:
            self.send_text("Bad request", 400)
            return
        params = parse_qs(body)
        username = params.get("username", [""])[0]
        password = params.get("password", [""])[0]

        if verify_user(username, password):
            login_failures.pop(client_ip, None)
            token = create_session_token(username)
            audit_log.info("login ok user=%s ip=%s", one_line(username), client_ip)
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", generate_session_cookie(token, self.is_https_origin()))
            self.end_headers()
        else:
            login_failures[client_ip] = time.time()
            audit_log.warning("login failed user=%s ip=%s", one_line(username), client_ip)
            self.send_html(render_login_page("用户名或密码错误"), 401)

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

        length = self.headers.get("Content-Length", "").strip()
        if not length.isdigit():
            self.send_text("Bad request", 400)
            return
        content_length = int(length)
        raw_path = self.headers.get("X-Current-Path", "")
        current_path = unquote(raw_path) if raw_path else ""
        target_dir = safe_path(current_path)
        if not target_dir:
            self.send_text("Invalid path", 400)
            return
        try:
            os.makedirs(target_dir, exist_ok=True)
            limited = LengthLimitedReader(self.rfile, content_length)
            files, renamed, truncated = parse_multipart_streaming(limited, boundary, target_dir)
            client_ip = self.get_client_ip()
            if truncated:
                audit_log.warning("upload truncated user=%s ip=%s dropped=%s",
                                  username, client_ip, one_line("；".join(truncated)))
                self.send_text("上传中断，已丢弃不完整文件：" + "；".join(truncated), 400)
                return
            if not files:
                self.send_text("No file", 400)
                return
            audit_log.info("upload user=%s ip=%s path=%s files=%s renamed=%s",
                           username, client_ip, one_line(current_path) or "/",
                           one_line("；".join(files)), one_line("；".join(renamed)) or "-")
            if renamed:
                self.send_text("OK\n已有同名文件，已重命名：" + "；".join(renamed))
            else:
                self.send_text("OK")
        except Exception:
            audit_log.error("upload error user=%s path=%s", username, one_line(current_path))
            self.send_text("Upload error", 500)

    def handle_download(self, filename):
        valid, username = self.is_authenticated()
        if not valid:
            self.send_redirect("/login")
            return

        filepath = safe_path(filename)
        if not filepath or not os.path.exists(filepath) or not os.path.isfile(filepath):
            audit_log.warning("download not found user=%s ip=%s file=%s",
                              username, self.get_client_ip(), one_line(filename))
            self.send_text("File not found", 404)
            return
        audit_log.info("download user=%s ip=%s file=%s size=%s",
                       username, self.get_client_ip(), one_line(filename), format_size(os.path.getsize(filepath)))

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

        body = read_form_body(self)
        if body is None:
            self.send_text("Bad request", 400)
            return
        params = parse_qs(body)
        name = unquote(params.get("filename", [""])[0])
        is_dir = params.get("is_dir", ["0"])[0] == "1"
        current_path = unquote(params.get("current_path", [""])[0])

        if not name:
            self.send_redirect(f"/folder/{quote(current_path, safe='')}" if current_path else "/")
            return

        target = safe_path(current_path + "/" + name if current_path else name)
        kind = "folder" if is_dir else "file"
        if target and os.path.exists(target):
            failed = None
            try:
                if is_dir:
                    shutil.rmtree(target, ignore_errors=True)
                else:
                    os.remove(target)
            except IsADirectoryError:
                shutil.rmtree(target, ignore_errors=True)
            except OSError as e:
                # 只兜住异常，避免整个连接被 handle() 静默吞掉；删除语义与原来保持一致
                failed = e
            if failed:
                audit_log.error("delete failed user=%s ip=%s %s=%s error=%s", username,
                                self.get_client_ip(), kind, one_line(target), one_line(failed))
            else:
                audit_log.warning("delete user=%s ip=%s %s=%s", username, self.get_client_ip(),
                                  kind, one_line(target.replace(STORAGE_DIR, "storage")))
        else:
            audit_log.warning("delete missed user=%s ip=%s name=%s",
                              username, self.get_client_ip(), one_line(name))

        redir = f"/folder/{quote(current_path, safe='')}" if current_path else "/"
        self.send_response(302)
        self.send_header("Location", redir)
        self.end_headers()

    def handle_mkdir(self):
        valid, username = self.is_authenticated()
        if not valid:
            self.send_redirect("/login")
            return

        body = read_form_body(self)
        if body is None:
            self.send_text("Bad request", 400)
            return
        params = parse_qs(body)
        folder_name = unquote(params.get("folder_name", [""])[0]).strip()
        current_path = unquote(params.get("current_path", [""])[0])

        if folder_name and not "/" in folder_name and not "\\" in folder_name:
            target = safe_path(current_path + "/" + folder_name if current_path else folder_name)
            if target:
                try:
                    os.makedirs(target, exist_ok=True)
                except OSError as e:
                    # Windows 等平台的非法字符（<>:"|?*）会在这里失败，必须给明确响应而不是断连
                    audit_log.warning("mkdir failed user=%s name=%s error=%s",
                                      username, one_line(folder_name), one_line(e))
                    self.send_text("文件夹名称无效或无法创建", 400)
                    return
                audit_log.info("mkdir user=%s ip=%s path=%s", username, self.get_client_ip(),
                               one_line(os.path.relpath(target, STORAGE_DIR).replace("\\", "/")))

        redir = f"/folder/{quote(current_path, safe='')}" if current_path else "/"
        self.send_response(302)
        self.send_header("Location", redir)
        self.end_headers()

    def handle_zip_start(self):
        valid, username = self.is_authenticated()
        if not valid:
            self.send_text("Unauthorized", 401)
            return

        zip_sweep()
        if sum(1 for t in zip_tasks.values() if t["status"] == "compressing") >= MAX_ZIP_TASKS:
            self.send_text("压缩任务已满，请稍后再试", 429)
            return

        body = read_form_body(self)
        if body is None:
            self.send_text("Bad request", 400)
            return
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

        zip_drop_task(task_id)

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

        body = read_form_body(self)
        if body is None:
            self.send_text("Bad request", 400)
            return
        params = parse_qs(body, keep_blank_values=True)
        source_str = params.get("source", [""])[0]
        # 移动到根目录时前端传空串，必须与“参数缺失”区分开
        target_dir = params.get("target_dir", [None])[0]

        if not source_str or target_dir is None:
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
            audit_log.info("move user=%s ip=%s to=%s moved=%d sources=%s", username,
                           self.get_client_ip(), one_line(unquote(target_dir)) or "/", moved,
                           one_line("；".join(sources)))
            self.send_text("OK")
        else:
            audit_log.warning("move nothing moved user=%s ip=%s sources=%s", username,
                              self.get_client_ip(), one_line("；".join(sources)))
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
            self.send_html(render_login_page())
        elif path == "/logout":
            token = self.get_cookie("session")
            valid, username = is_valid_session(token)
            if token and token in sessions:
                del sessions[token]
            if valid:
                audit_log.info("logout user=%s ip=%s", username, self.get_client_ip())
            self.send_response(302)
            self.send_header("Location", "/login")
            clear_cookie = "session=; Path=/; Max-Age=0"
            if self.is_https_origin():
                clear_cookie += "; Secure"
            self.send_header("Set-Cookie", clear_cookie)
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


def sweep_zip_tasks_dir():
    if not os.path.isdir(ZIP_TASKS_DIR):
        return
    for name in os.listdir(ZIP_TASKS_DIR):
        path = os.path.join(ZIP_TASKS_DIR, name)
        if os.path.isfile(path):
            remove_quietly(path)


def main():
    try:
        setup_audit_log()
    except OSError as e:
        print(f"审计日志不可写（{e}），仅本次进程不记录")
    os.makedirs(STORAGE_DIR, exist_ok=True)
    sweep_zip_tasks_dir()
    threading.Thread(target=state_janitor, daemon=True).start()

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
