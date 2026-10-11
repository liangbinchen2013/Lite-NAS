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
import socket
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


class Pacer:
    """按累计字节数控制发送/接收节奏（漏桶式），0 表示不限速。"""

    def __init__(self, kbytes_per_sec):
        self.rate = kbytes_per_sec * 1024 if kbytes_per_sec and kbytes_per_sec > 0 else 0
        self._start = time.monotonic()
        self._done = 0

    def throttle(self, nbytes):
        if not self.rate or nbytes <= 0:
            return
        self._done += nbytes
        delay = self._start + self._done / self.rate - time.monotonic()
        if delay > 0:
            time.sleep(delay)


def get_limits():
    config = load_config()
    def positive(key):
        value = config.get(key, 0)
        return value if isinstance(value, int) and value > 0 else 0
    return positive("upload_limit_kb"), positive("download_limit_kb")


class LengthLimitedReader:
    def __init__(self, rfile, limit, pacer=None):
        self._rfile = rfile
        self._remaining = limit
        self._pacer = pacer

    def read(self, n=-1):
        if self._remaining <= 0:
            return b''
        to_read = n if n > 0 else self._remaining
        to_read = min(to_read, self._remaining)
        chunk = self._rfile.read(to_read)
        self._remaining -= len(chunk)
        # 读得慢就会让 TCP 窗口收住，客户端上行被自然限速，无需浏览器配合
        if self._pacer:
            self._pacer.throttle(len(chunk))
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

api_failures = {}
api_key_usage = {}
API_TOKEN_PREFIX = "lnas"
API_SCOPES = ("read", "write", "delete")
MAX_API_KEYS = 20
API_LIST_DEFAULT = 500
API_LIST_MAX = 2000


DEFAULT_CONFIG = {"username": "", "password": "", "nas_name": "Lite-NAS",
                  "rate_limit_interval": 60, "upload_limit_kb": 0, "download_limit_kb": 0}


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


def api_secret_hash(secret):
    # 密钥本身是 256 位随机串，无需慢派生；API 每次请求都要验，用 SHA-256 才不至于拖慢下载
    return hashlib.sha256(("lite-nas-api:" + secret).encode("utf-8")).hexdigest()


def parse_api_token(token):
    parts = token.split("_")
    if len(parts) != 3 or parts[0] != API_TOKEN_PREFIX or not parts[1] or not parts[2]:
        return None, None
    return parts[1], parts[2]


def find_api_key(config, token):
    key_id, secret = parse_api_token(token)
    if not key_id:
        return None
    digest = api_secret_hash(secret)
    for entry in config.get("api_keys") or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("id") == key_id and hmac.compare_digest(str(entry.get("secret_hash", "")), digest):
            return entry
    return None


def create_api_key(name, scopes):
    key_id = secrets.token_hex(4)
    secret = secrets.token_hex(32)
    entry = {"id": key_id, "name": name, "scopes": list(scopes),
             "secret_hash": api_secret_hash(secret), "created": int(time.time())}
    return entry, f"{API_TOKEN_PREFIX}_{key_id}_{secret}"


def usable_scopes(entry):
    return [s for s in (entry.get("scopes") or []) if s in API_SCOPES]


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
    for ip in [i for i, failed_at in api_failures.items() if now - failed_at > rate_interval]:
        api_failures.pop(ip, None)
    known = {str(entry.get("id")) for entry in load_config().get("api_keys") or [] if isinstance(entry, dict)}
    for key_id in [k for k in api_key_usage if k not in known]:
        api_key_usage.pop(key_id, None)
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


def render_api_keys_rows(config):
    entries = [e for e in (config.get("api_keys") or []) if isinstance(e, dict)]
    if not entries:
        return '<tr><td colspan="4" class="empty">还没有密钥</td></tr>'
    rows = ""
    for entry in entries:
        key_id = esc(entry.get("id", ""))
        name = esc(entry.get("name", ""))
        scopes = esc("、".join(usable_scopes(entry)) or "无")
        used = api_key_usage.get(entry.get("id"))
        used_text = time.strftime("%m-%d %H:%M", time.localtime(used)) if used else "-"
        rows += f"""
      <tr><td class="mono">{key_id}</td><td>{name}</td><td>{scopes}</td>
          <td>{used_text}<button type="submit" class="revoke" name="revoke_key" value="{key_id}">吊销</button></td></tr>"""
    return rows


def render_settings_page(message=None, ok=True):
    config = load_config()
    values = {
        "{{nas_name}}": esc(config.get("nas_name", "Lite-NAS")),
        "{{username}}": esc(config.get("username", "")),
        "{{rate_limit_interval}}": esc(config.get("rate_limit_interval", 60)),
        "{{upload_limit_kb}}": esc(config.get("upload_limit_kb", 0)),
        "{{download_limit_kb}}": esc(config.get("download_limit_kb", 0)),
        "{{api_key_count}}": str(len([e for e in (config.get("api_keys") or []) if isinstance(e, dict)])),
        "{{api_keys_rows}}": render_api_keys_rows(config),
        "{{message}}": esc(message or ""),
        "{{message_class}}": ("ok" if ok else "err") if message else "",
    }
    html = load_template("settings")
    for key, value in values.items():
        html = html.replace(key, value)
    return html


def normalize_api_rel(rel):
    """API 路径不接受 . / .. 段：越界意图应明确报错，而不是静默改写后落盘。"""
    rel = str(rel).strip("/")
    if not rel:
        return ""
    parts = rel.split("/")
    if any(not part or part in (".", "..") for part in parts):
        return None
    return "/".join(parts)


def make_entry(fp):
    try:
        is_dir = os.path.isdir(fp)
        mtime = int(os.path.getmtime(fp))
        size = None if is_dir else os.path.getsize(fp)
    except OSError:
        return None
    name = os.path.basename(fp)
    return {"name": name, "path": os.path.relpath(fp, STORAGE_DIR).replace("\\", "/"),
            "is_dir": is_dir, "size": size, "mtime": mtime,
            "type": "folder" if is_dir else get_file_ext_type(name)}


def storage_stats(root):
    files = dirs = 0
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirs += len(dirnames)
        files += len(filenames)
        for f in filenames:
            fp = os.path.join(dirpath, f)
            try:
                if os.path.isfile(fp):
                    total += os.path.getsize(fp)
            except OSError:
                continue
    return files, dirs, total


def list_entries(base, recursive, limit, offset):
    collected = []
    if recursive:
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames.sort()
            filenames.sort()
            for name in dirnames + filenames:
                entry = make_entry(os.path.join(dirpath, name))
                if entry:
                    collected.append(entry)
                if len(collected) >= offset + limit:
                    break
            if len(collected) >= offset + limit:
                break
    else:
        try:
            names = sorted(os.listdir(base), key=lambda n: (not os.path.isdir(os.path.join(base, n)), n.lower()))
        except OSError:
            return [], False
        for name in names:
            entry = make_entry(os.path.join(base, name))
            if entry:
                collected.append(entry)
    return collected[offset:offset + limit], len(collected) >= offset + limit


def move_entries(sources, target_rel):
    """把若干相对路径移动到目标目录；返回 (moved, skipped)，moved 为 None 表示目标非法。
    同名不覆盖，按 Windows 风格改名。网页与 API 共用同一套规则。"""
    target_abs = safe_path(target_rel)
    if not target_abs or not os.path.isdir(target_abs):
        return None, []
    moved = 0
    skipped = []
    for source in sources:
        source_abs = safe_path(source)
        if not source_abs or not os.path.exists(source_abs):
            skipped.append({"path": source, "reason": "not_found"})
            continue
        real_source = os.path.realpath(source_abs)
        real_target = os.path.realpath(target_abs)
        if real_target == real_source or real_target.startswith(real_source + os.sep):
            skipped.append({"path": source, "reason": "into_itself"})
            continue
        dest, renamed = unique_path(os.path.join(target_abs, os.path.basename(source_abs)))
        try:
            shutil.move(source_abs, dest)
        except OSError:
            skipped.append({"path": source, "reason": "io_error"})
            continue
        moved += 1
    return moved, skipped


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

    def send_json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (ConnectionAbortedError, BrokenPipeError):
            pass

    def api_fail_limited(self, client_ip):
        interval = load_config().get("rate_limit_interval", 60)
        marked = api_failures.get(client_ip)
        return bool(interval) and marked and time.time() - marked < interval

    def authenticate_api(self, scope):
        """返回 (principal, error)。Authorization: Bearer <key> 优先，其次浏览器会话 Cookie。"""
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            client_ip = self.get_client_ip()
            if self.api_fail_limited(client_ip):
                return None, "rate_limited"
            entry = find_api_key(load_config(), auth[len("Bearer "):].strip())
            if not entry:
                api_failures[client_ip] = time.time()
                audit_log.warning("api denied (unknown key) ip=%s prefix=%s",
                                  client_ip, one_line(auth[len("Bearer "):len('Bearer ') + 12]))
                return None, "invalid_key"
            if scope not in usable_scopes(entry):
                audit_log.warning("api denied (scope=%s missing) key=%s ip=%s",
                                  scope, one_line(entry.get("name") or entry["id"]), client_ip)
                return None, "insufficient_scope"
            api_failures.pop(client_ip, None)
            api_key_usage[entry["id"]] = time.time()
            return "key:" + str(entry.get("name") or entry["id"]), None
        valid, username = self.is_authenticated()
        if valid:
            return "session:" + str(username), None
        return None, "unauthorized"

    def reject_api(self, error):
        status = {"invalid_key": 401, "unauthorized": 401, "insufficient_scope": 403,
                  "rate_limited": 429, "not_found": 404, "invalid_path": 400,
                  "bad_json": 400, "bad_request": 400}.get(error, 400)
        message = {"invalid_key": "密钥无效或已被吊销", "unauthorized": "未登录且未提供 API 密钥",
                   "insufficient_scope": "该密钥缺少所需权限位", "rate_limited": "认证失败过于频繁，请稍后再试",
                   "not_found": "路径不存在", "invalid_path": "路径非法：只接受 storage 内的相对路径，不得包含 . 或 .. 段",
                   "bad_json": "请求体不是合法的 JSON 对象",
                   "bad_request": "请求体过大或缺少合法 Content-Length"}.get(error, error)
        self.send_json({"ok": False, "error": error, "message": message}, status)

    def get_client_ip(self):
        peer = self.client_address[0]
        # 代理头仅在 TCP 对端确为本机回环（CF Tunnel/Nginx 同机）时可信，否则客户端可自造 IP 绕过限流
        if is_loopback_addr(peer):
            for value in self.headers.get("CF-Connecting-IP", "").split(","):
                value = value.strip()
                if parse_ip(value):
                    return value
        return peer

    def is_https_origin(self):
        # 只有同机反代（隧道）声明的 X-Forwarded-Proto 才可信，理由同 CF-Connecting-IP
        if not is_loopback_addr(self.client_address[0]):
            return False
        proto = self.headers.get("X-Forwarded-Proto", "").split(",")[0].strip().lower()
        return proto == "https"

    def handle_login(self):
        client_ip = self.get_client_ip()
        rate_limit_interval = load_config().get("rate_limit_interval", 60)

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

    def reject_settings(self, message, status):
        self.send_html(render_settings_page(message, ok=False), status)

    def handle_api_keys(self, config, action, revoke_id, params, username):
        client_ip = self.get_client_ip()
        if action == "create_key":
            keys = [e for e in (config.get("api_keys") or []) if isinstance(e, dict)]
            if len(keys) >= MAX_API_KEYS:
                self.reject_settings(f"密钥数量已达上限 {MAX_API_KEYS} 个，请先吊销一些", 400)
                return
            name = params.get("key_name", [""])[0].strip()
            if not name:
                self.reject_settings("请先填写密钥名称，否则以后没法辨认该吊销哪个", 400)
                return
            if len(name) > 40:
                self.reject_settings("密钥名称请控制在 40 字以内", 400)
                return
            scopes = [s for s in params.get("key_scopes", []) if s in API_SCOPES]
            if not scopes:
                self.reject_settings("至少要勾选一个权限位", 400)
                return
            entry, token = create_api_key(name, scopes)
            keys.append(entry)
            config["api_keys"] = keys
            save_config(config)
            audit_log.info("api key created id=%s name=%s scopes=%s by=%s ip=%s",
                           entry["id"], one_line(name), ",".join(scopes), username, client_ip)
            self.send_html(render_settings_page(
                "密钥已创建，明文只显示这一次，请立即保存：" + token))
            return

        keys = [e for e in (config.get("api_keys") or []) if isinstance(e, dict)]
        removed = [e for e in keys if e.get("id") == revoke_id]
        if not removed:
            self.reject_settings("没有找到要吊销的密钥", 400)
            return
        config["api_keys"] = [e for e in keys if e.get("id") != revoke_id]
        save_config(config)
        api_key_usage.pop(revoke_id, None)
        audit_log.info("api key revoked id=%s name=%s by=%s ip=%s",
                       revoke_id, one_line(removed[0].get("name", "")), username, client_ip)
        self.send_html(render_settings_page("已吊销密钥：" + str(removed[0].get("name") or revoke_id)))

    def handle_settings(self):
        valid, username = self.is_authenticated()
        if not valid:
            self.send_redirect("/login")
            return

        body = read_form_body(self)
        if body is None:
            self.send_text("Bad request", 400)
            return
        params = parse_qs(body, keep_blank_values=True)
        config = load_config()

        current_password = params.get("current_password", [""])[0]
        if not verify_password(current_password, config.get("password", "")):
            audit_log.warning("settings rejected, wrong current password user=%s ip=%s",
                              username, self.get_client_ip())
            self.reject_settings("当前密码不正确，未做任何修改", 403)
            return

        def text(key, default=""):
            return params.get(key, [default])[0].strip()

        def number(key, default, maximum, label):
            raw = text(key, str(default))
            if not raw:
                return default, None
            try:
                value = int(raw)
            except ValueError:
                return None, f"{label}需要是整数"
            if value < 0 or value > maximum:
                return None, f"{label}需在 0 到 {maximum} 之间"
            return value, None

        action = params.get("do", [""])[0]
        revoke_id = params.get("revoke_key", [""])[0]
        if action == "create_key" or revoke_id:
            self.handle_api_keys(config, action, revoke_id, params, username)
            return

        nas_name = text("nas_name") or "Lite-NAS"
        new_username = text("username")
        if not new_username:
            self.reject_settings("用户名不能为空", 400)
            return

        new_password = params.get("password", [""])[0]
        if new_password and new_password != params.get("password_confirm", [""])[0]:
            self.reject_settings("两次输入的新密码不一致", 400)
            return

        rate_limit, err = number("rate_limit_interval", config.get("rate_limit_interval", 60),
                                 86400, "限流间隔")
        if err:
            self.reject_settings(err, 400)
            return
        upload_limit, err = number("upload_limit_kb", config.get("upload_limit_kb", 0),
                                   1048576, "上传限速")
        if err:
            self.reject_settings(err, 400)
            return
        download_limit, err = number("download_limit_kb", config.get("download_limit_kb", 0),
                                     1048576, "下载限速")
        if err:
            self.reject_settings(err, 400)
            return

        changed = []
        for key, value in (("nas_name", nas_name), ("username", new_username),
                           ("rate_limit_interval", rate_limit),
                           ("upload_limit_kb", upload_limit), ("download_limit_kb", download_limit)):
            if config.get(key) != value:
                config[key] = value
                changed.append(key)
        if new_password:
            config["password"] = hash_password(new_password)
            changed.append("password")

        if not changed:
            self.send_html(render_settings_page("没有发现改动"))
            return

        save_config(config)
        if "password" in changed or "username" in changed:
            current_token = self.get_cookie("session")
            for token in [t for t in sessions if t != current_token]:
                sessions.pop(token, None)
            if current_token in sessions:
                sessions[current_token]["username"] = new_username
        audit_log.info("settings updated user=%s ip=%s changed=%s",
                       username, self.get_client_ip(), ",".join(changed))
        labels = {"nas_name": "NAS 名称", "username": "用户名", "password": "密码",
                  "rate_limit_interval": "限流间隔", "upload_limit_kb": "上传限速",
                  "download_limit_kb": "下载限速"}
        self.send_html(render_settings_page("已保存：" + "、".join(labels[c] for c in changed)))

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
            upload_limit_kb, _ = get_limits()
            limited = LengthLimitedReader(self.rfile, content_length, Pacer(upload_limit_kb))
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

            self.send_file_stream(filepath)
        except (ConnectionAbortedError, BrokenPipeError):
            pass
        except Exception as e:
            print(f"Download error: {e}")

    def send_file_stream(self, path):
        _, download_limit_kb = get_limits()
        pacer = Pacer(download_limit_kb)
        with open(path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
                pacer.throttle(len(chunk))

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

            self.send_file_stream(out_path)
        except (ConnectionAbortedError, BrokenPipeError):
            pass
        except Exception as e:
            print(f"Archive download error: {e}")

        zip_drop_task(task_id)

    def api_query(self):
        return parse_qs(urlparse(self.path).query, keep_blank_values=True)

    def param(self, params, key, default=""):
        return params.get(key, [default])[0]

    def int_param(self, params, key, default, maximum):
        raw = self.param(params, key, "").strip()
        if not raw:
            return default, None
        if not raw.isdigit() or int(raw) > maximum:
            return None, f"{key} 需为 0 到 {maximum} 之间的整数"
        return int(raw), None

    def resolve_api_path(self, params, key="path"):
        rel = normalize_api_rel(unquote(self.param(params, key, "")))
        if rel is None:
            return None, None, "invalid_path"
        fp = safe_path(rel)
        if fp is None:
            return None, None, "invalid_path"
        if not os.path.exists(fp):
            return None, None, "not_found"
        return fp, rel, None

    def handle_api_info(self):
        principal, error = self.authenticate_api("read")
        if not principal:
            self.reject_api(error)
            return
        params = self.api_query()
        fp, rel, perr = self.resolve_api_path(params)
        if perr:
            self.reject_api(perr)
            return
        files, dirs, used = storage_stats(fp if os.path.isdir(fp) else STORAGE_DIR)
        upload_limit_kb, download_limit_kb = get_limits()
        is_root = os.path.realpath(fp) == os.path.realpath(STORAGE_DIR)
        payload = {
            "ok": True,
            "nas_name": load_config().get("nas_name", "Lite-NAS"),
            "authenticated_as": principal.split(":", 1)[0],
            "path": rel.strip("/"),
            "is_dir": os.path.isdir(fp),
            "entry": None if is_root else make_entry(fp),
            "root_files": files,
            "root_dirs": dirs,
            "used_bytes": used,
            "used": format_size(used),
            "limits": {"upload_kb": upload_limit_kb, "download_kb": download_limit_kb},
        }
        audit_log.info("api info as=%s path=%s", principal, one_line(rel) or "/")
        self.send_json(payload)

    def handle_api_list(self):
        principal, error = self.authenticate_api("read")
        if not principal:
            self.reject_api(error)
            return
        params = self.api_query()
        limit, err = self.int_param(params, "limit", API_LIST_DEFAULT, API_LIST_MAX)
        if not err:
            offset, err = self.int_param(params, "offset", 0, 10 ** 7)
        else:
            offset = 0
        if not err:
            recursive = self.param(params, "recursive", "").lower() in ("1", "true", "yes")
        if err:
            self.send_json({"ok": False, "error": "bad_request", "message": err}, 400)
            return
        fp, rel, perr = self.resolve_api_path(params)
        if perr:
            self.reject_api(perr)
            return
        if not os.path.isdir(fp):
            self.send_json({"ok": False, "error": "not_a_folder", "message": "该路径不是目录"}, 400)
            return
        entries, truncated = list_entries(fp, recursive, limit, offset)
        audit_log.info("api list as=%s path=%s recursive=%s n=%s",
                       principal, one_line(rel) or "/", recursive, len(entries))
        self.send_json({"ok": True, "path": rel.strip("/"), "recursive": recursive,
                        "count": len(entries), "truncated": truncated,
                        "offset": offset, "limit": limit, "entries": entries})

    def handle_api_download(self):
        principal, error = self.authenticate_api("read")
        if not principal:
            self.reject_api(error)
            return
        params = self.api_query()
        fp, rel, perr = self.resolve_api_path(params)
        if perr:
            self.reject_api(perr)
            return
        if not os.path.isfile(fp):
            self.send_json({"ok": False, "error": "not_a_file", "message": "该路径不是文件，目录请用 /api/list"}, 400)
            return
        audit_log.info("api download as=%s file=%s size=%s",
                       principal, one_line(rel), format_size(os.path.getsize(fp)))
        try:
            mime, _ = mimetypes.guess_type(fp)
            self.send_response(200)
            self.send_header("Content-Type", mime or "application/octet-stream")
            self.send_header("Content-Disposition",
                             f"attachment; filename*=UTF-8''{quote(os.path.basename(fp))}")
            self.send_header("Content-Length", str(os.path.getsize(fp)))
            self.end_headers()
            self.send_file_stream(fp)
        except (ConnectionAbortedError, BrokenPipeError):
            pass

    def read_json_body(self):
        body = read_form_body(self)
        if body is None:
            return None, "bad_request"
        if not body.strip():
            return {}, None
        try:
            obj = json.loads(body)
        except ValueError:
            return None, "bad_json"
        if not isinstance(obj, dict):
            return None, "bad_json"
        return obj, None

    def handle_api_upload(self):
        principal, error = self.authenticate_api("write")
        if not principal:
            self.reject_api(error)
            return
        params = self.api_query()
        rel_dir = normalize_api_rel(unquote(self.param(params, "path", "")))
        if rel_dir is None:
            self.reject_api("invalid_path")
            return
        name = unquote(self.param(params, "name", ""))
        if not name or name in (".", "..") or "/" in name or "\\" in name:
            self.send_json({"ok": False, "error": "invalid_name",
                            "message": "name 必须是无路径分隔符的文件名"}, 400)
            return
        target_dir = safe_path(rel_dir)
        if target_dir is None:
            self.reject_api("invalid_path")
            return
        length = self.headers.get("Content-Length", "").strip()
        if not length.isdigit():
            self.send_json({"ok": False, "error": "length_required",
                            "message": "上传必须带正确的 Content-Length"}, 411)
            return

        remaining = int(length)
        written = 0
        final = None
        upload_limit_kb, _ = get_limits()
        pacer = Pacer(upload_limit_kb)
        try:
            os.makedirs(target_dir, exist_ok=True)
            final, renamed = unique_path(os.path.join(target_dir, name))
            with open(final, "wb") as f:
                while remaining > 0:
                    chunk = self.rfile.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        break
                    f.write(chunk)
                    written += len(chunk)
                    remaining -= len(chunk)
                    pacer.throttle(len(chunk))
            if remaining:
                remove_quietly(final)
                audit_log.warning("api upload truncated as=%s name=%s wrote=%d expected=%s",
                                  principal, one_line(name), written, length)
                self.send_json({"ok": False, "error": "truncated", "written_bytes": written,
                                "message": "请求体提前结束，已丢弃不完整文件"}, 400)
                return
        except OSError as e:
            remove_quietly(final)
            audit_log.error("api upload failed as=%s name=%s error=%s",
                            principal, one_line(name), one_line(e))
            self.send_json({"ok": False, "error": "write_failed",
                            "message": "写入失败（磁盘满、无权限或文件名在本机非法）"}, 500)
            return

        rel_out = os.path.relpath(final, STORAGE_DIR).replace("\\", "/")
        audit_log.info("api upload as=%s path=%s size=%s renamed=%s", principal, one_line(rel_out),
                       format_size(written), "yes" if renamed else "no")
        self.send_json({"ok": True, "path": rel_out, "size": written, "renamed": bool(renamed)}, 201)

    def handle_api_mkdir(self):
        principal, error = self.authenticate_api("write")
        if not principal:
            self.reject_api(error)
            return
        body, jerr = self.read_json_body()
        if jerr:
            self.reject_api(jerr)
            return
        raw_path = str(body.get("path") or unquote(self.param(self.api_query(), "path", "")))
        rel = normalize_api_rel(raw_path)
        if rel is None:
            self.reject_api("invalid_path")
            return
        if not rel:
            self.send_json({"ok": False, "error": "invalid_name", "message": "path 不能为空（根目录已存在）"}, 400)
            return
        fp = safe_path(rel)
        if fp is None:
            self.reject_api("invalid_path")
            return
        try:
            os.makedirs(fp, exist_ok=True)
        except OSError as e:
            audit_log.error("api mkdir failed as=%s path=%s error=%s", principal, one_line(rel), one_line(e))
            self.send_json({"ok": False, "error": "write_failed", "message": "无法创建目录（名称非法或写入失败）"}, 500)
            return
        audit_log.info("api mkdir as=%s path=%s", principal, one_line(rel))
        self.send_json({"ok": True, "path": rel}, 201)

    def handle_api_move(self):
        principal, error = self.authenticate_api("write")
        if not principal:
            self.reject_api(error)
            return
        body, jerr = self.read_json_body()
        if jerr:
            self.reject_api(jerr)
            return
        raw_sources = body.get("sources") or body.get("source")
        if isinstance(raw_sources, str):
            raw_sources = [s.strip() for s in raw_sources.split("\n") if s.strip()]
        if not isinstance(raw_sources, list) or not raw_sources:
            self.send_json({"ok": False, "error": "invalid_name", "message": "sources 需是非空字符串数组"}, 400)
            return
        sources = []
        for item in raw_sources:
            rel = normalize_api_rel(str(item))
            if rel is None or not rel:
                self.reject_api("invalid_path")
                return
            sources.append(rel)
        if "target_dir" not in body:
            self.send_json({"ok": False, "error": "missing_target",
                            "message": "缺少 target_dir（移到根目录请传空字符串）"}, 400)
            return
        target_dir = normalize_api_rel(str(body.get("target_dir") or ""))
        if target_dir is None:
            self.reject_api("invalid_path")
            return
        moved, skipped = move_entries(sources, target_dir)
        if moved is None:
            self.send_json({"ok": False, "error": "not_found", "message": "目标目录不存在"}, 404)
            return
        audit_log.info("api move as=%s to=%s moved=%d skipped=%d", principal,
                       target_dir or "/", moved, len(skipped))
        self.send_json({"ok": moved > 0, "moved": moved, "skipped": skipped,
                        "message": None if moved else "没有文件被移动"})

    def handle_api_delete(self):
        principal, error = self.authenticate_api("delete")
        if not principal:
            self.reject_api(error)
            return
        body, jerr = self.read_json_body()
        if jerr:
            self.reject_api(jerr)
            return
        rel = normalize_api_rel(str(body.get("path") or ""))
        if rel is None:
            self.reject_api("invalid_path")
            return
        fp = safe_path(rel)
        if fp is None:
            self.reject_api("invalid_path")
            return
        if os.path.realpath(fp) == os.path.realpath(STORAGE_DIR):
            self.send_json({"ok": False, "error": "forbidden_target", "message": "不允许删除存储根目录"}, 400)
            return
        if not os.path.exists(fp):
            self.reject_api("not_found")
            return
        is_dir = os.path.isdir(fp)
        try:
            if is_dir:
                shutil.rmtree(fp)
            else:
                os.remove(fp)
        except OSError as e:
            audit_log.error("api delete failed as=%s path=%s error=%s", principal, one_line(rel), one_line(e))
            self.send_json({"ok": False, "error": "write_failed", "message": "删除失败（可能被占用或无权限）"}, 500)
            return
        audit_log.warning("api delete as=%s %s=%s", principal, "dir" if is_dir else "file",
                          one_line(os.path.relpath(fp, STORAGE_DIR).replace("\\", "/")))
        self.send_json({"ok": True, "deleted": os.path.relpath(fp, STORAGE_DIR).replace("\\", "/"),
                        "is_dir": is_dir})

    def handle_api_folders(self):
        principal, error = self.authenticate_api("read")
        if not principal:
            self.reject_api(error)
            return

        folders = [""]
        for dirpath, dirnames, filenames in os.walk(STORAGE_DIR):
            dirnames.sort()
            rel = os.path.relpath(dirpath, STORAGE_DIR)
            if rel == ".":
                continue
            folders.append(rel.replace("\\", "/"))

        self.send_json(folders)

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

        moved, skipped = move_entries(sources, unquote(target_dir))
        if moved is None:
            self.send_text("Invalid target", 400)
            return

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
        elif path == "/settings":
            valid, username = self.is_authenticated()
            if not valid:
                self.send_redirect("/login")
                return
            self.send_html(render_settings_page())
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
        elif path == "/api/info":
            self.handle_api_info()
        elif path == "/api/list":
            self.handle_api_list()
        elif path == "/api/download":
            self.handle_api_download()
        else:
            self.send_text("Not found", 404)

    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/login":
            self.handle_login()
        elif path == "/api/upload":
            self.handle_api_upload()
        elif path == "/api/mkdir":
            self.handle_api_mkdir()
        elif path == "/api/move":
            self.handle_api_move()
        elif path == "/api/delete":
            self.handle_api_delete()
        elif path == "/settings":
            self.handle_settings()
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


def port_in_use():
    # Windows 上 SO_REUSEADDR 允许多个进程同时绑同一端口，请求被随机分摊到不同实例，
    # 表现为“刚登录就又说没登录”。启动前先探一次，宁可拒绝启动。
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(1)
    try:
        probe.connect(("127.0.0.1", PORT))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def main():
    try:
        setup_audit_log()
    except OSError as e:
        print(f"审计日志不可写（{e}），仅本次进程不记录")
    if port_in_use():
        print(f"端口 {PORT} 已有服务在监听，请先停止旧实例再启动")
        return
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
