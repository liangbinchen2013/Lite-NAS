# Lite-NAS

轻量级个人云盘，基于 Python 标准库，无需额外依赖。

## 功能

- 文件上传（支持拖拽、多文件；同名自动改名为 `xxx (1).ext` 并在页面提示，不覆盖旧文件）
- 上传队列控制（可暂停 / 继续 / 取消；取消时已上传的保留，未上传的不再发送）
- 文件夹上传（选择文件夹 / 拖拽文件夹，保留目录结构）
- 文件下载（支持中文文件名）
- 文件夹 / 多文件下载（ZIP 压缩包，可选压缩级别）
- 文件删除（支持文件和文件夹）
- 新建文件夹
- 文件移动（单个移动 / 批量移动 / 拖拽移动）
- 上传进度条（大小 / 速度 / 剩余时间 / 百分比）
- 用户名 + 密码登录认证
- 已使用空间显示
- 文件按字典序排列（文件夹在前）
- 登录限流（可配置限流间隔，防止暴力破解）
- 上传 / 下载限速（KB/s，0 为不限速）
- 图形化设置页 `/settings`（NAS 名称、用户名、密码、限流间隔、上下行限速、API 密钥管理）
- JSON API（`/api/*`）：用可精确到文件夹的密钥读写文件，把 NAS 当轻量对象存储用
- 本机、局域网、隧道访问都直接可用，无需额外开关

## 使用方法

### 1. 配置用户

**交互式配置（推荐）：**

```bash
python setup.py
```

按提示输入：
- 用户名
- 密码（不回显，需确认）
- NAS 名称，默认 Lite-NAS
- 登录限流间隔（秒），默认 60

**命令行参数配置：**

```bash
python setup.py --username admin --nas-name "我的云盘"
```

| 参数 | 简写 | 说明 | 示例 |
|------|------|------|------|
| `--username` | `-u` | 登录用户名 | `--username admin` |
| `--password` | `-p` | 登录密码（见下方提示） | `--password 123456` |
| `--nas-name` | `-n` | NAS 显示名称 | `--nas-name "我的云盘"` |
| `--rate-limit` | `-r` | 登录限流间隔（秒） | `--rate-limit 120` |

可混合使用命令行参数，未指定的参数保留原值或使用默认值。

> **提示**：`-p/--password` 会把明文口令留在 shell 历史和进程列表里，同机其他用户可能读到。
> 只改口令时优先用交互式；确需用 `-p` 时，在不共享账号的机器上执行，或改完立刻用
> `python setup.py` 重设一次。

生成 `config.json`（写入脚本所在目录，权限尝试收紧为 600）。

### 2. 启动服务

```bash
python server.py
```

访问 http://127.0.0.1:8888

### 3. 停止服务

`Ctrl+C`

## 目录结构

```
Lite-NAS/
├── server.py          # 主程序
├── setup.py           # 用户配置工具
├── config.json        # 用户凭据及配置（已 gitignore）
├── templates/
│   ├── login.html     # 登录页
│   ├── index.html     # 文件管理页
│   └── settings.html  # 设置页
├── storage/           # 文件存储目录（已 gitignore）
├── .zip_tasks/        # 临时压缩文件（自动清理）
├── nas.log            # 审计日志，2MB×3 滚动（已 gitignore）
├── .gitignore
└── README.md
```

## 配置说明

`config.json` 字段：

| 字段 | 说明 | 默认值 |
|------|------|--------|
| `username` | 登录用户名 | - |
| `password` | 密码（PBKDF2-SHA256 + 随机盐） | - |
| `nas_name` | NAS 显示名称 | Lite-NAS |
| `rate_limit_interval` | 登录失败后限流间隔（秒），0 为不锁定 | 60 |
| `upload_limit_kb` | 上传限速（KB/s），0 为不限速 | 0 |
| `download_limit_kb` | 下载限速（KB/s），0 为不限速 | 0 |

以上三项也可以直接在设置页里改，保存后立即对新请求生效。

`api_keys` 字段由设置页维护，不手工编辑：每项含 `id`、`name`、`scopes`、`root`（授权目录）、
`secret_hash`（SHA-256 摘要）与 `created`，**不保存密钥明文**。

## API（把 NAS 当对象存储用）

### 认证

在设置页「API 密钥」卡片创建密钥，得到形如 `lnas_<id>_<64位十六进制>` 的明文，
**只在创建那一次显示**。请求时带上：

```
Authorization: Bearer lnas_xxxxxxxx_yyyyy...
```

权限位按端点强制，最小够用即可：

| 权限位 | 允许的操作 |
|--------|------------|
| `read` | 列出、信息、下载 |
| `write` | 上传、建目录、移动 |
| `delete` | 删除 |

创建密钥时还要选**授权目录**（设置页的下拉框），权限因此精确到某个文件夹：

- 该目录就是这把密钥的“根”，所有 `path` 都相对它解析，也只允许落在它内部
- 它看不到上层与同级其它目录，`/api/info` 的用量也只统计自己这棵子树
- 想给整个存储就选「整个存储」（留空同义；不带 `root` 字段的旧密钥按整个存储处理）
- 被授权的目录之后被删除或改名，该密钥会得到 `403 root_missing` 的明确提示而不是莫名 404

密钥无效或缺权限分别返回 `401 invalid_key` / `403 insufficient_scope`；
越界路径一律 `400 invalid_path`（不静默改写）；认证失败次数过多会按来源 IP 限流（复用登录限流间隔）。

### 端点

所有路径都是相对路径：对密钥而言相对于它的**授权目录**，对浏览器会话而言相对于整个 storage。
用 `/` 分隔；空串表示各自的根目录。含 `.` 或 `..` 段一律 `400 invalid_path`（不静默改写）。
响应统一为 JSON，错误形如 `{"ok": false, "error": "...", "message": "..."}`。

| 方法 | 路径 | 权限 | 说明 |
|------|------|------|------|
| GET | `/api/info?path=` | read | 名称、用量、条目数；指定目录只统计该子树 |
| GET | `/api/list?path=&recursive=&limit=&offset=` | read | 目录在前排序；默认 500 条，上限 2000，`truncated` 表示还有 |
| GET | `/api/download?path=` | read | 流式下载，受下载限速；目录返回 `not_a_file` |
| GET | `/api/folders` | read | 全部目录列表 |
| POST | `/api/upload?path=&name=` | write | 请求体即文件内容；必须带 `Content-Length`；返回 `201`，同名自动改名并回报 `renamed` |
| POST | `/api/mkdir` | write | JSON `{"path": "a/b"}`，多级自动创建 |
| POST | `/api/move` | write | JSON `{"sources": ["a.txt"], "target_dir": "b"}`，移到根目录传空串 |
| POST | `/api/delete` | delete | JSON `{"path": "a/b"}`，目录递归删除；不允许删存储根目录 |

### 示例

上传与下载：

```bash
curl -X POST "http://NAS:8888/api/upload?path=%E5%9B%BE%E7%89%87&name=1.jpg" \
     -H "Authorization: Bearer lnas_...." --data-binary @1.jpg
curl -o out.jpg "http://NAS:8888/api/download?path=%E5%9B%BE%E7%89%87/1.jpg" \
     -H "Authorization: Bearer lnas_...."
```

列举并翻页、建目录、移动、删除：

```bash
curl -G "http://NAS:8888/api/list" --data-urlencode "recursive=1" \
     --data-urlencode "limit=200" -H "Authorization: Bearer lnas_...."
curl -X POST "http://NAS:8888/api/mkdir" -H "Authorization: Bearer lnas_...." \
     -H "Content-Type: application/json" -d '{"path":"备份/2026"}'
curl -X POST "http://NAS:8888/api/move" -H "Authorization: Bearer lnas_...." \
     -H "Content-Type: application/json" -d '{"sources":["备份/a.txt"],"target_dir":""}'
curl -X POST "http://NAS:8888/api/delete" -H "Authorization: Bearer lnas_...." \
     -H "Content-Type: application/json" -d '{"path":"备份"}'
```

Python：

```python
import requests

BASE = "http://NAS:8888"
HDR = {"Authorization": "Bearer lnas_...."}

with open("photo.jpg", "rb") as f:
    r = requests.post(f"{BASE}/api/upload", params={"path": "相册", "name": "photo.jpg"},
                      data=f, headers=HDR, timeout=None)
    print(r.status_code, r.json()["path"], r.json().get("renamed"))

entries = requests.get(f"{BASE}/api/list", params={"recursive": 1, "limit": 500},
                       headers=HDR, timeout=30).json()["entries"]
```

### API 安全注意

- 走公网请务必经 HTTPS（隧道/反代）。纯 HTTP 下密钥是明文传输的；经同机反代时，
  `X-Forwarded-Proto: https` 会让会话 Cookie 自动带上 `Secure`
- 未开放 CORS，跨站网页脚本无法拿你的密钥发起请求；会话 Cookie 为 `SameSite=Strict`
- 吊销密钥立即生效（下一次请求即失效），无需重启服务
- 审计日志 `nas.log` 记录每个 API 调用的密钥名称、路径与大小，**不含密钥明文与摘要**
- 上传/下载限速对 API 同样生效（全局值，按连接独立）

## 安全特性

- **口令存储**：PBKDF2-SHA256 + 随机盐；旧版 MD5 配置在下次登录成功时自动升级，无需重新配置
- **审计日志**：登录成功/失败、被限流、上传、下载、删除、移动、登出均记入 `nas.log`（含用户名与客户端 IP），2MB×3 滚动，目录不可写时服务仍正常启动
- **会话 Cookie**：`HttpOnly` + `SameSite=Strict`（可挡跨站表单提交）；空闲 1 天或累计 7 天过期，服务重启后失效
- **响应加固**：所有响应附带 CSP（禁外部脚本、禁嵌框、限表单与请求同源）、`X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`、`Referrer-Policy: same-origin`，`Server` 头不暴露运行时版本
- **登录限流**：连续登录失败后，该 IP 将被限流，间隔时间可配置
- **客户端 IP 判定**：仅当 TCP 对端是本机回环地址（说明前面是同机的 Cloudflare Tunnel / Nginx）时才采信 `CF-Connecting-IP`；其余连接一律使用真实对端地址，避免伪造请求头绕过限流或定向锁死他人 IP
- **访问范围**：本机（127.0.0.1）、局域网、隧道进来的访客都可直接使用登录页，不再需要调试开关

## 依赖

无。仅使用 Python 标准库。
