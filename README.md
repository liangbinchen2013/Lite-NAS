# Lite-NAS

轻量级个人云盘，基于 Python 标准库，无需额外依赖。

## 功能

- 文件上传（支持拖拽、多文件；同名自动改名为 `xxx (1).ext` 并在页面提示，不覆盖旧文件）
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
│   └── index.html     # 文件管理页
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
| `rate_limit_interval` | 登录失败后限流间隔（秒） | 60 |

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
