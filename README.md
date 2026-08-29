# Lite-NAS

轻量级个人云盘，基于 Python 标准库，无需额外依赖。

## 功能

- 文件上传（支持拖拽、多文件）
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
- 环境异常检测（自动识别回环地址，支持调试模式）

## 使用方法

### 1. 配置用户

**交互式配置：**

```bash
python setup.py
```

按提示输入：
- 用户名
- 密码（需确认）
- NAS 名称，默认 Lite-NAS
- 登录限流间隔（秒），默认 60
- 调试模式（允许 127.0.0.1 登录），默认关闭

**命令行参数配置：**

```bash
python setup.py --username admin --password 123456 --nas-name "我的云盘"
```

| 参数 | 简写 | 说明 | 示例 |
|------|------|------|------|
| `--username` | `-u` | 登录用户名 | `--username admin` |
| `--password` | `-p` | 登录密码 | `--password 123456` |
| `--nas-name` | `-n` | NAS 显示名称 | `--nas-name "我的云盘"` |
| `--rate-limit` | `-r` | 登录限流间隔（秒） | `--rate-limit 120` |
| `--debug` | `-d` | 启用调试模式 | `--debug` |
| `--no-debug` | | 禁用调试模式 | `--no-debug` |

可混合使用命令行参数，未指定的参数保留原值或使用默认值。

自动生成 `config.json`。

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
├── .gitignore
└── README.md
```

## 配置说明

`config.json` 字段：

| 字段 | 说明 | 默认值 |
|------|------|--------|
| `username` | 登录用户名 | - |
| `password` | 密码（MD5 哈希） | - |
| `nas_name` | NAS 显示名称 | Lite-NAS |
| `rate_limit_interval` | 登录失败后限流间隔（秒） | 60 |
| `debug` | 调试模式，允许 127.0.0.1 登录 | false |

## 安全特性

- **登录限流**：连续登录失败后，该 IP 将被限流，间隔时间可配置
- **环境异常检测**：自动识别 127.0.0.1 / ::1 / 0.0.0.0 等回环地址
  - `debug: false` → 拒绝访问并提示"环境异常"
  - `debug: true` → 允许通过（开发环境使用）
- **IP 检测优先级**：CF-Connecting-IP → remote_addr

## 依赖

无。仅使用 Python 标准库。
