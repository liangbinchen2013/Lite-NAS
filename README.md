# Lite-NAS

轻量级个人云盘，基于 Python 标准库，无需额外依赖。

## 功能

- 文件上传（支持拖拽、多文件）
- 文件夹上传（选择文件夹 / 拖拽文件夹，保留目录结构）
- 文件下载（支持中文文件名）
- 文件夹 / 多文件下载（ZIP 压缩包，可选压缩级别）
- 文件删除（支持文件和文件夹）
- 新建文件夹
- 上传进度条（大小 / 速度 / 剩余时间 / 百分比）
- 用户名 + 密码登录认证
- 已使用空间显示
- 文件按字典序排列（文件夹在前）

## 使用方法

### 1. 配置用户

```bash
python setup.py
```

按提示输入用户名和密码，自动生成 `config.json`。

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
├── config.json        # 用户凭据（MD5 哈希，已 gitignore）
├── templates/
│   ├── login.html     # 登录页
│   └── index.html     # 文件管理页
├── storage/           # 文件存储目录（已 gitignore）
├── .zip_tasks/        # 临时压缩文件（自动清理）
├── .gitignore
└── README.md
```

## 依赖

无。仅使用 Python 标准库。
