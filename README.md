# Lite-NAS

轻量级个人云盘，基于 Python 标准库，无需额外依赖。

## 功能

- 文件上传（支持拖拽、多文件）
- 文件下载（支持中文文件名）
- 文件删除
- 上传进度条（大小 / 速度 / 百分比）
- 用户名 + 密码登录认证
- 已使用空间显示

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
├── .gitignore
└── README.md
```

## 依赖

无。仅使用 Python 标准库。
