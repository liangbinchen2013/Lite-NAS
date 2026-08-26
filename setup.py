import hashlib
import json
import getpass

CONFIG_FILE = "config.json"


def md5_hash(password):
    return hashlib.md5(password.encode()).hexdigest()


def setup():
    print("=== Lite-NAS 用户配置 ===\n")
    
    username = input("用户名: ").strip()
    if not username:
        print("用户名不能为空")
        return
    
    password = getpass.getpass("密码: ")
    if not password:
        print("密码不能为空")
        return
    
    confirm = getpass.getpass("确认密码: ")
    if password != confirm:
        print("两次密码不一致")
        return
    
    config = {
        "username": username,
        "password": md5_hash(password)
    }
    
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
    print(f"\n配置完成！用户: {username}")


if __name__ == "__main__":
    setup()
