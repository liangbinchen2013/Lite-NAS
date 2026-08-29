import hashlib
import json
import getpass

CONFIG_FILE = "config.json"


def md5_hash(password):
    return hashlib.md5(password.encode()).hexdigest()


def load_config():
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def setup():
    print("=== Lite-NAS 用户配置 ===\n")

    old_config = load_config()

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

    default_nas_name = old_config.get("nas_name", "Lite-NAS")
    nas_name = input(f"NAS名称 [默认{default_nas_name}]: ").strip()
    if not nas_name:
        nas_name = default_nas_name

    default_interval = old_config.get("rate_limit_interval", 60)
    interval_input = input(f"登录限流间隔(秒) [默认{default_interval}]: ").strip()
    if interval_input:
        try:
            rate_limit_interval = int(interval_input)
            if rate_limit_interval < 0:
                print("间隔不能为负数")
                return
        except ValueError:
            print("请输入有效数字")
            return
    else:
        rate_limit_interval = default_interval

    debug_input = input("调试模式 (允许127.0.0.1登录) [默认false]: ").strip().lower()
    debug = debug_input in ("true", "1", "yes", "y")

    config = {
        "username": username,
        "password": md5_hash(password),
        "nas_name": nas_name,
        "rate_limit_interval": rate_limit_interval,
        "debug": debug
    }

    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    print(f"\n配置完成！用户: {username}")
    print(f"NAS名称: {nas_name}")
    print(f"限流间隔: {rate_limit_interval}秒")
    print(f"调试模式: {'开启' if debug else '关闭'}")


if __name__ == "__main__":
    setup()
