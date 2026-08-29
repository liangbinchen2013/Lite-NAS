import hashlib
import json
import getpass
import argparse

CONFIG_FILE = "config.json"


def md5_hash(password):
    return hashlib.md5(password.encode()).hexdigest()


def load_config():
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def setup_interactive():
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


def setup_command_line(args):
    old_config = load_config()
    config = old_config.copy()

    if args.username:
        config["username"] = args.username

    if args.password:
        config["password"] = md5_hash(args.password)

    if args.nas_name is not None:
        config["nas_name"] = args.nas_name

    if args.rate_limit is not None:
        if args.rate_limit < 0:
            print("限流间隔不能为负数")
            return
        config["rate_limit_interval"] = args.rate_limit

    if args.debug is not None:
        config["debug"] = args.debug

    if "username" not in config or not config["username"]:
        print("用户名不能为空")
        return
    if "password" not in config or not config["password"]:
        print("密码不能为空")
        return
    if "nas_name" not in config:
        config["nas_name"] = "Lite-NAS"
    if "rate_limit_interval" not in config:
        config["rate_limit_interval"] = 60
    if "debug" not in config:
        config["debug"] = False

    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    print(f"配置已更新！用户: {config['username']}")
    print(f"NAS名称: {config['nas_name']}")
    print(f"限流间隔: {config['rate_limit_interval']}秒")
    print(f"调试模式: {'开启' if config['debug'] else '关闭'}")


def main():
    parser = argparse.ArgumentParser(description="Lite-NAS 配置工具")
    parser.add_argument("--username", "-u", help="登录用户名")
    parser.add_argument("--password", "-p", help="登录密码")
    parser.add_argument("--nas-name", "-n", help="NAS 显示名称")
    parser.add_argument("--rate-limit", "-r", type=int, help="登录限流间隔（秒）")
    parser.add_argument("--debug", "-d", action="store_true", default=None, help="启用调试模式")
    parser.add_argument("--no-debug", dest="debug", action="store_false", help="禁用调试模式")

    args = parser.parse_args()

    has_args = any([args.username, args.password, args.nas_name is not None,
                    args.rate_limit is not None, args.debug is not None])

    if has_args:
        setup_command_line(args)
    else:
        setup_interactive()


if __name__ == "__main__":
    main()
