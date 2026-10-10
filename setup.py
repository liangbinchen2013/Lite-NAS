import getpass
import argparse
from server import hash_password, load_config, save_config


def ask_username():
    while True:
        username = input("用户名: ").strip()
        if username:
            return username
        print("用户名不能为空，请重新输入")


def ask_password():
    while True:
        password = getpass.getpass("密码: ")
        if not password:
            print("密码不能为空，请重新输入")
            continue
        if password != getpass.getpass("确认密码: "):
            print("两次密码不一致，请重新设置密码")
            continue
        return password


def ask_interval(default_interval):
    while True:
        value = input(f"登录限流间隔(秒) [默认{default_interval}]: ").strip()
        if not value:
            return default_interval
        try:
            interval = int(value)
        except ValueError:
            print("请输入有效数字，例如 60")
            continue
        if interval < 0:
            print("间隔不能为负数，请重新输入")
            continue
        return interval


def setup_interactive():
    print("=== Lite-NAS 用户配置 ===\n")

    old_config = load_config()

    username = ask_username()
    password = ask_password()

    default_nas_name = old_config.get("nas_name", "Lite-NAS")
    nas_name = input(f"NAS名称 [默认{default_nas_name}]: ").strip() or default_nas_name

    rate_limit_interval = ask_interval(old_config.get("rate_limit_interval", 60))

    config = {
        "username": username,
        "password": hash_password(password),
        "nas_name": nas_name,
        "rate_limit_interval": rate_limit_interval
    }

    save_config(config)

    print(f"\n配置完成！用户: {username}")
    print(f"NAS名称: {nas_name}")
    print(f"限流间隔: {rate_limit_interval}秒")


def setup_command_line(args):
    old_config = load_config()
    config = old_config.copy()

    if args.username:
        config["username"] = args.username

    if args.password:
        config["password"] = hash_password(args.password)

    if args.nas_name is not None:
        config["nas_name"] = args.nas_name

    if args.rate_limit is not None:
        if args.rate_limit < 0:
            print("限流间隔不能为负数")
            return
        config["rate_limit_interval"] = args.rate_limit

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

    save_config(config)

    print(f"配置已更新！用户: {config['username']}")
    print(f"NAS名称: {config['nas_name']}")
    print(f"限流间隔: {config['rate_limit_interval']}秒")


def main():
    parser = argparse.ArgumentParser(description="Lite-NAS 配置工具")
    parser.add_argument("--username", "-u", help="登录用户名")
    parser.add_argument("--password", "-p", help="登录密码")
    parser.add_argument("--nas-name", "-n", help="NAS 显示名称")
    parser.add_argument("--rate-limit", "-r", type=int, help="登录限流间隔（秒）")

    args = parser.parse_args()

    has_args = any([args.username, args.password, args.nas_name is not None,
                    args.rate_limit is not None])

    if has_args:
        setup_command_line(args)
    else:
        setup_interactive()


if __name__ == "__main__":
    main()
