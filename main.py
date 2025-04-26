# main.py
import ctypes
import os
import sys
import getpass
import logging
import platform
from xidian_zfw import XidianZFW
import network_utils
from time import sleep
from pathlib import Path
import winreg
import base64
from Crypto.Cipher import AES

# 确保能找到同目录下的模块
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/app.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("main")

# --- 全局变量 ---
# 校园网认证页面 (需要替换为实际的固定IP或域名)
XDU_WEB_AUTH_URL = "https://10.255.44.33/srun_portal_success?ac_id=8"
# 常用的校园网 Wifi 名称 (用于后续判断是否需要禁用IPv6等)
XDU_WIFI_NAMES = ["stu-xdwlan", "xd-wlan"] # 可能需要根据实际情况调整
# 常用的有线连接名称 (用于后续PPPoE或禁用IPv6)
XDU_WIRED_NAME = "以太网" # Windows 默认名称，可能需要用户确认或自动检测
XDU_PPPOE_NAME = "宽带连接" # Windows 默认名称，用户可能自定义

CONFIG_DIR = Path.home() / ".xidian_zfw"
CONFIG_FILE = CONFIG_DIR / "config.enc"
SECRET_KEY = "this_is_a_32_byte_key_for_aes256"

# --- 辅助函数 ---
def clear_screen():
    """清空控制台屏幕"""
    os.system('cls' if platform.system() == "Windows" else 'clear')

def print_header(title="西安电子科技大学校园网助手"):
    """打印程序标题头"""
    clear_screen()
    print("=" * 60)
    print(f"{title:^60}")
    print("=" * 60)
    print() # 空一行

def print_account_info(account_info):
    """格式化打印账户信息"""
    if not account_info:
        print("未能获取到有效的账户信息。")
        return
    
    print("-" * 60)
    print("  账户基本信息")
    print("-" * 60)
    print(f"  姓名: {account_info.get('realname', 'N/A')}")
    print(f"  状态: {account_info.get('user_status', 'N/A')}")
    print(f"  电子钱包: ￥{account_info.get('wallet', 0):.2f}")
    
    print("\n 套餐信息:")
    print(f"  套餐数量: {account_info.get('plan_num', 0)}")
    print(f"  联通套餐: {'是' if account_info.get('unicom_plan') else '否'}")
    print(f"  电信套餐: {'是' if account_info.get('telecom_plen') else '否'}")
    
    # print("\n 在线设备:")
    # print(f"  付费IP数量: {account_info.get('ip_pay', 0)}")
    # print(f"  免费IP数量: {account_info.get('ip_free', 0)}")
    print("-" * 60)

def check_admin():
    """检查管理员权限"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def _encrypt_data(data: str) -> str:
    """AES加密"""
    cipher = AES.new(SECRET_KEY.encode(), AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def _decrypt_data(encrypted: str) -> str:
    """AES解密"""
    data = base64.b64decode(encrypted)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(SECRET_KEY.encode(), AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def save_credentials(username: str, password: str):
    """保存加密后的凭证"""
    CONFIG_DIR.mkdir(exist_ok=True, parents=True)
    encrypted = _encrypt_data(f"{username}:{password}")
    CONFIG_FILE.write_text(encrypted)

def load_credentials():
    """加载保存的凭证"""
    if not CONFIG_FILE.exists():
        return None, None
    try:
        data = _decrypt_data(CONFIG_FILE.read_text())
        return data.split(':', 1)
    except Exception as e:
        print(f"凭证解密失败: {str(e)}")
        return None, None

def clear_credentials():
    """清除保存的凭证"""
    if CONFIG_FILE.exists():
        CONFIG_FILE.unlink()

# --- 主菜单功能 ---

def show_main_menu(account_info=None):
    """显示主菜单并获取用户选择"""
    print("\n请选择需要执行的操作:")
    print(" --- 网络修复 ---")
    print(" 1. 检查网络连接状态")
    print(" 2. 重置系统代理设置 (修复Clash等代理悬空)")
    print(" 3. 打开校园网 Web 认证页面")
    print(" 4. 网络适配器管理")
    print(" --- 账号相关 ---")
    print(" 8. 刷新校园网账户信息")
    print(" 9. 高级菜单")
    print(" --- 其他 ---")
    print(" 0. 退出程序")
    print("-" * 60)

    while True:
        try:
            choice = input("请输入选项数字: ")
            return int(choice)
        except ValueError:
            print("输入无效，请输入数字。")
        except EOFError: # 处理 Ctrl+Z 等输入结束符
             return 0 # 视为退出

def show_advanced_menu():
        print("\n高级选项:")
        print("1. 退出当前账号")
        print("2. 清除保存的密码")
        print("0. 返回主菜单")
        return input("请选择: ")
    
def network_adapter_menu():
    """网络适配器管理子菜单"""
    from network_utils import get_network_adapters, sort_adapters, select_adapter_interactive
    
    adapters = sort_adapters(get_network_adapters())
    if not adapters:
        print("未找到可用的网络适配器")
        return
    
    selected_adapter = select_adapter_interactive(adapters)
    if not selected_adapter:
        return
    
    print(f"\n当前操作适配器: {selected_adapter}")
    print("1. 修改DNS服务器")
    print("2. 禁用IPv6协议")
    print("3. 恢复默认设置")
    choice = input("请选择操作: ")
    
    if choice == "1":
        dns_servers = input("请输入DNS服务器 (多个用空格分隔): ").split()
        success, msg = network_utils.change_dns(selected_adapter, dns_servers)
        print(f"\n{msg}")
    elif choice == "2":
        success, msg = network_utils.disable_ipv6(selected_adapter)
        print(f"\n{msg}")
    # 其他操作类似...
    else:
        print("无效选择")
        
def handle_adapter_operations():
    """处理网络适配器管理流程"""
    from network_utils import (
        get_network_adapters,
        sort_adapters,
        select_adapter_interactive,
        change_dns,
        disable_ipv6,
        reset_adapter
    )
    
    # 获取并排序适配器
    adapters = get_network_adapters()
    if not adapters:
        print("\n未找到可用的网络适配器")
        return
    
    sorted_adapters = sort_adapters(adapters)
    
    # 交互式选择适配器
    selected = select_adapter_interactive(sorted_adapters)
    if not selected:
        return
    
    # 显示适配器操作菜单
    while True:
        print(f"\n当前操作适配器: {selected['name']}")
        print("1. 修改DNS服务器")
        print("2. 禁用IPv6协议")
        print("3. 重启网络适配器")
        print("4. 刷新适配器状态")
        print("0. 返回上级菜单")
        
        choice = input("请选择操作: ")
        
        if choice == "1":
            dns_servers = input("请输入DNS服务器（空格分隔，留空恢复DHCP）: ").split()
            success, msg = change_dns(selected['name'], dns_servers)
            print(f"\n{msg}")
        elif choice == "2":
            success, msg = disable_ipv6(selected['name'])
            print(f"\n{msg}")
        elif choice == "3":
            success, msg = reset_adapter(selected['name'])
            print(f"\n{msg}")
        elif choice == "4":
            # 刷新状态
            new_adapters = get_network_adapters()
            selected = next((a for a in new_adapters if a['name'] == selected['name']), None)
            print("\n适配器状态已刷新")
        elif choice == "0":
            break
        else:
            print("无效输入")
        
        input("\n按 Enter 继续...")

# --- 主程序逻辑 ---
def main():
    print_header()
    logger.info("程序启动。")
    zfw = XidianZFW()

    # 尝试读取保存的凭据或提示输入
    account_info = None
    saved_user, saved_pwd = load_credentials()
    # 自动登录逻辑
    if saved_user and saved_pwd:
        print(f"\n检测到上次登录的账号: {saved_user}")
        choice = input("是否使用保存的凭证登录? (Y/n) ").lower()
        if choice in ('', 'y', 'yes'):
            account_info = zfw.login(saved_user, saved_pwd)
            if account_info['status'] != 'success':
                print("自动登录失败，请手动输入凭证")
                
    # 手动登录流程
    if not account_info or account_info['status'] != 'success':
        username = input("请输入校园网账号 (学号): ")
        password = getpass.getpass("请输入密码: ")
        
        account_info = zfw.login(username, password)
        if account_info['status'] == 'success':
            # remember = input("是否记住密码? (y/N) ").lower()
            # if remember == 'y':
            #     save_credentials(username, password)
            #     print("密码已安全保存")
            save_credentials(username, password)
        else:
            print("登录失败，请检查凭证")
            return
    session = None
    
    if not account_info:
        logger.error("超过最大重试次数，登录失败")
        input("按 Enter 退出...")
        return


    # 主菜单循环
    while True:
        print_header()
        print_account_info(account_info)

        choice = show_main_menu()

        if choice == 1: # 检查网络连接状态
            print("\n正在检查网络连接...")
            status, message = network_utils.check_internet_connectivity()
            print(f"检查结果: {message} (状态: {status})")
            if status == "portal":
                 print("检测到可能需要 Web 认证，请尝试选项 3。")
            elif status == "offline":
                 print("网络似乎未连接，请检查物理连接或 Wi-Fi/有线设置。")
                 # 后续可以引导用户检查适配器状态或进行PPPoE拨号等

        elif choice == 2: # 重置系统代理
            print("\n正在尝试重置系统代理设置...")
            current_proxy = network_utils.get_system_proxy_settings()
            if not current_proxy.get('enabled'):
                 print("当前系统代理已禁用，无需重置。")
            else:
                 print(f"当前代理服务器: {current_proxy.get('server')}")
                 confirm = input("确定要重置吗 (y/n)? ").lower()
                 if confirm == 'y':
                     success, message = network_utils.reset_system_proxy()
                     if success:
                         print(f"成功: {message}")
                     else:
                         print(f"失败: {message}")
                         if "权限" in message:
                             print("提示：此操作可能需要以管理员身份运行程序。")
                 else:
                      print("操作已取消。")

        elif choice == 3: # 打开 Web 认证页面
            print(f"\n正在尝试打开 Web 认证页面: {XDU_WEB_AUTH_URL}")
            success, message = network_utils.open_web_page(XDU_WEB_AUTH_URL)
            if success:
                print(message)
            else:
                print(f"失败: {message}")
                
        elif choice == 4:
            handle_adapter_operations()

        # --- 账号相关 ---
        elif choice == 8: # 刷新账户信息
            logger.info("刷新账户信息...")
            account_info = zfw.get_plan_info(username)
            print("\n信息已刷新！")

        elif choice == 9:  # 新增高级菜单
            sub_choice = show_advanced_menu()
            if sub_choice == '1':
                zfw.session.close()
                clear_credentials()
                print("已退出登录")
                return
            elif sub_choice == '2':
                clear_credentials()
                print("已清除保存的密码")
            elif sub_choice == '0':
                continue

        elif choice == 0: # 退出
            print("正在退出程序...")
            if session:
                session.close() # 关闭 requests 会话
                logger.info("Requests session closed.")
            logger.info("程序退出。")
            break # 跳出 while 循环

        else:
            print("无效选项，请输入列表中的数字。")

        # --- 等待用户继续 ---
        print("\n" + "=" * 60)
        input("按 Enter 返回主菜单...")


if __name__ == "__main__":
    if platform.system() == "Windows" and not check_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
        sys.exit()
        
    if not os.path.exists("logs"):
        try:
            os.makedirs("logs")
        except OSError as e:
            print(f"警告：无法创建 logs 目录: {e}")
            # 程序可以继续运行，但日志可能无法写入文件

    # 设置控制台标题 (Windows)
    if platform.system() == "Windows":
         os.system("title 西安电子科技大学校园网助手")

    main()

    # 程序结束前等待用户按键（可选）
    # input("按 Enter 键退出...")