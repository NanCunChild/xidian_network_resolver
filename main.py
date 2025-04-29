# main.py
"""
西安电子科技大学校园网助手
提供校园网连接、认证和管理功能
"""

import asyncio
import ctypes
import os
import sys
import getpass
import logging
import platform
import threading
import json
import base64
import uuid
from pathlib import Path
from datetime import datetime
from typing import Dict, Tuple, List, Optional, Any, Union
from dataclasses import dataclass
import aiohttp

# 确保能找到同目录下的模块
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 导入自定义模块
from xidian_zfw import XidianZFW
import network_utils
from security import SecurityManager, CredentialManager

# 配置常量
CONFIG_DIR = Path.home() / ".xidian_network"
CONFIG_FILE = CONFIG_DIR / "config.enc"
LOGS_DIR = Path("logs")

# 校园网认证页面
XDU_WEB_AUTH_URL = "https://10.255.44.33/srun_portal_success?ac_id=8"
XDU_WIFI_NAMES = ["stu-xdwlan", "xd-wlan"]
XDU_WIRED_NAME = "以太网"
XDU_PPPOE_NAME = "宽带连接"

# 配置日志
def setup_logging():
    """设置日志系统"""
    LOGS_DIR.mkdir(exist_ok=True, parents=True)
    log_file = LOGS_DIR / f"app_{datetime.now().strftime('%Y%m%d')}.log"
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger("xidian_network")

# 创建全局日志对象
logger = setup_logging()


@dataclass
class AppState:
    """应用状态管理类"""
    account_info: Optional[Dict[str, Any]] = None
    zfw_client: Optional[XidianZFW] = None
    asyncio_loop: Optional[asyncio.AbstractEventLoop] = None
    asyncio_thread: Optional[threading.Thread] = None
    stop_event: threading.Event = threading.Event()


class AsyncManager:
    """异步操作管理类"""
    
    @staticmethod
    def run_asyncio_loop(app_state: AppState):
        """在独立线程中运行asyncio事件循环"""
        app_state.asyncio_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(app_state.asyncio_loop)
        logger.info("Asyncio事件循环在后台线程启动")
        app_state.asyncio_loop.run_forever()
        logger.info("Asyncio事件循环停止")
        app_state.asyncio_loop.close()

    @staticmethod
    def submit_async_task(app_state: AppState, coro):
        """安全地提交协程到后台事件循环"""
        if app_state.asyncio_loop and app_state.asyncio_loop.is_running():
            asyncio.run_coroutine_threadsafe(coro, app_state.asyncio_loop)
        else:
            logger.warning("Asyncio事件循环未运行，无法提交任务")

    @staticmethod
    def start_asyncio_thread(app_state: AppState):
        """启动后台asyncio线程"""
        app_state.stop_event.clear()
        app_state.asyncio_thread = threading.Thread(
            target=AsyncManager.run_asyncio_loop,
            args=(app_state,),
            daemon=True
        )
        app_state.asyncio_thread.start()
        logger.info("Asyncio后台线程已启动")

    @staticmethod
    def stop_asyncio_thread(app_state: AppState):
        """停止后台asyncio线程"""
        if app_state.asyncio_loop and app_state.asyncio_loop.is_running():
            logger.info("正在停止asyncio事件循环...")
            app_state.asyncio_loop.call_soon_threadsafe(app_state.asyncio_loop.stop)


class UIManager:
    """用户界面管理类"""
    
    @staticmethod
    def clear_screen():
        """清空控制台屏幕"""
        os.system('cls' if platform.system() == "Windows" else 'clear')

    @staticmethod
    def print_header(title="西安电子科技大学校园网助手"):
        """打印程序标题头"""
        UIManager.clear_screen()
        print("=" * 60)
        print(f"{title:^60}")
        print("=" * 60)
        print()

    @staticmethod
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
        print(f"  电子钱包: {account_info.get('wallet', 0):.2f}")
        print("\n  套餐信息:")
        print(f"  套餐数量: {account_info.get('plan_num', 0)}")
        print(f"  联通套餐: {'是' if account_info.get('unicom_plan') else '否'}")
        print(f"  电信套餐: {'是' if account_info.get('telecom_plan') else '否'}")
        print("-" * 60)

    @staticmethod
    def show_main_menu():
        """显示主菜单并获取用户选择"""
        print("\n请选择需要执行的操作:")
        print(" --- 网络修复 ---")
        print(" 1. 检查网络连接状态")
        print(" 2. 重置系统代理设置")
        print(" 3. 打开校园网Web认证页面")
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
            except EOFError:
                return 0

    @staticmethod
    def show_advanced_menu():
        """显示高级菜单"""
        print("\n高级选项:")
        print("1. 退出当前账号")
        print("2. 清除保存的密码")
        print("0. 返回主菜单")
        return input("请选择: ")


class NetworkManager:
    """网络功能管理类"""
    
    @staticmethod
    def check_admin():
        """检查程序是否有管理员权限"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False

    @staticmethod
    def handle_adapter_operations():
        """处理网络适配器管理流程"""
        adapters = network_utils.get_network_adapters()
        if not adapters:
            print("\n未找到可用的网络适配器")
            return
            
        selected = network_utils.select_adapter_interactive(adapters)
        if not selected:
            return
            
        while True:
            print(f"\n当前操作适配器: {selected['name']}")
            print("1. 修改DNS服务器")
            print("2. 禁用IPv6协议")
            print("3. 重启网络适配器")
            print("4. 刷新适配器状态")
            print("0. 返回上级菜单")
            
            choice = input("请选择操作: ")
            
            if choice == "1":
                dns_servers = input("请输入DNS服务器，空格分隔，留空恢复DHCP: ").split()
                success, msg = network_utils.change_dns(selected['name'], dns_servers)
                print(f"\n{msg}")
                
            elif choice == "2":
                success, msg = network_utils.disable_ipv6(selected['name'])
                print(f"\n{msg}")
                
            elif choice == "3":
                success, msg = network_utils.reset_adapter(selected['name'])
                print(f"\n{msg}")
                
            elif choice == "4":
                new_adapters = network_utils.get_network_adapters()
                selected = next((a for a in new_adapters if a['name'] == selected['name']), None)
                print("\n适配器状态已刷新")
                if not selected:
                    print("警告，当前选定的适配器似乎已不再可用。")
                    break
                    
            elif choice == "0":
                break
                
            else:
                print("无效输入")
                
            input("\n按Enter继续...")


class AppController:
    """应用控制器，处理主要业务逻辑"""
    
    def __init__(self):
        """初始化应用控制器"""
        self.state = AppState()
        self.state.zfw_client = XidianZFW()
        self.credential_manager = CredentialManager(CONFIG_DIR, CONFIG_FILE)
        self.security_manager = SecurityManager()
        
    def start(self):
        """启动应用"""
        UIManager.print_header()
        logger.info("程序启动")
        
        # 启动后台异步线程
        AsyncManager.start_asyncio_thread(self.state)
        
        # 尝试登录
        if not self._handle_login():
            logger.error("登录失败，程序退出")
            input("按Enter退出...")
            return
            
        # 进入主菜单循环
        self._main_menu_loop()
        
        # 停止后台线程
        AsyncManager.stop_asyncio_thread(self.state)
        logger.info("程序已退出")

    def _handle_login(self) -> bool:
        """处理用户登录，返回是否成功登录"""
        # 尝试读取保存的凭据
        saved_user, saved_pwd = self.credential_manager.load_credentials()
        
        # 自动登录逻辑
        if saved_user and saved_pwd:
            print(f"\n检测到上次登录的账号: {saved_user}")
            choice = input("是否使用保存的凭证登录? (Y/n) ").lower()
            
            if choice in ('', 'y', 'yes'):
                self.state.account_info = self.state.zfw_client.login(saved_user, saved_pwd)
                
                if self.state.account_info and self.state.account_info.get('status') == 'success':
                    logger.info(f"用户 {saved_user} 自动登录成功")
                    return True
                    
                print("自动登录失败，请手动输入凭证")
        
        # 手动登录
        username = input("请输入校园网账号 (学号): ")
        password = getpass.getpass("请输入密码: ")
        
        self.state.account_info = self.state.zfw_client.login(username, password)
        
        if self.state.account_info and self.state.account_info.get('status') == 'success':
            logger.info(f"用户 {username} 手动登录成功")
            # 登录成功后保存凭证
            save_choice = input("是否保存登录凭证以便下次自动登录? (Y/n) ").lower()
            if save_choice in ('', 'y', 'yes'):
                self.credential_manager.save_credentials(username, password)
            return True
            
        print("登录失败，请检查凭证")
        return False

    def _main_menu_loop(self):
        """主菜单循环"""
        while True:
            UIManager.print_header()
            UIManager.print_account_info(self.state.account_info)
            choice = UIManager.show_main_menu()
            
            if choice == 1:  # 检查网络连接状态
                self._check_network_connectivity()
                
            elif choice == 2:  # 重置系统代理
                self._reset_system_proxy()
                
            elif choice == 3:  # 打开Web认证页面
                self._open_web_auth_page()
                
            elif choice == 4:  # 网络适配器管理
                NetworkManager.handle_adapter_operations()
                
            elif choice == 8:  # 刷新账户信息
                self._refresh_account_info()
                
            elif choice == 9:  # 高级菜单
                if not self._handle_advanced_menu():
                    return  # 如果高级菜单处理函数返回False，表示需要退出
                    
            elif choice == 0:  # 退出
                print("正在退出程序...")
                logger.info("程序退出")
                break
                
            else:
                print("无效选项，请输入列表中的数字。")
                
            # 等待用户继续
            if choice not in (0, 9):
                print("\n" + "=" * 60)
                input("按Enter返回主菜单...")

    def _check_network_connectivity(self):
        """检查网络连接状态"""
        print("\n正在检查网络连接...")
        status, message = network_utils.check_internet_connectivity()
        print(f"检查结果: {message} (状态: {status})")
        
        if status == "portal":
            print("检测到可能需要Web认证，请尝试选项3。")
        elif status == "offline":
            print("网络似乎未连接，请检查物理连接或Wi-Fi/有线设置。")

    def _reset_system_proxy(self):
        """重置系统代理设置"""
        print("\n正在尝试重置系统代理设置...")
        current_proxy = network_utils.get_system_proxy_settings()
        
        if current_proxy and not current_proxy.get('enabled'):
            print("当前系统代理已禁用，无需重置。")
        elif current_proxy:
            print(f"当前代理服务器: {current_proxy.get('server')}")
            confirm = input("确定要重置吗 (y/n)? ").lower()
            
            if confirm == 'y':
                success, message = network_utils.reset_system_proxy()
                if success:
                    print(f"成功: {message}")
                else:
                    print(f"失败: {message}")
                    if "权限" in message:
                        print("提示: 此操作可能需要以管理员身份运行程序。")
            else:
                print("操作已取消。")
        else:
            print("未能获取到当前代理设置。")

    def _open_web_auth_page(self):
        """打开Web认证页面"""
        print(f"\n正在尝试打开Web认证页面: {XDU_WEB_AUTH_URL}")
        success, message = network_utils.open_web_page(XDU_WEB_AUTH_URL)
        
        if success:
            print(message)
        else:
            print(f"失败: {message}")

    def _refresh_account_info(self):
        """刷新账户信息"""
        logger.info("刷新账户信息...")
        
        if self.state.account_info and 'username' in self.state.account_info:
            self.state.account_info = self.state.zfw_client.get_plan_info(
                self.state.account_info['username']
            )
            print("\n信息已刷新")
        else:
            print("\n当前没有登录账号信息可供刷新。")

    def _handle_advanced_menu(self) -> bool:
        """处理高级菜单，返回是否继续主菜单"""
        sub_choice = UIManager.show_advanced_menu()
        
        if sub_choice == '1':  # 退出当前账号
            self.credential_manager.clear_credentials()
            print("已退出登录")
            self.state.account_info = None
            return False  # 返回False表示退出主菜单
            
        elif sub_choice == '2':  # 清除保存的密码
            self.credential_manager.clear_credentials()
            print("已清除保存的密码")
            
        elif sub_choice != '0':  # 非法选项
            print("无效高级选项。")
            input("\n按Enter继续...")
            
        return True  # 默认继续主菜单


# 程序入口
if __name__ == "__main__":
    # 确保logs目录存在
    LOGS_DIR.mkdir(exist_ok=True, parents=True)
    
    # 设置控制台标题 (Windows)
    if platform.system() == "Windows":
        os.system("title 西安电子科技大学校园网助手")
    
    # 运行主程序
    try:
        app = AppController()
        app.start()
    except KeyboardInterrupt:
        print("\n程序被用户中断")
        logger.info("程序被用户中断")
    except Exception as e:
        logger.critical(f"主程序发生未捕获错误: {e}", exc_info=True)
        print(f"\n程序发生错误: {e}")
        input("按Enter退出...")
    
    logger.info("程序已退出")