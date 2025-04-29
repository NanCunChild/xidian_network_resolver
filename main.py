# main.py
"""
西安电子科技大学校园网助手 (Windows版)
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
import time
import uuid
import webbrowser # 使用 webbrowser 替代 network_utils.open_web_page (更标准)
from pathlib import Path
from datetime import datetime
from typing import Dict, Tuple, List, Optional, Any, Union
from dataclasses import dataclass, field
from concurrent.futures import Future

# 确保能找到同目录下的模块 (如果它们确实在同目录)
# 更好的方式是使用包结构或设置 PYTHONPATH
# sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# --- 假设这些模块存在且功能符合预期 ---
# 导入自定义模块
try:
    from xidian_zfw import XidianZFW
    import network_utils # 假设包含 check_internet_connectivity, reset_system_proxy, get_system_proxy_settings, get_network_adapters, select_adapter_interactive, change_dns, disable_ipv6, reset_adapter
    from security import SecurityManager, CredentialManager # 假设存在且功能正确
except ImportError as e:
    print(f"错误：缺少必要的模块: {e}")
    print("请确保 xidian_zfw.py, network_utils.py, security.py 文件与 main.py 在同一目录或已正确安装。")
    sys.exit(1)
# --- --------------------------------- ---

# 配置常量
CONFIG_DIR = Path.home() / ".xidian_network"
CONFIG_FILE = CONFIG_DIR / "config.enc"
LOGS_DIR = Path("logs") # 日志放在程序当前目录的 logs 子目录

# 校园网认证页面
XDU_WEB_AUTH_URL = "https://10.255.44.33/srun_portal_success?ac_id=8"
XDU_WIFI_NAMES = ["stu-xdwlan", "xd-wlan"] # 也许可以在 network_utils 中使用
XDU_WIRED_NAME = "以太网" # 也许可以在 network_utils 中使用
XDU_PPPOE_NAME = "宽带连接" # 也许可以在 network_utils 中使用

# 配置日志
def setup_logging():
    """设置日志系统"""
    LOGS_DIR.mkdir(exist_ok=True, parents=True)
    log_file = LOGS_DIR / f"app_{datetime.now().strftime('%Y%m%d')}.log"

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - [%(threadName)s] - %(message)s', # 添加线程名
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    # 防止第三方库（如 aiohttp）日志过于冗余
    logging.getLogger("aiohttp").setLevel(logging.WARNING)
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
    stop_event: threading.Event = field(default_factory=threading.Event) # 使用 field 确保每次实例化 AppState 时创建新的 Event

class AsyncManager:
    """异步操作管理类"""

    @staticmethod
    def run_asyncio_loop(app_state: AppState):
        """在独立线程中运行asyncio事件循环"""
        try:
            app_state.asyncio_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(app_state.asyncio_loop)
            logger.info("Asyncio事件循环在后台线程启动")
            app_state.asyncio_loop.run_forever()
        except Exception as e:
            logger.error(f"Asyncio事件循环出错: {e}", exc_info=True)
        finally:
            # 清理循环资源
            if app_state.asyncio_loop:
                logger.info("正在关闭Asyncio事件循环...")
                try:
                    # 取消所有剩余任务
                    tasks = asyncio.all_tasks(loop=app_state.asyncio_loop)
                    for task in tasks:
                        task.cancel()
                    # 等待任务取消完成
                    app_state.asyncio_loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
                    app_state.asyncio_loop.run_until_complete(app_state.asyncio_loop.shutdown_asyncgens())
                except Exception as ex:
                     logger.error(f"关闭asyncio任务时出错: {ex}", exc_info=True)
                finally:
                     app_state.asyncio_loop.close()
                     logger.info("Asyncio事件循环已关闭")
                     app_state.asyncio_loop = None


    @staticmethod
    def submit_async_task(app_state: AppState, coro) -> Optional[Future]:
        """安全地提交协程到后台事件循环"""
        if app_state.asyncio_loop and app_state.asyncio_loop.is_running():
            # 返回 concurrent.futures.Future 对象，允许主线程等待结果
            return asyncio.run_coroutine_threadsafe(coro, app_state.asyncio_loop)
        else:
            logger.warning("Asyncio事件循环未运行，无法提交任务")
            return None

    @staticmethod
    def start_asyncio_thread(app_state: AppState):
        """启动后台asyncio线程"""
        if app_state.asyncio_thread and app_state.asyncio_thread.is_alive():
            logger.warning("Asyncio后台线程已在运行")
            return

        app_state.stop_event.clear() # 重置停止信号
        app_state.asyncio_thread = threading.Thread(
            target=AsyncManager.run_asyncio_loop,
            args=(app_state,),
            daemon=True, # 设置为守护线程，主线程退出时它也会退出
            name="AsyncioLoopThread" # 给线程命名方便调试
        )
        app_state.asyncio_thread.start()
        # 等待循环实际启动 (可选，但有时有用)
        while not (app_state.asyncio_loop and app_state.asyncio_loop.is_running()):
            time.sleep(0.1)
        logger.info("Asyncio后台线程已启动")

    @staticmethod
    def stop_asyncio_thread(app_state: AppState):
        """停止后台asyncio线程"""
        if app_state.asyncio_loop and app_state.asyncio_loop.is_running():
            logger.info("正在请求停止asyncio事件循环...")
            # 使用 call_soon_threadsafe 安排 stop() 在循环线程中执行
            app_state.asyncio_loop.call_soon_threadsafe(app_state.asyncio_loop.stop)

            # 等待线程结束 (可选，但确保资源清理)
            if app_state.asyncio_thread and threading.current_thread() != app_state.asyncio_thread:
                 logger.info("等待Asyncio线程结束...")
                 app_state.asyncio_thread.join(timeout=5.0) # 设置超时
                 if app_state.asyncio_thread.is_alive():
                      logger.warning("Asyncio线程在超时后仍未结束")
                 else:
                      logger.info("Asyncio线程已停止")
                 app_state.asyncio_thread = None
        else:
             logger.info("Asyncio事件循环未运行或已停止")

    @staticmethod
    async def run_sync_in_executor(func, *args):
        """在asyncio的executor中运行同步阻塞函数"""
        loop = asyncio.get_running_loop()
        # 使用默认的 ThreadPoolExecutor
        result = await loop.run_in_executor(None, func, *args)
        return result


class UIManager:
    """用户界面管理类 (Windows特定)"""

    @staticmethod
    def clear_screen():
        """清空控制台屏幕"""
        os.system('cls')

    @staticmethod
    def print_separator(char="=", length=60):
        """打印分隔线"""
        print(char * length)

    @staticmethod
    def print_header(title="西安电子科技大学校园网助手 (Windows版)"):
        """打印程序标题头"""
        UIManager.clear_screen()
        UIManager.print_separator()
        print(f"{title:^60}")
        UIManager.print_separator()
        print()

    @staticmethod
    def print_account_info(account_info):
        """格式化打印账户信息"""
        UIManager.print_separator("-")
        if not account_info:
            print("  未能获取到有效的账户信息。")
        else:
            print("  账户基本信息")
            UIManager.print_separator("-")
            print(f"  姓名: {account_info.get('realname', 'N/A')}")
            print(f"  状态: {account_info.get('user_status', 'N/A')}") # 假设 'user_status' 存在
            print(f"  电子钱包: {account_info.get('wallet', 0):.2f}") # 假设 'wallet' 存在
            print("\n  套餐信息:")
            # 假设 zfw_client 返回的 account_info 包含这些键
            print(f"  套餐数量: {account_info.get('plan_num', 0)}")
            print(f"  联通套餐: {'是' if account_info.get('unicom_plan') else '否'}")
            print(f"  电信套餐: {'是' if account_info.get('telecom_plan') else '否'}")
        UIManager.print_separator("-")

    @staticmethod
    def show_main_menu():
        """显示主菜单并获取用户选择"""
        print("\n请选择需要执行的操作:")
        print(" --- 网络修复 ---")
        print(" 1. 检查网络连接状态 (异步)")
        print(" 2. 重置系统代理设置 (异步)")
        print(" 3. 打开校园网Web认证页面")
        print(" 4. 网络适配器管理 (部分操作异步)")
        print(" --- 账号相关 ---")
        print(" 8. 刷新校园网账户信息 (异步)")
        print(" 9. 高级菜单")
        print(" --- 其他 ---")
        print(" 0. 退出程序")
        UIManager.print_separator("-")

        while True:
            try:
                choice = input("请输入选项数字: ")
                return int(choice)
            except ValueError:
                print("输入无效，请输入数字。")
            except EOFError: # 处理 Ctrl+Z 或输入流结束的情况
                print("\n检测到输入结束，将退出程序。")
                return 0

    @staticmethod
    def show_advanced_menu():
        """显示高级菜单"""
        UIManager.print_separator("-")
        print("\n高级选项:")
        print("1. 退出当前账号")
        print("2. 清除保存的密码")
        print("0. 返回主菜单")
        UIManager.print_separator("-")
        return input("请选择: ")

    @staticmethod
    def get_confirmation(prompt="确定要执行此操作吗?", default_yes=False):
        """获取用户确认"""
        suffix = " (Y/n)" if default_yes else " (y/N)"
        while True:
            choice = input(f"{prompt}{suffix} ").lower().strip()
            if not choice: # 用户直接按回车
                return default_yes
            if choice in ['y', 'yes']:
                return True
            if choice in ['n', 'no']:
                return False
            print("输入无效，请输入 'y' 或 'n'。")


class NetworkManager:
    """网络功能管理类"""

    def __init__(self, app_state: AppState):
        self.state = app_state # 需要 app_state 来提交异步任务

    @staticmethod
    def check_admin() -> bool:
        """检查程序是否有管理员权限 (仅 Windows)"""
        try:
            is_admin = (ctypes.windll.shell32.IsUserAnAdmin() != 0)
            logger.info(f"管理员权限检查: {'是' if is_admin else '否'}")
            return is_admin
        except AttributeError:
            logger.warning("无法检查管理员权限 (可能非Windows或缺少ctypes)。假定没有管理员权限。")
            return False
        except Exception as e:
            logger.error(f"检查管理员权限时出错: {e}", exc_info=True)
            return False

    def handle_adapter_operations(self):
        """处理网络适配器管理流程 (部分操作异步)"""
        if not self.check_admin():
            print("\n警告：许多网络适配器操作需要管理员权限。")
            if not UIManager.get_confirmation("仍要继续吗?", default_yes=False):
                return

        print("\n正在获取网络适配器列表...")
        adapters = network_utils.get_network_adapters()
        if not adapters:
            print("\n未找到可用的网络适配器。")
            return

        selected_adapter = network_utils.select_adapter_interactive(adapters)
        if not selected_adapter:
            return

        while True:
            UIManager.clear_screen()
            UIManager.print_header("网络适配器管理")
            # Safely display adapter info using .get()
            print(f"\n当前操作适配器: {selected_adapter.get('name', '未知名称')} ({selected_adapter.get('description', 'N/A')})")
            print(f"状态: {selected_adapter.get('status', '未知')}, DHCP: {selected_adapter.get('dhcp_enabled', '未知')}, IPv6: {selected_adapter.get('ipv6_enabled', '未知')}")
            print(f"IP地址: {', '.join(selected_adapter.get('ip_addresses', ['N/A']))}")
            print(f"DNS服务器: {', '.join(selected_adapter.get('dns_servers', ['N/A']))}")
            UIManager.print_separator("-")
            print("1. 修改DNS服务器 (异步)")
            print("2. 禁用/启用 IPv6协议 (异步)") # Assuming network_utils handles toggle logic
            print("3. 重启网络适配器 (异步)")
            print("4. 刷新适配器状态")
            print("0. 返回上级菜单")
            UIManager.print_separator("-")

            choice = input("请选择操作: ")

            future: Optional[Future] = None
            task_description = ""
            original_adapter_name = selected_adapter.get('name', '未知名称') # Store name before potential async op

            if choice == "1":
                adapter_name_for_op = selected_adapter.get('name')
                if not adapter_name_for_op:
                     print("\n错误：无法操作，选定的适配器缺少名称。")
                     input("按Enter继续...")
                     continue # Skip to next loop iteration

                dns_input = input("请输入DNS服务器 (空格分隔, 如 114.114.114.114 8.8.8.8), 留空恢复DHCP: ")
                dns_servers = dns_input.split()
                task_description = "修改DNS服务器"
                coro = AsyncManager.run_sync_in_executor(
                    network_utils.change_dns, adapter_name_for_op, dns_servers
                )
                future = AsyncManager.submit_async_task(self.state, coro)

            elif choice == "2":
                adapter_name_for_op = selected_adapter.get('name')
                if not adapter_name_for_op:
                     print("\n错误：无法操作，选定的适配器缺少名称。")
                     input("按Enter继续...")
                     continue

                # Assuming network_utils.toggle_ipv6 or similar exists and handles the logic
                # We need the current state to decide the action description
                current_ipv6_enabled = selected_adapter.get('ipv6_enabled', False) # Get current state safely
                action = "禁用" if current_ipv6_enabled else "启用"

                if UIManager.get_confirmation(f"确定要 {action} {adapter_name_for_op} 的 IPv6 吗?", default_yes=False):
                    if action == "启用":
                        func_to_run = network_utils.enable_ipv6
                    else: # action == "禁用"
                        func_to_run = network_utils.disable_ipv6

                    logger.info(f"Submitting task to {action} IPv6 using function: {func_to_run.__name__}")
                    coro = AsyncManager.run_sync_in_executor(func_to_run, adapter_name_for_op)
                    future = AsyncManager.submit_async_task(self.state, coro)
                else:
                    print("操作已取消。")

            elif choice == "3":
                 adapter_name_for_op = selected_adapter.get('name')
                 if not adapter_name_for_op:
                     print("\n错误：无法操作，选定的适配器缺少名称。")
                     input("按Enter继续...")
                     continue

                 if UIManager.get_confirmation(f"确定要重启网络适配器 '{adapter_name_for_op}' 吗?", default_yes=False):
                    task_description = "重启网络适配器"
                    coro = AsyncManager.run_sync_in_executor(network_utils.reset_adapter, adapter_name_for_op)
                    future = AsyncManager.submit_async_task(self.state, coro)
                 else:
                    print("操作已取消。")

            elif choice == "4":
                print("\n正在刷新适配器状态...")
                new_adapters = network_utils.get_network_adapters()
                original_name = selected_adapter.get('name') # Use the potentially updated name if already refreshed
                if original_name:
                    updated_adapter = next((a for a in new_adapters if a.get('name') == original_name), None)
                    logger.info(f"Manual refresh for adapter '{original_name}'. Found match: {'Yes' if updated_adapter else 'No'}")
                else:
                    updated_adapter = None
                    logger.warning("Cannot refresh status manually: The selected adapter dictionary is missing the 'name' key.")

                if updated_adapter:
                    selected_adapter = updated_adapter # Update with fresh data
                    print("适配器状态已刷新。")
                else:
                    print(f"警告：刷新后未能找到名为 '{original_name}' 的适配器。请返回上级菜单重新选择。")
                    input("\n按Enter继续...") # Pause before returning
                    return # Force user to re-select as current selection might be invalid
                # No need for extra input here, loop will reprint status

            elif choice == "0":
                break

            else:
                print("无效输入，请输入列表中的数字。")
                input("\n按Enter继续...")
                continue # Skip async result waiting for invalid input


            # --- Wait for async task result if one was submitted ---
            if future:
                print(f"\n正在后台执行: {task_description}...")
                operation_success = False # Flag to check if the operation itself succeeded
                try:
                    # future.result() blocks until the task completes or timeout
                    result_data = future.result(timeout=60) # Set appropriate timeout

                    # Assuming the wrapped function returns (success_bool, message_str)
                    if isinstance(result_data, tuple) and len(result_data) == 2:
                         success, msg = result_data
                         operation_success = success # Store the operation result
                         print(f"\n{task_description} 完成:")
                         print(f"结果: {'成功' if success else '失败'}")
                         print(f"信息: {msg}")
                    else:
                         # Handle unexpected return type from the network_utils function
                         logger.error(f"任务 '{task_description}' 返回了意外的结果类型: {type(result_data)}")
                         print(f"\n{task_description} 完成，但返回结果格式不符预期。")
                         print(f"原始返回: {result_data}")


                    # --- Auto-refresh status after successful operation ---
                    if operation_success and choice in ["1", "2", "3"]:
                         print("\n操作成功，正在自动刷新适配器状态...")
                         time.sleep(2) # Give system more time to update after network changes
                         new_adapters = network_utils.get_network_adapters()

                         # Use original_adapter_name captured before the async op for matching
                         if original_adapter_name and original_adapter_name != '未知名称':
                             updated_adapter = next((a for a in new_adapters if a.get('name') == original_adapter_name), None)
                             logger.info(f"Auto-refresh attempt for '{original_adapter_name}'. Found match: {'Yes' if updated_adapter else 'No'}")
                         else:
                             updated_adapter = None
                             logger.warning(f"Cannot auto-refresh status: Original adapter name was invalid ('{original_adapter_name}').")

                         if updated_adapter:
                             selected_adapter = updated_adapter # Update with the fresh info
                             print("适配器状态已自动刷新。")
                         else:
                             print(f"警告：自动刷新状态时未能找到名为 '{original_adapter_name}' 的适配器。状态可能未更新。")
                             # Keep the old selected_adapter, loop will show its (possibly outdated) info

                except asyncio.TimeoutError:
                    logger.error(f"执行 '{task_description}' 超时")
                    print(f"\n错误: 执行 '{task_description}' 超时。")
                except Exception as e:
                    # Catching the error here prevents the main loop from crashing due to the refresh logic itself
                    logger.error(f"执行 '{task_description}' 或后续刷新时发生错误: {e}", exc_info=True)
                    print(f"\n执行 '{task_description}' 或刷新状态时出错: {e}")

                # Pause after any async operation completes or fails
                input("\n按Enter继续...")


class AppController:
    """应用控制器，处理主要业务逻辑"""

    def __init__(self):
        """初始化应用控制器"""
        self.state = AppState()
        # 实例化依赖项
        self.state.zfw_client = XidianZFW() # 假设 XidianZFW 不需要参数
        self.credential_manager = CredentialManager(CONFIG_DIR, CONFIG_FILE) # 假设 CredentialManager 内部处理 SecurityManager
        # self.security_manager = SecurityManager() # 可能被 CredentialManager 内部使用
        self.network_manager = NetworkManager(self.state) # 传入 state

    def start(self):
        """启动应用"""
        # 设置控制台标题 (Windows)
        os.system(f"title 西安电子科技大学校园网助手 v{self._get_version()}") # 添加版本号

        UIManager.print_header()
        logger.info(f"程序启动 v{self._get_version()}")

        # 启动后台异步线程
        AsyncManager.start_asyncio_thread(self.state)
        if not (self.state.asyncio_loop and self.state.asyncio_loop.is_running()):
             logger.error("无法启动后台Asyncio事件循环，部分异步功能将不可用。")
             print("\n错误：无法启动后台处理线程，部分功能可能受影响。")
             # 可以选择退出或继续（同步模式）
             # input("按Enter退出...")
             # return

        # 尝试登录 (同步阻塞)
        if not self._handle_login():
            logger.error("登录失败，程序退出")
            print("\n登录失败，请检查账号密码或网络连接。")
            input("按Enter退出...")
        else:
            # 进入主菜单循环
            self._main_menu_loop()

        # 停止后台线程
        AsyncManager.stop_asyncio_thread(self.state)
        logger.info("程序准备退出")
        print("\n感谢使用！")
        time.sleep(1) # 短暂停留

    def _get_version(self):
        # 一个简单的获取版本号的方法，可以根据需要修改
        return "1.1.0" # 示例版本号

    def _handle_login(self) -> bool:
        """处理用户登录 (同步阻塞)，返回是否成功登录"""
        saved_user, saved_pwd = self.credential_manager.load_credentials()

        if saved_user and saved_pwd:
            print(f"\n检测到上次登录的账号: {saved_user}")
            # 默认使用保存的凭证
            if UIManager.get_confirmation("是否使用保存的凭证登录?", default_yes=True):
                print("正在使用保存的凭证登录...")
                try:
                    # 这是同步阻塞调用
                    login_result = self.state.zfw_client.login(saved_user, saved_pwd)
                    # 假设 login 返回类字典对象，包含 status 和其他信息
                    if login_result and login_result.get('status') == 'success':
                        logger.info(f"用户 {saved_user} 自动登录成功")
                        self.state.account_info = login_result # 保存账户信息
                        print("自动登录成功！")
                        return True
                    else:
                        error_msg = login_result.get('message', '未知错误') if login_result else '无响应'
                        logger.warning(f"用户 {saved_user} 自动登录失败: {error_msg}")
                        print(f"自动登录失败: {error_msg}。请尝试手动输入。")
                        # 清除无效的旧凭证可能不是好主意，万一是临时网络问题
                        # self.credential_manager.clear_credentials()
                except Exception as e:
                    logger.error(f"使用保存凭证登录时发生异常: {e}", exc_info=True)
                    print(f"登录过程中发生错误: {e}")
                    # 继续尝试手动登录

        # 手动登录
        print("\n--- 手动登录 ---")
        username = input("请输入校园网账号 (学号): ").strip()
        if not username:
            print("账号不能为空。")
            return False
        password = getpass.getpass("请输入密码: ")
        if not password:
            print("密码不能为空。")
            return False

        print("正在登录...")
        try:
            # 这是同步阻塞调用
            login_result = self.state.zfw_client.login(username, password)

            if login_result and login_result.get('status') == 'success':
                logger.info(f"用户 {username} 手动登录成功")
                self.state.account_info = login_result # 保存账户信息
                print("登录成功！")
                # 登录成功后询问是否保存凭证
                if UIManager.get_confirmation("是否保存登录凭证以便下次自动登录?", default_yes=True):
                    self.credential_manager.save_credentials(username, password)
                    print("凭证已保存。")
                return True
            else:
                error_msg = login_result.get('message', '未知错误') if login_result else '无响应'
                logger.warning(f"用户 {username} 手动登录失败: {error_msg}")
                print(f"登录失败: {error_msg}")
                return False
        except Exception as e:
            logger.error(f"手动登录时发生异常: {e}", exc_info=True)
            print(f"登录过程中发生错误: {e}")
            return False


    def _main_menu_loop(self):
        """主菜单循环"""
        while True:
            UIManager.print_header()
            UIManager.print_account_info(self.state.account_info) # 显示当前账户信息
            choice = UIManager.show_main_menu()

            action_taken = True # 标记是否执行了某个操作

            if choice == 1:  # 检查网络连接状态 (异步)
                self._check_network_connectivity_async()
            elif choice == 2:  # 重置系统代理 (异步)
                self._reset_system_proxy_async()
            elif choice == 3:  # 打开Web认证页面 (同步)
                self._open_web_auth_page()
            elif choice == 4:  # 网络适配器管理
                self.network_manager.handle_adapter_operations() # 这个方法内部处理异步
            elif choice == 8:  # 刷新账户信息 (异步)
                self._refresh_account_info_async()
            elif choice == 9:  # 高级菜单
                if not self._handle_advanced_menu():
                    # 如果高级菜单要求退出登录，则结束主循环
                    break
            elif choice == 0:  # 退出
                logger.info("用户选择退出程序")
                break
            else:
                action_taken = False
                print("无效选项，请输入列表中的数字。")

            # 如果执行了非退出/高级菜单操作，或者输入无效，则暂停等待用户
            if choice != 0 and choice != 9:
                 # 对于异步立即返回的操作，不需要input暂停
                 # 对于异步等待结果的操作，input已在其内部处理
                 # 对于同步操作 (如 choice 3)，或者无效输入，需要暂停
                 if choice == 3 or not action_taken:
                      input("\n按Enter返回主菜单...")
            elif not action_taken and choice != 0: # 处理无效输入的情况
                 input("\n按Enter返回主菜单...")


    def _execute_async_task(self, coro, task_description: str, timeout: int = 30):
        """通用函数：执行异步任务并等待结果，处理反馈和错误"""
        future = AsyncManager.submit_async_task(self.state, coro)
        if not future:
            print(f"\n错误：无法提交 '{task_description}' 任务。")
            return None # 返回 None 表示失败

        print(f"\n正在后台执行: {task_description}...")
        try:
            # 等待后台任务完成并获取结果
            result = future.result(timeout=timeout) # 阻塞主线程直到协程完成
            logger.info(f"后台任务 '{task_description}' 完成")
            return result # 返回任务的实际结果
        except asyncio.TimeoutError:
            logger.error(f"执行 '{task_description}' 超时")
            print(f"\n错误: 执行 '{task_description}' 超时。")
        except Exception as e:
            logger.error(f"执行 '{task_description}' 时发生错误: {e}", exc_info=True)
            print(f"\n执行 '{task_description}' 时出错: {e}")
        return None # 返回 None 表示失败

    def _check_network_connectivity_async(self):
        """(异步) 检查网络连接状态"""
        async def task():
            # 假设 network_utils.check_internet_connectivity 是同步阻塞的
            return await AsyncManager.run_sync_in_executor(
                network_utils.check_internet_connectivity
            )

        result = self._execute_async_task(task(), "检查网络连接状态")

        if result is not None:
            status, message = result
            print(f"\n检查结果: {message} (状态: {status})")
            if status == "portal":
                print("检测到可能需要Web认证，请尝试选项3。")
            elif status == "offline":
                print("网络似乎未连接，请检查物理连接或Wi-Fi/有线设置。")
        # 不管结果如何，暂停一下让用户看到信息
        input("\n按Enter返回主菜单...")


    def _reset_system_proxy_async(self):
        """(异步) 重置系统代理设置"""
        print("\n正在获取当前代理设置...")
        # 获取当前设置通常是快的，同步执行
        try:
            current_proxy = network_utils.get_system_proxy_settings()
            if current_proxy and not current_proxy.get('enabled'):
                print("当前系统代理已禁用或未设置，无需重置。")
            elif current_proxy:
                print(f"当前代理服务器: {current_proxy.get('server', 'N/A')}")
                if UIManager.get_confirmation("确定要重置系统代理吗 (禁用代理)?", default_yes=False):
                     # 检查管理员权限
                    if not NetworkManager.check_admin():
                         print("\n警告：重置系统代理通常需要管理员权限。")
                         if not UIManager.get_confirmation("仍要尝试吗?", default_yes=False):
                             print("操作已取消。")
                             input("\n按Enter返回主菜单...")
                             return

                    async def task():
                        # 假设 network_utils.reset_system_proxy 是同步阻塞的
                        return await AsyncManager.run_sync_in_executor(
                            network_utils.reset_system_proxy
                        )

                    result = self._execute_async_task(task(), "重置系统代理")
                    if result is not None:
                        success, message = result
                        print(f"\n重置结果: {'成功' if success else '失败'}")
                        print(f"信息: {message}")
                        if not success and "权限" in message:
                            print("提示: 此操作可能需要以管理员身份运行程序。")
                else:
                    print("操作已取消。")
            else:
                print("未能获取到当前代理设置信息。")

        except Exception as e:
             logger.error(f"处理代理设置时出错: {e}", exc_info=True)
             print(f"处理代理设置时遇到错误: {e}")

        input("\n按Enter返回主菜单...")


    def _open_web_auth_page(self):
        """(同步) 打开Web认证页面"""
        print(f"\n正在尝试在默认浏览器中打开页面: {XDU_WEB_AUTH_URL}")
        try:
            opened = webbrowser.open(XDU_WEB_AUTH_URL)
            if opened:
                print("已尝试打开页面。请检查你的浏览器。")
                logger.info(f"已尝试打开Web认证页面: {XDU_WEB_AUTH_URL}")
            else:
                print("无法自动打开浏览器。请手动复制以下链接访问：")
                print(XDU_WEB_AUTH_URL)
                logger.warning("webbrowser.open 返回 False，可能无法打开浏览器")
        except Exception as e:
            logger.error(f"打开Web认证页面时出错: {e}", exc_info=True)
            print(f"尝试打开页面时出错: {e}")
            print("请手动复制以下链接访问：")
            print(XDU_WEB_AUTH_URL)
        # input("\n按Enter返回主菜单...") # 这个操作很快，不需要暂停


    def _refresh_account_info_async(self):
        """(异步) 刷新账户信息"""
        if not (self.state.account_info and 'username' in self.state.account_info):
            print("\n错误：当前没有登录账号信息可供刷新。请先登录。")
            input("\n按Enter返回主菜单...")
            return

        username = self.state.account_info['username']

        async def task():
            # 假设 zfw_client.get_plan_info 是同步阻塞的
            logger.info(f"后台任务：开始为用户 {username} 刷新账户信息")
            try:
                 # 需要 zfw_client 实例来调用方法
                 new_info = await AsyncManager.run_sync_in_executor(
                     self.state.zfw_client.get_plan_info, username
                 )
                 logger.info(f"后台任务：用户 {username} 信息刷新完成")
                 return new_info
            except Exception as e:
                 logger.error(f"后台刷新用户 {username} 信息时出错: {e}", exc_info=True)
                 return None # 返回 None 表示失败

        new_account_info = self._execute_async_task(task(), "刷新校园网账户信息")

        if new_account_info is not None:
             # 检查返回的信息是否有效 (至少应该是个字典)
             if isinstance(new_account_info, dict):
                  # 更新状态，需要确保线程安全，但字典赋值通常是原子的
                  # 如果 account_info 结构复杂且多线程访问，可能需要锁
                  self.state.account_info = new_account_info
                  print("\n账户信息已刷新。")
             else:
                  print("\n刷新失败：未能获取到有效的账户信息。")
                  # 保留旧信息还是清空？这里选择保留旧信息
                  # self.state.account_info = None
        else:
             print("\n刷新账户信息失败。请稍后重试或检查网络。")
        # 不管结果如何，暂停
        input("\n按Enter返回主菜单...")


    def _handle_advanced_menu(self) -> bool:
        """处理高级菜单，返回是否继续主菜单"""
        UIManager.print_header("高级菜单")
        sub_choice = UIManager.show_advanced_menu()

        if sub_choice == '1':  # 退出当前账号
            print("\n正在退出当前账号...")
            # 清除内存中的信息
            self.state.account_info = None
            # 清除保存的凭证
            self.credential_manager.clear_credentials()
            print("已退出登录，并已清除保存的凭证。")
            logger.info("用户执行了退出登录操作")
            input("按Enter返回登录界面...")
            return False  # 返回False表示不继续主菜单，将退回到登录逻辑或程序退出

        elif sub_choice == '2':  # 清除保存的密码
            if UIManager.get_confirmation("确定要清除已保存的登录密码吗?", default_yes=False):
                self.credential_manager.clear_credentials()
                print("已清除保存的密码。下次启动需要手动登录。")
                logger.info("用户清除了保存的凭证")
            else:
                print("操作已取消。")
            input("\n按Enter返回主菜单...")

        elif sub_choice == '0': # 返回主菜单
            print("返回主菜单...")
            # 不需要 input 暂停

        else:  # 非法选项
            print("无效高级选项。")
            input("\n按Enter继续...")

        return True  # 默认继续主菜单


# --- 程序入口 ---
if __name__ == "__main__":
    # 平台检查
    if platform.system() != "Windows":
        print("错误：此脚本目前仅设计用于 Windows 系统。")
        input("按 Enter 退出...")
        sys.exit(1)

    # 确保日志目录存在
    try:
        LOGS_DIR.mkdir(exist_ok=True, parents=True)
    except Exception as e:
        print(f"无法创建日志目录 {LOGS_DIR}: {e}")
        # 可以选择继续，只是没有日志文件

    # 导入 time 模块
    import time

    # 运行主程序
    app = None
    try:
        app = AppController()
        app.start()
    except KeyboardInterrupt:
        print("\n程序被用户中断 (Ctrl+C)")
        logger.warning("程序被用户中断")
    except ImportError as e:
         # 上面已经有导入检查，这里再捕获一次以防万一
         logger.critical(f"启动失败，缺少模块: {e}", exc_info=True)
         print(f"\n启动失败，缺少必要的组件: {e}")
         input("按 Enter 退出...")
    except Exception as e:
        logger.critical(f"主程序发生未捕获的严重错误: {e}", exc_info=True)
        print(f"\n程序遇到严重错误，详情请查看日志文件。错误信息: {e}")
        input("按 Enter 退出...")
    finally:
        # 确保即使出错也尝试停止后台线程
        if app and app.state.asyncio_loop and app.state.asyncio_loop.is_running():
            logger.info("程序结束前，尝试停止Asyncio线程...")
            AsyncManager.stop_asyncio_thread(app.state)
        logger.info("程序退出。")
        # 在最终退出前给用户一点时间看最后的信息
        # time.sleep(1)
