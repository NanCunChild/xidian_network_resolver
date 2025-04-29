# network_utils.py
import subprocess
import requests
import logging
import platform
import webbrowser
import winreg
from typing import List, Dict, Tuple, Optional
import socket
import re
import locale

logger = logging.getLogger(__name__) # 使用与 zfw_apis 相同的 logger 配置

# 配置校园网特征 (按需修改)
CAMPUS_NETWORK_FEATURES = {
    "dns_suffix": ".xidian.edu.cn",
    "test_domain": "auth.xidian.edu.cn",
    "gateway_ips": ["202.117.0.1"],
    "typical_ips": ["10.", "202.117."],
}

SYSTEM_PREFERRED_ENCODING = "utf-8"
logger.info(f"System preferred encoding detected: {SYSTEM_PREFERRED_ENCODING}")

# --- 代理相关 ---

def get_system_proxy_settings():
    """获取当前用户的系统代理设置 (Windows)"""
    settings = {'enabled': False, 'server': '', 'override': ''}
    if platform.system() != "Windows":
        logger.warning("获取系统代理设置目前仅支持 Windows。")
        return settings # 或者抛出 NotImplementedError

    try:
        # 打开注册表项 HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings
        registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                      r'Software\Microsoft\Windows\CurrentVersion\Internet Settings',
                                      0, winreg.KEY_READ)

        # 读取代理启用状态 (ProxyEnable)
        proxy_enable_value, reg_type = winreg.QueryValueEx(registry_key, 'ProxyEnable')
        settings['enabled'] = bool(proxy_enable_value)

        # 如果启用，读取代理服务器地址 (ProxyServer)
        if settings['enabled']:
            proxy_server_value, reg_type = winreg.QueryValueEx(registry_key, 'ProxyServer')
            settings['server'] = proxy_server_value

        # 读取代理例外列表 (ProxyOverride)
        try:
            proxy_override_value, reg_type = winreg.QueryValueEx(registry_key, 'ProxyOverride')
            settings['override'] = proxy_override_value
        except FileNotFoundError:
            settings['override'] = '<local>' # 默认值

        winreg.CloseKey(registry_key)
        logger.info(f"当前系统代理设置: Enabled={settings['enabled']}, Server='{settings['server']}', Override='{settings['override']}'")
        return settings

    except FileNotFoundError:
        logger.warning("找不到 Internet Settings 注册表项，无法读取代理设置。")
        return settings # 返回默认值
    except Exception as e:
        logger.error(f"读取系统代理设置时发生错误: {e}", exc_info=True)
        return settings # 返回默认值

def reset_system_proxy():
    """
    重置当前用户的系统代理设置 (Windows)。
    这会禁用代理并将服务器和覆盖列表清空。
    """
    if platform.system() != "Windows":
        logger.error("重置系统代理目前仅支持 Windows。")
        return False, "仅支持 Windows"
    
    success = True
    messages = []
    methods_used = []

    # 第一阶段：优先使用注册表修改
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                          r'Software\Microsoft\Windows\CurrentVersion\Internet Settings',
                          0, winreg.KEY_WRITE) as reg_key:
            # 禁用代理
            winreg.SetValueEx(reg_key, 'ProxyEnable', 0, winreg.REG_DWORD, 0)
            # 清空代理服务器地址（可选）
            try:
                winreg.SetValueEx(reg_key, 'ProxyServer', 0, winreg.REG_SZ, '')
            except FileNotFoundError:
                pass
            # 清空例外列表（可选）
            try:
                winreg.SetValueEx(reg_key, 'ProxyOverride', 0, winreg.REG_SZ, '')
            except FileNotFoundError:
                pass
        methods_used.append("注册表修改")
        success = True
        messages.append("通过注册表禁用代理成功")
    except Exception as e:
        messages.append(f"注册表修改失败: {str(e)}")
        
    if not success:
        # 修复 netsh 命令执行问题
        try:
            result = subprocess.run(
                ['netsh', 'winhttp', 'reset', 'proxy'],
                check=True,
                capture_output=True,
                encoding='utf-8',  # 强制使用UTF-8编码
                errors='ignore',    # 忽略解码错误
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            # 安全处理输出
            output = (result.stdout or '').strip()
            error_output = (result.stderr or '').strip()
            
            if output:
                logger.info(f"netsh 命令输出: {output}")
                messages.append(output)
            if error_output:
                logger.warning(f"netsh 警告: {error_output}")
                messages.append(f"警告: {error_output}")
                
        except FileNotFoundError:
            logger.error("未找到 'netsh' 命令")
            messages.append("无法执行网络重置命令")
        except subprocess.CalledProcessError as e:
            error_msg = (e.stderr or '未知错误').strip()
            logger.error(f"命令执行失败 [代码 {e.returncode}]: {error_msg}")
            messages.append(f"网络重置失败: {error_msg}")
            success = False
        except subprocess.TimeoutExpired:
            logger.error("命令执行超时")
            messages.append("操作超时")
            success = False
        except Exception as e:
            logger.error(f"意外错误: {str(e)}")
            messages.append(f"意外错误: {str(e)}")
            success = False

    return success, " | ".join(messages)


# --- 网络连接与页面跳转 ---

def open_web_page(url):
    """在默认浏览器中打开指定的 URL"""
    try:
        logger.info(f"尝试在浏览器中打开 URL: {url}")
        opened = webbrowser.open(url)
        if opened:
            logger.info("成功调用 webbrowser.open()")
            return True, f"已尝试打开 {url}"
        else:
            logger.warning("webbrowser.open() 返回 False，可能没有找到合适的浏览器。")
            return False, "无法找到或打开默认浏览器"
    except Exception as e:
        logger.error(f"打开网页 {url} 时发生错误: {e}", exc_info=True)
        return False, f"打开网页时出错: {e}"

# --- 其他网络工具 (占位符) ---

def check_internet_connectivity(test_url="http://detectportal.firefox.com/success.txt", timeout=5):
    """
    检查基本的互联网连接和是否可能处于强制门户后。

    返回:
        tuple: (status, message)
        status: "connected", "portal", "offline", "error"
    """
    try:
        response = requests.get(test_url, timeout=timeout, allow_redirects=False) # 不允许自动重定向

        if response.status_code == 200 and "success" in response.text.lower():
             logger.info("网络连接检查：连接正常。")
             return "connected", "网络连接正常"
        elif 300 <= response.status_code < 400 or "html" in response.headers.get("Content-Type", ""):
             # 如果被重定向或者返回的是 HTML 页面，很可能是在强制门户后面
             redirect_location = response.headers.get('Location', '未知目标')
             logger.warning(f"网络连接检查：可能处于强制网络门户之后。状态码: {response.status_code}, Content-Type: {response.headers.get('Content-Type', '')}, 重定向到: {redirect_location}")
             # 尝试提取重定向目标作为可能的认证页面
             portal_url = redirect_location if redirect_location != '未知目标' else '无法确定认证页面'
             return "portal", f"需要网页认证 ({portal_url})"
        else:
            logger.warning(f"网络连接检查：访问测试 URL 失败或响应异常。状态码: {response.status_code}, 内容: {response.text[:100]}")
            return "offline", f"无法访问测试页面 (状态码: {response.status_code})"

    except requests.exceptions.Timeout:
        logger.warning("网络连接检查：访问测试 URL 超时。")
        return "offline", "网络连接超时"
    except requests.exceptions.ConnectionError:
        logger.warning("网络连接检查：无法连接到测试 URL。")
        return "offline", "无法建立连接"
    except Exception as e:
        logger.error(f"网络连接检查时发生错误: {e}", exc_info=True)
        return "error", f"检查连接时出错: {e}"

def get_network_adapters() -> List[Dict]:
    """安全获取网络适配器列表（兼容中文环境）"""
    cmd = ["netsh", "interface", "show", "interface"]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding=SYSTEM_PREFERRED_ENCODING,
            errors='replace',  # 替换无法解码的字符
            timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        # 解析输出
        return parse_netsh_output(result.stdout)
        
    except Exception as e:
        logger.error(f"获取适配器失败: {safe_str(e)}")
        return []

def parse_netsh_output(output: str) -> List[Dict]:
    """解析netsh命令输出"""
    adapters = []
    in_table = False
    headers = []
    
    for line in output.split('\n'):
        line = line.strip()
        
        # 检测表格开始
        if not in_table and re.match(r"^-+$", line):
            in_table = True
            continue
            
        if in_table:
            # 解析表头
            if not headers:
                headers = re.split(r"\s{2,}", line)
                continue
                
            # 跳过分隔线
            if re.match(r"^-+$", line):
                continue
                
            # 解析数据行
            if match := re.match(r"^(\S+.*?)\s{2,}(\S+.*?)\s{2,}(\S+.*?)\s{2,}(.+)$", line):
                adapter = {
                    'admin_state': match.group(1).strip(),
                    'state': convert_state(match.group(2)),
                    'type': match.group(3).strip(),
                    'name': match.group(4).strip()
                }
                adapters.append(adapter)
                
    return adapters

def convert_state(state: str) -> str:
    """统一状态标识"""
    state_map = {
        '已连接': 'Connected',
        'Connected': 'Connected',
        '已断开连接': 'Disconnected',
        'Disconnected': 'Disconnected'
    }
    return state_map.get(state, 'Unknown')

def detect_campus_adapter(adapter_name: str) -> bool:
    """安全检测校园网适配器"""
    try:
        result = subprocess.run(
            ["netsh", "interface", "ipv4", "show", "config", f"name={adapter_name}"],
            capture_output=True,
            text=True,
            encoding=SYSTEM_PREFERRED_ENCODING,
            errors='replace',
            timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        return "xidian.edu.cn" in result.stdout
    except Exception as e:
        logger.error(f"检测适配器失败: {safe_str(e)}")
        return False

def reset_adapter(adapter_name: str) -> Tuple[bool, str]:
    """安全重启适配器"""
    try:
        # 禁用适配器
        subprocess.run(
            ["netsh", "interface", "set", "interface", 
             f'name="{adapter_name}"', "admin=disable"],
            check=True,
            timeout=10,
            encoding=SYSTEM_PREFERRED_ENCODING,
            errors='replace',
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        # 启用适配器
        subprocess.run(
            ["netsh", "interface", "set", "interface", 
             f'name="{adapter_name}"', "admin=enable"],
            check=True,
            timeout=10,
            encoding=SYSTEM_PREFERRED_ENCODING,
            errors='replace',
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        return True, "适配器重启成功"
    except subprocess.CalledProcessError as e:
        error_msg = safe_str(e.stderr)
        logger.error(f"重置失败: {error_msg}")
        return False, f"操作失败: {error_msg}"
    except Exception as e:
        error_msg = safe_str(e)
        logger.error(f"意外错误: {error_msg}")
        return False, f"发生意外错误: {error_msg}"

def safe_str(obj) -> str:
    """安全转换为字符串"""
    try:
        return str(obj)
    except UnicodeEncodeError:
        return obj.encode(SYSTEM_PREFERRED_ENCODING, errors='replace').decode(SYSTEM_PREFERRED_ENCODING)
    except:
        return "无法解码的错误信息"
    
def select_adapter_interactive(adapters: List[Dict], max_retry: int = 3) -> Optional[Dict]:
    """
    交互式网络适配器选择函数
    
    参数：
    adapters - 网络适配器列表
    max_retry - 最大重试次数
    
    返回：
    选中的适配器字典或None
    """
    def display_adapters(adapter_list: List[Dict]) -> None:
        """格式化显示适配器列表"""
        print("\n{:-^60}".format(" 可用网络适配器 "))
        print("{:<5}{:<30}{:<15}{:<10}".format("序号", "适配器名称", "连接状态", "类型"))
        print("-" * 60)
        for idx, adapter in enumerate(adapter_list, 1):
            # 自动检测校园网适配器
            is_campus = detect_campus_adapter(adapter['name'])
            campus_mark = " (校园网)" if is_campus else ""
            
            status_map = {
                "Connected": "已连接",
                "Disconnected": "未连接"
            }
            
            print("{:<5}{:<30}{:<15}{:<10}{}".format(
                idx,
                adapter['name'][:27] + (adapter['name'][27:] and '..'),
                status_map.get(adapter['state'], "未知状态"),
                adapter['type'][:8] + (adapter['type'][8:] and '..'),
                campus_mark
            ))
        print("-" * 60)
        print("输入 0 返回上级菜单")
    
    # 最大重试机制
    for attempt in range(max_retry):
        try:
            display_adapters(adapters)
            
            # 获取用户输入
            selection = input("请选择适配器序号 (1-{}): ".format(len(adapters)))
            
            # 处理退出选项
            if selection.strip() == '0':
                return None
                
            # 输入验证
            if not selection.isdigit():
                raise ValueError("请输入有效数字")
                
            index = int(selection)
            if not (1 <= index <= len(adapters)):
                raise IndexError("序号超出范围")
                
            # 返回选中适配器
            selected = adapters[index-1]
            print("已选择适配器：{}".format(selected['name']))
            return selected
            
        except (ValueError, IndexError) as e:
            print("输入错误：{}".format(str(e)))
            remaining = max_retry - attempt - 1
            if remaining > 0:
                print("您还有 {} 次重试机会".format(remaining))
            else:
                print("超过最大重试次数")
                return None
                
    return None

# 新增适配器重置功能
def reset_adapter(adapter_name: str) -> tuple:
    """重启网络适配器（需要管理员权限）"""
    try:
        # 禁用适配器
        subprocess.run(
            ["netsh", "interface", "set", "interface", f'name="{adapter_name}"', "admin=disable"],
            check=True, timeout=10
        )
        # 启用适配器
        subprocess.run(
            ["netsh", "interface", "set", "interface", f'name="{adapter_name}"', "admin=enable"],
            check=True, timeout=10
        )
        return True, "适配器重启成功"
    except subprocess.CalledProcessError as e:
        logger.error(f"适配器操作失败: {e.stderr}")
        return False, f"操作失败: {e.stderr}"
    except Exception as e:
        return False, f"意外错误: {str(e)}"

# 优化DNS设置功能
def change_dns(adapter_name: str, dns_servers: list) -> tuple:
    """智能DNS设置（支持DHCP恢复）"""
    try:
        # 清除现有DNS设置
        subprocess.run(
            ["netsh", "interface", "ipv4", "set", "dns", 
             f"name={adapter_name}", "source=dhcp"],
            check=True, timeout=10
        )
        
        # 如果指定了DNS服务器
        if dns_servers:
            # 设置主DNS
            subprocess.run(
                ["netsh", "interface", "ipv4", "set", "dns",
                 f"name={adapter_name}", "static", dns_servers[0]],
                check=True, timeout=10
            )
            # 设置备用DNS（如果存在）
            if len(dns_servers) > 1:
                subprocess.run(
                    ["netsh", "interface", "ipv4", "add", "dns",
                     f"name={adapter_name}", dns_servers[1], "index=2"],
                    check=True, timeout=10
                )
        return True, "DNS设置更新成功"
    except subprocess.CalledProcessError as e:
        logger.error(f"DNS设置失败: {e.stderr}")
        return False, f"操作失败: {e.stderr}"
    except Exception as e:
        return False, f"意外错误: {str(e)}"

def disable_ipv6(adapter_name: str) -> Tuple[bool, str]:
    """
    Attempts to modify IPv6 settings using netsh (e.g., disable dynamic DNS).
    NOTE: This specific command may not fully disable the IPv6 protocol itself.
    Requires Administrator privileges.
    """
    # Use the correct argument format for netsh: name="Adapter Name" or interface="Adapter Name"
    # For 'set interface', 'name=' seems less common than 'interface='. Let's try 'interface='.
    # Also ensure adapter_name with spaces is quoted correctly WITHIN the list item.
    cmd = ["netsh", "interface", "ipv6", "set", "interface",
           f'interface="{adapter_name}"', # Quote the name correctly
           "disableddns=enabled",
           "store=persistent"]
    logger.info(f"Executing command: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            # shell=False is default and safer when command is a list
            check=True,           # Raise exception on non-zero exit code
            capture_output=True,  # Capture stdout and stderr
            text=True,            # Decode output as text
            encoding='utf-8',     # *** TRY UTF-8 FIRST ***
            errors='replace',     # *** REPLACE undecodable bytes ***
            timeout=15,           # Slightly longer timeout
            creationflags=subprocess.CREATE_NO_WINDOW # Hide console window
        )
        # Log actual output for debugging
        stdout = result.stdout.strip() if result.stdout else ""
        stderr = result.stderr.strip() if result.stderr else ""
        if stdout: logger.info(f"disable_ipv6 stdout: {stdout}")
        if stderr: logger.warning(f"disable_ipv6 stderr: {stderr}")

        # Return a more accurate message based on the command ACTUALLY run
        # This command modifies DDNS behaviour, not the protocol state directly.
        return True, f"IPv6 dynamic DNS setting updated for '{adapter_name}'. (Output: {stdout or 'OK'})"
        # return True, "IPv6已禁用" # Original inaccurate message

    except subprocess.CalledProcessError as e:
        # Decode stderr carefully as well, trying multiple encodings if necessary
        stderr_decoded = "N/A"
        if e.stderr:
            try:
                # Try decoding stderr with UTF-8 first, then system default
                stderr_decoded = e.stderr.decode('utf-8', errors='replace').strip()
            except Exception:
                try:
                    stderr_decoded = e.stderr.decode(SYSTEM_PREFERRED_ENCODING, errors='replace').strip()
                except Exception:
                     stderr_decoded = repr(e.stderr) # Raw representation if all decodes fail
        logger.error(f"Command '{' '.join(cmd)}' failed with code {e.returncode}. Stderr: {stderr_decoded}")
        # Provide a more informative error message to the user
        err_msg = f"操作失败 (命令错误码 {e.returncode})"
        if stderr_decoded and stderr_decoded != "N/A":
            err_msg += f": {stderr_decoded}"
        # Check for common permission error message patterns (adjust keywords as needed)
        if "administrator" in stderr_decoded.lower() or "管理员" in stderr_decoded or "权限" in stderr_decoded:
             err_msg += " - 可能需要管理员权限运行此程序。"
        return False, err_msg

    except FileNotFoundError:
         logger.error("Command 'netsh' not found.")
         return False, "找不到 'netsh' 命令，无法执行操作。"
    except subprocess.TimeoutExpired:
        logger.error(f"Command '{' '.join(cmd)}' timed out.")
        return False, "操作超时"
    except Exception as e:
        # Catch potential encoding errors during the run itself if 'replace' wasn't sufficient
        # or other unexpected errors
        logger.error(f"Unexpected error executing disable_ipv6: {e}", exc_info=True)
        # Check if it's an encoding error during processing, though less likely now
        if isinstance(e, UnicodeDecodeError):
             return False, f"处理命令输出时发生编码错误: {e}"
        return False, f"发生意外错误: {str(e)}"


def enable_ipv6(adapter_name: str) -> Tuple[bool, str]:
    """
    Attempts to enable IPv6 settings using netsh.
    Requires Administrator privileges. (Implementation needed)
    """
    # Correct command might be: netsh interface ipv6 set state interface="Adapter Name" state=enabled
    cmd = ["netsh", "interface", "ipv6", "set", "state",
           f'interface="{adapter_name}"',
           "state=enabled"]
    logger.info(f"Executing command: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd, check=True, capture_output=True, text=True,
            encoding='utf-8', errors='replace', timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        stdout = result.stdout.strip() if result.stdout else ""
        stderr = result.stderr.strip() if result.stderr else ""
        if stdout: logger.info(f"enable_ipv6 stdout: {stdout}")
        if stderr: logger.warning(f"enable_ipv6 stderr: {stderr}")
        # Check output for confirmation, e.g., "Ok." is common for netsh success
        if "ok" in stdout.lower() or not stderr:
             return True, f"IPv6 已尝试启用 for '{adapter_name}'. (Output: {stdout or 'OK'})"
        else:
             # Command ran but output might indicate issues
             return False, f"启用 IPv6 命令完成，但输出可疑: {stdout} / {stderr}"

    except subprocess.CalledProcessError as e:
        stderr_decoded = "N/A"
        if e.stderr:
             try: stderr_decoded = e.stderr.decode('utf-8', errors='replace').strip()
             except Exception: stderr_decoded = repr(e.stderr)
        logger.error(f"Command '{' '.join(cmd)}' failed with code {e.returncode}. Stderr: {stderr_decoded}")
        err_msg = f"启用失败 (错误码 {e.returncode})"
        if stderr_decoded and stderr_decoded != "N/A": err_msg += f": {stderr_decoded}"
        if "administrator" in stderr_decoded.lower() or "管理员" in stderr_decoded or "权限" in stderr_decoded:
             err_msg += " - 可能需要管理员权限。"
        return False, err_msg
    except FileNotFoundError:
         logger.error("Command 'netsh' not found.")
         return False, "找不到 'netsh' 命令。"
    except subprocess.TimeoutExpired:
        logger.error(f"Command '{' '.join(cmd)}' timed out.")
        return False, "操作超时"
    except Exception as e:
        logger.error(f"Unexpected error executing enable_ipv6: {e}", exc_info=True)
        if isinstance(e, UnicodeDecodeError): return False, f"处理命令输出时发生编码错误: {e}"
        return False, f"发生意外错误: {str(e)}"


def run_pppoe_dial(connection_name, username=None, password=None):
     """执行 PPPoE 拨号 (Windows) - 占位符"""
     if platform.system() != "Windows":
        logger.error("PPPoE 拨号目前仅支持 Windows。")
        return False, "仅支持 Windows"

     logger.warning(f"PPPoE 拨号功能 ('{connection_name}') 尚未完全实现。需要 rasdial 命令。")
     # 示例命令 (不推荐直接传密码):
     # if username and password:
     #    cmd = ['rasdial', connection_name, username, password]
     # else:
     #    cmd = ['rasdial', connection_name] # 依赖系统保存的凭据
     # subprocess.run(cmd, ...)
     return False, "功能待实现"

def run_pppoe_hangup(connection_name):
    """断开 PPPoE 连接 (Windows) - 占位符"""
    if platform.system() != "Windows":
        logger.error("PPPoE 断开目前仅支持 Windows。")
        return False, "仅支持 Windows"

    logger.warning(f"PPPoE 断开功能 ('{connection_name}') 尚未完全实现。需要 rasdial 命令。")
     # 示例命令: subprocess.run(['rasdial', connection_name, '/disconnect'], ...)
    return False, "功能待实现"