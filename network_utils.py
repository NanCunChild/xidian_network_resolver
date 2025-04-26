# network_utils.py
import subprocess
import requests
import logging
import platform
import webbrowser
import winreg
from typing import List, Dict
import socket
import re

logger = logging.getLogger(__name__) # 使用与 zfw_apis 相同的 logger 配置

# 配置校园网特征 (按需修改)
CAMPUS_NETWORK_FEATURES = {
    "dns_suffix": ".xidian.edu.cn",
    "test_domain": "auth.xidian.edu.cn",
    "gateway_ips": ["202.117.0.1"],
    "typical_ips": ["10.", "202.117."],
}

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
    """获取系统网络适配器列表 (Windows实现)"""
    if platform.system() != "Windows":
        return []

    try:
        result = subprocess.run(
            ["netsh", "interface", "show", "interface"],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore',
            timeout=5
        )
        adapters = []
        current_adapter = {}
        
        # 解析 netsh 输出
        for line in result.stdout.split('\n'):
            if "---" in line:
                continue
            if match := re.match(r"^\s*(\S+)\s+(\S.+?)\s+(\S+)\s+(\S+)\s+(\S+)\s*$", line):
                current_adapter = {
                    "name": match.group(2).strip(),
                    "state": "Connected" if "Connected" in match.group(3) else "Disconnected",
                    "type": match.group(4),
                    "physical": "Dedicated" if "Dedicated" in match.group(5) else "Other"
                }
                adapters.append(current_adapter)
        return adapters
    except Exception as e:
        logger.error(f"获取网络适配器失败: {str(e)}")
        return []


def detect_campus_adapter(adapter_name: str) -> bool:
    """检测是否为校园网适配器"""
    try:
        # 方法1: 检测DNS后缀
        output = subprocess.check_output(
            ["netsh", "interface", "ipv4", "show", "config", f"name={adapter_name}"],
            text=True, timeout=5
        )
        if CAMPUS_NETWORK_FEATURES["dns_suffix"] in output:
            return True
        
        # 方法2: 检测特定域名解析
        try:
            socket.gethostbyname(CAMPUS_NETWORK_FEATURES["test_domain"])
            return True
        except socket.gaierror:
            pass
        
        # 方法3: 检查IP地址段
        ip_output = subprocess.check_output(["ipconfig"], text=True)
        ip_pattern = re.compile(r"IPv4 Address.*?(\d+\.\d+\.\d+\.\d+)")
        for ip in ip_pattern.findall(ip_output):
            if any(ip.startswith(prefix) for prefix in CAMPUS_NETWORK_FEATURES["typical_ips"]):
                return True
    except Exception:
        pass
    return False

def detect_campus_adapter(adapter_info: dict) -> bool:
    """增强型校园网适配器检测"""
    try:
        # 方法1: 检查IP地址段
        ip_output = subprocess.check_output(
            ["netsh", "interface", "ipv4", "show", "address", f"name={adapter_info['name']}"],
            text=True, timeout=5, errors='ignore'
        )
        if re.search(r"IP Address:\s+10\.\d+\.\d+\.\d+", ip_output):
            return True
        
        # 方法2: 测试内网域名解析
        try:
            socket.gethostbyname(CAMPUS_NETWORK_FEATURES["test_domain"])
            return True
        except socket.gaierror:
            pass
        
        # 方法3: 追踪路由检测
        trace_result = subprocess.run(
            ["tracert", "-d", "-w", "2", CAMPUS_NETWORK_FEATURES["test_domain"]],
            capture_output=True, text=True, timeout=10
        )
        if any(ip.startswith("202.117") for ip in re.findall(r"\d+\.\d+\.\d+\.\d+", trace_result.stdout)):
            return True
        
    except Exception as e:
        logger.warning(f"校园网检测异常: {str(e)}")
    
    return False

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

def change_dns(adapter_name: str, dns_servers: list):
    """修改DNS服务器设置 (需要管理员权限)"""
    try:
        # 清除现有DNS
        subprocess.run(
            ["netsh", "interface", "ipv4", "set", "dns", 
             f"name={adapter_name}", "source=static", "addr=none"],
            check=True, timeout=10
        )
        # 设置新DNS
        for i, dns in enumerate(dns_servers, 1):
            subprocess.run(
                ["netsh", "interface", "ipv4", "add", "dns",
                 f"name={adapter_name}", dns, f"index={i}"],
                check=True, timeout=10
            )
        return True, "DNS修改成功"
    except subprocess.CalledProcessError as e:
        logger.error(f"DNS修改失败: {e.stderr}")
        return False, f"操作失败: {e.stderr}"
    except Exception as e:
        return False, f"意外错误: {str(e)}"

def disable_ipv6(adapter_name: str):
    """禁用IPv6协议 (需要管理员权限)"""
    try:
        subprocess.run(
            ["netsh", "interface", "ipv6", "set", "interface",
             f'"{adapter_name}"', "admin=disable"],
            check=True, shell=True, timeout=10
        )
        return True, "IPv6已禁用"
    except subprocess.CalledProcessError as e:
        logger.error(f"禁用IPv6失败: {e.stderr}")
        return False, f"操作失败: {e.stderr}"
    except Exception as e:
        return False, f"意外错误: {str(e)}"

def enable_ipv6(adapter_name):
    """启用指定网络适配器的 IPv6 (Windows, 需要管理员权限) - 占位符"""
    if platform.system() != "Windows":
        logger.error("启用 IPv6 目前仅支持 Windows。")
        return False, "仅支持 Windows"

    logger.warning(f"启用 IPv6 功能 ('{adapter_name}') 尚未完全实现。需要管理员权限和 netsh 命令。")
    # 示例命令: subprocess.run(['netsh', 'interface', 'ipv6', 'set', 'state', f'interface="{adapter_name}"', 'state=enabled'], ...)
    return False, "功能待实现"

def set_dns(adapter_name, dns_servers):
    """设置指定网络适配器的 DNS 服务器 (Windows, 需要管理员权限) - 占位符"""
    if platform.system() != "Windows":
        logger.error("设置 DNS 目前仅支持 Windows。")
        return False, "仅支持 Windows"

    logger.warning(f"设置 DNS 功能 ('{adapter_name}') 尚未完全实现。需要管理员权限和 netsh 命令。")
    # 示例命令:
    # subprocess.run(['netsh', 'interface', 'ipv4', 'set', 'dnsserver', f'name="{adapter_name}"', 'static', dns_servers[0], 'primary'], ...)
    # if len(dns_servers) > 1:
    #     subprocess.run(['netsh', 'interface', 'ipv4', 'add', 'dnsserver', f'name="{adapter_name}"', dns_servers[1], 'index=2'], ...)
    return False, "功能待实现"

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