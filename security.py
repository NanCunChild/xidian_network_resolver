# security.py
"""
安全相关功能模块
包含：加密、解密、凭证管理
"""

import os
import base64
import logging
import json
from pathlib import Path
from typing import Tuple, Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    logging.error("未安装cryptography库，请使用 pip install cryptography 安装")
    raise

logger = logging.getLogger("security")

class SecurityManager:
    """安全管理器，提供加密解密功能"""
    
    def __init__(self):
        # 使用设备ID作为盐值基础
        self.salt = self._get_device_id().encode()[:16]
        
    def _get_device_id(self) -> str:
        """获取设备唯一标识，用于派生密钥"""
        # 从系统获取相对唯一的设备标识
        import platform
        import uuid
        
        system_info = platform.uname()
        machine_id = str(uuid.getnode())  # MAC地址的整数表示
        
        # 组合成唯一标识并使用SHA256哈希
        device_info = f"{system_info.node}:{machine_id}:{system_info.system}"
        
        # 使用哈希函数生成固定长度的设备ID
        h = hashes.Hash(hashes.SHA256())
        h.update(device_info.encode())
        return h.finalize().hex()
    
    def derive_key(self, password: str) -> bytes:
        """从密码派生密钥"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256位密钥
            salt=self.salt,
            iterations=100000,
        )
        return kdf.derive(password.encode())
    
    def encrypt_data(self, data: str, password: str = "xidian_network_default") -> Optional[str]:
        """使用AES-GCM加密数据"""
        try:
            key = self.derive_key(password)
            aesgcm = AESGCM(key)
            nonce = os.urandom(12)  # GCM推荐的nonce长度
            
            # 加密
            ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
            
            # 组合nonce和密文并进行Base64编码
            return base64.b64encode(nonce + ciphertext).decode()
        except Exception as e:
            logger.error(f"加密失败: {e}")
            return None
    
    def decrypt_data(self, encrypted: str, password: str = "xidian_network_default") -> Optional[str]:
        """使用AES-GCM解密数据"""
        try:
            key = self.derive_key(password)
            aesgcm = AESGCM(key)
            
            # Base64解码
            data = base64.b64decode(encrypted)
            
            # 分离nonce和密文
            nonce, ciphertext = data[:12], data[12:]
            
            # 解密
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode()
        except Exception as e:
            logger.error(f"解密失败: {e}")
            return None


class CredentialManager:
    """凭证管理器，处理用户凭证的安全存储和读取"""
    
    def __init__(self, config_dir: Path, config_file: Path):
        self.config_dir = config_dir
        self.config_file = config_file
        self.security = SecurityManager()
        
    def save_credentials(self, username: str, password: str) -> bool:
        """安全保存用户凭证"""
        self.config_dir.mkdir(exist_ok=True, parents=True)
        
        # 将用户名和密码组合成JSON字符串
        cred_data = json.dumps({"username": username, "password": password})
        
        # 加密数据
        encrypted = self.security.encrypt_data(cred_data)
        if not encrypted:
            logger.error("加密失败，无法保存凭证")
            return False
        
        try:
            # 写入文件
            self.config_file.write_text(encrypted)
            logger.info("凭证已安全保存")
            return True
        except Exception as e:
            logger.error(f"写入凭证文件失败: {e}")
            return False
    
    def load_credentials(self) -> Tuple[Optional[str], Optional[str]]:
        """加载保存的凭证"""
        if not self.config_file.exists():
            return None, None
        
        try:
            encrypted_data = self.config_file.read_text().strip()
            if not encrypted_data:
                logger.warning("凭证文件为空")
                return None, None
                
            # 解密数据
            decrypted_data = self.security.decrypt_data(encrypted_data)
            if not decrypted_data:
                return None, None
                
            # 解析JSON
            cred_json = json.loads(decrypted_data)
            username = cred_json.get("username")
            password = cred_json.get("password")
            
            if username and password:
                logger.info("凭证已成功加载")
                return username, password
            else:
                logger.error("解密后的凭证格式不正确")
                return None, None
                
        except json.JSONDecodeError:
            logger.error("凭证JSON解析失败")
            return None, None
        except Exception as e:
            logger.error(f"加载凭证失败: {e}")
            return None, None
    
    def clear_credentials(self) -> bool:
        """清除保存的凭证"""
        if self.config_file.exists():
            try:
                self.config_file.unlink()
                logger.info("已清除保存的凭证")
                return True
            except Exception as e:
                logger.error(f"删除凭证文件失败: {e}")
                return False
        return True  # 文件不存在视为清除成功