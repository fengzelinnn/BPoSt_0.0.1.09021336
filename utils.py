"""
通用工具函数

- sha256_hex：返回输入字节的SHA-256十六进制字符串。
- h_join：将若干字符串以竖线连接后取SHA-256（用于确定性承诺/序列化）。
"""
import hashlib


def sha256_hex(data: bytes) -> str:
    """计算 SHA-256 并返回十六进制字符串。"""
    return hashlib.sha256(data).hexdigest()


def h_join(*parts: str) -> str:
    """以"|"连接所有字符串参数后进行哈希，便于统一的可重复承诺。"""
    return sha256_hex("|".join(parts).encode())


# ---- Logging helpers appended by simulation refactor ----
# 全局日志详细级别控制（True 输出 DEBUG 级别）
VERBOSE = True


def log_msg(level, actor_type, actor_id, msg: str):
    """结构化日志输出，区分消息层级。
    level: INFO/DEBUG/WARN/ERROR；
    actor_type: USER/STORAGE/SYSTEM/NETWORK/VERIFY 等；
    actor_id: 参与者ID，系统级可为 None；
    msg: 文本内容。
    """
    if not VERBOSE and level == "DEBUG":
        return
    import time as _t
    ts = _t.strftime("%H:%M:%S")
    who = f"{actor_type}({actor_id})" if actor_id else actor_type
    print(f"[{ts}] {level} {who}: {msg}")
