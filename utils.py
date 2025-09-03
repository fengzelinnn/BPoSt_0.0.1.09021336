"""
通用工具函数模块

提供项目中普遍使用的辅助函数，主要包括：
- 哈希计算:
  - sha256_hex: 计算数据的SHA-256哈希并返回十六进制字符串。
  - h_join: 用于确定性地组合和哈希多个字符串部分。
- 日志记录:
  - init_logging: 初始化全局日志系统。
  - log_msg: 提供结构化的日志记录接口。
"""
import hashlib
import logging
from logging.handlers import RotatingFileHandler

def sha256_hex(data: bytes) -> str:
    """计算SHA-256哈希并返回十六进制字符串。"""
    return hashlib.sha256(data).hexdigest()

def h_join(*parts: str) -> str:
    """将所有字符串参数用'|'连接后进行哈希，用于创建统一且可复现的承诺。"""
    return sha256_hex("|".join(parts).encode())


# ---------------------------- 日志记录辅助函数 ----------------------------

_LOG_INITIALIZED = False
_LOGGER = logging.getLogger("BPoSt")

def init_logging(log_file: str = "bpst.log", level: str = "INFO", console: bool = True,
                 max_bytes: int = 10 * 1024 * 1024, backup_count: int = 5):
    """
    初始化全局日志记录器。

    :param log_file: 日志文件名。
    :param level: 日志级别字符串 (例如, "DEBUG", "INFO", "WARN")。
    :param console: 如果为True，日志也会输出到控制台。
    :param max_bytes: 每个日志文件的最大大小（字节）。
    :param backup_count: 保留的旧日志文件数量。
    """
    global _LOG_INITIALIZED
    if _LOG_INITIALIZED:
        return

    log_level = _to_logging_level(level)

    _LOGGER.setLevel(log_level)
    _LOGGER.propagate = False  # 防止日志向上传播到根记录器，避免重复输出

    # 定义日志格式
    fmt = logging.Formatter(fmt="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")

    # 文件处理器，支持日志文件滚动
    fh = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8")
    fh.setLevel(log_level)
    fh.setFormatter(fmt)
    _LOGGER.addHandler(fh)

    # 如果需要，添加控制台处理器
    if console:
        ch = logging.StreamHandler()
        ch.setLevel(log_level)
        ch.setFormatter(fmt)
        _LOGGER.addHandler(ch)

    _LOG_INITIALIZED = True

def _to_logging_level(level: str) -> int:
    """将字符串形式的日志级别转换为logging库的常量。"""
    level = (level or "INFO").upper()
    return {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARN": logging.WARNING,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }.get(level, logging.INFO)

def log_msg(level, actor_type, actor_id, msg: str):
    """
    记录一条结构化的日志消息。

    :param level: 日志级别 (例如, "INFO", "DEBUG")。
    :param actor_type: 产生日志的模块或角色类型 (例如, "NODE", "SYSTEM")。
    :param actor_id: 参与者的唯一ID，对于系统级日志可为None。
    :param msg: 日志消息内容。
    """
    if not _LOG_INITIALIZED:
        # 如果日志系统未初始化，则使用默认配置进行初始化
        init_logging()
    
    # 格式化日志前缀，包含参与者信息
    who = f"{actor_type}({actor_id})" if actor_id else actor_type
    _LOGGER.log(_to_logging_level(level), f"{who}: {msg}")
