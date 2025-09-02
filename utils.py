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


# ---- Logging helpers (redirect to file instead of console) ----
import logging
from logging.handlers import RotatingFileHandler

# 默认：不向控制台输出，只写入文件，避免控制台行数受限
_VERBOSITY_DEBUG = True  # True 输出 DEBUG，否则 INFO 及以上
_LOG_INITIALIZED = False
_LOGGER = logging.getLogger("BPoSt")


def init_logging(log_file: str = "bpst.log", level: str = None, console: bool = False,
                 max_bytes: int = 10 * 1024 * 1024, backup_count: int = 5):
    """初始化全局日志。
    log_file: 日志文件名（相对当前工作目录）。
    level: 日志等级字符串（DEBUG/INFO/WARNING/ERROR/CRITICAL）。默认根据 _VERBOSITY_DEBUG 设置。
    console: 是否同时输出到控制台（默认 False）。
    max_bytes: 单个日志文件最大字节；达到后滚动。
    backup_count: 滚动保留的历史文件个数。
    """
    global _LOG_INITIALIZED
    if _LOG_INITIALIZED:
        return

    log_level = logging.DEBUG if (level or "").upper() == "DEBUG" or (level is None and _VERBOSITY_DEBUG) else logging.INFO

    _LOGGER.setLevel(log_level)
    _LOGGER.propagate = False  # 不向上冒泡，避免重复输出

    fmt = logging.Formatter(fmt="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")

    # 文件滚动处理器
    fh = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8")
    fh.setLevel(log_level)
    fh.setFormatter(fmt)
    _LOGGER.addHandler(fh)

    if console:
        ch = logging.StreamHandler()
        ch.setLevel(log_level)
        ch.setFormatter(fmt)
        _LOGGER.addHandler(ch)

    _LOG_INITIALIZED = True


def _to_logging_level(level: str) -> int:
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
    """结构化日志输出到文件。
    level: INFO/DEBUG/WARN/ERROR；
    actor_type: USER/STORAGE/SYSTEM/NETWORK/VERIFY 等；
    actor_id: 参与者ID，系统级可为 None；
    msg: 文本内容。
    """
    if not _LOG_INITIALIZED:
        # 默认初始化为文件日志，DEBUG 等级，且不输出到控制台
        init_logging()
    who = f"{actor_type}({actor_id})" if actor_id else actor_type
    _LOGGER.log(_to_logging_level(level), f"{who}: {msg}")
