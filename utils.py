"""
通用工具函数模块

本模块已将所有哈希操作迁移为 SNARK 友好的哈希：
- 基于 BN254 曲线（与本项目的密码学后端一致）的 MiMC-7 置换与简单 sponge。
- sha256_hex: 名称保持兼容，但内部改为返回 MiMC-7 sponge 的 32 字节字段元素十六进制字符串。
- h_join: 采用 MiMC-7 sponge（带域分离）对多段字符串进行确定性组合哈希。
- 其余接口（Merkle 构建与日志）维持不变，但都会使用上述 SNARK 友好的哈希。
"""
import hashlib
import logging
from logging.handlers import RotatingFileHandler
from functools import lru_cache
from typing import List, Dict

from crypto import CURVE_ORDER as FIELD_PRIME  # 使用 BN254 曲线阶作为字段素数


# ---------------------------- SNARK 友好哈希（MiMC-7 over BN254） ----------------------------

@lru_cache(maxsize=None)
def _mimc_constants(rounds: int = 91) -> List[int]:
    """
    生成 MiMC-7 的轮常量，确定性（从固定种子派生），对 BN254 的字段取模。
    """
    consts: List[int] = []
    seed = b"MIMC7_BN254_CONST"
    for i in range(rounds):
        # 简单的确定性常量派生：迭代哈希再取模
        seed = hashlib.sha256(seed + i.to_bytes(4, "big")).digest()
        consts.append(int.from_bytes(seed, "big") % FIELD_PRIME)
    return consts


def _mimc7_permute(x: int, k: int = 0) -> int:
    """
    单次 MiMC-7 置换（固定 91 轮），最后一轮后加 key。
    变体：每轮使用 x <- (x + k + c_i)^7 (mod p)，最终 x <- x + k (mod p)。
    """
    p = FIELD_PRIME
    x = x % p
    k = k % p
    C = _mimc_constants()
    # 前 rounds-1 轮
    for i in range(len(C) - 1):
        t = (x + k + C[i]) % p
        x = pow(t, 7, p)
    # 最后一轮再加 key
    t = (x + k + C[-1]) % p
    x = pow(t, 7, p)
    x = (x + k) % p
    return x


def _bytes_to_field_elems(data: bytes, chunk_size: int = 31) -> List[int]:
    """
    将任意字节流分块映射到 BN254 字段元素列表（31字节一块，确保 < p）。
    空输入映射为 [0]。
    """
    if not data:
        return [0]
    elems: List[int] = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        elems.append(int.from_bytes(chunk, "big") % FIELD_PRIME)
    return elems


def hash_to_field(data: bytes) -> int:
    """
    将任意字节流哈希为一个字段元素（MiMC-7 sponge）。
    """
    state = 0
    for m in _bytes_to_field_elems(data):
        state = _mimc7_permute((state + m) % FIELD_PRIME, 0)
    return state % FIELD_PRIME


def snark_hash_bytes(data: bytes) -> bytes:
    """
    SNARK 友好哈希（MiMC-7 sponge）输出 32 字节大端表示的字段元素。
    """
    h = hash_to_field(data)
    return int(h).to_bytes(32, "big")


def snark_hash_hex(data: bytes) -> str:
    """
    SNARK 友好哈希十六进制（小写），长度固定为 64（32 字节）。
    """
    return snark_hash_bytes(data).hex()


def h_join(*parts: str) -> str:
    """
    使用 MiMC-7 sponge 对多段字符串进行有序组合哈希。
    提供域分离（HJOINv1），确保不同用途的哈希域分离。
    """
    # 域分离种子
    state = hash_to_field(b"HJOINv1")
    for part in parts:
        piece = hash_to_field(part.encode())
        state = _mimc7_permute((state + piece) % FIELD_PRIME, 0)
    return int(state).to_bytes(32, "big").hex()


def sha256_hex(data: bytes) -> str:
    """
    兼容接口：名称保留，但内部已迁移为 SNARK 友好的 MiMC-7 sponge。
    返回 32 字节的字段元素十六进制字符串。
    """
    return snark_hash_hex(data)


def build_merkle_root(leaf_hashes: List[str]) -> str:
    """
    从一个叶子哈希列表构建并返回Merkle树的根哈希。
    如果列表为空，则返回一个固定的空哈希（MiMC-7 哈希的空输入）。
    """
    if not leaf_hashes:
        return sha256_hex(b'')

    if len(leaf_hashes) == 1:
        return leaf_hashes[0]

    # 确保叶子数量是偶数
    if len(leaf_hashes) % 2 != 0:
        leaf_hashes.append(leaf_hashes[-1])

    next_level = []
    for i in range(0, len(leaf_hashes), 2):
        # 将配对的哈希排序以确保一致性
        pair = sorted([leaf_hashes[i], leaf_hashes[i + 1]])
        combined_hash = h_join(pair[0], pair[1])
        next_level.append(combined_hash)

    return build_merkle_root(next_level)


def build_merkle_tree(leaf_hashes: List[str]) -> (str, Dict[str, List[str]]):
    """
    从一个叶子哈希列表构建Merkle树，并返回根哈希和树本身。
    树以字典形式返回，将每个父哈希映射到其子哈希列表。
    """
    if not leaf_hashes:
        empty_hash = sha256_hex(b'')
        return empty_hash, {}

    if len(leaf_hashes) == 1:
        return leaf_hashes[0], {}

    nodes: Dict[str, List[str]] = {}
    level = list(leaf_hashes)

    while len(level) > 1:
        if len(level) % 2 != 0:
            level.append(level[-1])

        next_level = []
        for i in range(0, len(level), 2):
            child1, child2 = level[i], level[i + 1]
            sorted_children = sorted([child1, child2])
            parent = h_join(sorted_children[0], sorted_children[1])
            nodes[parent] = sorted_children
            next_level.append(parent)
        level = next_level

    root = level[0]
    return root, nodes


# ---------------------------- 日志记录辅助函数 ----------------------------

_LOG_INITIALIZED = False
_LOGGER = logging.getLogger("BPoSt")


def init_logging(log_file: str = "bpst.log", level: str = "DEBUG", console: bool = True,
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
