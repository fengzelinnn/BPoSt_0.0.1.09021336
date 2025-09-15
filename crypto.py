"""
dPDP方案的密码学原语，使用py_ecc库。

此模块提供基于BLS12-381曲线的必要密码学函数。
它使用`py_ecc`库进行所有椭圆曲线和配对操作，确保密码学安全性。
"""
import hashlib
import secrets
from typing import TypeAlias, Any

# 优化模块中的核心原语，提供更稳定的API
from py_ecc.optimized_bls12_381 import (
    G1, G2, Z1,
    add,
    multiply,
    pairing as ecc_pairing,
    curve_order as CURVE_ORDER
)

# 序列化函数在g2_primitives中
from py_ecc.bls.g2_primitives import (
    G1_to_pubkey,
    pubkey_to_G1,
    G2_to_signature,
    signature_to_G2,
)

# --- 为清晰起见定义的类型别名 ---
# 使用`Any`避免导入py_ecc内部类型（如Fq），这可能导致版本问题。
# py_ecc函数返回的实际值是元组，但其元素类型不是稳定公共API的一部分。
Scalar: TypeAlias = int
G1Element: TypeAlias = Any
G2Element: TypeAlias = Any
GTElement: TypeAlias = Any

# --- 密码学原语 ---
g1_generator: G1Element = G1
g2_generator: G2Element = G2
G1_IDENTITY: G1Element = Z1

def random_scalar() -> Scalar:
    """生成一个范围在[1, CURVE_ORDER - 1]内的随机标量。"""
    return secrets.randbelow(CURVE_ORDER - 1) + 1

def hash_to_scalar(data: bytes) -> Scalar:
    """将字节字符串哈希为标量，模曲线阶。"""
    h = hashlib.sha256(data).digest()
    return int.from_bytes(h, 'big') % CURVE_ORDER

def hash_to_g1(data: bytes) -> G1Element:
    """将字节字符串哈希为G1中的一个点（简化版，非完整哈希到曲线）。"""
    scalar = hash_to_scalar(data)
    return multiply(g1_generator, scalar)

def pairing(p1: G1Element, p2: G2Element) -> GTElement:
    """计算BLS配对e(p1, p2)，封装py_ecc的(G2, G1)顺序。"""
    # 注意：py_ecc的底层配对函数期望(G2, G1)顺序
    return ecc_pairing(p2, p1)

# --- 序列化 / 反序列化 ---
def serialize_g1(p: G1Element) -> str:
    return G1_to_pubkey(p).hex()

def deserialize_g1(s: str) -> G1Element:
    return pubkey_to_G1(bytes.fromhex(s))

def serialize_g2(p: G2Element) -> str:
    return G2_to_signature(p).hex()

def deserialize_g2(s: str) -> G2Element:
    return signature_to_G2(bytes.fromhex(s))

def serialize_scalar(s: Scalar) -> str:
    return s.to_bytes(32, 'big').hex()

def deserialize_scalar(s: str) -> Scalar:
    return int.from_bytes(bytes.fromhex(s), 'big')
