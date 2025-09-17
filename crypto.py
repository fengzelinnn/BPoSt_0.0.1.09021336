"""
dPDP 方案的密码学原语，使用 py_ecc 库。

本实现切换为 BN128（altbn128/BN254）曲线，并提供必要的通用序列化/反序列化工具。
注意：本模块的 serialize_* 返回 bytes（未压缩、定长、确定性编码），便于网络传输后再 hex。
"""
import hashlib
import secrets
from typing import TypeAlias, Any, Tuple

# 优化模块（BN128）
try:
    from py_ecc.optimized_bn128 import (
        FQ, FQ2,
        G1, G2, Z1,
        add,
        multiply,
        pairing as ecc_pairing,
        is_inf,
    )
    try:
        # 优先从 optimized 模块获取曲线阶
        from py_ecc.optimized_bn128 import curve_order as CURVE_ORDER
    except Exception:
        # 兼容不同 py_ecc 版本
        from py_ecc.bn128 import curve_order as CURVE_ORDER  # type: ignore
except Exception as _:
    # 兜底常量（以太坊 altbn128 曲线阶）
    CURVE_ORDER = int("21888242871839275222246405745257275088548364400416034343698204186575808495617")
    # 延迟导入失败：留给运行时更早暴露错误
    from py_ecc.optimized_bn128 import (  # type: ignore
        FQ, FQ2,
        G1, G2, Z1,
        add, multiply, pairing as ecc_pairing, is_inf
    )

# --- 为清晰起见定义的类型别名 ---
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
    """将字节字符串哈希为 G1 中的一个点（简化映射，非严格 hash-to-curve）。"""
    k = hash_to_scalar(data)
    return multiply(g1_generator, k)

def pairing_g2_g1(q_g2: G2Element, p_g1: G1Element) -> GTElement:
    """计算双线性对 e(Q, P)，Q ∈ G2，P ∈ G1（BN128 默认顺序）。"""
    return ecc_pairing(q_g2, p_g1)

# --- 内部工具：提取 int/坐标 ---
def _int_of(x: Any) -> int:
    if hasattr(x, "n"):
        return int(x.n)
    return int(x)

def _fq2_to_pair(x: Any) -> Tuple[int, int]:
    # FQ2 可能有 coeffs 成员，或直接是 (c0, c1)
    if hasattr(x, "coeffs"):
        a, b = x.coeffs
        return _int_of(a), _int_of(b)
    elif isinstance(x, (list, tuple)) and len(x) == 2:
        return _int_of(x[0]), _int_of(x[1])
    else:
        # 不期望的形态，尽力而为
        return _int_of(x), 0

# --- 序列化 / 反序列化（bytes） ---
# 约定：
# - G1: x(32) || y(32) || z(32) 共 96 字节，Z1 用全 0 表示
# - G2: x.c0(32)||x.c1(32)||y.c0(32)||y.c1(32)||z.c0(32)||z.c1(32) 共 192 字节，Z2 同理全 0
def serialize_g1(p: G1Element) -> bytes:
    if is_inf(p):
        return b"\x00" * 96
    # 兼容 2/3 元组坐标，缺省 z=1
    x = _int_of(p[0])
    y = _int_of(p[1])
    z = _int_of(p[2]) if len(p) > 2 else 1
    return x.to_bytes(32, "big") + y.to_bytes(32, "big") + z.to_bytes(32, "big")

def deserialize_g1(b: bytes) -> G1Element:
    if len(b) != 96:
        raise ValueError("G1 序列化长度应为 96 字节")
    if b == b"\x00" * 96:
        return G1_IDENTITY
    x = int.from_bytes(b[0:32], "big")
    y = int.from_bytes(b[32:64], "big")
    z = int.from_bytes(b[64:96], "big")
    return (FQ(x), FQ(y), FQ(z))

def serialize_g2(p: G2Element) -> bytes:
    # 约定 Z2 使用全 0
    # G2 为三元组 (X, Y, Z) 每个为 FQ2
    if hasattr(p, "__len__") and len(p) >= 3:
        X, Y, Z = p[0], p[1], p[2]
        x0, x1 = _fq2_to_pair(X)
        y0, y1 = _fq2_to_pair(Y)
        z0, z1 = _fq2_to_pair(Z)
        return (
            x0.to_bytes(32, "big") + x1.to_bytes(32, "big") +
            y0.to_bytes(32, "big") + y1.to_bytes(32, "big") +
            z0.to_bytes(32, "big") + z1.to_bytes(32, "big")
        )
    # 退化处理
    return b"\x00" * 192

def deserialize_g2(b: bytes) -> G2Element:
    if len(b) != 192:
        raise ValueError("G2 序列化长度应为 192 字节")
    if b == b"\x00" * 192:
        # Z2
        return (FQ2([FQ(0), FQ(0)]), FQ2([FQ(1), FQ(0)]), FQ2([FQ(0), FQ(0)]))
    x0 = int.from_bytes(b[0:32], "big")
    x1 = int.from_bytes(b[32:64], "big")
    y0 = int.from_bytes(b[64:96], "big")
    y1 = int.from_bytes(b[96:128], "big")
    z0 = int.from_bytes(b[128:160], "big")
    z1 = int.from_bytes(b[160:192], "big")
    X = FQ2([FQ(x0), FQ(x1)])
    Y = FQ2([FQ(y0), FQ(y1)])
    Z = FQ2([FQ(z0), FQ(z1)])
    return (X, Y, Z)

def serialize_scalar(s: Scalar) -> bytes:
    return int(s).to_bytes(32, "big")

def deserialize_scalar(b: bytes) -> Scalar:
    return int.from_bytes(b, "big")
