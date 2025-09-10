"""
Cryptographic primitives for the dPDP scheme, using the py_ecc library.

This module provides the necessary cryptographic functions based on the BLS12-381 curve.
It uses the `py_ecc` library for all elliptic curve and pairing operations, ensuring
cryptographic security.
"""
import hashlib
import secrets
from typing import TypeAlias, Any

# Core primitives from the optimized module, which is a more stable API
from py_ecc.optimized_bls12_381 import (
    G1, G2, Z1,
    add,
    multiply,
    pairing as ecc_pairing,
    curve_order as CURVE_ORDER
)

# Serialization functions are in g2_primitives
from py_ecc.bls.g2_primitives import (
    G1_to_pubkey,
    pubkey_to_G1,
    G2_to_signature,
    signature_to_G2,
)

# --- Type Aliases for clarity ---
# Use `Any` to avoid importing internal py_ecc types like Fq, which can cause
# versioning issues. The actual values returned by py_ecc functions are tuples,
# but the types of their elements are not part of the stable public API.
Scalar: TypeAlias = int
G1Element: TypeAlias = Any
G2Element: TypeAlias = Any
GTElement: TypeAlias = Any

# --- Cryptographic Primitives ---
g1_generator: G1Element = G1
g2_generator: G2Element = G2
G1_IDENTITY: G1Element = Z1

def random_scalar() -> Scalar:
    """Generates a random scalar in the range [1, CURVE_ORDER - 1]."""
    return secrets.randbelow(CURVE_ORDER - 1) + 1

def hash_to_scalar(data: bytes) -> Scalar:
    """Hashes a byte string to a scalar, modulo the curve order."""
    h = hashlib.sha256(data).digest()
    return int.from_bytes(h, 'big') % CURVE_ORDER

def hash_to_g1(data: bytes) -> G1Element:
    """Hashes a byte string to a point in G1 (simplified, not a full hash-to-curve)."""
    scalar = hash_to_scalar(data)
    return multiply(g1_generator, scalar)

def pairing(p1: G1Element, p2: G2Element) -> GTElement:
    """Computes the BLS pairing e(p1, p2), wrapping py_ecc's (G2, G1) order."""
    # Note: py_ecc's low-level pairing function expects (G2, G1)
    return ecc_pairing(p2, p1)

# --- Serialization / Deserialization ---
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
