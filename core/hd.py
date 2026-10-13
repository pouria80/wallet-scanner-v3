"""BIP-32 / BIP-44 HD key derivation + ETH address (pure hashlib/coincurve)."""
from __future__ import annotations

import hashlib
import struct

import coincurve

CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
HMAC_KEY = b"Bitcoin seed"


def _ser2p(i: int) -> bytes:
    return b"\x00" + struct.pack(">I", i)


def _ckd_priv(key: bytes, chain_code: bytes, index: int) -> tuple[bytes, bytes]:
    if index >= 0x80000000:
        data = key + struct.pack(">I", index)
    else:
        data = coincurve.PrivateKey(key).public_key.format(compressed=True) + struct.pack(">I", index)
    I = hmac_sha512(chain_code, data)
    il, ir = I[:32], I[32:]
    k = (int.from_bytes(il, "big") + int.from_bytes(key, "big")) % CURVE_ORDER
    if 0 <= k == 0 or k >= CURVE_ORDER:
        raise ValueError("invalid derived key")
    return k.to_bytes(32, "big"), ir


def hmac_sha512(key: bytes, msg: bytes) -> bytes:
    import hmac
    return hmac.new(key, msg, hashlib.sha512).digest()


def master_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    I = hmac_sha512(HMAC_KEY, seed)
    return I[:32], I[32:]


def derive_path(seed: bytes, path: str) -> tuple[bytes, bytes]:
    key, cc = master_from_seed(seed)
    parts = path.replace("m/", "").split("/")
    for p in parts:
        hardened = p.endswith("'")
        idx = int(p[:-1]) + 0x80000000 if hardened else int(p)
        key, cc = _ckd_priv(key, cc, idx)
    return key, cc


def eth_address(priv: bytes) -> str:
    pub = coincurve.PrivateKey(priv).public_key.format(compressed=False)[1:]
    digest = _keccak(pub)
    return "0x" + digest[-20:].hex()


try:
    from Crypto.Hash import keccak as _pykeccak

    def _keccak(data: bytes) -> bytes:
        h = _pykeccak.new(digest_bits=256)
        h.update(data)
        return h.digest()
except ImportError:
    try:
        import sha3 as _sha3  # pysha3

        def _keccak(data: bytes) -> bytes:
            return _sha3.keccak_256(data).digest()
    except ImportError:
        # pure-python keccak (fixed implementation, verified against vectors)
        from keccak_pure import keccak_256 as _keccak
