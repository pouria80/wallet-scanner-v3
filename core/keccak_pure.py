"""Pure-python Keccak-256 (fallback when pycryptodome is unavailable).

NOTE: previously this fallback had two fatal bugs that made *every* derived
address wrong (and every balance check silently useless):
  1. rho step used the sha3 (NIST) rotation offsets instead of Keccak's,
  2. padding byte was 0x01 instead of Keccak's domain separator 0x06.
Both fixed here; verified against known vectors in tests/test_keccak.py.
"""
from __future__ import annotations

_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
       0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
       0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
       0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
       0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
       0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
       0x8000000000008080, 0x0000000080000001, 0x8000000080008008]

# Keccak rho rotation offsets, indexed by lane A[x][y]
_RHO = [[0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14]]

_M64 = 0xFFFFFFFFFFFFFFFF


def _rotl(x: int, n: int) -> int:
    if n == 0:
        return x
    return ((x << n) | (x >> (64 - n))) & _M64


def _permute(a: list[list[int]]) -> None:
    for rnd in range(24):
        # theta  (column parities C[x] = A[x][0..4]; D[x] = C[x-1] ^ rot(C[x+1],1))
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x + 4) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]
        # rho + pi   B[y][(2x+3y)%5] = rot(A[x][y], r[x][y])
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl(a[x][y], _RHO[x][y])
        # chi
        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y] & _M64) & b[(x + 2) % 5][y])
        # iota
        a[0][0] ^= _RC[rnd]


def keccak_256(data: bytes) -> bytes:
    """Return the 32-byte Keccak-256 digest of ``data``."""
    rate = 136  # 1088 bits
    state = [[0] * 5 for _ in range(5)]
    padded = bytearray(data)
    padded.append(0x01)               # original Keccak padding (not SHA3's 0x06)
    while len(padded) % rate != 0:
        padded.append(0)
    padded[-1] |= 0x80
    for blk_start in range(0, len(padded), rate):
        block = padded[blk_start:blk_start + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            state[x][y] ^= int.from_bytes(block[i * 8:(i + 1) * 8], "little")
        _permute(state)
    out = bytearray()
    for i in range(4):
        x, y = i % 5, i // 5
        out += state[x][y].to_bytes(8, "little")
    return bytes(out[:32])
