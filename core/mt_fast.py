"""Fast MT19937 entropy generation — bit-exact with mt19937_reference.MT19937Reference.

Why this exists: the reference engine seeds a fresh 624-word state per seed and
we only need the low byte of its first 16 outputs.  Doing that one seed at a
time in Python is ~500 seeds/s; batching across seeds with numpy gives
~35k seeds/s, and a lean pure-python path (~2.5k seeds/s) keeps things fast
even when numpy is not installed (e.g. a bare Windows machine).

Both paths were verified bit-for-bit against the reference engine
(see tests/test_mt_fast.py).
"""
from __future__ import annotations

_M32 = 0xFFFFFFFF
_INIT_MULT = 1812433253
_N, _M, _MATRIX_A = 624, 397, 0x9908B0DF


def _seed_state(s: int) -> list[int]:
    """init_genrand — identical recurrence to MT19937Reference.seed_scalar."""
    mt = [0] * _N
    prev = s & _M32
    mt[0] = prev
    for i in range(1, _N):
        prev = (_INIT_MULT * (prev ^ (prev >> 30)) + i) & _M32
        mt[i] = prev
    return mt


def first_outputs(s: int, n: int = 16) -> list[int]:
    """First ``n`` uint32 outputs of a freshly scalar-seeded engine (twist once)."""
    mt = _seed_state(s)
    out = [0] * _N
    for k in range(_N - _M):
        y = (mt[k] & 0x80000000) | (mt[k + 1] & 0x7FFFFFFF)
        out[k] = mt[k + _M] ^ (y >> 1) ^ (_MATRIX_A if (y & 1) else 0)
    for k in range(_N - _M, _N - 1):
        y = (mt[k] & 0x80000000) | (mt[k + 1] & 0x7FFFFFFF)
        out[k] = mt[k + _M - _N] ^ (y >> 1) ^ (_MATRIX_A if (y & 1) else 0)
    y = (mt[_N - 1] & 0x80000000) | (mt[0] & 0x7FFFFFFF)
    out[_N - 1] = mt[_M - 1] ^ (y >> 1) ^ (_MATRIX_A if (y & 1) else 0)
    res = []
    for k in range(n):
        t = out[k]
        t ^= t >> 11
        t ^= (t << 7) & 0x9D2C5680
        t ^= (t << 15) & 0xEFC60000
        t ^= t >> 18
        res.append(t & _M32)
    return res


def entropy_pure(seed: int, length: int = 16) -> bytes:
    """Low byte of each of the first ``length`` outputs (the Trust Wallet model)."""
    return bytes(v & 0xFF for v in first_outputs(seed, length))


try:
    import numpy as _np

    _U = _np.uint32

    def entropy_batch(seeds: "_np.ndarray", length: int = 16) -> "list[bytes]":
        """Vectorised entropy for a block of uint32 seeds. Bit-exact vs ``entropy_pure``."""
        k = len(seeds)
        mt = _np.empty((k, _N), dtype=_U)
        prev = seeds.astype(_U, copy=True)
        mt[:, 0] = prev
        for i in range(1, _N):
            prev = (_U(_INIT_MULT) * (prev ^ (prev >> _U(30))) + _U(i)).astype(_U)
            mt[:, i] = prev
        upper = mt & _U(0x80000000)
        nxt_lane = _np.roll(mt, -1, axis=1)
        nxt_lane[:, -1] = mt[:, 0]
        y = upper | (nxt_lane & _U(0x7FFFFFFF))
        shifted = _np.concatenate([mt[:, _M:], mt[:, :_M]], axis=1)
        o = (shifted ^ (y >> _U(1))
             ^ _np.where((y & _U(1)) == 1, _U(_MATRIX_A), _U(0))).astype(_U)
        o ^= o >> _U(11)
        o ^= (o << _U(7)) & _U(0x9D2C5680)
        o ^= (o << _U(15)) & _U(0xEFC60000)
        o ^= o >> _U(18)
        # pack each row's low bytes contiguously: uint32 -> uint8 view, take
        # byte 0 of every word (little-endian), keep the first ``length``.
        words = o[:, :_N] if length <= _N else o
        nbytes = words.view(_np.uint8).reshape(k, -1, 4)[:, :, 0]
        return [row[:length].tobytes() for row in nbytes]

    HAS_NUMPY = True
except ImportError:  # pragma: no cover - numpy absent on a bare install
    HAS_NUMPY = False

    def entropy_batch(seeds, length: int = 16) -> list[bytes]:  # type: ignore
        return [entropy_pure(int(s), length) for s in seeds]
