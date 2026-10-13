"""On-chain balance checks via public Ethereum JSON-RPC.

- ETH: eth_getBalance
- USDT / USDC (ERC-20): eth_call balanceOf on the canonical mainnet contracts

No API key required. Public endpoints with automatic failover and a
30-second backoff window for dead nodes (they are retried once the cooldown
expires). Standard browser User-Agent avoids 403 blocks on eth_call.

V3.1 additions:
- batched RPC (JSON array) — one HTTP round-trip per wallet instead of three,
  which roughly triples throughput through the GIL-bound worker pool;
- endpoint health probe at startup + rate-limit friendly concurrency cap.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request

RPC_ENDPOINTS = [
    "https://ethereum-rpc.publicnode.com",
    "https://eth.drpc.org",
    "https://1rpc.io/eth",
    "https://cloudflare-eth.com",
    "https://rpc.flashbots.net",
    "https://eth.llamarpc.com",
]

# Canonical mainnet ERC-20 contracts
USDT_CONTRACT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"   # 6 decimals
USDC_CONTRACT = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"   # 6 decimals

BALANCEOF_SELECTOR = "0x70a08231"

TIMEOUT = 10.0
BACKOFF_SEC = 30.0          # dead-node cooldown
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

_lock = threading.Lock()
_failed_until: dict[str, float] = {}   # endpoint -> monotonic time it may be retried
_round_robin = 0


def _healthy_endpoints() -> list[str]:
    """Endpoints not in backoff, rotated round-robin so no single node is hammered."""
    global _round_robin
    now = time.monotonic()
    with _lock:
        ok = [u for u in RPC_ENDPOINTS if _failed_until.get(u, 0.0) <= now]
        if not ok:
            # all dead? fall back to whichever recovers soonest
            return sorted(RPC_ENDPOINTS, key=lambda u: _failed_until.get(u, 0.0))[:1]
        n = len(ok)
        start = _round_robin % n
        _round_robin += 1
        return ok[start:] + ok[:start]


def _mark_failed(url: str) -> None:
    with _lock:
        _failed_until[url] = time.monotonic() + BACKOFF_SEC


def _mark_ok(url: str) -> None:
    with _lock:
        _failed_until.pop(url, None)


def _post(url: str, payload) -> object:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"content-type": "application/json", "user-agent": UA})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read())


class RPCUnavailable(RuntimeError):
    """Every endpoint failed for this call — caller should drop/retry the item."""


def _rpc_multi(calls: list[tuple[str, list]]) -> list[str]:
    """Run a batch of JSON-RPC calls with failover + backoff.

    Sends them as ONE batch request per endpoint (public nodes support JSON
    arrays); returns hex result strings aligned with ``calls``.
    Raises RPCUnavailable when every endpoint fails.
    """
    last_err: Exception | None = None
    payload = [{"jsonrpc": "2.0", "method": m, "params": p, "id": i}
               for i, (m, p) in enumerate(calls)]
    single = len(calls) == 1
    for url in _healthy_endpoints():
        try:
            out = _post(url, payload[0] if single else payload)
            items = out if isinstance(out, list) else [out]
            by_id = {it.get("id"): it for it in items if isinstance(it, dict)}
            results = []
            bad = False
            for i in range(len(calls)):
                it = by_id.get(i)
                if it is None or "result" not in it:
                    bad = True
                    last_err = RuntimeError(f"{url}: {it.get('error') if it else 'missing id'}")
                    break
                results.append(it["result"])
            if not bad:
                _mark_ok(url)
                return results
        except Exception as exc:  # noqa: BLE001 - failover by design
            last_err = exc
            _mark_failed(url)
    raise RPCUnavailable(f"all RPC endpoints failed: {last_err}")


def _rpc(method: str, params: list) -> str:
    return _rpc_multi([(method, params)])[0]


def _balance_of_data(contract: str, address: str) -> str:
    return BALANCEOF_SELECTOR + address.lower()[2:].rjust(64, "0")


def get_balance_wei(address: str) -> int:
    """Return ETH balance in wei. Raises RPCUnavailable if every endpoint fails."""
    res = _rpc("eth_getBalance", [address, "latest"])
    return int(res, 16)


def get_all_balances(address: str) -> tuple[int, int, int]:
    """One batched RPC round-trip -> (eth_wei, usdt_raw, usdc_raw)."""
    res = _rpc_multi([
        ("eth_getBalance", [address, "latest"]),
        ("eth_call", [{"to": USDT_CONTRACT, "data": _balance_of_data(USDT_CONTRACT, address)}, "latest"]),
        ("eth_call", [{"to": USDC_CONTRACT, "data": _balance_of_data(USDC_CONTRACT, address)}, "latest"]),
    ])
    def _i(h):
        return int(h, 16) if h and h != "0x" else 0
    return _i(res[0]), _i(res[1]), _i(res[2])


def get_token_balances(address: str) -> tuple[int, int]:
    """Return (usdt_raw, usdc_raw) integer balances (6 decimals each)."""
    _, u, c = get_all_balances(address)
    return u, c


def probe_endpoints() -> dict[str, bool]:
    """Ping every endpoint once (chainId) so the UI knows what's alive at boot."""
    results: dict[str, bool] = {}

    def one(url: str) -> None:
        try:
            _post(url, {"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1})
            results[url] = True
            _mark_ok(url)
        except Exception:  # noqa: BLE001
            results[url] = False
            _mark_failed(url)

    threads = [threading.Thread(target=one, args=(u,), daemon=True) for u in RPC_ENDPOINTS]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=TIMEOUT + 2)
    return results


def wei_to_eth(wei: int) -> float:
    return wei / 1e18


def raw_to_usd(raw: int) -> float:
    """USDT/USDC use 6 decimals."""
    return raw / 1e6
