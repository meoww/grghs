"""Public read-only balance lookups (no signing, no transfers)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

# Mainnet USDT (ERC-20)
USDT_ERC20 = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
# USDT has 6 decimals
USDT_DECIMALS = 6

DEFAULT_ETH_RPCS = [
    "https://cloudflare-eth.com",
    "https://rpc.ankr.com/eth",
    "https://ethereum.publicnode.com",
    "https://1rpc.io/eth",
]

DEFAULT_BTC_APIS = [
    "https://blockstream.info/api",
    "https://mempool.space/api",
]


@dataclass
class ChainBalance:
    chain: str
    address: str
    symbol: str
    raw: int
    amount: float
    ok: bool
    error: str | None = None


@dataclass
class BalanceReport:
    eth: ChainBalance | None = None
    usdt_erc20: ChainBalance | None = None
    btc_legacy: ChainBalance | None = None
    btc_segwit: ChainBalance | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def has_funds(self) -> bool:
        for b in (self.eth, self.usdt_erc20, self.btc_legacy, self.btc_segwit):
            if b and b.ok and b.raw > 0:
                return True
        return False

    @property
    def priority(self) -> str:
        """critical if any funds, high if check failed partially, else low."""
        if self.has_funds:
            return "critical"
        if self.errors:
            return "medium"
        return "low"

    def summary_line(self) -> str:
        parts = []
        if self.eth and self.eth.ok:
            parts.append(f"ETH={self.eth.amount:.6f}")
        if self.usdt_erc20 and self.usdt_erc20.ok:
            parts.append(f"USDT={self.usdt_erc20.amount:.2f}")
        if self.btc_legacy and self.btc_legacy.ok:
            parts.append(f"BTC44={self.btc_legacy.amount:.8f}")
        if self.btc_segwit and self.btc_segwit.ok:
            parts.append(f"BTC84={self.btc_segwit.amount:.8f}")
        if not parts:
            return "balances=n/a"
        return " ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        def bal(b: ChainBalance | None) -> dict[str, Any] | None:
            if not b:
                return None
            return {
                "chain": b.chain,
                "address": b.address,
                "symbol": b.symbol,
                "raw": b.raw,
                "amount": b.amount,
                "ok": b.ok,
                "error": b.error,
            }

        return {
            "has_funds": self.has_funds,
            "priority": self.priority,
            "eth": bal(self.eth),
            "usdt_erc20": bal(self.usdt_erc20),
            "btc_legacy": bal(self.btc_legacy),
            "btc_segwit": bal(self.btc_segwit),
            "errors": list(self.errors),
        }


def _httpx():
    try:
        import httpx
    except ImportError as e:
        raise RuntimeError("Install httpx: pip install httpx") from e
    return httpx


def _eth_rpcs() -> list[str]:
    custom = os.environ.get("SEEDLEAK_ETH_RPC")
    if custom:
        return [custom, *DEFAULT_ETH_RPCS]
    return list(DEFAULT_ETH_RPCS)


def _btc_apis() -> list[str]:
    custom = os.environ.get("SEEDLEAK_BTC_API")
    if custom:
        return [custom, *DEFAULT_BTC_APIS]
    return list(DEFAULT_BTC_APIS)


def _eth_rpc_call(method: str, params: list[Any]) -> Any:
    httpx = _httpx()
    last_err: Exception | None = None
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    for url in _eth_rpcs():
        try:
            with httpx.Client(timeout=20.0) as client:
                r = client.post(url, json=payload)
                r.raise_for_status()
                data = r.json()
            if "error" in data and data["error"]:
                last_err = RuntimeError(str(data["error"]))
                continue
            return data.get("result")
        except Exception as e:
            last_err = e
            continue
    raise RuntimeError(f"All ETH RPCs failed: {last_err}")


def eth_balance_wei(address: str) -> int:
    result = _eth_rpc_call("eth_getBalance", [address, "latest"])
    return int(result, 16)


def erc20_balance_raw(token: str, holder: str) -> int:
    """balanceOf(holder) via eth_call."""
    # balanceOf(address) selector 0x70a08231 + address padded to 32 bytes
    holder_clean = holder.lower().removeprefix("0x")
    data = "0x70a08231" + holder_clean.rjust(64, "0")
    result = _eth_rpc_call(
        "eth_call",
        [{"to": token, "data": data}, "latest"],
    )
    if not result or result == "0x":
        return 0
    return int(result, 16)


def btc_balance_sats(address: str) -> int:
    httpx = _httpx()
    last_err: Exception | None = None
    for base in _btc_apis():
        url = f"{base.rstrip('/')}/address/{address}"
        try:
            with httpx.Client(timeout=20.0) as client:
                r = client.get(url)
                r.raise_for_status()
                data = r.json()
            # blockstream/mempool format
            chain = data.get("chain_stats") or {}
            mem = data.get("mempool_stats") or {}
            funded = int(chain.get("funded_txo_sum") or 0) + int(
                mem.get("funded_txo_sum") or 0
            )
            spent = int(chain.get("spent_txo_sum") or 0) + int(
                mem.get("spent_txo_sum") or 0
            )
            return funded - spent
        except Exception as e:
            last_err = e
            continue
    raise RuntimeError(f"All BTC APIs failed: {last_err}")


def check_balances(
    *,
    eth: str,
    btc_legacy: str,
    btc_segwit: str,
    check_usdt: bool = True,
) -> BalanceReport:
    """Query public balances for derived addresses."""
    report = BalanceReport()

    try:
        wei = eth_balance_wei(eth)
        report.eth = ChainBalance(
            chain="ethereum",
            address=eth,
            symbol="ETH",
            raw=wei,
            amount=wei / 1e18,
            ok=True,
        )
    except Exception as e:
        report.errors.append(f"ETH: {e}")
        report.eth = ChainBalance(
            chain="ethereum",
            address=eth,
            symbol="ETH",
            raw=0,
            amount=0.0,
            ok=False,
            error=str(e),
        )

    if check_usdt:
        try:
            raw = erc20_balance_raw(USDT_ERC20, eth)
            report.usdt_erc20 = ChainBalance(
                chain="ethereum",
                address=eth,
                symbol="USDT",
                raw=raw,
                amount=raw / (10**USDT_DECIMALS),
                ok=True,
            )
        except Exception as e:
            report.errors.append(f"USDT: {e}")
            report.usdt_erc20 = ChainBalance(
                chain="ethereum",
                address=eth,
                symbol="USDT",
                raw=0,
                amount=0.0,
                ok=False,
                error=str(e),
            )

    try:
        sats = btc_balance_sats(btc_legacy)
        report.btc_legacy = ChainBalance(
            chain="bitcoin",
            address=btc_legacy,
            symbol="BTC",
            raw=sats,
            amount=sats / 1e8,
            ok=True,
        )
    except Exception as e:
        report.errors.append(f"BTC44: {e}")
        report.btc_legacy = ChainBalance(
            chain="bitcoin",
            address=btc_legacy,
            symbol="BTC",
            raw=0,
            amount=0.0,
            ok=False,
            error=str(e),
        )

    try:
        sats = btc_balance_sats(btc_segwit)
        report.btc_segwit = ChainBalance(
            chain="bitcoin",
            address=btc_segwit,
            symbol="BTC",
            raw=sats,
            amount=sats / 1e8,
            ok=True,
        )
    except Exception as e:
        report.errors.append(f"BTC84: {e}")
        report.btc_segwit = ChainBalance(
            chain="bitcoin",
            address=btc_segwit,
            symbol="BTC",
            raw=0,
            amount=0.0,
            ok=False,
            error=str(e),
        )

    return report
