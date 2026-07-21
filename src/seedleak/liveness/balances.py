"""Public read-only multi-chain balance lookups (no signing, no transfers)."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

from seedleak.liveness.chains import CHAIN_SPECS, BalanceKind, ChainSpec, specs_by_id
from seedleak.liveness.derive import DerivedWallet


@dataclass
class ChainBalance:
    chain_id: str
    label: str
    address: str
    symbol: str
    raw: int
    amount: float
    ok: bool
    error: str | None = None
    kind: str = "native"  # native | token


@dataclass
class BalanceReport:
    items: list[ChainBalance] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def has_funds(self) -> bool:
        return any(b.ok and b.raw > 0 for b in self.items)

    @property
    def funded_chains(self) -> list[str]:
        return sorted({b.chain_id for b in self.items if b.ok and b.raw > 0})

    @property
    def priority(self) -> str:
        if self.has_funds:
            return "critical"
        if self.errors:
            return "medium"
        return "low"

    def summary_line(self, max_parts: int = 8) -> str:
        funded = [b for b in self.items if b.ok and b.raw > 0]
        if funded:
            parts = [f"{b.symbol}@{b.chain_id}={b.amount:g}" for b in funded[:max_parts]]
            more = len(funded) - len(parts)
            s = " ".join(parts)
            if more > 0:
                s += f" +{more}more"
            return s
        ok_n = sum(1 for b in self.items if b.ok)
        return f"checked={ok_n} funded=0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "has_funds": self.has_funds,
            "priority": self.priority,
            "funded_chains": self.funded_chains,
            "items": [
                {
                    "chain_id": b.chain_id,
                    "label": b.label,
                    "address": b.address,
                    "symbol": b.symbol,
                    "raw": b.raw,
                    "amount": b.amount,
                    "ok": b.ok,
                    "error": b.error,
                    "kind": b.kind,
                }
                for b in self.items
            ],
            "errors": list(self.errors),
        }

    # Back-compat attributes for old CLI/tests
    @property
    def eth(self) -> ChainBalance | None:
        return next((b for b in self.items if b.chain_id == "eth" and b.symbol == "ETH"), None)

    @property
    def usdt_erc20(self) -> ChainBalance | None:
        return next(
            (b for b in self.items if b.chain_id == "eth" and b.symbol == "USDT"), None
        )

    @property
    def btc_legacy(self) -> ChainBalance | None:
        return next((b for b in self.items if b.chain_id == "btc_legacy"), None)

    @property
    def btc_segwit(self) -> ChainBalance | None:
        return next((b for b in self.items if b.chain_id == "btc_segwit"), None)


def _httpx():
    try:
        import httpx
    except ImportError as e:
        raise RuntimeError("Install httpx") from e
    return httpx


def _rpc_list(spec: ChainSpec) -> list[str]:
    env_key = f"SEEDLEAK_RPC_{spec.id.upper()}"
    custom = os.environ.get(env_key) or os.environ.get("SEEDLEAK_ETH_RPC")
    out = list(spec.rpcs)
    if custom and spec.balance == BalanceKind.ETH_RPC:
        out = [custom, *out]
    return out


def _eth_rpc_call(rpcs: list[str], method: str, params: list[Any]) -> Any:
    httpx = _httpx()
    last_err: Exception | None = None
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    for url in rpcs:
        try:
            with httpx.Client(timeout=15.0) as client:
                r = client.post(url, json=payload)
                r.raise_for_status()
                data = r.json()
            if data.get("error"):
                last_err = RuntimeError(str(data["error"]))
                continue
            return data.get("result")
        except Exception as e:
            last_err = e
            continue
    raise RuntimeError(f"RPC failed: {last_err}")


def _check_eth_rpc(spec: ChainSpec, address: str) -> list[ChainBalance]:
    rpcs = _rpc_list(spec)
    out: list[ChainBalance] = []
    try:
        result = _eth_rpc_call(rpcs, "eth_getBalance", [address, "latest"])
        wei = int(result, 16)
        symbol = {
            "eth": "ETH",
            "bsc": "BNB",
            "polygon": "MATIC",
            "avax_c": "AVAX",
            "arbitrum": "ETH",
            "optimism": "ETH",
            "base": "ETH",
            "fantom": "FTM",
            "celo": "CELO",
            "etc": "ETC",
        }.get(spec.id, "NATIVE")
        out.append(
            ChainBalance(
                chain_id=spec.id,
                label=spec.label,
                address=address,
                symbol=symbol,
                raw=wei,
                amount=wei / (10**spec.decimals),
                ok=True,
                kind="native",
            )
        )
    except Exception as e:
        out.append(
            ChainBalance(
                chain_id=spec.id,
                label=spec.label,
                address=address,
                symbol="NATIVE",
                raw=0,
                amount=0.0,
                ok=False,
                error=str(e),
            )
        )
        return out

    for symbol, contract, decimals in spec.tokens:
        try:
            holder = address.lower().removeprefix("0x")
            data = "0x70a08231" + holder.rjust(64, "0")
            result = _eth_rpc_call(
                rpcs, "eth_call", [{"to": contract, "data": data}, "latest"]
            )
            raw = int(result, 16) if result and result != "0x" else 0
            out.append(
                ChainBalance(
                    chain_id=spec.id,
                    label=f"{spec.label} {symbol}",
                    address=address,
                    symbol=symbol,
                    raw=raw,
                    amount=raw / (10**decimals),
                    ok=True,
                    kind="token",
                )
            )
        except Exception as e:
            out.append(
                ChainBalance(
                    chain_id=spec.id,
                    label=f"{spec.label} {symbol}",
                    address=address,
                    symbol=symbol,
                    raw=0,
                    amount=0.0,
                    ok=False,
                    error=str(e),
                    kind="token",
                )
            )
    return out


def _check_btc_api(spec: ChainSpec, address: str) -> list[ChainBalance]:
    httpx = _httpx()
    apis = list(spec.btc_apis)
    custom = os.environ.get("SEEDLEAK_BTC_API")
    if custom:
        apis = [custom, *apis]
    last_err: Exception | None = None
    for base in apis:
        url = f"{base.rstrip('/')}/address/{address}"
        try:
            with httpx.Client(timeout=15.0) as client:
                r = client.get(url)
                r.raise_for_status()
                data = r.json()
            chain = data.get("chain_stats") or {}
            mem = data.get("mempool_stats") or {}
            funded = int(chain.get("funded_txo_sum") or 0) + int(
                mem.get("funded_txo_sum") or 0
            )
            spent = int(chain.get("spent_txo_sum") or 0) + int(
                mem.get("spent_txo_sum") or 0
            )
            sats = funded - spent
            return [
                ChainBalance(
                    chain_id=spec.id,
                    label=spec.label,
                    address=address,
                    symbol="BTC",
                    raw=sats,
                    amount=sats / 1e8,
                    ok=True,
                )
            ]
        except Exception as e:
            last_err = e
            continue
    return [
        ChainBalance(
            chain_id=spec.id,
            label=spec.label,
            address=address,
            symbol="BTC",
            raw=0,
            amount=0.0,
            ok=False,
            error=str(last_err),
        )
    ]


def _check_tron(spec: ChainSpec, address: str) -> list[ChainBalance]:
    httpx = _httpx()
    out: list[ChainBalance] = []
    base = os.environ.get("SEEDLEAK_TRON_API", "https://api.trongrid.io")
    try:
        with httpx.Client(timeout=15.0) as client:
            r = client.get(f"{base.rstrip('/')}/v1/accounts/{address}")
            r.raise_for_status()
            data = r.json()
        acc = (data.get("data") or [{}])[0] if data.get("data") else {}
        # balance in sun (1 TRX = 1e6 sun)
        sun = int(acc.get("balance") or 0)
        out.append(
            ChainBalance(
                chain_id=spec.id,
                label=spec.label,
                address=address,
                symbol="TRX",
                raw=sun,
                amount=sun / 1e6,
                ok=True,
            )
        )
        # TRC-20
        trc20 = acc.get("trc20") or []
        token_map = {c: (sym, dec) for sym, c, dec in spec.tokens}
        if isinstance(trc20, list):
            for entry in trc20:
                if not isinstance(entry, dict):
                    continue
                for contract, raw_s in entry.items():
                    if contract in token_map:
                        sym, dec = token_map[contract]
                        raw = int(raw_s)
                        out.append(
                            ChainBalance(
                                chain_id=spec.id,
                                label=f"TRON {sym}",
                                address=address,
                                symbol=sym,
                                raw=raw,
                                amount=raw / (10**dec),
                                ok=True,
                                kind="token",
                            )
                        )
    except Exception as e:
        out.append(
            ChainBalance(
                chain_id=spec.id,
                label=spec.label,
                address=address,
                symbol="TRX",
                raw=0,
                amount=0.0,
                ok=False,
                error=str(e),
            )
        )
    return out


def _check_solana(spec: ChainSpec, address: str) -> list[ChainBalance]:
    httpx = _httpx()
    rpc = os.environ.get("SEEDLEAK_SOL_RPC", "https://api.mainnet-beta.solana.com")
    try:
        with httpx.Client(timeout=15.0) as client:
            r = client.post(
                rpc,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "getBalance",
                    "params": [address],
                },
            )
            r.raise_for_status()
            data = r.json()
        if data.get("error"):
            raise RuntimeError(str(data["error"]))
        lamports = int((data.get("result") or {}).get("value") or 0)
        return [
            ChainBalance(
                chain_id=spec.id,
                label=spec.label,
                address=address,
                symbol="SOL",
                raw=lamports,
                amount=lamports / 1e9,
                ok=True,
            )
        ]
    except Exception as e:
        return [
            ChainBalance(
                chain_id=spec.id,
                label=spec.label,
                address=address,
                symbol="SOL",
                raw=0,
                amount=0.0,
                ok=False,
                error=str(e),
            )
        ]


def _check_cosmos(spec: ChainSpec, address: str) -> list[ChainBalance]:
    httpx = _httpx()
    lcd = spec.cosmos_lcd.rstrip("/")
    try:
        with httpx.Client(timeout=15.0) as client:
            r = client.get(f"{lcd}/cosmos/bank/v1beta1/balances/{address}")
            r.raise_for_status()
            data = r.json()
        balances = data.get("balances") or []
        raw = 0
        for b in balances:
            if b.get("denom") == spec.cosmos_denom:
                raw = int(b.get("amount") or 0)
                break
        return [
            ChainBalance(
                chain_id=spec.id,
                label=spec.label,
                address=address,
                symbol="ATOM",
                raw=raw,
                amount=raw / (10**spec.decimals),
                ok=True,
            )
        ]
    except Exception as e:
        return [
            ChainBalance(
                chain_id=spec.id,
                label=spec.label,
                address=address,
                symbol="ATOM",
                raw=0,
                amount=0.0,
                ok=False,
                error=str(e),
            )
        ]


def _check_xrp(spec: ChainSpec, address: str) -> list[ChainBalance]:
    httpx = _httpx()
    url = os.environ.get("SEEDLEAK_XRP_RPC", "https://xrplcluster.com")
    try:
        with httpx.Client(timeout=15.0) as client:
            r = client.post(
                url,
                json={
                    "method": "account_info",
                    "params": [{"account": address, "ledger_index": "validated"}],
                },
            )
            r.raise_for_status()
            data = r.json()
        result = data.get("result") or {}
        if result.get("status") == "error":
            # actNotFound = zero
            if result.get("error") == "actNotFound":
                drops = 0
            else:
                raise RuntimeError(result.get("error_message") or result.get("error"))
        else:
            drops = int((result.get("account_data") or {}).get("Balance") or 0)
        return [
            ChainBalance(
                chain_id=spec.id,
                label=spec.label,
                address=address,
                symbol="XRP",
                raw=drops,
                amount=drops / 1e6,
                ok=True,
            )
        ]
    except Exception as e:
        return [
            ChainBalance(
                chain_id=spec.id,
                label=spec.label,
                address=address,
                symbol="XRP",
                raw=0,
                amount=0.0,
                ok=False,
                error=str(e),
            )
        ]


def _check_aptos(spec: ChainSpec, address: str) -> list[ChainBalance]:
    httpx = _httpx()
    base = os.environ.get("SEEDLEAK_APTOS_API", "https://fullnode.mainnet.aptoslabs.com")
    try:
        # Ensure 0x prefix
        addr = address if address.startswith("0x") else f"0x{address}"
        with httpx.Client(timeout=15.0) as client:
            r = client.get(f"{base.rstrip('/')}/v1/accounts/{addr}/resource/0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>")
            if r.status_code == 404:
                raw = 0
            else:
                r.raise_for_status()
                data = r.json()
                raw = int(((data.get("data") or {}).get("coin") or {}).get("value") or 0)
        return [
            ChainBalance(
                chain_id=spec.id,
                label=spec.label,
                address=addr,
                symbol="APT",
                raw=raw,
                amount=raw / 1e8,
                ok=True,
            )
        ]
    except Exception as e:
        return [
            ChainBalance(
                chain_id=spec.id,
                label=spec.label,
                address=address,
                symbol="APT",
                raw=0,
                amount=0.0,
                ok=False,
                error=str(e),
            )
        ]


def _check_sui(spec: ChainSpec, address: str) -> list[ChainBalance]:
    httpx = _httpx()
    rpc = os.environ.get("SEEDLEAK_SUI_RPC", "https://fullnode.mainnet.sui.io:443")
    try:
        with httpx.Client(timeout=15.0) as client:
            r = client.post(
                rpc,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "suix_getBalance",
                    "params": [address],
                },
            )
            r.raise_for_status()
            data = r.json()
        if data.get("error"):
            raise RuntimeError(str(data["error"]))
        total = int((data.get("result") or {}).get("totalBalance") or 0)
        return [
            ChainBalance(
                chain_id=spec.id,
                label=spec.label,
                address=address,
                symbol="SUI",
                raw=total,
                amount=total / 1e9,
                ok=True,
            )
        ]
    except Exception as e:
        return [
            ChainBalance(
                chain_id=spec.id,
                label=spec.label,
                address=address,
                symbol="SUI",
                raw=0,
                amount=0.0,
                ok=False,
                error=str(e),
            )
        ]


def _probe(spec: ChainSpec, address: str) -> list[ChainBalance]:
    if spec.balance == BalanceKind.ETH_RPC:
        return _check_eth_rpc(spec, address)
    if spec.balance == BalanceKind.BTC_API:
        return _check_btc_api(spec, address)
    if spec.balance == BalanceKind.TRON:
        return _check_tron(spec, address)
    if spec.balance == BalanceKind.SOLANA:
        return _check_solana(spec, address)
    if spec.balance == BalanceKind.COSMOS:
        return _check_cosmos(spec, address)
    if spec.balance == BalanceKind.XRP:
        return _check_xrp(spec, address)
    if spec.balance == BalanceKind.APTOS:
        return _check_aptos(spec, address)
    if spec.balance == BalanceKind.SUI:
        return _check_sui(spec, address)
    # derive-only chains
    return []


def check_balances(
    wallet: DerivedWallet | None = None,
    *,
    eth: str | None = None,
    btc_legacy: str | None = None,
    btc_segwit: str | None = None,
    check_usdt: bool = True,
    max_workers: int = 12,
) -> BalanceReport:
    """Query public balances for derived addresses (parallel).

    Accepts either a DerivedWallet or legacy eth/btc kwargs.
    """
    report = BalanceReport()
    by_id = wallet.by_id() if wallet else {}

    # Legacy kwargs
    if eth and "eth" not in by_id:
        from seedleak.liveness.derive import AddressEntry

        by_id["eth"] = AddressEntry("eth", "Ethereum", eth, "", "bip44")
    if btc_legacy and "btc_legacy" not in by_id:
        from seedleak.liveness.derive import AddressEntry

        by_id["btc_legacy"] = AddressEntry(
            "btc_legacy", "Bitcoin legacy", btc_legacy, "", "bip44"
        )
    if btc_segwit and "btc_segwit" not in by_id:
        from seedleak.liveness.derive import AddressEntry

        by_id["btc_segwit"] = AddressEntry(
            "btc_segwit", "Bitcoin segwit", btc_segwit, "", "bip84"
        )

    specs = specs_by_id()
    jobs: list[tuple[ChainSpec, str]] = []
    for chain_id, entry in by_id.items():
        spec = specs.get(chain_id)
        if not spec or spec.balance == BalanceKind.NONE:
            continue
        if not check_usdt:
            # still check native; tokens filtered inside by empty tokens — clone not needed
            pass
        jobs.append((spec, entry.address))

    if not jobs:
        report.errors.append("no balance-capable addresses")
        return report

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futs = {pool.submit(_probe, spec, addr): spec.id for spec, addr in jobs}
        for fut in as_completed(futs):
            cid = futs[fut]
            try:
                items = fut.result()
                if not check_usdt:
                    items = [i for i in items if i.kind != "token"]
                report.items.extend(items)
                for i in items:
                    if not i.ok and i.error:
                        report.errors.append(f"{cid}/{i.symbol}: {i.error}")
            except Exception as e:
                report.errors.append(f"{cid}: {e}")

    # Stable sort
    report.items.sort(key=lambda b: (0 if b.raw > 0 else 1, b.chain_id, b.symbol))
    return report


# Back-compat function signature used in tests
def eth_balance_wei(address: str) -> int:
    spec = specs_by_id()["eth"]
    result = _eth_rpc_call(_rpc_list(spec), "eth_getBalance", [address, "latest"])
    return int(result, 16)
