"""Multi-chain registry for HD derivation + balance probes.

Read-only. Used to estimate exposure severity across common wallets,
not to move funds. Paths follow bip-utils / SLIP-0044 conventions.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable


class Family(str, Enum):
    BIP44 = "bip44"
    BIP84 = "bip84"
    BIP49 = "bip49"


class BalanceKind(str, Enum):
    NONE = "none"  # derive only
    ETH_RPC = "eth_rpc"  # eth_getBalance (+ optional ERC20)
    BTC_API = "btc_api"  # blockstream-style or blockcypher
    TRON = "tron"
    SOLANA = "solana"
    COSMOS = "cosmos"
    XRP = "xrp"
    APTOS = "aptos"
    SUI = "sui"


@dataclass(frozen=True, slots=True)
class ChainSpec:
    id: str
    label: str
    family: Family
    # bip_utils enum member name, e.g. "ETHEREUM", "BITCOIN"
    bip_coin: str
    balance: BalanceKind
    decimals: int = 18
    # For eth_rpc: list of public RPC URLs
    rpcs: tuple[str, ...] = ()
    # ERC-20 / TRC-20 style token contracts for stablecoins (optional)
    tokens: tuple[tuple[str, str, int], ...] = ()  # (symbol, contract, decimals)
    # Cosmos LCD / denom
    cosmos_lcd: str = ""
    cosmos_denom: str = ""
    # BTC-like API bases (blockstream-compatible or handled specially)
    btc_apis: tuple[str, ...] = ()
    # Human path description
    path: str = ""


def _eth_tokens_usdt_usdc() -> tuple[tuple[str, str, int], ...]:
    return (
        ("USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7", 6),
        ("USDC", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 6),
    )


# Public RPCs — best-effort, may rate-limit; override via env later.
_ETH = (
    "https://cloudflare-eth.com",
    "https://ethereum.publicnode.com",
    "https://rpc.ankr.com/eth",
)
_BSC = (
    "https://bsc-dataseed.binance.org",
    "https://bsc.publicnode.com",
)
_POLYGON = (
    "https://polygon-rpc.com",
    "https://polygon.publicnode.com",
)
_AVAX = (
    "https://api.avax.network/ext/bc/C/rpc",
    "https://avalanche.publicnode.com",
)
_ARB = (
    "https://arb1.arbitrum.io/rpc",
    "https://arbitrum.publicnode.com",
)
_OP = (
    "https://mainnet.optimism.io",
    "https://optimism.publicnode.com",
)
_FTM = ("https://rpc.ftm.tools", "https://fantom.publicnode.com")
_BASE = ("https://mainnet.base.org", "https://base.publicnode.com")
_CELO = ("https://forno.celo.org",)
_ETC = ("https://etc.rivet.link", "https://etc.mytokenpocket.vip")

# Core multi-wallet set used by MetaMask / Trust / Exodus / Ledger / Trezor-style paths
CHAIN_SPECS: tuple[ChainSpec, ...] = (
    # --- Bitcoin family ---
    ChainSpec(
        id="btc_legacy",
        label="Bitcoin (BIP44 legacy)",
        family=Family.BIP44,
        bip_coin="BITCOIN",
        balance=BalanceKind.BTC_API,
        decimals=8,
        btc_apis=("https://blockstream.info/api", "https://mempool.space/api"),
        path="m/44'/0'/0'/0/0",
    ),
    ChainSpec(
        id="btc_segwit",
        label="Bitcoin (BIP84 native segwit)",
        family=Family.BIP84,
        bip_coin="BITCOIN",
        balance=BalanceKind.BTC_API,
        decimals=8,
        btc_apis=("https://blockstream.info/api", "https://mempool.space/api"),
        path="m/84'/0'/0'/0/0",
    ),
    ChainSpec(
        id="ltc",
        label="Litecoin",
        family=Family.BIP44,
        bip_coin="LITECOIN",
        balance=BalanceKind.NONE,  # optional later
        decimals=8,
        path="m/44'/2'/0'/0/0",
    ),
    ChainSpec(
        id="doge",
        label="Dogecoin",
        family=Family.BIP44,
        bip_coin="DOGECOIN",
        balance=BalanceKind.NONE,
        decimals=8,
        path="m/44'/3'/0'/0/0",
    ),
    ChainSpec(
        id="bch",
        label="Bitcoin Cash",
        family=Family.BIP44,
        bip_coin="BITCOIN_CASH",
        balance=BalanceKind.NONE,
        decimals=8,
        path="m/44'/145'/0'/0/0",
    ),
    ChainSpec(
        id="dash",
        label="Dash",
        family=Family.BIP44,
        bip_coin="DASH",
        balance=BalanceKind.NONE,
        decimals=8,
        path="m/44'/5'/0'/0/0",
    ),
    # --- EVM family (same style address for many) ---
    ChainSpec(
        id="eth",
        label="Ethereum",
        family=Family.BIP44,
        bip_coin="ETHEREUM",
        balance=BalanceKind.ETH_RPC,
        decimals=18,
        rpcs=_ETH,
        tokens=_eth_tokens_usdt_usdc(),
        path="m/44'/60'/0'/0/0",
    ),
    ChainSpec(
        id="etc",
        label="Ethereum Classic",
        family=Family.BIP44,
        bip_coin="ETHEREUM_CLASSIC",
        balance=BalanceKind.ETH_RPC,
        decimals=18,
        rpcs=_ETC,
        path="m/44'/61'/0'/0/0",
    ),
    ChainSpec(
        id="bsc",
        label="BNB Smart Chain",
        family=Family.BIP44,
        bip_coin="BINANCE_SMART_CHAIN",
        balance=BalanceKind.ETH_RPC,
        decimals=18,
        rpcs=_BSC,
        tokens=(
            ("USDT", "0x55d398326f99059fF775485246999027B3197955", 18),
            ("USDC", "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", 18),
        ),
        path="m/44'/60'/0'/0/0",
    ),
    ChainSpec(
        id="polygon",
        label="Polygon",
        family=Family.BIP44,
        bip_coin="POLYGON",
        balance=BalanceKind.ETH_RPC,
        decimals=18,
        rpcs=_POLYGON,
        tokens=(
            ("USDT", "0xc2132D05D31c914a87C6611C10748AEb04B58e8F", 6),
            ("USDC", "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", 6),
        ),
        path="m/44'/60'/0'/0/0",
    ),
    ChainSpec(
        id="avax_c",
        label="Avalanche C-Chain",
        family=Family.BIP44,
        bip_coin="AVAX_C_CHAIN",
        balance=BalanceKind.ETH_RPC,
        decimals=18,
        rpcs=_AVAX,
        tokens=(
            ("USDT", "0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7", 6),
            ("USDC", "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E", 6),
        ),
        path="m/44'/60'/0'/0/0",
    ),
    ChainSpec(
        id="arbitrum",
        label="Arbitrum One",
        family=Family.BIP44,
        bip_coin="ARBITRUM",
        balance=BalanceKind.ETH_RPC,
        decimals=18,
        rpcs=_ARB,
        tokens=(
            ("USDT", "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", 6),
            ("USDC", "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", 6),
        ),
        path="m/44'/60'/0'/0/0",
    ),
    ChainSpec(
        id="optimism",
        label="Optimism",
        family=Family.BIP44,
        bip_coin="OPTIMISM",
        balance=BalanceKind.ETH_RPC,
        decimals=18,
        rpcs=_OP,
        tokens=(
            ("USDT", "0x94b008aA00579c1307B0EF2c499aD98a8ce58e58", 6),
            ("USDC", "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", 6),
        ),
        path="m/44'/60'/0'/0/0",
    ),
    ChainSpec(
        id="base",
        label="Base",
        family=Family.BIP44,
        bip_coin="OPTIMISM",  # same addr derivation as ETH-style; balance via Base RPC
        balance=BalanceKind.ETH_RPC,
        decimals=18,
        rpcs=_BASE,
        tokens=(("USDC", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", 6),),
        path="m/44'/60'/0'/0/0",
    ),
    ChainSpec(
        id="fantom",
        label="Fantom",
        family=Family.BIP44,
        bip_coin="FANTOM_OPERA",
        balance=BalanceKind.ETH_RPC,
        decimals=18,
        rpcs=_FTM,
        path="m/44'/60'/0'/0/0",
    ),
    ChainSpec(
        id="celo",
        label="Celo",
        family=Family.BIP44,
        bip_coin="CELO",
        balance=BalanceKind.ETH_RPC,
        decimals=18,
        rpcs=_CELO,
        path="m/44'/52752'/0'/0/0",
    ),
    # --- Other major wallets ---
    ChainSpec(
        id="tron",
        label="TRON",
        family=Family.BIP44,
        bip_coin="TRON",
        balance=BalanceKind.TRON,
        decimals=6,
        tokens=(
            # Major TRC-20 stables / commons
            ("USDT", "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", 6),
            ("USDC", "TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8", 6),
            ("TUSD", "TUpMhErZL2fhh4sVNULAbNKLokS4GjC1F4", 18),
            ("USDD", "TPYmHEhy5n8TCEfYGqW2rPxsghSfzghPDn", 18),
            ("USDJ", "TMwFHYXLJaRUPeW6421aqXL4ZEzPRFGkGT", 18),
            ("WTRX", "TNUC9Qb1rRpS5CbWLmNMxXBjyFoydXjWFR", 6),
            ("JST", "TCFLL5dx5ZJdKnWuesXxi1VPwjLVmWZZy9", 18),
            ("SUN", "TSSMHYeV2uE9qYH95DqyoCuNCzEL1NvU3S", 18),
            ("BTT", "TAFjULxiVgT4qWk6UZwjqwZXTSaGaqnVp4", 18),
            ("WIN", "TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7", 6),
            ("NFT", "TFczxzPhnThNSqr5by8tvxsdCFRRz6cPNh", 6),
            ("BTC", "TN3W4H6rK2ce4vX9YnFQHwKENnHjoxb3m9", 8),  # BTC TRC20
            ("ETH", "THb4CqiFdwNHsWsQCs4JhzwjMWys4aqCbF", 18),
        ),
        path="m/44'/195'/0'/0/0",
    ),
    ChainSpec(
        id="sol",
        label="Solana",
        family=Family.BIP44,
        bip_coin="SOLANA",
        balance=BalanceKind.SOLANA,
        decimals=9,
        # SPL mints (symbol, mint, decimals)
        tokens=(
            ("USDT", "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", 6),
            ("USDC", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", 6),
            ("PYUSD", "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo", 6),
            ("EURC", "HzwqbKZw8HxMN6bF2yFZNrht3c2iXXzpKcFu7uBEDKtr", 6),
            ("BONK", "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263", 5),
            ("JUP", "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN", 6),
            ("RAY", "4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R", 6),
            ("WIF", "EKpQGSJtjMFqKZ9KQanSqYXRcF8fBopzLHYxdM65zcjm", 6),
            ("MSOL", "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So", 9),
            ("JITOSOL", "J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn", 9),
        ),
        path="m/44'/501'/0'/0'",
    ),
    ChainSpec(
        id="atom",
        label="Cosmos Hub",
        family=Family.BIP44,
        bip_coin="COSMOS",
        balance=BalanceKind.COSMOS,
        decimals=6,
        cosmos_lcd="https://cosmos-rest.publicnode.com",
        cosmos_denom="uatom",
        path="m/44'/118'/0'/0/0",
    ),
    ChainSpec(
        id="xrp",
        label="XRP Ledger",
        family=Family.BIP44,
        bip_coin="RIPPLE",
        balance=BalanceKind.XRP,
        decimals=6,
        path="m/44'/144'/0'/0/0",
    ),
    ChainSpec(
        id="near",
        label="NEAR",
        family=Family.BIP44,
        bip_coin="NEAR_PROTOCOL",
        balance=BalanceKind.NONE,
        decimals=24,
        path="m/44'/397'/0'",
    ),
    ChainSpec(
        id="aptos",
        label="Aptos",
        family=Family.BIP44,
        bip_coin="APTOS",
        balance=BalanceKind.APTOS,
        decimals=8,
        path="m/44'/637'/0'/0'/0'",
    ),
    ChainSpec(
        id="sui",
        label="Sui",
        family=Family.BIP44,
        bip_coin="SUI",
        balance=BalanceKind.SUI,
        decimals=9,
        path="m/44'/784'/0'/0'/0'",
    ),
    ChainSpec(
        id="dot",
        label="Polkadot",
        family=Family.BIP44,
        bip_coin="POLKADOT_ED25519_SLIP",
        balance=BalanceKind.NONE,
        decimals=10,
        path="m/44'/354'/0'/0'/0'",
    ),
    ChainSpec(
        id="algo",
        label="Algorand",
        family=Family.BIP44,
        bip_coin="ALGORAND",
        balance=BalanceKind.NONE,
        decimals=6,
        path="m/44'/283'/0'/0'/0'",
    ),
    ChainSpec(
        id="fil",
        label="Filecoin",
        family=Family.BIP44,
        bip_coin="FILECOIN",
        balance=BalanceKind.NONE,
        decimals=18,
        path="m/44'/461'/0'/0/0",
    ),
    ChainSpec(
        id="bnb_beacon",
        label="BNB Beacon Chain",
        family=Family.BIP44,
        bip_coin="BINANCE_CHAIN",
        balance=BalanceKind.NONE,
        decimals=8,
        path="m/44'/714'/0'/0/0",
    ),
)


def specs_by_id() -> dict[str, ChainSpec]:
    return {s.id: s for s in CHAIN_SPECS}


def list_chain_ids() -> list[str]:
    return [s.id for s in CHAIN_SPECS]


def resolve_bip_coin(name: str, family: Family = Family.BIP44):
    """Return bip_utils coin enum value by name for the given path family."""
    from bip_utils import Bip44Coins, Bip84Coins

    if family == Family.BIP84:
        if name in Bip84Coins.__members__:
            return Bip84Coins[name]
        raise KeyError(f"Unknown Bip84 coin {name}")
    if name in Bip44Coins.__members__:
        return Bip44Coins[name]
    raise KeyError(f"Unknown Bip44 coin {name}")
