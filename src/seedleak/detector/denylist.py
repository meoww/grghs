"""Known public / test BIP39 mnemonics that must never generate alerts.

These appear in docs, BIP vectors, Hardhat, MetaMask tests, etc.
Store only normalized lowercase space-joined phrases.
"""

from __future__ import annotations

# Well-known test vectors and tutorial seeds (public, zero/low value).
DEFAULT_DENYLIST: frozenset[str] = frozenset(
    {
        # BIP39 all-zero entropy (very common in tests)
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        # 24-word all-zero
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        # BIP39 TREZOR test vectors
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        "all hour make first leader extend simple mechanical into captivate soft wear splash with night machine manual pomp regular depend race wilderness spike unveil",
        # Hardhat / ethers sample
        "test test test test test test test test test test test junk",
        # MetaMask / docs frequently used
        "bottom drive obey lake curtain smoke basket hold race lonely fit walk",
        # iancoleman bip39 online tool examples
        "witch collapse practice feed shame open despair creek road again ice least",
        # Another widely copied tutorial seed (empty/low funds demos)
        "army van defense carry jealous true garbage claim echo media make crunch",
        "outside twice turtle salon dramatic april fluid scare distance introduction settle upset",
        # Ganache / truffle classic
        "candy maple cake sugar pudding cream honey rich smooth crumble sweet treat",
        # OpenZeppelin / various docs
        "myth like bonus scare over problem client lizard pioneer submit female collect",
        # BIP39 multi-lang zero entropy often translated — english already covered
    }
)


def load_denylist(extra_paths: list[str] | None = None) -> set[str]:
    """Return denylist set, optionally extended from newline-delimited files."""
    out: set[str] = set(DEFAULT_DENYLIST)
    for path in extra_paths or []:
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip().lower()
                    if not line or line.startswith("#"):
                        continue
                    out.add(" ".join(line.split()))
        except OSError:
            continue
    return out
