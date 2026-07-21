"""BIP39 mnemonic detection and validation (multi-language).

Finds candidate sequences in free text, validates against BIP39 wordlists
and checksum. Never persists the mnemonic — callers fingerprint and drop.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from pathlib import Path

VALID_LENGTHS = (12, 15, 18, 21, 24)

_LENGTH_META = {
    12: (128, 4),
    15: (160, 5),
    18: (192, 6),
    21: (224, 7),
    24: (256, 8),
}

# Bundled language → filename under seedleak/data/
LANGUAGES: dict[str, str] = {
    "english": "bip39_english.txt",
    "chinese_simplified": "bip39_chinese_simplified.txt",
    "chinese_traditional": "bip39_chinese_traditional.txt",
    "czech": "bip39_czech.txt",
    "french": "bip39_french.txt",
    "italian": "bip39_italian.txt",
    "japanese": "bip39_japanese.txt",
    "korean": "bip39_korean.txt",
    "portuguese": "bip39_portuguese.txt",
    "spanish": "bip39_spanish.txt",
}

# CJK single-character wordlists need character-level tokenization.
_CJK_LANGS = frozenset({"chinese_simplified", "chinese_traditional"})

# Letters including common Latin diacritics used in FR/ES/PT/IT/CS wordlists.
_LATIN_WORD_RE = re.compile(
    r"[A-Za-z"
    r"\u00C0-\u024F"  # Latin extended
    r"\u1E00-\u1EFF"  # Latin extended additional
    r"]+"
)

# Japanese / Korean: sequences of letters/syllables (no pure punctuation).
_CJK_SCRIPT_WORD_RE = re.compile(
    r"["
    r"\u3040-\u30FF"  # Hiragana + Katakana
    r"\u4E00-\u9FFF"  # CJK unified
    r"\uAC00-\uD7AF"  # Hangul syllables
    r"\u1100-\u11FF"  # Hangul jamo
    r"A-Za-z"
    r"]+"
)


@dataclass(frozen=True, slots=True)
class Finding:
    """A detected BIP39 mnemonic candidate (plaintext kept only in-memory)."""

    words: tuple[str, ...]
    word_count: int
    start_offset: int
    end_offset: int
    checksum_valid: bool
    is_denylisted: bool
    context_preview: str
    language: str = "english"

    @property
    def normalized(self) -> str:
        return " ".join(self.words)

    @property
    def is_alert(self) -> bool:
        return self.checksum_valid and not self.is_denylisted


def _read_wordlist_file(filename: str) -> str:
    try:
        pkg = resources.files("seedleak")
        candidate = pkg.joinpath("data", filename)
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    except (TypeError, FileNotFoundError, ModuleNotFoundError, AttributeError):
        pass

    here = Path(__file__).resolve()
    for base in (
        here.parents[1] / "data",
        here.parents[3] / "data",
        Path.cwd() / "data",
        Path.cwd() / "src" / "seedleak" / "data",
    ):
        p = base / filename
        if p.is_file():
            return p.read_text(encoding="utf-8")

    raise FileNotFoundError(f"BIP39 wordlist not found: {filename}")


@lru_cache(maxsize=32)
def load_wordlist(language: str = "english") -> tuple[tuple[str, ...], dict[str, int]]:
    """Load a BIP39 wordlist. Returns (words_tuple, word→index)."""
    lang = language.lower().replace("-", "_")
    if lang not in LANGUAGES:
        raise ValueError(f"Unknown language {language!r}. Known: {sorted(LANGUAGES)}")
    raw = _read_wordlist_file(LANGUAGES[lang])
    words = tuple(line.strip().lower() for line in raw.splitlines() if line.strip())
    if len(words) != 2048:
        raise ValueError(f"Expected 2048 BIP39 words for {lang}, got {len(words)}")
    # Japanese wordlist may use full-width spaces in sources; normalize NFKC-ish
    index = {w: i for i, w in enumerate(words)}
    return words, index


def load_wordlist_path(path: str) -> tuple[tuple[str, ...], dict[str, int]]:
    raw = Path(path).read_text(encoding="utf-8")
    words = tuple(line.strip().lower() for line in raw.splitlines() if line.strip())
    if len(words) != 2048:
        raise ValueError(f"Expected 2048 BIP39 words, got {len(words)} in {path}")
    return words, {w: i for i, w in enumerate(words)}


def validate_checksum(
    words: list[str] | tuple[str, ...],
    word_index: dict[str, int],
) -> bool:
    """Return True if words form a BIP39 mnemonic with a valid checksum."""
    n = len(words)
    if n not in _LENGTH_META:
        return False
    try:
        indices = [word_index[w] for w in words]
    except KeyError:
        return False

    entropy_bits, checksum_bits = _LENGTH_META[n]
    bits = 0
    for idx in indices:
        bits = (bits << 11) | idx

    shift = checksum_bits
    entropy_int = bits >> shift
    checksum = bits & ((1 << shift) - 1)

    entropy_bytes = entropy_int.to_bytes(entropy_bits // 8, "big")
    h = hashlib.sha256(entropy_bytes).digest()
    expected = h[0] >> (8 - checksum_bits)
    return checksum == expected


def mnemonic_from_entropy(
    entropy: bytes,
    language: str = "english",
    wordlist: tuple[str, ...] | None = None,
) -> str:
    """Build a BIP39 mnemonic from entropy (16/20/24/28/32 bytes)."""
    if wordlist is None:
        wordlist, _ = load_wordlist(language)
    ent_bits = len(entropy) * 8
    if ent_bits not in (128, 160, 192, 224, 256):
        raise ValueError("entropy must be 16–32 bytes (multiples of 4)")
    cs_bits = ent_bits // 32
    h = hashlib.sha256(entropy).digest()
    ent_int = int.from_bytes(entropy, "big")
    checksum = h[0] >> (8 - cs_bits)
    bits = (ent_int << cs_bits) | checksum
    total = (ent_bits + cs_bits) // 11
    out = []
    for i in range(total - 1, -1, -1):
        idx = (bits >> (i * 11)) & 0x7FF
        out.append(wordlist[idx])
    return " ".join(out)


def _redact_preview(text: str, start: int, end: int, window: int = 40) -> str:
    left = text[max(0, start - window) : start]
    right = text[end : min(len(text), end + window)]
    left = left.replace("\n", " ").strip()
    right = right.replace("\n", " ").strip()
    return f"…{left}[REDACTED_MNEMONIC]{right}…"


def _tokenize_latin(text: str) -> list[tuple[str, int, int]]:
    return [(m.group(0).lower(), m.start(), m.end()) for m in _LATIN_WORD_RE.finditer(text)]


def _tokenize_cjk_chars(text: str, word_index: dict[str, int]) -> list[tuple[str, int, int]]:
    """Each character that is a BIP39 word becomes a token (Chinese lists)."""
    tokens: list[tuple[str, int, int]] = []
    for i, ch in enumerate(text):
        low = ch.lower()
        if low in word_index:
            tokens.append((low, i, i + 1))
    return tokens


def _tokenize_script_words(text: str) -> list[tuple[str, int, int]]:
    return [
        (m.group(0).lower(), m.start(), m.end())
        for m in _CJK_SCRIPT_WORD_RE.finditer(text)
    ]


def _tokens_for_language(
    text: str,
    language: str,
    word_index: dict[str, int],
) -> list[tuple[str, int, int]]:
    if language in _CJK_LANGS:
        return _tokenize_cjk_chars(text, word_index)
    if language in ("japanese", "korean"):
        return _tokenize_script_words(text)
    return _tokenize_latin(text)


def _scan_with_wordlist(
    text: str,
    *,
    language: str,
    word_index: dict[str, int],
    denylist: set[str],
    require_checksum: bool,
) -> list[Finding]:
    tokens = _tokens_for_language(text, language, word_index)
    if len(tokens) < min(VALID_LENGTHS):
        return []

    findings: list[Finding] = []
    seen_spans: set[tuple[int, int]] = set()

    for length in sorted(VALID_LENGTHS, reverse=True):
        if len(tokens) < length:
            continue
        for i in range(0, len(tokens) - length + 1):
            chunk = tokens[i : i + length]
            words = tuple(t[0] for t in chunk)
            if any(w not in word_index for w in words):
                continue

            # For non-CJK: require tokens to be "near" each other (not pages apart).
            start = chunk[0][1]
            end = chunk[-1][2]
            if language not in _CJK_LANGS:
                # Allow up to ~3 chars average gap (spaces/punct); reject if span huge.
                max_span = length * 24
                if end - start > max_span:
                    continue
                # Require roughly contiguous: gaps between consecutive tokens small.
                gaps_ok = True
                for a, b in zip(chunk, chunk[1:]):
                    if b[1] - a[2] > 8:
                        gaps_ok = False
                        break
                if not gaps_ok:
                    continue

            span = (start, end)
            if span in seen_spans:
                continue
            if any(s <= start and end <= e for s, e in seen_spans):
                continue

            ok = validate_checksum(words, word_index)
            if require_checksum and not ok:
                continue

            normalized = " ".join(words)
            is_denied = normalized in denylist
            findings.append(
                Finding(
                    words=words,
                    word_count=length,
                    start_offset=start,
                    end_offset=end,
                    checksum_valid=ok,
                    is_denylisted=is_denied,
                    context_preview=_redact_preview(text, start, end),
                    language=language,
                )
            )
            seen_spans.add(span)

    findings.sort(key=lambda f: f.start_offset)
    return findings


def scan_text(
    text: str,
    *,
    languages: list[str] | None = None,
    wordlist_path: str | None = None,
    denylist: set[str] | None = None,
    require_checksum: bool = True,
) -> list[Finding]:
    """Scan free text for BIP39 mnemonic candidates across languages."""
    denylist = denylist or set()
    all_findings: list[Finding] = []

    if wordlist_path:
        _, word_index = load_wordlist_path(wordlist_path)
        all_findings.extend(
            _scan_with_wordlist(
                text,
                language="custom",
                word_index=word_index,
                denylist=denylist,
                require_checksum=require_checksum,
            )
        )
        return all_findings

    langs = languages or ["english"]
    for lang in langs:
        _, word_index = load_wordlist(lang)
        all_findings.extend(
            _scan_with_wordlist(
                text,
                language=lang,
                word_index=word_index,
                denylist=denylist,
                require_checksum=require_checksum,
            )
        )

    # Dedupe overlapping same span (prefer english if same offsets + words)
    all_findings.sort(key=lambda f: (f.start_offset, f.end_offset, f.language))
    deduped: list[Finding] = []
    seen: set[tuple[int, int, str]] = set()
    for f in all_findings:
        key = (f.start_offset, f.end_offset, f.normalized)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    return deduped


def scan_file(
    path: Path | str,
    *,
    languages: list[str] | None = None,
    wordlist_path: str | None = None,
    denylist: set[str] | None = None,
    max_bytes: int = 5_000_000,
) -> list[Finding]:
    """Scan a single file. Skips binary / oversized files."""
    p = Path(path)
    try:
        if p.stat().st_size > max_bytes:
            return []
        raw = p.read_bytes()
    except OSError:
        return []

    if b"\x00" in raw[:8192]:
        return []
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("latin-1")
        except UnicodeDecodeError:
            return []

    return scan_text(
        text,
        languages=languages,
        wordlist_path=wordlist_path,
        denylist=denylist,
    )


def default_languages(all_langs: bool = False) -> list[str]:
    if all_langs:
        return list(LANGUAGES.keys())
    return ["english"]
