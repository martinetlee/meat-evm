from __future__ import annotations

import re
import sys
from dataclasses import dataclass, asdict
from urllib.parse import urlparse

from meat.config import get_config

TX_HASH_RE = re.compile(r"0x[0-9a-fA-F]{64}")
ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
NOISE_RE = re.compile(r"[\[\](){}<>`\"'*_~|]")


@dataclass
class ParsedInput:
    type: str  # "tx_hash", "address", "unknown"
    value: str
    chain: str | None = None
    source: str = "raw"  # "raw", "url"

    def to_dict(self) -> dict:
        return asdict(self)


def _clean_text(raw: str) -> list[str]:
    cleaned = NOISE_RE.sub(" ", raw)
    tokens = cleaned.split()
    return [t.strip(",;") for t in tokens if t.strip(",;")]


def _parse_url(url: str) -> ParsedInput | None:
    try:
        parsed = urlparse(url)
    except Exception:
        return None

    if not parsed.scheme or not parsed.netloc:
        return None

    config = get_config()
    chain = config.detect_chain_from_url(url)
    path = parsed.path.rstrip("/")

    if "/tx/" in path:
        parts = path.split("/tx/")
        if len(parts) == 2:
            tx_hash = parts[1].split("/")[0].split("?")[0].split("#")[0]
            if TX_HASH_RE.fullmatch(tx_hash):
                return ParsedInput(type="tx_hash", value=tx_hash.lower(), chain=chain, source="url")

    if "/address/" in path:
        parts = path.split("/address/")
        if len(parts) == 2:
            addr = parts[1].split("/")[0].split("?")[0].split("#")[0]
            if ADDRESS_RE.fullmatch(addr):
                return ParsedInput(type="address", value=addr, chain=chain, source="url")

    if "/token/" in path:
        parts = path.split("/token/")
        if len(parts) == 2:
            addr = parts[1].split("/")[0].split("?")[0].split("#")[0]
            if ADDRESS_RE.fullmatch(addr):
                return ParsedInput(type="address", value=addr, chain=chain, source="url")

    return None


def parse_single(raw: str) -> ParsedInput:
    raw = raw.strip()

    url_result = _parse_url(raw)
    if url_result:
        return url_result

    if TX_HASH_RE.fullmatch(raw):
        return ParsedInput(type="tx_hash", value=raw.lower())

    if ADDRESS_RE.fullmatch(raw):
        return ParsedInput(type="address", value=raw)

    return ParsedInput(type="unknown", value=raw)


def parse_batch(raw: str) -> list[ParsedInput]:
    results = []
    seen = set()

    tokens = _clean_text(raw)
    i = 0
    while i < len(tokens):
        token = tokens[i]

        if token.startswith("http://") or token.startswith("https://"):
            result = _parse_url(token)
            if result and result.value not in seen:
                results.append(result)
                seen.add(result.value)
                i += 1
                continue

        tx_match = TX_HASH_RE.search(token)
        if tx_match:
            value = tx_match.group().lower()
            if value not in seen:
                results.append(ParsedInput(type="tx_hash", value=value))
                seen.add(value)
            i += 1
            continue

        addr_match = ADDRESS_RE.search(token)
        if addr_match:
            value = addr_match.group()
            if value not in seen:
                results.append(ParsedInput(type="address", value=value))
                seen.add(value)
            i += 1
            continue

        i += 1

    if not results and raw.strip():
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            for match in TX_HASH_RE.finditer(line):
                value = match.group().lower()
                if value not in seen:
                    results.append(ParsedInput(type="tx_hash", value=value))
                    seen.add(value)
            for match in ADDRESS_RE.finditer(line):
                value = match.group()
                if value not in seen:
                    results.append(ParsedInput(type="address", value=value))
                    seen.add(value)

    return results


def parse_stdin() -> list[ParsedInput]:
    if sys.stdin.isatty():
        return []
    raw = sys.stdin.read()
    return parse_batch(raw)
