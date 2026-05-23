"""Unit tests for input parsing — no API calls needed."""
from __future__ import annotations
from meat.parse import parse_single, parse_batch


def test_parse_bare_tx_hash():
    r = parse_single("0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d")
    assert r.type == "tx_hash"
    assert r.value == "0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d"
    assert r.chain is None
    assert r.source == "raw"


def test_parse_bare_address():
    r = parse_single("0x27182842e098f60e3d576794a5bffb0777e025d3")
    assert r.type == "address"
    assert r.value == "0x27182842e098f60e3d576794a5bffb0777e025d3"


def test_parse_etherscan_tx_url():
    r = parse_single("https://etherscan.io/tx/0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d")
    assert r.type == "tx_hash"
    assert r.chain == "ethereum"
    assert r.source == "url"


def test_parse_polygonscan_address_url():
    r = parse_single("https://polygonscan.com/address/0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174")
    assert r.type == "address"
    assert r.chain == "polygon"


def test_parse_basescan_url():
    r = parse_single("https://basescan.org/tx/0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    assert r.type == "tx_hash"
    assert r.chain == "base"


def test_parse_unknown_input():
    r = parse_single("hello world")
    assert r.type == "unknown"


def test_parse_batch_mixed():
    raw = """Check these:
    https://etherscan.io/tx/0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d
    The attacker is 0xDEAD000000000000000000000000000000000000
    and also look at 0xBEEF000000000000000000000000000000000000"""
    results = parse_batch(raw)
    assert len(results) == 3
    types = [r.type for r in results]
    assert "tx_hash" in types
    assert types.count("address") == 2


def test_parse_batch_deduplication():
    raw = "0xDEAD000000000000000000000000000000000000 0xDEAD000000000000000000000000000000000000"
    results = parse_batch(raw)
    assert len(results) == 1


def test_parse_batch_noisy_markdown():
    raw = "**Attacker**: `0xDEAD000000000000000000000000000000000000` [link](https://etherscan.io/tx/0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)"
    results = parse_batch(raw)
    assert len(results) >= 1
    values = [r.value for r in results]
    assert "0xDEAD000000000000000000000000000000000000" in values
