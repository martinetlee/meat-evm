"""Integration tests against live APIs. Validates against known exploits.

These tests make real API calls and verify that MEAT produces correct results
for well-known historical transactions. They serve as both regression tests
and documentation of how the tool handles real exploits.

Run with: pytest tests/test_integration.py -v --timeout=60
Skip with: pytest tests/ -k "not integration"
"""
from __future__ import annotations
import json
import subprocess
import os

import pytest
from dotenv import load_dotenv
from pathlib import Path

load_dotenv(Path(__file__).parent.parent / ".env")

EULER_HACK_TX = "0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d"
EULER_ATTACKER_EOA = "0x5f259d0b76665c337c6104145894f4d1d2758b8c"
EULER_ATTACKER_CONTRACT = "0xebc29199c817dc47ba12e3f86102564d640cbf99"
EULER_VICTIM = "0x27182842e098f60e3d576794a5bffb0777e025d3"
BINANCE_14 = "0x28c6c06298d514db089934071355e5743bf21d60"
DAI_ADDRESS = "0x6b175474e89094c44da98b954eedeac495271d0f"

pytestmark = pytest.mark.skipif(
    not os.environ.get("ETHERSCAN_API_KEY"),
    reason="ETHERSCAN_API_KEY not set"
)


def _run(args: list[str], timeout: int = 45) -> dict:
    env = os.environ.copy()
    result = subprocess.run(
        ["python3", "-m", "meat"] + args,
        capture_output=True, text=True, timeout=timeout, env=env,
    )
    if result.returncode != 0:
        pytest.fail(f"Command failed: {result.stderr}")
    return json.loads(result.stdout)


class TestEulerHack:
    """Euler Finance hack, March 13 2023. Flash loan + donation attack on eToken.
    Attacker: 0x5f259d0b (EOA) → 0xebc29199 (exploit contract)
    Victim: 0x27182842 (Euler proxy)
    ~$200M DAI stolen in this single transaction.
    """

    def test_parse_euler_url(self):
        data = _run(["parse", f"https://etherscan.io/tx/{EULER_HACK_TX}"])
        assert len(data) == 1
        assert data[0]["type"] == "tx_hash"
        assert data[0]["chain"] == "ethereum"
        assert data[0]["value"] == EULER_HACK_TX

    def test_tx_basic_fields(self):
        data = _run(["tx", EULER_HACK_TX, "--chain", "ethereum", "--compact"])
        assert data["hash"] == EULER_HACK_TX
        assert data["status"] == "success"
        assert data["from"] == EULER_ATTACKER_EOA
        assert data["to"] == EULER_ATTACKER_CONTRACT
        assert data["value_formatted"] == "0.0 ETH"
        assert data["transfer_count"] == 20

    def test_tx_has_meta(self):
        data = _run(["tx", EULER_HACK_TX, "--chain", "ethereum", "--compact"])
        assert "_meta" in data
        assert "data_sources" in data["_meta"]
        assert len(data["_meta"]["data_sources"]) > 0

    def test_tx_net_flows_contain_dai(self):
        data = _run(["tx", EULER_HACK_TX, "--chain", "ethereum", "--compact"])
        net = data.get("net_flows", {})
        dai_flows = {}
        for addr, flows in net.items():
            for token, val in flows.items():
                if "Dai" in token or "dai" in token.lower():
                    dai_flows[addr] = val
        assert len(dai_flows) > 0, "Should find DAI movements in Euler hack"

    def test_classify_attacker_eoa(self):
        data = _run(["classify", EULER_ATTACKER_EOA, "--chain", "ethereum"])
        assert data["type"] == "eoa"
        assert data["is_contract"] is False

    def test_classify_euler_proxy(self):
        data = _run(["classify", EULER_VICTIM, "--chain", "ethereum"])
        assert data["type"] == "contract"
        assert data["is_verified"] is True
        assert data["is_proxy"] is True
        assert "Euler" in str(data["labels"])

    def test_classify_binance_known_entity(self):
        data = _run(["classify", BINANCE_14, "--chain", "ethereum"])
        assert data["type"] == "eoa"
        assert data["known_entity"] is not None
        assert data["known_entity"]["category"] == "cex"
        assert "Binance" in data["known_entity"]["label"]

    def test_quick_euler(self):
        data = _run(["quick", EULER_HACK_TX, "--chain", "ethereum"], timeout=60)
        assert data["status"] == "success"
        assert data["transfer_count"] == 20
        assert "_meta" in data
        assert "elapsed_seconds" in data["_meta"]
        assert "addresses" in data
        assert EULER_ATTACKER_EOA in data["addresses"]
        assert data["addresses"][EULER_ATTACKER_EOA]["type"] == "eoa"


class TestParseEdgeCases:
    """Parse command edge cases — these don't need API calls."""

    def test_parse_multiple_chains(self):
        data = _run(["parse",
            "https://etherscan.io/tx/0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "https://polygonscan.com/address/0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        ])
        chains = [d.get("chain") for d in data]
        assert "ethereum" in chains
        assert "polygon" in chains

    def test_parse_noisy_telegram(self):
        data = _run(["parse",
            "🚨 EXPLOIT ALERT: tx 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa on ETH"
        ])
        assert any(d["type"] == "tx_hash" for d in data)
