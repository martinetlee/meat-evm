"""Tests for environment-based chain configuration."""

import pytest

from meat.config import ChainConfig, Config


@pytest.fixture
def chain():
    return ChainConfig(
        name="arbitrum",
        chain_id=42161,
        rpc_env="ARBITRUM_RPC_URL",
        explorer_api_env="ARBISCAN_API_KEY",
        explorer_base="https://api.etherscan.io/v2/api",
        explorer_url="https://arbiscan.io",
        native_token="ETH",
        alchemy_network="arb-mainnet",
    )


def test_explicit_rpc_url_takes_precedence(monkeypatch, chain):
    monkeypatch.setenv("ARBITRUM_RPC_URL", " https://rpc.example.test/arbitrum ")
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-key")

    assert chain.rpc_url == "https://rpc.example.test/arbitrum"


def test_alchemy_key_builds_chain_rpc_url(monkeypatch, chain):
    monkeypatch.delenv("ARBITRUM_RPC_URL", raising=False)
    monkeypatch.setenv("ALCHEMY_API_KEY", " alchemy-key ")

    assert chain.rpc_url == "https://arb-mainnet.g.alchemy.com/v2/alchemy-key"
    assert chain.has_rpc() is True


def test_blank_explicit_url_falls_back_to_alchemy(monkeypatch, chain):
    monkeypatch.setenv("ARBITRUM_RPC_URL", "   ")
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-key")

    assert chain.rpc_url == "https://arb-mainnet.g.alchemy.com/v2/alchemy-key"


@pytest.mark.parametrize("alchemy_key", [None, "", "   "])
def test_missing_alchemy_key_leaves_rpc_unconfigured(monkeypatch, chain, alchemy_key):
    monkeypatch.delenv("ARBITRUM_RPC_URL", raising=False)
    if alchemy_key is None:
        monkeypatch.delenv("ALCHEMY_API_KEY", raising=False)
    else:
        monkeypatch.setenv("ALCHEMY_API_KEY", alchemy_key)

    assert chain.rpc_url is None
    assert chain.has_rpc() is False


def test_all_configured_chains_have_alchemy_fallback(monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "shared-key")
    for rpc_env in (
        "ETH_RPC_URL",
        "POLYGON_RPC_URL",
        "BASE_RPC_URL",
        "ARBITRUM_RPC_URL",
        "BSC_RPC_URL",
        "OPTIMISM_RPC_URL",
    ):
        # Keep load_dotenv from restoring values from the developer's local .env.
        monkeypatch.setenv(rpc_env, " ")

    config = Config()
    expected = {
        "ethereum": "eth-mainnet",
        "polygon": "polygon-mainnet",
        "base": "base-mainnet",
        "arbitrum": "arb-mainnet",
        "bsc": "bnb-mainnet",
        "optimism": "opt-mainnet",
    }

    assert {
        name: chain.rpc_url
        for name, chain in config.all_chains().items()
    } == {
        name: f"https://{network}.g.alchemy.com/v2/shared-key"
        for name, network in expected.items()
    }
