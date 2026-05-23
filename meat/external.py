"""External API integrations: DeFiLlama, Sourcify, Tenderly."""
from __future__ import annotations

import json
import os
import time

import requests

_price_cache: dict[str, dict] = {}
_sig_cache: dict[str, list[str]] = {}


# ---------------------------------------------------------------------------
# DeFiLlama — token prices (free, no auth)
# ---------------------------------------------------------------------------

LLAMA_COINS_BASE = "https://coins.llama.fi"
CHAIN_TO_LLAMA = {
    "ethereum": "ethereum",
    "polygon": "polygon",
    "base": "base",
    "arbitrum": "arbitrum",
    "bsc": "bsc",
    "optimism": "optimism",
}


def get_token_price(chain: str, token_address: str,
                    timestamp: int | None = None) -> dict | None:
    llama_chain = CHAIN_TO_LLAMA.get(chain, chain)
    coin_id = f"{llama_chain}:{token_address.lower()}"

    cache_key = f"{coin_id}:{timestamp or 'current'}"
    if cache_key in _price_cache:
        return _price_cache[cache_key]

    try:
        if timestamp:
            url = f"{LLAMA_COINS_BASE}/prices/historical/{timestamp}/{coin_id}"
        else:
            url = f"{LLAMA_COINS_BASE}/prices/current/{coin_id}"

        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return None

        data = resp.json()
        coins = data.get("coins", {})
        info = coins.get(coin_id)
        if info:
            result = {
                "price_usd": info.get("price"),
                "symbol": info.get("symbol", ""),
                "decimals": info.get("decimals"),
                "timestamp": info.get("timestamp"),
                "confidence": info.get("confidence", 0),
            }
            _price_cache[cache_key] = result
            return result
    except (requests.RequestException, json.JSONDecodeError, KeyError):
        pass

    return None


def get_token_prices_batch(chain: str, token_addresses: list[str],
                           timestamp: int | None = None) -> dict[str, dict]:
    llama_chain = CHAIN_TO_LLAMA.get(chain, chain)
    coins = ",".join(f"{llama_chain}:{addr.lower()}" for addr in token_addresses)

    try:
        if timestamp:
            url = f"{LLAMA_COINS_BASE}/prices/historical/{timestamp}/{coins}"
        else:
            url = f"{LLAMA_COINS_BASE}/prices/current/{coins}"

        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return {}

        data = resp.json()
        result = {}
        for coin_id, info in data.get("coins", {}).items():
            addr = coin_id.split(":")[-1]
            result[addr] = {
                "price_usd": info.get("price"),
                "symbol": info.get("symbol", ""),
                "decimals": info.get("decimals"),
            }
        return result
    except (requests.RequestException, json.JSONDecodeError):
        return {}


# ---------------------------------------------------------------------------
# Sourcify — signature database (free, no auth) + contract verification
# ---------------------------------------------------------------------------

SOURCIFY_SIG_BASE = "https://api.openchain.xyz/signature-database/v1"
SOURCIFY_VERIFY_BASE = "https://sourcify.dev/server"


def lookup_selector_sourcify(selector: str) -> list[str]:
    selector = selector.lower()
    if selector in _sig_cache:
        return _sig_cache[selector]

    try:
        resp = requests.get(
            f"{SOURCIFY_SIG_BASE}/lookup",
            params={"function": selector, "filter": "true"},
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json()
            results_data = data.get("result", {}).get("function", {}).get(selector) or []
            sigs = [r.get("name", "") for r in results_data if isinstance(r, dict) and r.get("name")]
            _sig_cache[selector] = sigs
            return sigs
    except (requests.RequestException, json.JSONDecodeError):
        pass

    # Fallback to 4byte.directory
    try:
        resp = requests.get(
            f"https://www.4byte.directory/api/v1/signatures/?hex_signature={selector}",
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json()
            sigs = [r["text_signature"] for r in data.get("results", [])]
            _sig_cache[selector] = sigs
            return sigs
    except (requests.RequestException, json.JSONDecodeError):
        pass

    return []


def lookup_event_sourcify(topic0: str) -> list[str]:
    topic0 = topic0.lower()
    cache_key = f"event:{topic0}"
    if cache_key in _sig_cache:
        return _sig_cache[cache_key]

    try:
        resp = requests.get(
            f"{SOURCIFY_SIG_BASE}/lookup",
            params={"event": topic0, "filter": "true"},
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json()
            results_data = data.get("result", {}).get("event", {}).get(topic0) or []
            sigs = [r.get("name", "") for r in results_data if isinstance(r, dict) and r.get("name")]
            _sig_cache[cache_key] = sigs
            return sigs
    except (requests.RequestException, json.JSONDecodeError):
        pass

    return []


def get_sourcify_source(chain_id: int, address: str) -> dict | None:
    try:
        resp = requests.get(
            f"{SOURCIFY_VERIFY_BASE}/files/any/{chain_id}/{address}",
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            files = data.get("files", []) if isinstance(data, dict) else data
            if files:
                return {"files": files, "status": data.get("status", "unknown")}
    except (requests.RequestException, json.JSONDecodeError):
        pass
    return None


def get_sourcify_abi(chain_id: int, address: str) -> list | None:
    source = get_sourcify_source(chain_id, address)
    if not source:
        return None
    for f in source.get("files", []):
        name = f.get("name", "")
        if name == "metadata.json":
            try:
                metadata = json.loads(f.get("content", "{}"))
                output = metadata.get("output", {})
                abi = output.get("abi")
                if abi:
                    return abi
            except json.JSONDecodeError:
                pass
    return None


# ---------------------------------------------------------------------------
# Tenderly — transaction simulation & traces (free tier: 60 sims/min)
# ---------------------------------------------------------------------------

TENDERLY_API_BASE = "https://api.tenderly.co/api/v1"


def tenderly_trace_transaction(chain_id: int, tx_hash: str) -> dict | None:
    access_key = os.environ.get("TENDERLY_ACCESS_KEY")
    account = os.environ.get("TENDERLY_ACCOUNT")
    project = os.environ.get("TENDERLY_PROJECT")

    if not all([access_key, account, project]):
        return None

    network_id = str(chain_id)

    try:
        url = f"{TENDERLY_API_BASE}/account/{account}/project/{project}/simulate"
        headers = {"X-Access-Key": access_key, "Content-Type": "application/json"}

        resp = requests.get(
            f"https://api.tenderly.co/api/v1/public-contract/{network_id}/trace/{tx_hash}",
            headers=headers,
            timeout=30,
        )

        if resp.status_code == 200:
            data = resp.json()
            return {
                "method": "tenderly",
                "call_trace": data.get("call_trace"),
                "logs": data.get("logs"),
                "state_diff": data.get("state_diff"),
                "asset_changes": data.get("asset_changes"),
            }
    except (requests.RequestException, json.JSONDecodeError):
        pass

    try:
        url = f"{TENDERLY_API_BASE}/account/{account}/project/{project}/trace/{tx_hash}"
        headers = {"X-Access-Key": access_key}
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "method": "tenderly",
                "trace": data,
            }
    except (requests.RequestException, json.JSONDecodeError):
        pass

    return None
