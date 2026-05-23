from __future__ import annotations

import json
import sys
from itertools import count

import requests


class RPCError(Exception):
    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message
        super().__init__(f"RPC error {code}: {message}")


class RPCClient:
    _id_counter = count(1)

    def __init__(self, url: str, timeout: int = 30):
        self.url = url
        self.timeout = timeout
        self.is_alchemy = "alchemy.com" in url.lower()
        self._session = requests.Session()
        self._session.headers["Content-Type"] = "application/json"

    def _call(self, method: str, params: list | None = None) -> dict | str | list | None:
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or [],
            "id": next(self._id_counter),
        }

        try:
            resp = self._session.post(self.url, json=payload, timeout=self.timeout)
            resp.raise_for_status()
        except requests.ConnectionError as e:
            raise RPCError(-1, f"Connection failed: {e}")
        except requests.Timeout:
            raise RPCError(-2, f"Request timed out after {self.timeout}s")
        except requests.HTTPError as e:
            raise RPCError(-3, f"HTTP error: {e}")

        try:
            data = resp.json()
        except json.JSONDecodeError:
            raise RPCError(-4, f"Invalid JSON response: {resp.text[:200]}")

        if "error" in data and data["error"]:
            err = data["error"]
            raise RPCError(err.get("code", -1), err.get("message", str(err)))

        return data.get("result")

    def get_transaction(self, tx_hash: str) -> dict | None:
        return self._call("eth_getTransactionByHash", [tx_hash])

    def get_transaction_receipt(self, tx_hash: str) -> dict | None:
        return self._call("eth_getTransactionReceipt", [tx_hash])

    def get_code(self, address: str, block: str = "latest") -> str:
        return self._call("eth_getCode", [address, block])

    def get_storage_at(self, address: str, slot: str, block: str = "latest") -> str:
        return self._call("eth_getStorageAt", [address, slot, block])

    def eth_call(self, tx: dict, block: str = "latest") -> str:
        return self._call("eth_call", [tx, block])

    def get_block_number(self) -> int:
        result = self._call("eth_blockNumber")
        return int(result, 16)

    def get_block(self, block: str | int, full_txs: bool = False) -> dict | None:
        if isinstance(block, int):
            block = hex(block)
        return self._call("eth_getBlockByNumber", [block, full_txs])

    def debug_trace_transaction(self, tx_hash: str, tracer: str = "callTracer") -> dict | None:
        return self._call("debug_traceTransaction", [tx_hash, {"tracer": tracer}])

    def trace_transaction(self, tx_hash: str) -> list | None:
        return self._call("trace_transaction", [tx_hash])

    # --- Alchemy enhanced APIs ---

    def alchemy_get_asset_transfers(self, from_address: str | None = None,
                                     to_address: str | None = None,
                                     from_block: str = "0x0",
                                     to_block: str = "latest",
                                     category: list[str] | None = None,
                                     max_count: str = "0x64",
                                     order: str = "asc",
                                     page_key: str | None = None,
                                     with_metadata: bool = True) -> dict | None:
        if not self.is_alchemy:
            return None
        params = {
            "fromBlock": from_block,
            "toBlock": to_block,
            "category": category or ["external", "internal", "erc20", "erc721", "erc1155"],
            "withMetadata": with_metadata,
            "excludeZeroValue": True,
            "maxCount": max_count,
            "order": order,
        }
        if from_address:
            params["fromAddress"] = from_address
        if to_address:
            params["toAddress"] = to_address
        if page_key:
            params["pageKey"] = page_key
        return self._call("alchemy_getAssetTransfers", [params])

    def alchemy_get_token_balances(self, address: str,
                                    token_type: str = "erc20") -> dict | None:
        if not self.is_alchemy:
            return None
        return self._call("alchemy_getTokenBalances", [address, token_type])

    def alchemy_simulate_asset_changes(self, tx: dict) -> dict | None:
        if not self.is_alchemy:
            return None
        return self._call("alchemy_simulateAssetChanges", [tx])
