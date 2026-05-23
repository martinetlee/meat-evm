from __future__ import annotations

import time

import requests


class ExplorerError(Exception):
    pass


class RateLimitError(ExplorerError):
    pass


class RateLimiter:
    def __init__(self, rate: float = 5.0):
        self.rate = rate
        self.tokens = rate
        self.last = time.monotonic()

    def wait(self):
        now = time.monotonic()
        elapsed = now - self.last
        self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
        if self.tokens < 1:
            sleep_time = (1 - self.tokens) / self.rate
            time.sleep(sleep_time)
            self.tokens = 0
        else:
            self.tokens -= 1
        self.last = time.monotonic()


class ExplorerClient:
    def __init__(self, base_url: str, api_key: str | None = None,
                 rate_limiter: RateLimiter | None = None, chain_id: int | None = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.chain_id = chain_id
        self.rate_limiter = rate_limiter or RateLimiter()
        self._session = requests.Session()

    def _request(self, params: dict, timeout: int = 30, _retries: int = 3) -> dict:
        if self.api_key:
            params["apikey"] = self.api_key
        if self.chain_id is not None:
            params["chainid"] = self.chain_id

        for attempt in range(_retries):
            self.rate_limiter.wait()

            try:
                resp = self._session.get(self.base_url, params=params, timeout=timeout)
                resp.raise_for_status()
            except requests.ConnectionError as e:
                raise ExplorerError(f"Connection failed: {e}")
            except requests.Timeout:
                raise ExplorerError(f"Request timed out after {timeout}s")
            except requests.HTTPError as e:
                if e.response is not None and e.response.status_code == 429:
                    if attempt < _retries - 1:
                        time.sleep(1)
                        continue
                    raise RateLimitError("Rate limited by explorer API")
                raise ExplorerError(f"HTTP error: {e}")

            data = resp.json()

            if data.get("status") == "0" and data.get("message") not in ("No transactions found", "No records found", None):
                result = data.get("result", "")
                if "rate limit" in str(result).lower() or "Max rate limit" in str(result):
                    if attempt < _retries - 1:
                        time.sleep(1)
                        continue
                    raise RateLimitError(f"Rate limited: {result}")
                if "Invalid API Key" in str(result):
                    raise ExplorerError(f"Invalid API key: {result}")
                if isinstance(result, str) and "deprecated" in result.lower():
                    raise ExplorerError(f"API deprecated: {result}")

            return data

        raise ExplorerError("Max retries exceeded")

    # --- Proxy methods (RPC via explorer) ---

    def proxy_get_transaction(self, tx_hash: str) -> dict | None:
        data = self._request({
            "module": "proxy",
            "action": "eth_getTransactionByHash",
            "txhash": tx_hash,
        })
        return data.get("result")

    def proxy_get_receipt(self, tx_hash: str) -> dict | None:
        data = self._request({
            "module": "proxy",
            "action": "eth_getTransactionReceipt",
            "txhash": tx_hash,
        })
        return data.get("result")

    def proxy_get_code(self, address: str, block: str = "latest") -> str:
        params = {
            "module": "proxy",
            "action": "eth_getCode",
            "address": address,
            "tag": block,
        }
        data = self._request(params)
        return data.get("result", "0x")

    # --- Contract methods ---

    def get_source_code(self, address: str) -> dict:
        data = self._request({
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
        })
        results = data.get("result", [])
        if isinstance(results, list) and results:
            return results[0]
        return {}

    def get_abi(self, address: str) -> str:
        data = self._request({
            "module": "contract",
            "action": "getabi",
            "address": address,
        })
        result = data.get("result", "")
        if data.get("status") == "0":
            return ""
        return result

    def get_contract_creation(self, addresses: list[str]) -> list[dict]:
        data = self._request({
            "module": "contract",
            "action": "getcontractcreation",
            "contractaddresses": ",".join(addresses),
        })
        result = data.get("result")
        if isinstance(result, list):
            return result
        return []

    # --- Account methods ---

    def get_tx_list(self, address: str, start_block: int = 0, end_block: int = 99999999,
                    page: int = 1, offset: int = 50, sort: str = "desc") -> list[dict]:
        data = self._request({
            "module": "account",
            "action": "txlist",
            "address": address,
            "startblock": start_block,
            "endblock": end_block,
            "page": page,
            "offset": offset,
            "sort": sort,
        })
        result = data.get("result")
        if isinstance(result, list):
            return result
        return []

    def get_internal_tx_list(self, address: str, start_block: int = 0, end_block: int = 99999999,
                             page: int = 1, offset: int = 50, sort: str = "desc") -> list[dict]:
        data = self._request({
            "module": "account",
            "action": "txlistinternal",
            "address": address,
            "startblock": start_block,
            "endblock": end_block,
            "page": page,
            "offset": offset,
            "sort": sort,
        })
        result = data.get("result")
        if isinstance(result, list):
            return result
        return []

    def get_token_transfers(self, address: str | None = None, contract: str | None = None,
                            start_block: int = 0, end_block: int = 99999999,
                            page: int = 1, offset: int = 100, sort: str = "desc") -> list[dict]:
        params = {
            "module": "account",
            "action": "tokentx",
            "startblock": start_block,
            "endblock": end_block,
            "page": page,
            "offset": offset,
            "sort": sort,
        }
        if address:
            params["address"] = address
        if contract:
            params["contractaddress"] = contract

        data = self._request(params)
        result = data.get("result")
        if isinstance(result, list):
            return result
        return []

    def get_internal_txs_by_hash(self, tx_hash: str) -> list[dict]:
        data = self._request({
            "module": "account",
            "action": "txlistinternal",
            "txhash": tx_hash,
        })
        result = data.get("result")
        if isinstance(result, list):
            return result
        return []

    def get_token_transfers_by_hash(self, tx_hash: str) -> list[dict]:
        """Not directly supported by all explorers; use get_token_transfers with block range."""
        return []

    def get_logs(self, address: str | None = None,
                 topic0: str | None = None, topic1: str | None = None,
                 topic2: str | None = None, topic3: str | None = None,
                 from_block: int = 0, to_block: int = 99999999,
                 page: int = 1, offset: int = 1000) -> list[dict]:
        params = {
            "module": "logs",
            "action": "getLogs",
            "fromBlock": from_block,
            "toBlock": to_block,
            "page": page,
            "offset": offset,
        }
        if address:
            params["address"] = address
        if topic0:
            params["topic0"] = topic0
        if topic1:
            params["topic1"] = topic1
            params["topic0_1_opr"] = "and"
        if topic2:
            params["topic2"] = topic2
            params["topic0_2_opr"] = "and"
            if topic1:
                params["topic1_2_opr"] = "and"
        if topic3:
            params["topic3"] = topic3
            params["topic0_3_opr"] = "and"

        data = self._request(params)
        result = data.get("result")
        if isinstance(result, list):
            return result
        return []

    def proxy_get_storage_at(self, address: str, slot: str, block: str = "latest") -> str:
        data = self._request({
            "module": "proxy",
            "action": "eth_getStorageAt",
            "address": address,
            "position": slot,
            "tag": block if block == "latest" else hex(int(block)) if block.isdigit() else block,
        })
        return data.get("result", "0x")

    def get_balance(self, address: str) -> int:
        data = self._request({
            "module": "account",
            "action": "balance",
            "address": address,
            "tag": "latest",
        })
        result = data.get("result", "0")
        try:
            return int(result)
        except (ValueError, TypeError):
            return 0
