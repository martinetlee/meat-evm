from __future__ import annotations

import json
import re

import requests
from eth_abi import decode as abi_decode
from eth_utils import keccak


TRANSFER_TOPIC = "0x" + keccak(text="Transfer(address,address,uint256)").hex()
APPROVAL_TOPIC = "0x" + keccak(text="Approval(address,address,uint256)").hex()
WETH_DEPOSIT_TOPIC = "0x" + keccak(text="Deposit(address,uint256)").hex()
WETH_WITHDRAWAL_TOPIC = "0x" + keccak(text="Withdrawal(address,uint256)").hex()

_selector_cache: dict[str, list[str]] = {}
_token_info_cache: dict[str, dict | None] = {}


def compute_selector(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


def _parse_abi_functions(abi: list[dict]) -> dict[str, dict]:
    funcs = {}
    for item in abi:
        if item.get("type") not in ("function", None):
            continue
        name = item.get("name", "")
        if not name:
            continue
        inputs = item.get("inputs", [])
        type_str = ",".join(_abi_input_type(inp) for inp in inputs)
        sig = f"{name}({type_str})"
        selector = compute_selector(sig)
        funcs[selector] = {
            "name": name,
            "signature": sig,
            "inputs": inputs,
            "input_types": [_abi_input_type(inp) for inp in inputs],
        }
    return funcs


def _parse_abi_events(abi: list[dict]) -> dict[str, dict]:
    events = {}
    for item in abi:
        if item.get("type") != "event":
            continue
        name = item.get("name", "")
        inputs = item.get("inputs", [])
        type_str = ",".join(_abi_input_type(inp) for inp in inputs)
        sig = f"{name}({type_str})"
        topic = "0x" + keccak(text=sig).hex()
        indexed = [inp for inp in inputs if inp.get("indexed")]
        non_indexed = [inp for inp in inputs if not inp.get("indexed")]
        events[topic] = {
            "name": name,
            "signature": sig,
            "inputs": inputs,
            "indexed": indexed,
            "non_indexed": non_indexed,
        }
    return events


def _abi_input_type(inp: dict) -> str:
    t = inp.get("type", "")
    if t == "tuple":
        components = inp.get("components", [])
        inner = ",".join(_abi_input_type(c) for c in components)
        return f"({inner})"
    if t.startswith("tuple["):
        components = inp.get("components", [])
        inner = ",".join(_abi_input_type(c) for c in components)
        suffix = t[5:]
        return f"({inner}){suffix}"
    return t


def decode_function_input(abi: list[dict], calldata: str) -> dict | None:
    if not calldata or calldata == "0x" or len(calldata) < 10:
        return None

    selector = calldata[:10].lower()
    funcs = _parse_abi_functions(abi)

    func = funcs.get(selector)
    if not func:
        return None

    data_bytes = bytes.fromhex(calldata[10:])
    if not func["input_types"]:
        return {"function": func["name"], "signature": func["signature"], "params": {}}

    try:
        decoded = abi_decode(func["input_types"], data_bytes)
    except Exception:
        return {"function": func["name"], "signature": func["signature"], "params": None, "error": "decode_failed"}

    params = {}
    for i, inp in enumerate(func["inputs"]):
        val = decoded[i]
        params[inp.get("name", f"param_{i}")] = _format_decoded_value(val, inp.get("type", ""))

    return {"function": func["name"], "signature": func["signature"], "params": params}


def decode_log(abi: list[dict], log: dict) -> dict | None:
    topics = log.get("topics", [])
    if not topics:
        return None

    topic0 = topics[0].lower() if topics[0] else None
    if not topic0:
        return None

    events = _parse_abi_events(abi)
    event = events.get(topic0)
    if not event:
        return None

    params = {}

    topic_idx = 1
    for inp in event["indexed"]:
        if topic_idx < len(topics):
            raw = topics[topic_idx]
            params[inp["name"]] = _decode_topic(raw, inp["type"])
            topic_idx += 1

    if event["non_indexed"]:
        data_hex = log.get("data", "0x")
        if data_hex and data_hex != "0x":
            data_bytes = bytes.fromhex(data_hex[2:])
            types = [_abi_input_type(inp) for inp in event["non_indexed"]]
            try:
                decoded = abi_decode(types, data_bytes)
                for i, inp in enumerate(event["non_indexed"]):
                    params[inp["name"]] = _format_decoded_value(decoded[i], inp.get("type", ""))
            except Exception:
                pass

    return {"event": event["name"], "signature": event["signature"], "params": params}


def decode_erc20_transfer(log: dict) -> dict | None:
    topics = log.get("topics", [])
    if not topics or len(topics) < 3:
        return None

    if topics[0].lower() != TRANSFER_TOPIC:
        return None

    from_addr = "0x" + topics[1][-40:]
    to_addr = "0x" + topics[2][-40:]

    data = log.get("data", "0x")
    if data and data != "0x":
        try:
            (amount,) = abi_decode(["uint256"], bytes.fromhex(data[2:]))
        except Exception:
            amount = 0
    else:
        amount = 0

    return {
        "type": "transfer",
        "from": from_addr,
        "to": to_addr,
        "amount_raw": str(amount),
        "token_address": log.get("address", ""),
    }


def decode_approval(log: dict) -> dict | None:
    topics = log.get("topics", [])
    if not topics or len(topics) < 3:
        return None
    if topics[0].lower() != APPROVAL_TOPIC:
        return None

    owner = "0x" + topics[1][-40:]
    spender = "0x" + topics[2][-40:]

    data = log.get("data", "0x")
    if data and data != "0x":
        try:
            (amount,) = abi_decode(["uint256"], bytes.fromhex(data[2:]))
        except Exception:
            amount = 0
    else:
        amount = 0

    return {
        "type": "approval",
        "owner": owner,
        "spender": spender,
        "amount_raw": str(amount),
        "token_address": log.get("address", ""),
    }


def decode_weth_event(log: dict) -> dict | None:
    topics = log.get("topics", [])
    if not topics or len(topics) < 2:
        return None

    topic0 = topics[0].lower()
    token_address = log.get("address", "")

    if topic0 == WETH_DEPOSIT_TOPIC:
        dst = "0x" + topics[1][-40:]
        data = log.get("data", "0x")
        try:
            (amount,) = abi_decode(["uint256"], bytes.fromhex(data[2:]))
        except Exception:
            amount = 0
        return {
            "type": "weth_deposit",
            "from": dst,
            "to": token_address,
            "amount_raw": str(amount),
            "token_address": token_address,
            "note": "ETH wrapped to WETH",
        }

    if topic0 == WETH_WITHDRAWAL_TOPIC:
        src = "0x" + topics[1][-40:]
        data = log.get("data", "0x")
        try:
            (amount,) = abi_decode(["uint256"], bytes.fromhex(data[2:]))
        except Exception:
            amount = 0
        return {
            "type": "weth_withdrawal",
            "from": token_address,
            "to": src,
            "amount_raw": str(amount),
            "token_address": token_address,
            "note": "WETH unwrapped to ETH",
        }

    return None


def resolve_token_info(token_address: str, rpc_or_explorer) -> dict | None:
    addr_lower = token_address.lower()
    if addr_lower in _token_info_cache:
        return _token_info_cache[addr_lower]

    info = None
    from meat.rpc import RPCClient
    from meat.explorer import ExplorerClient

    if isinstance(rpc_or_explorer, RPCClient):
        try:
            name_hex = rpc_or_explorer.eth_call({"to": token_address, "data": "0x06fdde03"})
            symbol_hex = rpc_or_explorer.eth_call({"to": token_address, "data": "0x95d89b41"})
            decimals_hex = rpc_or_explorer.eth_call({"to": token_address, "data": "0x313ce567"})
            if symbol_hex and symbol_hex != "0x":
                from meat.classify import _decode_string
                info = {
                    "name": _decode_string(name_hex),
                    "symbol": _decode_string(symbol_hex),
                    "decimals": int(decimals_hex, 16) if decimals_hex and decimals_hex != "0x" else 18,
                }
        except Exception:
            pass

    if info is None and isinstance(rpc_or_explorer, ExplorerClient):
        try:
            source = rpc_or_explorer.get_source_code(token_address)
            if source and source.get("ContractName"):
                info = {"name": source["ContractName"], "symbol": source["ContractName"], "decimals": 18}
        except Exception:
            pass

    _token_info_cache[addr_lower] = info
    return info


def lookup_selector(selector: str) -> list[str]:
    selector = selector.lower()
    if selector in _selector_cache:
        return _selector_cache[selector]

    from meat.external import lookup_selector_sourcify
    results = lookup_selector_sourcify(selector)
    if results:
        _selector_cache[selector] = results
        return results

    return []


def format_value(raw: int | str, decimals: int) -> str:
    if isinstance(raw, str):
        raw = int(raw)
    if decimals == 0:
        return str(raw)
    whole = raw // (10 ** decimals)
    frac = raw % (10 ** decimals)
    frac_str = str(frac).zfill(decimals).rstrip("0") or "0"
    if len(frac_str) > 6:
        frac_str = frac_str[:6]
    return f"{whole}.{frac_str}"


def _format_decoded_value(val, type_str: str):
    if isinstance(val, bytes):
        return "0x" + val.hex()
    if isinstance(val, int) and "int" in type_str:
        if "address" in type_str or val > 10**15:
            return str(val)
        return val
    if isinstance(val, tuple):
        return [_format_decoded_value(v, "") for v in val]
    if isinstance(val, list):
        return [_format_decoded_value(v, "") for v in val]
    return val


def _decode_topic(raw: str, type_str: str) -> str:
    if type_str == "address":
        return "0x" + raw[-40:]
    if "int" in type_str:
        return str(int(raw, 16))
    return raw
