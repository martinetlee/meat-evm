from __future__ import annotations

import json
import os
import sys

import click

from meat.config import get_config, ChainConfig
from meat.parse import parse_single, parse_batch, parse_stdin
from meat.rpc import RPCClient, RPCError
from meat.explorer import ExplorerClient, ExplorerError, RateLimiter
from meat.decode import (
    decode_function_input, decode_erc20_transfer, decode_log,
    decode_approval, decode_weth_event, resolve_token_info,
    lookup_selector, format_value,
)
from meat.evidence import EvidenceStore
from meat.classify import classify_address


class Meta:
    """Collects metadata about a CLI command's execution."""
    def __init__(self):
        self.data_sources: list[str] = []
        self.evidence_paths: list[str] = []
        self.warnings: list[str] = []
        self.enrichment_failures: list[str] = []

    def to_dict(self) -> dict:
        d = {}
        if self.data_sources:
            d["data_sources"] = self.data_sources
        if self.evidence_paths:
            d["evidence_saved"] = self.evidence_paths
        if self.warnings:
            d["warnings"] = self.warnings
        if self.enrichment_failures:
            d["enrichment_failures"] = self.enrichment_failures
        return d


def _output(data, file=sys.stdout):
    json.dump(data, file, indent=2, default=str)
    file.write("\n")


def _error(msg: str):
    click.echo(json.dumps({"error": msg}), err=True)
    sys.exit(1)


def _resolve_chain(chain: str | None) -> str | None:
    if chain:
        return chain
    return os.environ.get("MEAT_CHAIN")


def _resolve_case(case: str | None) -> str | None:
    if case:
        return case
    return os.environ.get("MEAT_CASE")


def _get_chain_config(chain: str | None) -> ChainConfig:
    config = get_config()
    chain = _resolve_chain(chain)
    if not chain:
        _error("--chain is required (or set MEAT_CHAIN env var). Available: " + ", ".join(sorted(config.all_chains().keys())))
    try:
        return config.get_chain(chain)
    except ValueError as e:
        _error(str(e))


def _get_rpc(chain_cfg: ChainConfig) -> RPCClient | None:
    if chain_cfg.has_rpc():
        return RPCClient(chain_cfg.rpc_url)
    return None


def _get_explorer(chain_cfg: ChainConfig) -> ExplorerClient | None:
    if chain_cfg.has_explorer():
        limiter = RateLimiter(get_config().rate_limit)
        return ExplorerClient(chain_cfg.explorer_base, chain_cfg.explorer_api_key, limiter, chain_cfg.chain_id)
    return None


def _get_evidence(case: str | None) -> EvidenceStore | None:
    case = _resolve_case(case)
    if not case:
        return None
    config = get_config()
    case_dir = config.cases_dir / case
    return EvidenceStore(case_dir)


@click.group()
def cli():
    """MEAT-EVM: Martinet's Exploit Analysis Tool for EVM"""
    pass


@cli.command()
@click.argument("inputs", nargs=-1)
def parse(inputs):
    """Parse transaction hashes, addresses, or block explorer URLs."""
    if inputs:
        raw = " ".join(inputs)
    else:
        if sys.stdin.isatty():
            _error("Provide input as arguments or pipe via stdin")
        raw = sys.stdin.read()

    results = parse_batch(raw)
    if not results:
        single = parse_single(raw.strip())
        results = [single]

    _output([r.to_dict() for r in results])


@cli.command()
@click.argument("input_str")
@click.option("--chain", "-c", help="Chain name (auto-detected from URLs)")
@click.option("--case", help="Case name for evidence storage (or set MEAT_CASE)")
def quick(input_str, chain, case):
    """One-shot analysis: tx hash or URL → full decoded summary in one command."""
    import time as _time
    t0 = _time.monotonic()

    parsed = parse_single(input_str.strip())
    if parsed.type == "unknown":
        _error(f"Could not parse input as tx hash, address, or URL: {input_str}")

    if parsed.chain:
        chain = parsed.chain
    chain = _resolve_chain(chain)

    meta = Meta()

    if parsed.type == "address":
        chain_cfg = _get_chain_config(chain)
        rpc = _get_rpc(chain_cfg)
        explorer = _get_explorer(chain_cfg)
        if not rpc and not explorer:
            _error(f"No RPC or explorer configured for {chain}")

        classification = classify_address(parsed.value, rpc, explorer)
        classification["chain"] = chain
        classification["_meta"] = meta.to_dict()
        classification["_meta"]["elapsed_seconds"] = round(_time.monotonic() - t0, 1)
        _output(classification)
        return

    if parsed.type != "tx_hash":
        _error(f"Quick analysis requires a tx hash or address, got: {parsed.type}")

    tx_hash = parsed.value
    if not chain:
        chain = _auto_detect_chain(tx_hash, meta)

    chain_cfg = _get_chain_config(chain)
    rpc = _get_rpc(chain_cfg)
    explorer = _get_explorer(chain_cfg)
    evidence = _get_evidence(case)

    if not rpc and not explorer:
        _error(f"No RPC or explorer configured for {chain}")
    if not rpc:
        meta.warnings.append(f"No RPC for {chain} — token/admin detection limited")

    # Fetch tx + receipt
    tx_data, receipt_data = None, None
    if rpc:
        try:
            tx_data = rpc.get_transaction(tx_hash)
            receipt_data = rpc.get_transaction_receipt(tx_hash)
            if tx_data:
                meta.data_sources.append("rpc")
        except RPCError:
            pass
    if tx_data is None and explorer:
        try:
            tx_data = explorer.proxy_get_transaction(tx_hash)
            receipt_data = explorer.proxy_get_receipt(tx_hash)
            if tx_data:
                meta.data_sources.append("explorer_proxy")
        except ExplorerError as e:
            _error(f"Explorer error: {e}")
    if tx_data is None:
        _error(f"Transaction {tx_hash} not found on {chain}")

    # Classify from and to FIRST (before expensive ABI fetches)
    from_addr = tx_data.get("from", "")
    to_addr = tx_data.get("to", "")
    addresses = {}
    if from_addr:
        addresses[from_addr] = classify_address(from_addr, rpc, explorer)
    if to_addr and to_addr != from_addr:
        addresses[to_addr] = classify_address(to_addr, rpc, explorer)

    # Build tx result — skip expensive per-contract log decoding for speed
    tx_result = _build_tx_result(tx_data, receipt_data, chain_cfg, chain, rpc, explorer, meta, skip_log_decode=True)

    # Save evidence — save decoded result, not raw tx
    if evidence:
        p1, new1 = evidence.save("tx", tx_hash, tx_result, chain)
        meta.evidence_paths.append(f"{p1} ({'new' if new1 else 'cached'})")
        if receipt_data:
            p2, new2 = evidence.save("receipt", tx_hash, receipt_data, chain)
            meta.evidence_paths.append(f"{p2} ({'new' if new2 else 'cached'})")

    # Compact result
    compact = _compact_tx(tx_result)
    compact["addresses"] = {
        addr: {
            "type": c.get("type"),
            "is_contract": c.get("is_contract"),
            "labels": c.get("labels", []),
            "known_entity": c.get("known_entity"),
            "is_proxy": c.get("is_proxy"),
            "proxy_type": c.get("proxy_type"),
            "admin_info": c.get("admin_info"),
            "balance_formatted": c.get("balance_formatted"),
        }
        for addr, c in addresses.items()
    }
    compact["_meta"] = meta.to_dict()
    compact["_meta"]["elapsed_seconds"] = round(_time.monotonic() - t0, 1)

    _output(compact)


def _auto_detect_chain(tx_hash: str, meta: Meta) -> str:
    config = get_config()
    for name, chain_cfg in config.all_chains().items():
        if not chain_cfg.has_explorer():
            continue
        try:
            limiter = RateLimiter(config.rate_limit)
            client = ExplorerClient(chain_cfg.explorer_base, chain_cfg.explorer_api_key, limiter, chain_cfg.chain_id)
            result = client.proxy_get_transaction(tx_hash)
            if result and isinstance(result, dict) and result.get("hash"):
                meta.data_sources.append(f"chain_detected:{name}")
                return name
        except ExplorerError:
            continue
    _error(f"Could not find tx {tx_hash} on any configured chain. Specify --chain manually.")


@cli.command()
@click.argument("tx_hash")
@click.option("--chain", "-c", help="Chain name (ethereum, polygon, etc.)")
@click.option("--case", help="Case name for evidence storage (or set MEAT_CASE)")
@click.option("--compact", is_flag=True, help="Compact output: summary + net_flows only, skip raw arrays")
def tx(tx_hash, chain, case, compact):
    """Fetch full transaction details with decoded data."""
    tx_hash = tx_hash.lower()
    if not tx_hash.startswith("0x") or len(tx_hash) != 66:
        _error(f"Invalid transaction hash: {tx_hash}")

    chain = _resolve_chain(chain)
    chain_cfg = _get_chain_config(chain)
    rpc = _get_rpc(chain_cfg)
    explorer = _get_explorer(chain_cfg)
    evidence = _get_evidence(case)
    meta = Meta()

    if not rpc and not explorer:
        _error(f"No RPC URL or explorer API key configured for {chain}")

    if not rpc:
        meta.warnings.append(f"No RPC for {chain} — token/admin/proxy detection unavailable")

    tx_data = None
    receipt_data = None

    if rpc:
        try:
            tx_data = rpc.get_transaction(tx_hash)
            receipt_data = rpc.get_transaction_receipt(tx_hash)
            if tx_data:
                meta.data_sources.append("rpc")
        except RPCError as e:
            click.echo(f"RPC error, falling back to explorer: {e}", err=True)

    if tx_data is None and explorer:
        try:
            tx_data = explorer.proxy_get_transaction(tx_hash)
            receipt_data = explorer.proxy_get_receipt(tx_hash)
            if tx_data:
                meta.data_sources.append("explorer_proxy")
        except ExplorerError as e:
            _error(f"Explorer error: {e}")

    if tx_data is None:
        _error(f"Transaction {tx_hash} not found on {chain}")

    result = _build_tx_result(tx_data, receipt_data, chain_cfg, chain, rpc, explorer, meta)

    if evidence:
        p1, new1 = evidence.save("tx", tx_hash, result, chain)
        meta.evidence_paths.append(f"{p1} ({'new' if new1 else 'cached'})")
        if receipt_data:
            p2, new2 = evidence.save("receipt", tx_hash, receipt_data, chain)
            meta.evidence_paths.append(f"{p2} ({'new' if new2 else 'cached'})")

    if compact:
        result = _compact_tx(result)

    result["_meta"] = meta.to_dict()
    _output(result)


def _compact_tx(result: dict) -> dict:
    transfers = result.get("token_transfers", [])
    transfer_summary = {}
    for t in transfers:
        token = t.get("token_symbol") or t.get("token_address", "?")
        transfer_summary[token] = transfer_summary.get(token, 0) + 1

    # Simplify net_flows for compact mode: formatted + USD
    net_flows_simple = {}
    for addr, tokens in (result.get("net_flows") or {}).items():
        simple = {}
        for tok, detail in tokens.items():
            if isinstance(detail, dict):
                fmt = detail.get("formatted", detail.get("raw", "?"))
                usd = detail.get("usd_value")
                simple[tok] = f"{fmt} ({usd})" if usd else fmt
            else:
                simple[tok] = detail
        if simple:
            net_flows_simple[addr] = simple

    return {
        "hash": result.get("hash"),
        "chain": result.get("chain"),
        "block_number": result.get("block_number"),
        "from": result.get("from"),
        "to": result.get("to"),
        "value_formatted": result.get("value_formatted"),
        "status": result.get("status"),
        "tx_fee_formatted": result.get("tx_fee_formatted"),
        "decoded_input": result.get("decoded_input"),
        "transfer_count": len(transfers),
        "transfer_summary": transfer_summary,
        "net_flows": net_flows_simple,
        "approval_count": len(result.get("approvals", [])),
        "internal_tx_count": len(result.get("internal_transactions", [])),
        "decode_coverage": result.get("decode_coverage"),
    }


def _build_tx_result(tx_data: dict, receipt_data: dict | None,
                     chain_cfg: ChainConfig, chain: str,
                     rpc: RPCClient | None, explorer: ExplorerClient | None,
                     meta: Meta | None = None, skip_log_decode: bool = False) -> dict:
    value_wei = int(tx_data.get("value", "0x0"), 16)
    gas_price = int(tx_data.get("gasPrice", "0x0"), 16)
    tx_hash = tx_data.get("hash", "")

    result = {
        "hash": tx_hash,
        "chain": chain,
        "block_number": _hex_to_int(tx_data.get("blockNumber")),
        "from": tx_data.get("from", ""),
        "to": tx_data.get("to", ""),
        "value_wei": str(value_wei),
        "value_formatted": format_value(value_wei, 18) + f" {chain_cfg.native_token}",
        "gas_price_gwei": format_value(gas_price, 9) + " gwei",
        "input": tx_data.get("input", "0x"),
        "nonce": _hex_to_int(tx_data.get("nonce")),
    }

    if receipt_data:
        gas_used = _hex_to_int(receipt_data.get("gasUsed"))
        status = _hex_to_int(receipt_data.get("status"))
        result["status"] = "success" if status == 1 else "reverted" if status == 0 else "unknown"
        result["gas_used"] = gas_used
        result["tx_fee_wei"] = str(gas_used * gas_price)
        result["tx_fee_formatted"] = format_value(gas_used * gas_price, 18) + f" {chain_cfg.native_token}"

        logs = receipt_data.get("logs", [])
        result["log_count"] = len(logs)

        events = _extract_events(logs)
        token_info_map = _enrich_tokens(events, rpc or explorer, meta)
        result["token_transfers"] = events["transfers"]
        if events["approvals"]:
            result["approvals"] = events["approvals"]
        if events["weth"]:
            result["weth_events"] = events["weth"]
        result["net_flows"] = _compute_net_flows(
            events, token_info_map, value_wei, tx_data, chain_cfg
        )

    result["decoded_input"] = _decode_calldata(tx_data, explorer)

    if receipt_data and not skip_log_decode:
        decoded_logs = _decode_all_logs(receipt_data, explorer)
        result["decoded_logs"] = decoded_logs
        result["decode_coverage"] = f"{len(decoded_logs)}/{len(receipt_data.get('logs', []))} logs decoded"
    elif skip_log_decode and receipt_data:
        result["decode_coverage"] = "skipped (use `meat tx` for full log decoding)"

    _fetch_internal_txs(result, tx_hash, explorer)

    return result


def _extract_events(logs: list[dict]) -> dict:
    transfers, approvals, weth = [], [], []
    for log in logs:
        t = decode_erc20_transfer(log)
        if t:
            transfers.append(t)
            continue
        a = decode_approval(log)
        if a:
            approvals.append(a)
            continue
        w = decode_weth_event(log)
        if w:
            weth.append(w)
    return {"transfers": transfers, "approvals": approvals, "weth": weth}


MAX_TOKEN_RESOLVES = 20
MAX_ENRICH_SECONDS = 15


def _enrich_tokens(events: dict, resolver, meta: Meta | None) -> dict[str, dict]:
    """Resolve token info for each unique token address. Returns {addr: {name, symbol, decimals}}."""
    import time
    seen: dict[str, dict | None] = {}
    resolve_count = 0
    start_time = time.time()
    all_items = events["transfers"] + events["weth"] + events["approvals"]
    for item in all_items:
        addr = item.get("token_address", "").lower()
        if not addr or addr in seen:
            pass
        elif resolver and resolve_count < MAX_TOKEN_RESOLVES and (time.time() - start_time) < MAX_ENRICH_SECONDS:
            seen[addr] = resolve_token_info(addr, resolver)
            resolve_count += 1
        else:
            seen[addr] = None

    for item in events["transfers"] + events["weth"]:
        addr = item.get("token_address", "").lower()
        info = seen.get(addr)
        if info:
            item["token_name"] = info.get("name", "")
            item["token_symbol"] = info.get("symbol", "")
            decimals = info.get("decimals", 18)
            item["token_decimals"] = decimals
            item["amount_formatted"] = format_value(item["amount_raw"], decimals) + f" {info.get('symbol', '')}"
        elif meta and addr:
            meta.enrichment_failures.append(addr)

    for item in events["approvals"]:
        info = seen.get(item.get("token_address", "").lower())
        if info:
            item["token_name"] = info.get("name", "")
            item["token_symbol"] = info.get("symbol", "")

    if meta:
        meta.enrichment_failures = list(dict.fromkeys(meta.enrichment_failures))

    return {addr: info for addr, info in seen.items() if info}


def _compute_net_flows(events: dict, token_info_map: dict[str, dict],
                       value_wei: int, tx_data: dict, chain_cfg: ChainConfig) -> dict:
    """Compute per-address per-token net flows with USD values."""
    from collections import defaultdict
    from meat.external import get_token_prices_batch

    label_map: dict[str, tuple[str, int]] = {}
    for addr, info in token_info_map.items():
        label_map[addr] = (info.get("symbol", ""), info.get("decimals", 18))

    raw_flows: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    token_addrs_seen: dict[str, str] = {}

    for t in events["transfers"] + events["weth"]:
        token_addr = t.get("token_address", "").lower()
        label, _ = label_map.get(token_addr, (f"UNKNOWN({token_addr[:10]}...)", 18))
        token_addrs_seen[label] = token_addr
        try:
            val = int(t["amount_raw"])
        except (ValueError, TypeError):
            continue
        raw_flows[t["from"]][label] -= val
        raw_flows[t["to"]][label] += val

    if value_wei > 0:
        raw_flows[tx_data.get("from", "")][chain_cfg.native_token] -= value_wei
        to_addr = tx_data.get("to", "")
        if to_addr:
            raw_flows[to_addr][chain_cfg.native_token] += value_wei

    label_to_decimals: dict[str, int] = {chain_cfg.native_token: 18}
    for addr, (label, decimals) in label_map.items():
        label_to_decimals[label] = decimals

    # Fetch USD prices from DeFiLlama
    block_timestamp = _hex_to_int(tx_data.get("blockTimestamp") or tx_data.get("timestamp"))
    price_addrs = [a for a in token_addrs_seen.values() if not a.startswith("UNKNOWN")]
    prices = {}
    if price_addrs:
        try:
            prices = get_token_prices_batch(chain_cfg.name, price_addrs, timestamp=block_timestamp)
        except Exception:
            pass

    # Native token price
    native_price = None
    if chain_cfg.native_token in [l for l in label_to_decimals]:
        try:
            from meat.external import get_token_price
            native_data = get_token_price(chain_cfg.name, "0x0000000000000000000000000000000000000000", timestamp=block_timestamp)
            if not native_data:
                native_data = get_token_price(chain_cfg.name, "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", timestamp=block_timestamp)
            if native_data:
                native_price = native_data.get("price_usd")
        except Exception:
            pass

    out = {}
    for addr, tokens in raw_flows.items():
        non_zero = {}
        for tok, val in tokens.items():
            if val == 0:
                continue
            decimals = label_to_decimals.get(tok, 18)
            abs_formatted = format_value(abs(val), decimals)
            entry = {
                "raw": str(val),
                "formatted": ("-" + abs_formatted) if val < 0 else abs_formatted,
                "decimals": decimals,
            }

            # Add USD value
            token_addr = token_addrs_seen.get(tok)
            if token_addr and token_addr in prices:
                price = prices[token_addr].get("price_usd")
                if price:
                    human_val = abs(val) / (10 ** decimals)
                    usd = human_val * price
                    entry["usd_value"] = f"${usd:,.2f}" if val >= 0 else f"-${usd:,.2f}"
                    entry["price_usd"] = price
            elif tok == chain_cfg.native_token and native_price:
                human_val = abs(val) / (10 ** 18)
                usd = human_val * native_price
                entry["usd_value"] = f"${usd:,.2f}" if val >= 0 else f"-${usd:,.2f}"
                entry["price_usd"] = native_price

            non_zero[tok] = entry
        if non_zero:
            out[addr] = non_zero
    return out


def _decode_calldata(tx_data: dict, explorer: ExplorerClient | None) -> dict | None:
    calldata = tx_data.get("input", "0x")
    if not calldata or calldata == "0x" or len(calldata) < 10:
        return None

    to_addr = tx_data.get("to", "")
    if to_addr and explorer:
        try:
            abi_json = explorer.get_abi(to_addr)
            if abi_json:
                abi = json.loads(abi_json)
                decoded = decode_function_input(abi, calldata)
                if decoded:
                    return decoded
        except (ExplorerError, json.JSONDecodeError):
            pass

    selector = calldata[:10]
    sigs = lookup_selector(selector)
    if sigs:
        return {"function": sigs[0], "signature": sigs[0], "params": None, "note": "decoded_from_4byte"}
    return {"selector": selector, "note": "unknown_function"}


def _decode_all_logs(receipt_data: dict, explorer: ExplorerClient | None) -> list[dict]:
    if not explorer:
        return []
    abi_cache: dict[str, list | None] = {}
    decoded = []
    for log in receipt_data.get("logs", []):
        log_addr = log.get("address", "").lower()
        if log_addr not in abi_cache:
            try:
                raw = explorer.get_abi(log_addr)
                abi_cache[log_addr] = json.loads(raw) if raw else None
            except (ExplorerError, json.JSONDecodeError):
                abi_cache[log_addr] = None
        abi = abi_cache.get(log_addr)
        if abi:
            d = decode_log(abi, log)
            if d:
                d["address"] = log.get("address", "")
                decoded.append(d)
    return decoded


def _fetch_internal_txs(result: dict, tx_hash: str, explorer: ExplorerClient | None):
    if not explorer or not tx_hash:
        return
    try:
        internal = explorer.get_internal_txs_by_hash(tx_hash)
        if internal:
            result["internal_transactions"] = internal
    except ExplorerError:
        pass


@cli.command()
@click.argument("address")
@click.option("--chain", "-c", help="Chain name")
@click.option("--save", "save_dir", help="Directory to save source files")
@click.option("--case", help="Case name for evidence storage")
def source(address, chain, save_dir, case):
    """Fetch verified source code from block explorer."""
    chain_cfg = _get_chain_config(chain)
    explorer = _get_explorer(chain_cfg)
    meta = Meta()
    if not explorer:
        _error(f"No explorer API key configured for {chain}")
    meta.data_sources.append("explorer")

    evidence = _get_evidence(case)

    try:
        data = explorer.get_source_code(address)
    except ExplorerError as e:
        _error(f"Explorer error: {e}")

    if not data or not data.get("SourceCode"):
        from meat.external import get_sourcify_source
        sourcify_data = get_sourcify_source(chain_cfg.chain_id, address)
        if sourcify_data:
            meta.data_sources.clear()
            meta.data_sources.append("sourcify")
            sol_files = [f for f in sourcify_data.get("files", [])
                         if f.get("name", "").endswith(".sol")]
            if sol_files and save_dir:
                from pathlib import Path
                save_path = Path(save_dir) / address
                save_path.mkdir(parents=True, exist_ok=True)
                saved = []
                for f in sol_files:
                    fp = save_path / f["name"]
                    fp.parent.mkdir(parents=True, exist_ok=True)
                    fp.write_text(f.get("content", ""))
                    saved.append(f["name"])
                _output({"address": address, "chain": chain, "source": "sourcify",
                         "saved_files": saved, "_meta": meta.to_dict()})
                return
            _output({"address": address, "chain": chain, "source": "sourcify",
                     "file_count": len(sourcify_data.get("files", [])),
                     "_meta": meta.to_dict()})
            return
        _error(f"No verified source code for {address} on {chain} (checked Etherscan + Sourcify)")

    if evidence:
        evidence.save("source", address.lower(), data, chain)

    result = {
        "address": address,
        "chain": chain,
        "contract_name": data.get("ContractName", ""),
        "compiler_version": data.get("CompilerVersion", ""),
        "optimization_used": data.get("OptimizationUsed", ""),
        "license_type": data.get("LicenseType", ""),
        "proxy": data.get("Proxy", "0"),
        "implementation": data.get("Implementation", ""),
    }

    source_code = data.get("SourceCode", "")

    if save_dir:
        from pathlib import Path
        save_path = Path(save_dir) / address
        save_path.mkdir(parents=True, exist_ok=True)

        if source_code.startswith("{{"):
            try:
                inner = source_code[1:-1]
                sources = json.loads(inner)
                for filename, content in sources.get("sources", {}).items():
                    file_path = save_path / filename
                    file_path.parent.mkdir(parents=True, exist_ok=True)
                    file_path.write_text(content.get("content", ""))
                result["saved_files"] = list(sources.get("sources", {}).keys())
            except (json.JSONDecodeError, AttributeError):
                (save_path / f"{data.get('ContractName', 'Contract')}.sol").write_text(source_code)
                result["saved_files"] = [f"{data.get('ContractName', 'Contract')}.sol"]
        elif source_code.startswith("{"):
            try:
                sources = json.loads(source_code)
                for filename, content in sources.items():
                    file_path = save_path / filename
                    file_path.parent.mkdir(parents=True, exist_ok=True)
                    if isinstance(content, dict):
                        file_path.write_text(content.get("content", ""))
                    else:
                        file_path.write_text(str(content))
                result["saved_files"] = list(sources.keys())
            except json.JSONDecodeError:
                (save_path / f"{data.get('ContractName', 'Contract')}.sol").write_text(source_code)
                result["saved_files"] = [f"{data.get('ContractName', 'Contract')}.sol"]
        else:
            (save_path / f"{data.get('ContractName', 'Contract')}.sol").write_text(source_code)
            result["saved_files"] = [f"{data.get('ContractName', 'Contract')}.sol"]

    # Auto-follow proxy chain: fetch implementation source code too
    impl_chain = []
    impl_addr = data.get("Implementation", "").strip()
    proxy_names = {"BeaconProxy", "UpgradeableBeacon", "TransparentUpgradeableProxy",
                   "ERC1967Proxy", "AdminUpgradeabilityProxy", "InitializableImmutableAdminUpgradeabilityProxy"}
    seen = {address.lower()}
    current_data = data
    while impl_addr and impl_addr.lower() not in seen and len(impl_chain) < 5:
        seen.add(impl_addr.lower())
        try:
            impl_data = explorer.get_source_code(impl_addr)
        except ExplorerError:
            break
        if not impl_data or not impl_data.get("SourceCode"):
            break
        impl_name = impl_data.get("ContractName", "")
        impl_chain.append({
            "address": impl_addr,
            "contract_name": impl_name,
            "compiler_version": impl_data.get("CompilerVersion", ""),
        })
        if evidence:
            evidence.save("source", impl_addr.lower(), impl_data, chain)
        # Stop if we reached a non-proxy implementation
        if impl_name not in proxy_names:
            break
        impl_addr = impl_data.get("Implementation", "").strip()

    if impl_chain:
        result["implementation_chain"] = impl_chain
        meta.data_sources.append(f"proxy_chain({len(impl_chain)} hops)")

    result["_meta"] = meta.to_dict()
    _output(result)


@cli.command("abi")
@click.argument("address")
@click.option("--chain", "-c", help="Chain name")
@click.option("--case", help="Case name for evidence storage")
def get_abi(address, chain, case):
    """Fetch contract ABI from block explorer."""
    chain_cfg = _get_chain_config(chain)
    explorer = _get_explorer(chain_cfg)
    if not explorer:
        _error(f"No explorer API key configured for {chain}")

    evidence = _get_evidence(case)

    try:
        abi_json = explorer.get_abi(address)
    except ExplorerError as e:
        _error(f"Explorer error: {e}")

    if not abi_json:
        result = _try_proxy_abi(address, explorer)
        if result:
            if evidence:
                evidence.save("abi", address.lower(), result, chain)
            _output(result)
            return
        from meat.external import get_sourcify_abi
        sourcify_abi = get_sourcify_abi(chain_cfg.chain_id, address)
        if sourcify_abi:
            result = {"address": address, "chain": chain, "abi": sourcify_abi, "source": "sourcify"}
            if evidence:
                evidence.save("abi", address.lower(), result, chain)
            _output(result)
            return
        _error(f"No ABI available for {address} on {chain} (checked Etherscan + Sourcify)")

    try:
        abi = json.loads(abi_json)
    except json.JSONDecodeError:
        _error(f"Invalid ABI JSON for {address}")

    result = {"address": address, "chain": chain, "abi": abi}

    if evidence:
        evidence.save("abi", address.lower(), result, chain)

    _output(result)


def _try_proxy_abi(address: str, explorer: ExplorerClient) -> dict | None:
    try:
        source_data = explorer.get_source_code(address)
        if source_data and source_data.get("Proxy") == "1" and source_data.get("Implementation"):
            impl = source_data["Implementation"]
            impl_abi = explorer.get_abi(impl)
            if impl_abi:
                abi = json.loads(impl_abi)
                return {
                    "address": address,
                    "is_proxy": True,
                    "implementation": impl,
                    "abi": abi,
                }
    except (ExplorerError, json.JSONDecodeError):
        pass
    return None


@cli.command("classify")
@click.argument("address")
@click.option("--chain", "-c", help="Chain name")
@click.option("--case", help="Case name for evidence storage")
def classify(address, chain, case):
    """Classify an address (EOA, contract, token, proxy)."""
    chain_cfg = _get_chain_config(chain)
    rpc = _get_rpc(chain_cfg)
    explorer = _get_explorer(chain_cfg)
    meta = Meta()

    if not rpc and not explorer:
        _error(f"No RPC URL or explorer API key configured for {chain}")
    if rpc:
        meta.data_sources.append("rpc")
    if explorer:
        meta.data_sources.append("explorer")
    if not rpc:
        meta.warnings.append("No RPC — token/admin/proxy/LP detection unavailable")

    result = classify_address(address, rpc, explorer)
    result["chain"] = chain

    evidence = _get_evidence(case)
    if evidence:
        evidence.save("classify", address.lower(), result, chain)

    result["_meta"] = meta.to_dict()
    _output(result)


@cli.command("decode")
@click.argument("calldata")
@click.option("--abi-file", help="Path to ABI JSON file")
@click.option("--address", help="Contract address to fetch ABI for")
@click.option("--chain", "-c", help="Chain name (needed with --address)")
def decode(calldata, abi_file, address, chain):
    """Decode calldata using ABI or 4byte.directory lookup."""
    if not calldata.startswith("0x") or len(calldata) < 10:
        _error("Invalid calldata (must start with 0x and have at least 4-byte selector)")

    abi = None

    if abi_file:
        from pathlib import Path
        try:
            abi = json.loads(Path(abi_file).read_text())
        except (json.JSONDecodeError, FileNotFoundError) as e:
            _error(f"Failed to load ABI from {abi_file}: {e}")

    if not abi and address and chain:
        chain_cfg = _get_chain_config(chain)
        explorer = _get_explorer(chain_cfg)
        if explorer:
            try:
                abi_json = explorer.get_abi(address)
                if abi_json:
                    abi = json.loads(abi_json)
            except (ExplorerError, json.JSONDecodeError):
                pass

    if abi:
        result = decode_function_input(abi, calldata)
        if result:
            _output(result)
            return

    selector = calldata[:10]
    sigs = lookup_selector(selector)
    if sigs:
        _output({"selector": selector, "possible_functions": sigs, "params": None})
    else:
        _output({"selector": selector, "possible_functions": [], "params": None, "note": "unknown_selector"})


@cli.command("txlist")
@click.argument("address")
@click.option("--chain", "-c", help="Chain name")
@click.option("--page", default=1, help="Page number")
@click.option("--limit", "offset", default=50, help="Results per page")
@click.option("--start-block", default=0, help="Start block")
@click.option("--end-block", default=99999999, help="End block")
@click.option("--internal", is_flag=True, help="Get internal transactions")
@click.option("--sort", default="desc", help="Sort order (asc/desc)")
@click.option("--case", help="Case name for evidence storage")
def txlist(address, chain, page, offset, start_block, end_block, internal, sort, case):
    """List transactions for an address."""
    chain_cfg = _get_chain_config(chain)
    explorer = _get_explorer(chain_cfg)
    meta = Meta()
    if not explorer:
        _error(f"No explorer API key configured for {chain}")
    meta.data_sources.append("explorer")

    evidence = _get_evidence(case)

    try:
        if internal:
            txs = explorer.get_internal_tx_list(address, start_block, end_block, page, offset, sort)
        else:
            txs = explorer.get_tx_list(address, start_block, end_block, page, offset, sort)
    except ExplorerError as e:
        _error(f"Explorer error: {e}")

    result = {
        "address": address,
        "chain": chain,
        "type": "internal" if internal else "normal",
        "count": len(txs),
        "page": page,
        "transactions": txs,
    }

    if evidence:
        key = f"{address.lower()}_{'internal' if internal else 'normal'}_p{page}"
        evidence.save("txlist", key, result, chain)

    result["_meta"] = meta.to_dict()
    _output(result)


@cli.command("transfers")
@click.argument("target")
@click.option("--chain", "-c", help="Chain name")
@click.option("--start-block", default=0, help="Start block")
@click.option("--end-block", default=99999999, help="End block")
@click.option("--page", default=1, help="Page number")
@click.option("--limit", "offset", default=100, help="Results per page")
@click.option("--case", help="Case name for evidence storage")
def transfers(target, chain, start_block, end_block, page, offset, case):
    """Fetch ERC20 token transfers for an address."""
    chain_cfg = _get_chain_config(chain)
    explorer = _get_explorer(chain_cfg)
    meta = Meta()
    if not explorer:
        _error(f"No explorer API key configured for {chain}")
    meta.data_sources.append("explorer")

    evidence = _get_evidence(case)

    try:
        txs = explorer.get_token_transfers(
            address=target, start_block=start_block, end_block=end_block,
            page=page, offset=offset,
        )
    except ExplorerError as e:
        _error(f"Explorer error: {e}")

    result = {
        "address": target,
        "chain": chain,
        "count": len(txs),
        "transfers": txs,
        "_meta": meta.to_dict(),
    }

    if evidence:
        evidence.save("transfers", f"{target.lower()}_p{page}", result, chain)

    _output(result)


@cli.command("flow")
@click.argument("address")
@click.option("--chain", "-c", help="Chain name")
@click.option("--depth", default=2, help="Max hops to trace (default: 2)")
@click.option("--min-value", default=0, help="Minimum value in wei to include")
@click.option("--start-block", default=0, help="Only include transfers after this block")
@click.option("--end-block", default=99999999, help="Only include transfers before this block")
@click.option("--case", help="Case name for evidence storage")
def flow(address, chain, depth, min_value, start_block, end_block, case):
    """Build fund flow graph from an address (BFS)."""
    from meat.trace import build_flow_graph

    chain_cfg = _get_chain_config(chain)
    rpc = _get_rpc(chain_cfg)
    explorer = _get_explorer(chain_cfg)
    meta = Meta()

    if rpc and rpc.is_alchemy:
        meta.data_sources.append("alchemy_getAssetTransfers")
    elif explorer:
        meta.data_sources.append("explorer")
    else:
        _error(f"No RPC or explorer configured for {chain}")

    evidence = _get_evidence(case)

    graph = build_flow_graph(address, explorer, chain, depth=depth, min_value_wei=min_value,
                             start_block=start_block, end_block=end_block, rpc=rpc)
    result = graph.to_dict()
    result["root"] = address
    result["chain"] = chain
    result["depth"] = depth
    result["_meta"] = meta.to_dict()

    if evidence:
        evidence.save("flow", address.lower(), result, chain)

    _output(result)


@cli.command("calltrace")
@click.argument("tx_hash")
@click.option("--chain", "-c", help="Chain name")
@click.option("--case", help="Case name for evidence storage")
def calltrace(tx_hash, chain, case):
    """Fetch call trace for a transaction (debug_traceTransaction or cast run fallback)."""
    import subprocess

    tx_hash = tx_hash.lower()
    if not tx_hash.startswith("0x") or len(tx_hash) != 66:
        _error(f"Invalid transaction hash: {tx_hash}")

    chain_cfg = _get_chain_config(chain)
    rpc = _get_rpc(chain_cfg)
    evidence = _get_evidence(case)
    meta = Meta()
    methods_tried = []

    trace_data = None

    if rpc and chain_cfg.trace_method:
        try:
            trace_data = rpc.debug_trace_transaction(tx_hash, tracer="callTracer")
            if trace_data:
                meta.data_sources.append("debug_traceTransaction")
        except RPCError as e:
            methods_tried.append(f"debug_traceTransaction: failed ({e})")

        if trace_data is None:
            try:
                trace_data = rpc.trace_transaction(tx_hash)
                if trace_data:
                    meta.data_sources.append("trace_transaction")
            except RPCError:
                methods_tried.append("trace_transaction: failed")

    if trace_data is None:
        from meat.external import tenderly_trace_transaction
        try:
            trace_data = tenderly_trace_transaction(chain_cfg.chain_id, tx_hash)
            if trace_data:
                meta.data_sources.append("tenderly")
        except Exception:
            methods_tried.append("tenderly: failed or not configured")

    if trace_data is None and chain_cfg.trace_fallback == "cast_run":
        rpc_url = chain_cfg.rpc_url
        if rpc_url:
            try:
                proc = subprocess.run(
                    ["cast", "run", tx_hash, "--rpc-url", rpc_url, "--decode-internal"],
                    capture_output=True, text=True, timeout=120,
                )
                if proc.returncode == 0:
                    trace_data = {"cast_run_output": proc.stdout, "method": "cast_run"}
                    meta.data_sources.append("cast_run")
                else:
                    methods_tried.append(f"cast_run: failed ({proc.stderr[:100]})")
            except FileNotFoundError:
                methods_tried.append("cast_run: cast not installed")
            except subprocess.TimeoutExpired:
                methods_tried.append("cast_run: timed out (120s)")

    if trace_data is None:
        explorer = _get_explorer(chain_cfg)
        if explorer:
            try:
                internal = explorer.get_internal_txs_by_hash(tx_hash)
                if internal:
                    trace_data = {"internal_transactions": internal, "method": "explorer_txlistinternal"}
                    meta.data_sources.append("explorer_txlistinternal")
                    meta.warnings.append("Flat call list only — not a full nested trace")
            except ExplorerError:
                methods_tried.append("explorer_txlistinternal: failed")

    if trace_data is None:
        _error(f"Could not trace {tx_hash}. Tried: {methods_tried}")

    if methods_tried:
        meta.warnings.extend(methods_tried)

    # Resolve all selectors in the trace and save the map as evidence
    # Priority: 1) ABI from source evidence (definitive), 2) 4byte registry (guessed)
    selector_map = {}
    if isinstance(trace_data, dict) and "calls" in trace_data:
        unique_sels = set()
        def _collect_selectors(node):
            inp = node.get("input", "")
            if len(inp) >= 10:
                unique_sels.add(inp[:10])
            for c in node.get("calls", []):
                _collect_selectors(c)
        _collect_selectors(trace_data)

        # Pass 1: resolve from source evidence ABIs (definitive)
        abi_resolved = 0
        if evidence:
            abi_selectors = _build_abi_selector_map(evidence)
            for sel in unique_sels:
                if sel in abi_selectors:
                    selector_map[sel] = {"name": abi_selectors[sel], "source": "abi"}
                    abi_resolved += 1

        # Pass 2: unresolved selectors → 4byte registry (guessed)
        registry_resolved = 0
        for sel in unique_sels:
            if sel not in selector_map:
                results = lookup_selector(sel)
                if results:
                    selector_map[sel] = {"name": results[0].split("(")[0], "source": "4byte"}
                    registry_resolved += 1

        if abi_resolved:
            meta.data_sources.append(f"abi_selectors({abi_resolved} resolved)")
        if registry_resolved:
            meta.data_sources.append(f"4byte_registry({registry_resolved} guessed)")

    # Decode calldata using ABI evidence
    decoded_calls = []
    addr_labels = {}
    if evidence and isinstance(trace_data, dict) and "calls" in trace_data:
        address_abis = _build_address_abi_map(evidence)
        if address_abis:
            from meat.effects import format_params_human, format_effect
            addr_labels = _load_case_addr_labels(case)

            # Build a set of all ABIs (direct + via DELEGATECALL targets)
            # so we can decode calls to proxies using their implementation's ABI
            all_abis_by_selector = {}
            for addr, abi in address_abis.items():
                for entry in abi:
                    if entry.get("type") == "function":
                        from eth_utils import keccak as _keccak
                        inputs = ",".join(i["type"] for i in entry.get("inputs", []))
                        sig = f"{entry['name']}({inputs})"
                        sel = "0x" + _keccak(text=sig).hex()[:8]
                        if sel not in all_abis_by_selector:
                            all_abis_by_selector[sel] = (abi, addr)

            def _try_decode(to_addr, calldata):
                abi = address_abis.get(to_addr)
                if abi:
                    result = decode_function_input(abi, calldata)
                    if result and result.get("params") is not None:
                        return result
                sel = calldata[:10] if len(calldata) >= 10 else ""
                if sel in all_abis_by_selector:
                    impl_abi, _ = all_abis_by_selector[sel]
                    return decode_function_input(impl_abi, calldata)
                return None

            def _decode_walk(node):
                from_addr = (node.get("from") or "").lower()
                to_addr = (node.get("to") or "").lower()
                calldata = node.get("input", "")
                sel = calldata[:10] if len(calldata) >= 10 else ""
                if to_addr and sel and len(calldata) > 10:
                    decoded = _try_decode(to_addr, calldata)
                    if decoded and decoded.get("params") is not None:
                        fn = decoded["function"]
                        params_fmt = format_params_human(decoded["params"])
                        effect = format_effect(fn, params_fmt, addr_labels)
                        decoded_calls.append({
                            "from": from_addr,
                            "to": to_addr,
                            "selector": sel,
                            "function": fn,
                            "signature": decoded.get("signature", ""),
                            "params": {k: str(v) for k, v in decoded["params"].items()},
                            "params_formatted": params_fmt,
                            "effect": effect,
                        })
                for c in node.get("calls", []):
                    _decode_walk(c)

            _decode_walk(trace_data)

    result = {"tx_hash": tx_hash, "chain": chain, "trace": trace_data, "_meta": meta.to_dict()}

    if evidence:
        evidence.save("trace", tx_hash, result, chain)
        if selector_map:
            sel_path = evidence.evidence_dir / "selector_map.json"
            existing = {}
            if sel_path.exists():
                try:
                    existing = json.loads(sel_path.read_text())
                except (json.JSONDecodeError, IOError):
                    pass
            existing.update(selector_map)
            sel_path.write_text(json.dumps(existing, indent=2))
        if decoded_calls:
            decoded_path = evidence.evidence_dir / "decoded_calls.json"
            decoded_path.write_text(json.dumps({
                "tx_hash": tx_hash,
                "decoded_count": len(decoded_calls),
                "calls": decoded_calls,
            }, indent=2, default=str))
            meta.evidence_paths.append("evidence/decoded_calls.json")

    # Build decoded tree summary for readable output
    if isinstance(trace_data, dict) and "calls" in trace_data:
        if not addr_labels:
            addr_labels = _load_case_addr_labels(case)
        decoded_tree = _decode_trace_tree(trace_data, addr_labels)
        result["decoded_tree"] = decoded_tree

    _output(result)


@cli.command("logs")
@click.option("--address", "-a", help="Contract address to filter by")
@click.option("--event", "-e", help="Event signature (e.g. 'Transfer(address,address,uint256)') — auto-computes topic0")
@click.option("--topic0", help="Raw topic0 hex (overrides --event)")
@click.option("--topic1", help="Indexed param 1 (pad address to 32 bytes: 0x000...addr)")
@click.option("--topic2", help="Indexed param 2")
@click.option("--topic3", help="Indexed param 3")
@click.option("--from-block", default=0, help="Start block")
@click.option("--to-block", default=99999999, help="End block")
@click.option("--chain", "-c", required=True, help="Chain name")
@click.option("--decode-abi/--no-decode", default=True, help="Try to decode logs with contract ABI")
@click.option("--case", help="Case name for evidence storage")
def logs(address, event, topic0, topic1, topic2, topic3, from_block, to_block, chain, decode_abi, case):
    """Search event logs via eth_getLogs. Supports event signature or raw topics."""
    from meat.decode import compute_selector
    from eth_utils import keccak as eth_keccak

    chain_cfg = _get_chain_config(chain)
    explorer = _get_explorer(chain_cfg)
    rpc = _get_rpc(chain_cfg)

    if not explorer and not rpc:
        _error(f"No explorer or RPC configured for {chain}")

    if event and not topic0:
        topic0 = "0x" + eth_keccak(text=event).hex()

    raw_logs = []
    if explorer:
        try:
            raw_logs = explorer.get_logs(
                address=address, topic0=topic0, topic1=topic1,
                topic2=topic2, topic3=topic3,
                from_block=from_block, to_block=to_block,
            )
        except ExplorerError as e:
            _error(f"Explorer error: {e}")
    elif rpc:
        filt = {"fromBlock": hex(from_block), "toBlock": hex(to_block)}
        if address:
            filt["address"] = address
        topics = []
        for t in [topic0, topic1, topic2, topic3]:
            if t:
                topics.append(t)
            elif topics:
                topics.append(None)
        if topics:
            filt["topics"] = topics
        try:
            raw_logs = rpc._call("eth_getLogs", [filt]) or []
        except RPCError as e:
            _error(f"RPC error: {e}")

    decoded_logs = []
    if decode_abi and explorer:
        abi_cache: dict[str, list | None] = {}
        for log in raw_logs:
            log_addr = (log.get("address") or "").lower()
            if log_addr and log_addr not in abi_cache:
                try:
                    raw_abi = explorer.get_abi(log_addr)
                    abi_cache[log_addr] = json.loads(raw_abi) if raw_abi else None
                except (ExplorerError, json.JSONDecodeError):
                    abi_cache[log_addr] = None
            abi = abi_cache.get(log_addr)
            if abi:
                d = decode_log(abi, log)
                if d:
                    d["address"] = log.get("address", "")
                    d["transactionHash"] = log.get("transactionHash", "")
                    d["blockNumber"] = log.get("blockNumber", "")
                    decoded_logs.append(d)

    meta = Meta()
    meta.data_sources.append("explorer" if explorer else "rpc")

    result = {
        "chain": chain,
        "query": {"address": address, "event": event, "topic0": topic0,
                  "from_block": from_block, "to_block": to_block},
        "count": len(raw_logs),
        "logs": raw_logs[:200],
    }
    if decoded_logs:
        result["decoded"] = decoded_logs
        result["decode_coverage"] = f"{len(decoded_logs)}/{len(raw_logs)} logs decoded"

    result["_meta"] = meta.to_dict()

    evidence = _get_evidence(case)
    if evidence:
        key = f"logs_{address or 'any'}_{from_block}_{to_block}"
        evidence.save("logs", key, result, chain)

    _output(result)


@cli.command("storage")
@click.argument("address")
@click.option("--slot", required=True, help="Storage slot (hex or decimal)")
@click.option("--chain", "-c", help="Chain name")
@click.option("--block", "block_num", default="latest", help="Block number or 'latest'")
@click.option("--compare-block", help="Compare slot value at two blocks (shows before/after)")
def storage(address, slot, chain, block_num, compare_block):
    """Read a contract storage slot. Supports historical reads and before/after comparison."""
    chain_cfg = _get_chain_config(chain)
    rpc = _get_rpc(chain_cfg)
    explorer = _get_explorer(chain_cfg)

    if not rpc and not explorer:
        _error(f"No RPC or explorer configured for {chain}")

    if not slot.startswith("0x"):
        slot = hex(int(slot))

    meta = Meta()

    def _read_slot(blk: str) -> tuple[str, str]:
        """Returns (value, source)."""
        if rpc:
            try:
                val = rpc.get_storage_at(address, slot, blk if blk == "latest" else hex(int(blk)))
                return val, "rpc"
            except RPCError:
                pass
        if explorer:
            try:
                val = explorer.proxy_get_storage_at(address, slot, blk)
                return val, "explorer_proxy"
            except ExplorerError:
                pass
        return "0x", "failed"

    if compare_block:
        val_before, src1 = _read_slot(compare_block)
        val_after, src2 = _read_slot(block_num)
        meta.data_sources.extend([src1, src2])
        if "failed" in meta.data_sources:
            meta.warnings.append("One or more storage reads failed — '0x' may not be real value")
        _output({
            "address": address, "chain": chain, "slot": slot,
            "before": {"block": compare_block, "value": val_before,
                       "value_int": str(int(val_before, 16)) if val_before and val_before != "0x" else "0"},
            "after": {"block": block_num, "value": val_after,
                      "value_int": str(int(val_after, 16)) if val_after and val_after != "0x" else "0"},
            "changed": val_before != val_after,
            "_meta": meta.to_dict(),
        })
    else:
        result_hex, src = _read_slot(block_num)
        meta.data_sources.append(src)
        if src == "failed":
            meta.warnings.append("Storage read failed — '0x' may not be real value")
        _output({
            "address": address, "chain": chain, "slot": slot,
            "block": block_num,
            "value": result_hex,
            "value_int": str(int(result_hex, 16)) if result_hex and result_hex != "0x" else "0",
            "_meta": meta.to_dict(),
        })


@cli.command("block")
@click.argument("block_number")
@click.option("--chain", "-c", help="Chain name")
@click.option("--full", is_flag=True, help="Include full transaction objects")
def block(block_number, chain, full):
    """Get block information."""
    chain_cfg = _get_chain_config(chain)
    rpc = _get_rpc(chain_cfg)
    if not rpc:
        _error(f"No RPC URL configured for {chain} (block reads require RPC)")

    try:
        block_id = int(block_number)
    except ValueError:
        block_id = block_number

    try:
        data = rpc.get_block(block_id, full_txs=full)
    except RPCError as e:
        _error(f"RPC error: {e}")

    if data is None:
        _error(f"Block {block_number} not found on {chain}")

    _output(data)


@cli.group("case")
def case_group():
    """Manage investigation cases."""
    pass


@case_group.command("list")
def case_list():
    """List all cases with status."""
    from meat.case import Case
    config = get_config()
    cases = Case.list_cases(config.cases_dir)
    if not cases:
        _output({"cases": [], "count": 0})
        return

    results = []
    for name in cases:
        c = Case.load(config.cases_dir, name)
        if c:
            results.append({
                "name": c.name,
                "status": c.status,
                "chain": c.chain,
                "created": c.data.get("created", ""),
                "last_updated": c.data.get("last_updated", ""),
                "attacker_addresses": c.data.get("summary", {}).get("attacker_addresses", 0),
                "victim_addresses": c.data.get("summary", {}).get("victim_addresses", 0),
            })
    _output({"cases": results, "count": len(results)})


@case_group.command("show")
@click.argument("name")
def case_show(name):
    """Show case summary: addresses, evidence, journal tail."""
    from meat.case import Case
    config = get_config()
    c = Case.load(config.cases_dir, name)
    if not c:
        _error(f"Case '{name}' not found")

    evidence_dir = c.case_dir / "evidence"
    evidence_count = sum(1 for _ in evidence_dir.rglob("*.json")) if evidence_dir.exists() else 0

    addresses = c.get_addresses()

    journal_file = c.case_dir / "journal.md"
    journal_tail = ""
    if journal_file.exists():
        lines = journal_file.read_text().strip().splitlines()
        journal_tail = "\n".join(lines[-20:]) if len(lines) > 20 else "\n".join(lines)

    _output({
        "name": c.name,
        "status": c.status,
        "chain": c.chain,
        "created": c.data.get("created"),
        "last_updated": c.data.get("last_updated"),
        "summary": c.data.get("summary", {}),
        "monitored_addresses": c.data.get("monitored_addresses", []),
        "open_questions": c.data.get("open_questions", []),
        "address_count": len(addresses),
        "addresses": addresses,
        "evidence_file_count": evidence_count,
        "journal_tail": journal_tail,
    })


@case_group.command("create")
@click.argument("name")
@click.option("--chain", "-c", required=True, help="Chain name")
def case_create(name, chain):
    """Create a new investigation case."""
    from meat.case import Case
    config = get_config()

    config.get_chain(chain)

    existing = Case.load(config.cases_dir, name)
    if existing:
        _error(f"Case '{name}' already exists (status: {existing.status})")

    c = Case.create(config.cases_dir, name, chain)
    _output({
        "created": True,
        "name": c.name,
        "chain": c.chain,
        "path": str(c.case_dir),
        "hint": f"Set MEAT_CASE={name} MEAT_CHAIN={chain} to avoid repeating --case and --chain",
    })


@cli.command("label")
@click.argument("address")
@click.option("--role", "-r", help="Role: victim, attacker, collector, funder, exchange, mixer, bridge, intermediate")
@click.option("--name", "-n", help="Label name (e.g. 'Binance 14', 'Tornado Cash')")
@click.option("--confidence", default="HIGH", help="Confidence: CONFIRMED, HIGH, MEDIUM, LOW")
@click.option("--note", help="Free-text note about this address")
@click.option("--source", "-s", help="Intel source (e.g. 'Arkham', 'Nansen', 'manual')")
@click.option("--case", help="Case name")
@click.option("--chain", "-c", help="Chain name")
def label(address, role, name, confidence, note, source, case, chain):
    """Add or update a label for an address in a case."""
    from meat.case import Case

    config = get_config()
    case_name = _resolve_case(case)
    if not case_name:
        _error("--case is required (or set MEAT_CASE env var)")

    c = Case.load(config.cases_dir, case_name)
    if not c:
        _error(f"Case '{case_name}' not found")

    addr_file = c.case_dir / "addresses.json"
    addresses = {}
    if addr_file.exists():
        try:
            addresses = json.loads(addr_file.read_text())
        except json.JSONDecodeError:
            pass

    existing = addresses.get(address) or addresses.get(address.lower()) or {}
    addr_key = address

    for k in list(addresses.keys()):
        if k.lower() == address.lower():
            addr_key = k
            existing = addresses[k]
            break

    if role:
        existing["role"] = role
    if name:
        existing.setdefault("classify", {})
        existing["classify"]["known_entity"] = name
        if "labels" not in existing:
            existing["labels"] = []
        if name not in existing["labels"]:
            existing["labels"].append(name)
    if confidence:
        existing["confidence"] = confidence
    if note:
        existing["reason"] = note
    if source:
        existing["source"] = source

    existing.setdefault("role", "unknown")
    existing.setdefault("confidence", "MEDIUM")

    from datetime import datetime, timezone
    existing["updated_at"] = datetime.now(timezone.utc).isoformat()

    addresses[addr_key] = existing
    addr_file.write_text(json.dumps(addresses, indent=2))

    c.append_journal(f"Label: {address[:16]}... → role={existing.get('role')}, name={name or '—'}, source={source or '—'}")

    _output({
        "labeled": True,
        "address": addr_key,
        "role": existing.get("role"),
        "name": name,
        "confidence": existing.get("confidence"),
        "note": note,
        "source": source,
    })


@cli.command("funder")
@click.argument("addresses", nargs=-1, required=True)
@click.option("--chain", "-c", help="Chain name")
@click.option("--case", help="Case name for evidence storage")
def funder(addresses, chain, case):
    """Find the first gas funding source for one or more addresses."""
    chain_cfg = _get_chain_config(chain)
    rpc = _get_rpc(chain_cfg)
    if not rpc or not rpc.is_alchemy:
        _error("funder command requires Alchemy RPC")

    meta = Meta()
    meta.data_sources.append("alchemy_getAssetTransfers")
    evidence = _get_evidence(case)

    results = []
    clusters = {}

    for addr in addresses:
        addr = addr.strip().lower()
        try:
            data = rpc.alchemy_get_asset_transfers(
                to_address=addr,
                category=["external"],
                max_count="0x1",
                order="asc",
                with_metadata=True,
            )
        except Exception as e:
            results.append({"address": addr, "error": str(e)})
            continue

        transfers = (data or {}).get("transfers", [])
        if not transfers:
            results.append({"address": addr, "funder": None, "note": "no inbound native transfers found"})
            continue

        t = transfers[0]
        funder_addr = (t.get("from") or "").lower()
        raw_val = t.get("rawContract", {}).get("value", "0x0")
        try:
            value_wei = int(raw_val, 16) if raw_val.startswith("0x") else int(raw_val or 0)
        except (ValueError, TypeError):
            value_wei = 0
        value_formatted = f"{value_wei / 1e18:.6f} {chain_cfg.native_token}"

        ts = t.get("metadata", {}).get("blockTimestamp", "")
        block_hex = t.get("blockNum", "0x0")
        try:
            block = int(block_hex, 16)
        except (ValueError, TypeError):
            block = 0

        entry = {
            "address": addr,
            "funder": funder_addr,
            "value": str(value_wei),
            "value_formatted": value_formatted,
            "tx_hash": t.get("hash", ""),
            "block": block,
            "timestamp": ts,
        }
        results.append(entry)

        if funder_addr not in clusters:
            clusters[funder_addr] = []
        clusters[funder_addr].append(addr)

    cluster_list = []
    for funder_addr, funded in clusters.items():
        cluster_list.append({
            "funder": funder_addr,
            "funded_addresses": funded,
            "count": len(funded),
        })
    cluster_list.sort(key=lambda c: -c["count"])

    output = {
        "chain": chain_cfg.name,
        "queried": len(addresses),
        "results": results,
        "clusters": cluster_list,
        "_meta": meta.to_dict(),
    }

    if evidence:
        evidence.save("funder", "cluster_analysis", output, chain_cfg.name)

    _output(output)


@cli.command("annotate")
@click.argument("tx_hash")
@click.argument("annotations_json")
@click.option("--case", help="Case name")
def annotate(tx_hash, annotations_json, case):
    """Save trace annotations for a transaction.

    ANNOTATIONS_JSON is a JSON string or @file path containing:
    [{"path": ".8", "title": "Flash Loan", "purpose": "Borrow 160M USDC", "phase": "setup"}, ...]

    Each annotation has:
      path:    trace call path (e.g. ".8.1.0") — from calltrace depth indices
      title:   short step name
      purpose: why this call matters
      phase:   optional grouping (setup, manipulation, extraction, cashout)
    """
    from pathlib import Path as P

    case_name = _resolve_case(case)
    if not case_name:
        _error("--case is required (or set MEAT_CASE env var)")

    config = get_config()
    case_dir = config.cases_dir / case_name
    if not case_dir.exists():
        _error(f"Case '{case_name}' not found")

    if annotations_json.startswith("@"):
        file_path = P(annotations_json[1:])
        if not file_path.exists():
            _error(f"File not found: {file_path}")
        raw = file_path.read_text()
    else:
        raw = annotations_json

    try:
        annotations = json.loads(raw)
    except json.JSONDecodeError as e:
        _error(f"Invalid JSON: {e}")

    if isinstance(annotations, list):
        annotations = {"tx_hash": tx_hash, "annotations": annotations}
    elif isinstance(annotations, dict) and "annotations" not in annotations:
        _error("JSON must be a list of annotations or {annotations: [...]}")

    annotations["tx_hash"] = tx_hash

    out_path = case_dir / "evidence" / "trace_annotations.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(annotations, indent=2))

    _output({
        "saved": True,
        "path": str(out_path.relative_to(case_dir)),
        "annotation_count": len(annotations.get("annotations", [])),
    })


@cli.command("report")
@click.argument("case_name")
@click.option("-o", "--output", default=None, help="Output HTML file path")
def report(case_name, output):
    """Generate HTML report for a case."""
    from pathlib import Path
    from meat.report import generate_report
    from meat.case import Case

    config = get_config()
    case = Case.load(config.cases_dir, case_name)
    if not case:
        _error(f"Case '{case_name}' not found")

    output_path = Path(output) if output else None
    result = generate_report(case.case_dir, output_path)
    _output({
        "generated": True,
        "case": case_name,
        "output": str(result),
    })


def _build_address_abi_map(evidence: EvidenceStore) -> dict[str, list[dict]]:
    """Build address→parsed ABI map from all source evidence."""
    abi_map = {}
    source_dir = evidence.evidence_dir / "source"
    if not source_dir.exists():
        return abi_map
    for fp in source_dir.glob("*.json"):
        try:
            with open(fp) as f:
                envelope = json.load(f)
            data = envelope.get("data", envelope)
            addr = fp.stem.lower()
            abi_raw = data.get("ABI", "")
            if not abi_raw or abi_raw == "Contract source code not verified":
                continue
            abi = json.loads(abi_raw) if isinstance(abi_raw, str) else abi_raw
            if isinstance(abi, list) and abi:
                abi_map[addr] = abi
        except (json.JSONDecodeError, IOError, KeyError):
            continue
    return abi_map


def _build_abi_selector_map(evidence: EvidenceStore) -> dict[str, str]:
    """Build a selector→function_name map from all source evidence ABIs."""
    from eth_utils import keccak as eth_keccak
    sel_map = {}
    source_dir = evidence.evidence_dir / "source"
    if not source_dir.exists():
        return sel_map
    for fp in source_dir.glob("*.json"):
        try:
            with open(fp) as f:
                envelope = json.load(f)
            data = envelope.get("data", envelope)
            abi_raw = data.get("ABI", "")
            if not abi_raw or abi_raw == "Contract source code not verified":
                continue
            abi = json.loads(abi_raw) if isinstance(abi_raw, str) else abi_raw
            for entry in abi:
                if entry.get("type") != "function":
                    continue
                name = entry.get("name", "")
                inputs = ",".join(i["type"] for i in entry.get("inputs", []))
                sig = f"{name}({inputs})"
                sel = "0x" + eth_keccak(text=sig).hex()[:8]
                if sel not in sel_map:
                    sel_map[sel] = name
        except (json.JSONDecodeError, IOError, KeyError):
            continue
    return sel_map


def _hex_to_int(val) -> int | None:
    if val is None:
        return None
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        try:
            return int(val, 16)
        except ValueError:
            return None
    return None


def _load_case_addr_labels(case_name: str | None) -> dict[str, str]:
    """Load address labels from a case's addresses.json + classify evidence."""
    labels = {}
    if not case_name:
        case_name = os.environ.get("MEAT_CASE")
    if not case_name:
        return labels
    config = get_config()
    case_dir = config.cases_dir / case_name
    addr_file = case_dir / "addresses.json"
    if addr_file.exists():
        try:
            with open(addr_file) as f:
                addrs = json.load(f)
            for addr, info in addrs.items():
                if isinstance(info, dict):
                    lbl = info.get("name") or (info.get("labels") or [None])[0]
                    if lbl:
                        labels[addr.lower()] = lbl
        except (json.JSONDecodeError, OSError):
            pass
    classify_dir = case_dir / "evidence" / "classify"
    if classify_dir.exists():
        for fp in classify_dir.glob("*.json"):
            try:
                with open(fp) as f:
                    data = json.load(f)
                d = data.get("data", data)
                addr = d.get("address", fp.stem).lower()
                if addr not in labels:
                    ti = d.get("token_info")
                    if ti and isinstance(ti, dict) and ti.get("symbol"):
                        labels[addr] = ti["symbol"]
                    elif d.get("labels"):
                        labels[addr] = d["labels"][0]
            except (json.JSONDecodeError, OSError):
                pass
    return labels


def _decode_trace_tree(trace: dict, addr_labels: dict[str, str], max_depth: int = 6) -> list[str]:
    """Decode a call trace into a human-readable tree of lines."""
    selector_cache = {}

    def resolve_selector(sel: str) -> str:
        if sel in selector_cache:
            return selector_cache[sel]
        results = lookup_selector(sel)
        name = results[0].split("(")[0] if results else sel
        selector_cache[sel] = name
        return name

    def label(addr: str) -> str:
        return addr_labels.get(addr.lower(), addr[:10])

    lines = []

    def walk(node, depth=0):
        if depth > max_depth:
            subcalls = node.get("calls", [])
            if subcalls:
                lines.append(f"{'  ' * depth}... {len(subcalls)} subcalls")
            return
        typ = node.get("type", "CALL")
        if typ == "DELEGATECALL":
            for c in node.get("calls", []):
                walk(c, depth)
            return
        to_addr = node.get("to", "")
        if to_addr == "0x0000000000000000000000000000000000000000":
            return
        if to_addr.startswith("0x000000000000000000000000000000000000000"):
            return
        fr = label(node.get("from", ""))
        to = label(to_addr)
        inp = node.get("input", "")
        sel = inp[:10] if len(inp) >= 10 else ""
        fn_name = resolve_selector(sel) if sel else "(fallback)"
        val = int(node.get("value", "0x0"), 16) if node.get("value") else 0
        err = node.get("error", "")
        parts = [f"{'  ' * depth}{fr} → {to}.{fn_name}()"]
        if val > 0:
            parts.append(f" [{val / 1e18:.4f} ETH]")
        if err:
            parts.append(" ERROR")
        lines.append("".join(parts))
        for c in node.get("calls", []):
            walk(c, depth + 1)

    walk(trace)
    return lines


def _collect_trace_addresses(trace: dict) -> set[str]:
    """Recursively collect all unique addresses from a trace."""
    addrs = set()

    def walk(node):
        fr = node.get("from", "")
        to = node.get("to", "")
        if fr and fr != "0x0000000000000000000000000000000000000000":
            addrs.add(fr.lower())
        if to and to != "0x0000000000000000000000000000000000000000":
            addrs.add(to.lower())
        for c in node.get("calls", []):
            walk(c)

    walk(trace)
    return addrs


@cli.command("trace-addresses")
@click.argument("tx_hash")
@click.option("--case", help="Case name for evidence lookup")
@click.option("--chain", "-c", help="Chain name (default: from env)")
def trace_addresses(tx_hash, case, chain):
    """Extract all unique addresses from a saved call trace."""
    case_name = _resolve_case(case)
    if not case_name:
        _error("--case is required (or set MEAT_CASE env var)")

    config = get_config()
    case_dir = config.cases_dir / case_name

    tx_hash = tx_hash.lower()
    trace_path = case_dir / "evidence" / "trace" / f"{tx_hash}.json"
    if not trace_path.exists():
        _error(f"No trace evidence found at {trace_path}. Run `meat calltrace {tx_hash}` first.")

    with open(trace_path) as f:
        data = json.load(f)

    trace_data = data.get("data", data)
    trace = trace_data.get("trace", trace_data)
    if not isinstance(trace, dict):
        _error("Trace data is not a nested call trace")

    all_addrs = _collect_trace_addresses(trace)

    # Load existing labels
    addr_labels = _load_case_addr_labels(case_name)

    results = []
    for addr in sorted(all_addrs):
        entry = {"address": addr}
        if addr in addr_labels:
            entry["label"] = addr_labels[addr]
        else:
            entry["label"] = None
        results.append(entry)

    labeled = sum(1 for r in results if r["label"])
    _output({
        "tx_hash": tx_hash,
        "total_addresses": len(results),
        "labeled": labeled,
        "unlabeled": len(results) - labeled,
        "addresses": results,
    })
