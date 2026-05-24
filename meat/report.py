from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from meat.case import Case
from meat.config import get_config, ChainConfig
from meat.external import get_token_prices_batch
from meat.rpc import RPCClient


def generate_report(case_dir: Path, output_path: Path | None = None) -> Path:
    data = _build_report_data(case_dir)
    template_path = Path(__file__).parent / "templates" / "report.html"
    template = template_path.read_text()
    html = template.replace("{{REPORT_DATA}}", json.dumps(data, default=str))

    if output_path is None:
        output_path = case_dir / "report.html"
    output_path.write_text(html)
    return output_path


def _build_report_data(case_dir: Path) -> dict:
    case_json = json.loads((case_dir / "case.json").read_text())
    chain_name = case_json.get("chain", "ethereum")
    cfg = get_config()
    try:
        chain_obj = cfg.get_chain(chain_name)
        chain_cfg = {
            "chain_id": chain_obj.chain_id,
            "explorer_url": chain_obj.explorer_url,
            "native_token": chain_obj.native_token,
        }
    except ValueError:
        chain_cfg = {}

    addresses = {}
    addr_file = case_dir / "addresses.json"
    if addr_file.exists():
        try:
            addresses = json.loads(addr_file.read_text())
        except json.JSONDecodeError:
            pass

    evidence_dir = case_dir / "evidence"

    native_token = chain_cfg.get("native_token", "ETH")
    case_created = case_json.get("created")
    rpc = None
    explorer = None
    try:
        chain_obj = cfg.get_chain(chain_name)
        if chain_obj.has_rpc():
            rpc = RPCClient(chain_obj.rpc_url)
        if chain_obj.has_explorer():
            from meat.explorer import ExplorerClient, RateLimiter
            limiter = RateLimiter(cfg.rate_limit)
            explorer = ExplorerClient(chain_obj.explorer_base, chain_obj.explorer_api_key,
                                      limiter, chain_obj.chain_id)
    except (ValueError, Exception):
        pass

    _auto_collect(case_dir, case_json, addresses, rpc, explorer, chain_name)

    evidence_data = _load_evidence_data(evidence_dir)
    evidence_index = _build_evidence_index(evidence_dir)

    transactions = _extract_transactions(evidence_data)
    flow = _extract_flow(evidence_data, addresses, chain_name, native_token, rpc,
                         case_created)
    analysis = _extract_analysis(case_dir, evidence_data, addresses, evidence_data)

    journal = _parse_journal(case_dir / "journal.md")
    findings = _load_findings(case_dir / "findings")

    return {
        "report_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "meat-evm",
        "case": {
            "name": case_json.get("name", ""),
            "chain": chain_name,
            "chain_id": chain_cfg.get("chain_id"),
            "explorer_url": chain_cfg.get("explorer_url", ""),
            "native_token": chain_cfg.get("native_token", "ETH"),
            "status": case_json.get("status", "active"),
            "created": case_json.get("created"),
            "last_updated": case_json.get("last_updated"),
            "last_monitored": case_json.get("last_monitored"),
            "exploit_type": case_json.get("exploit_type", "unknown"),
            "exploit_subtype": case_json.get("exploit_subtype"),
            "confidence": case_json.get("confidence", "UNKNOWN"),
            "summary": case_json.get("summary", {}),
            "open_questions": case_json.get("open_questions", []),
            "monitored_addresses": case_json.get("monitored_addresses", []),
        },
        "addresses": addresses,
        "transactions": transactions,
        "flow": flow,
        "analysis": analysis,
        "evidence_index": evidence_index,
        "journal": journal,
        "findings": findings,
        "exploit_indicators": case_json.get("exploit_indicators", {}),
    }


def _auto_collect(case_dir: Path, case_json: dict, addresses: dict,
                  rpc: RPCClient | None, explorer, chain: str):
    """Auto-fetch missing evidence before building the report."""
    from meat.evidence import EvidenceStore
    evidence = EvidenceStore(case_dir)

    cfg = get_config()
    chain_obj = None
    try:
        chain_obj = cfg.get_chain(chain)
    except Exception:
        pass

    # 1. Collect attack tx hashes from all sources
    tx_hashes = set()

    # From trace evidence filenames (most reliable — we traced these)
    trace_dir = case_dir / "evidence" / "trace"
    if trace_dir.exists():
        for f in trace_dir.glob("*.json"):
            tx_hashes.add(f.stem.lower())

    # From flow evidence edges
    flow_dir = case_dir / "evidence" / "flow"
    if flow_dir.exists():
        for e_file in flow_dir.glob("*.json"):
            try:
                envelope = json.loads(e_file.read_text())
                for edge in envelope.get("data", {}).get("edges", []):
                    h = edge.get("tx_hash")
                    if h and h.startswith("0x"):
                        tx_hashes.add(h.lower())
            except (json.JSONDecodeError, IOError):
                pass

    # From monitored addresses (recent activity)
    if rpc and rpc.is_alchemy:
        for m in case_json.get("monitored_addresses", []):
            addr = m.get("address", "")
            if addr:
                try:
                    data = rpc.alchemy_get_asset_transfers(
                        from_address=addr, category=["external", "erc20"],
                        max_count="0xA", order="desc", with_metadata=True,
                    )
                    for t in (data or {}).get("transfers", []):
                        h = t.get("hash")
                        if h:
                            tx_hashes.add(h.lower())
                except Exception:
                    pass

    # Also include the attack tx hash from case.json summary if present
    attack_tx = case_json.get("attack_tx")
    if attack_tx:
        tx_hashes.add(attack_tx.lower())

    # 2. Fetch tx data — lightweight for large txs, full decode for small ones
    if rpc and chain_obj:
        from meat.cli import _build_tx_result
        for tx_hash in list(tx_hashes)[:10]:
            if evidence.exists("tx", tx_hash):
                continue
            try:
                raw_tx = rpc.get_transaction(tx_hash)
                raw_receipt = rpc.get_transaction_receipt(tx_hash)
                if not raw_tx:
                    continue
                log_count = len(raw_receipt.get("logs", [])) if raw_receipt else 0
                if log_count > 30:
                    # Large tx — save basic info without full token enrichment
                    value_wei = int(raw_tx.get("value", "0x0"), 16)
                    gas_used = int(raw_receipt.get("gasUsed", "0x0"), 16) if raw_receipt else 0
                    gas_price = int(raw_tx.get("gasPrice", "0x0"), 16)
                    status_hex = raw_receipt.get("status", "0x1") if raw_receipt else "0x1"
                    from meat.decode import format_value
                    tx_data = {
                        "hash": tx_hash, "chain": chain,
                        "block_number": int(raw_tx.get("blockNumber", "0x0"), 16),
                        "from": raw_tx.get("from", ""), "to": raw_tx.get("to", ""),
                        "value_wei": str(value_wei),
                        "value_formatted": format_value(value_wei, 18) + f" {chain_obj.native_token}",
                        "status": "success" if int(status_hex, 16) == 1 else "reverted",
                        "gas_used": gas_used,
                        "tx_fee_formatted": format_value(gas_used * gas_price, 18) + f" {chain_obj.native_token}",
                        "log_count": log_count,
                        "_note": f"Large tx ({log_count} logs) — run 'meat tx {tx_hash}' for full decode",
                    }
                    evidence.save("tx", tx_hash, tx_data, chain)
                else:
                    tx_data = _build_tx_result(
                        raw_tx, raw_receipt, chain_obj, chain,
                        rpc, explorer, skip_log_decode=True,
                    )
                    evidence.save("tx", tx_hash, tx_data, chain)
            except Exception:
                pass

    # 3. Fetch source code for victim contracts
    if explorer:
        for addr, info in addresses.items():
            if info.get("role") not in ("victim",):
                continue
            if evidence.exists("source", addr.lower()):
                continue
            try:
                src_data = explorer.get_source_code(addr)
                if src_data and src_data.get("SourceCode"):
                    evidence.save("source", addr.lower(), {
                        "address": addr,
                        "contract_name": src_data.get("ContractName", ""),
                        "compiler_version": src_data.get("CompilerVersion", ""),
                        "source_code": src_data.get("SourceCode", ""),
                        "abi": src_data.get("ABI", ""),
                    }, chain)
            except Exception:
                pass

    # 4. Flow graph — only auto-build for key compromise (EOA attacker, fund tracing)
    # For smart contract exploits, flow graph should be built via /meat-trace
    exploit_type = case_json.get("exploit_type", "")
    if exploit_type in ("key_compromise", "approval_abuse"):
        flow_dir = case_dir / "evidence" / "flow"
        if not flow_dir.exists() or not list(flow_dir.glob("*.json")):
            collector_addrs = [a for a, info in addresses.items()
                               if info.get("role") in ("collector",)]
            if collector_addrs and (rpc or explorer):
                try:
                    from meat.trace import build_flow_graph
                    root = collector_addrs[0]
                    graph = build_flow_graph(root, explorer, chain, depth=2, rpc=rpc)
                    result = graph.to_dict()
                    result["root"] = root
                    result["chain"] = chain
                    result["depth"] = 2
                    evidence.save("flow", root.lower(), result, chain)
                except Exception:
                    pass

    # 5. Classify addresses that lack classify data
    for addr, info in addresses.items():
        if evidence.exists("classify", addr.lower()):
            continue
        classify_data = info.get("classify")
        if classify_data:
            evidence.save("classify", addr.lower(), classify_data, chain)
        elif rpc or explorer:
            try:
                from meat.classify import classify_address
                result = classify_address(addr, rpc, explorer)
                if result:
                    evidence.save("classify", addr.lower(), result, chain)
            except Exception:
                pass


def _parse_journal(journal_path: Path) -> list[dict]:
    if not journal_path.exists():
        return []
    text = journal_path.read_text()
    entries = []
    parts = re.split(r"\n## ", text)
    for part in parts:
        part = part.strip()
        if not part:
            continue
        lines = part.split("\n", 1)
        timestamp = lines[0].strip().lstrip("# ").strip()
        entry = lines[1].strip() if len(lines) > 1 else ""
        entries.append({"timestamp": timestamp, "entry": entry})
    return entries


def _build_evidence_index(evidence_dir: Path) -> list[dict]:
    if not evidence_dir.exists():
        return []
    index = []
    for category_dir in sorted(evidence_dir.iterdir()):
        if not category_dir.is_dir():
            continue
        category = category_dir.name
        for f in sorted(category_dir.glob("*.json")):
            try:
                envelope = json.loads(f.read_text())
                meta = envelope.get("_meta", {})
                index.append({
                    "category": category,
                    "key": meta.get("key", f.stem),
                    "chain": meta.get("chain"),
                    "fetched_at": meta.get("fetched_at"),
                    "file_path": str(f.relative_to(evidence_dir.parent)),
                    "size_bytes": f.stat().st_size,
                })
            except (json.JSONDecodeError, IOError):
                index.append({
                    "category": category,
                    "key": f.stem,
                    "chain": None,
                    "fetched_at": None,
                    "file_path": str(f.relative_to(evidence_dir.parent)),
                    "size_bytes": f.stat().st_size,
                })
    return index


def _load_evidence_data(evidence_dir: Path) -> dict:
    data = {}
    if not evidence_dir.exists():
        return data
    for category_dir in evidence_dir.iterdir():
        if not category_dir.is_dir():
            continue
        category = category_dir.name
        data[category] = {}
        for f in category_dir.glob("*.json"):
            try:
                envelope = json.loads(f.read_text())
                key = envelope.get("_meta", {}).get("key", f.stem)
                data[category][key] = envelope.get("data", envelope)
            except (json.JSONDecodeError, IOError):
                pass
    return data


def _extract_transactions(evidence_data: dict) -> list[dict]:
    txs = []
    for key, data in evidence_data.get("tx", {}).items():
        if isinstance(data, dict):
            txs.append(data)
    txs.sort(key=lambda t: t.get("block_number", 0))
    return txs


def _extract_flow(evidence_data: dict, addresses: dict,
                   chain: str, native_token: str,
                   rpc: RPCClient | None = None,
                   case_created: str | None = None) -> dict | None:
    flow_data = evidence_data.get("flow", {})
    if not flow_data:
        return None
    for key, data in flow_data.items():
        if isinstance(data, dict) and "nodes" in data:
            enriched = _enrich_flow_nodes(data, addresses)
            if rpc and rpc.is_alchemy:
                _complete_flow_graph(enriched, addresses, rpc)
                _tag_attacker_addresses(enriched, addresses, rpc)
            filtered = _filter_spam_tokens(enriched, chain, native_token)
            if rpc:
                _fetch_node_balances(filtered, rpc, native_token)
                _compute_infra_scores(filtered, rpc, case_created, addresses=addresses)
            return filtered
    return None


def _complete_flow_graph(flow: dict, addresses: dict, rpc: RPCClient):
    """Fetch inbound transfers for the flow root and key actors to fill gaps."""
    import requests as _req

    existing_edges = set()
    for e in flow.get("edges", []):
        existing_edges.add(f"{e['from'].lower()}-{e['to'].lower()}-{e.get('tx_hash','')}")

    existing_nodes = {n["address"].lower() for n in flow.get("nodes", [])}

    addrs_to_fetch = set()
    root = (flow.get("root") or "").lower()
    if root:
        addrs_to_fetch.add(root)
    for addr, info in addresses.items():
        role = info.get("role", "")
        if role in ("victim", "funder", "collector"):
            addrs_to_fetch.add(addr.lower())

    new_edges = []
    new_nodes = {}

    for addr in addrs_to_fetch:
        for direction in ["to", "from"]:
            try:
                params = {
                    "category": ["external", "erc20"],
                    "order": "desc",
                    "maxCount": "0x64",
                    "withMetadata": True,
                }
                if direction == "to":
                    params["toAddress"] = addr
                else:
                    params["fromAddress"] = addr

                result = rpc._call("alchemy_getAssetTransfers", [params])
                if not result:
                    continue

                for t in result.get("transfers", []):
                    tx_hash = t.get("hash", "")
                    from_addr = t.get("from", "").lower()
                    to_addr = t.get("to", "").lower()
                    edge_key = f"{from_addr}-{to_addr}-{tx_hash}"

                    if edge_key in existing_edges:
                        continue
                    existing_edges.add(edge_key)

                    asset = t.get("asset", "ETH")
                    raw_val = t.get("rawContract", {}).get("value", "0x0")
                    try:
                        value = str(int(raw_val, 16)) if raw_val.startswith("0x") else raw_val
                    except (ValueError, TypeError):
                        value = "0"

                    ts = t.get("metadata", {}).get("blockTimestamp", "")
                    block_hex = t.get("blockNum", "0x0")
                    try:
                        block = int(block_hex, 16)
                    except (ValueError, TypeError):
                        block = 0

                    if value == "0" or value == "":
                        continue

                    new_edges.append({
                        "from": t.get("from", ""),
                        "to": t.get("to", ""),
                        "value": value,
                        "token": asset,
                        "tx_hash": tx_hash,
                        "block": block,
                        "timestamp": ts,
                    })

                    for a in [from_addr, to_addr]:
                        if a not in existing_nodes and a not in new_nodes:
                            new_nodes[a] = {
                                "address": a,
                                "label": None,
                                "type": "unknown",
                            }

            except Exception:
                continue

    if new_edges:
        flow["edges"] = flow.get("edges", []) + new_edges
    if new_nodes:
        flow["nodes"] = flow.get("nodes", []) + list(new_nodes.values())


def _filter_spam_tokens(flow: dict, chain: str, native_token: str) -> dict:
    edges = flow.get("edges", [])
    if not edges:
        return flow

    native_names = {native_token.upper(), "ETH", "MATIC", "POL", "BNB",
                    "WETH", "WMATIC", "WPOL", "WBNB"}

    token_addrs = set()
    for e in edges:
        token = (e.get("token") or "").upper()
        if token not in native_names and ":" not in token:
            token_addr = e.get("token_address")
            if token_addr and token_addr != "0x" * 20:
                token_addrs.add(token_addr.lower())

    valid_tokens = set()
    if token_addrs:
        batch = list(token_addrs)
        for i in range(0, len(batch), 25):
            chunk = batch[i:i+25]
            prices = get_token_prices_batch(chain, chunk)
            for addr in chunk:
                if addr in prices and prices[addr].get("price_usd") is not None:
                    valid_tokens.add(addr)

    filtered = []
    for e in edges:
        if e.get("value", "0") == "0" or e.get("value", "") == "":
            continue
        token = (e.get("token") or "").upper()
        if token in native_names:
            filtered.append(e)
            continue
        token_addr = (e.get("token_address") or "").lower()
        if token_addr and token_addr in valid_tokens:
            filtered.append(e)
            continue
        if not token_addr and token in native_names:
            filtered.append(e)
            continue
        # Check common stablecoin names as fallback
        if token in {"USDC", "USDT", "DAI", "USDC.E", "USDCE",
                     "USDT.E", "FRAX", "BUSD", "TUSD", "LUSD"}:
            filtered.append(e)
            continue

    nodes_in_edges = set()
    for e in filtered:
        nodes_in_edges.add(e["from"].lower())
        nodes_in_edges.add(e["to"].lower())
    flow["edges"] = filtered
    flow["nodes"] = [n for n in flow.get("nodes", [])
                     if n.get("address", "").lower() in nodes_in_edges]
    flow["_spam_filtered"] = len(edges) - len(filtered)
    return flow


def _tag_attacker_addresses(flow: dict, addresses: dict, rpc: RPCClient):
    """Use gas funding analysis to tag attacker-controlled addresses."""
    known_attackers = set()
    for addr, info in addresses.items():
        if info.get("role") in ("attacker", "collector"):
            known_attackers.add(addr.lower())

    if not known_attackers:
        return

    unknown_addrs = []
    for node in flow.get("nodes", []):
        addr = node.get("address", "").lower()
        role = node.get("role") or "unknown"
        if role == "unknown" and addr not in {a.lower() for a in addresses}:
            unknown_addrs.append(addr)

    if not unknown_addrs:
        return

    for addr in unknown_addrs:
        try:
            data = rpc.alchemy_get_asset_transfers(
                to_address=addr,
                category=["external"],
                max_count="0x1",
                order="asc",
                with_metadata=True,
            )
            transfers = (data or {}).get("transfers", [])
            if not transfers:
                continue
            funder_addr = (transfers[0].get("from") or "").lower()
            if funder_addr in known_attackers:
                for node in flow.get("nodes", []):
                    if node.get("address", "").lower() == addr:
                        node["role"] = "attacker"
                        node["_funder"] = funder_addr
                        break
                known_attackers.add(addr)
        except Exception:
            continue

    flow["_attacker_tagged"] = sum(
        1 for n in flow.get("nodes", []) if n.get("_funder")
    )


def _compute_infra_scores(flow: dict, rpc: RPCClient, case_created: str | None,
                          nonce_threshold: int = 1000, age_days_threshold: int = 30,
                          addresses: dict | None = None):
    """Score each node for likelihood of being public infrastructure."""
    from datetime import datetime, timezone

    attack_ts = None
    if case_created:
        try:
            attack_ts = datetime.fromisoformat(case_created.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            pass
    if not attack_ts:
        attack_ts = datetime.now(timezone.utc)

    age_threshold_ts = attack_ts - __import__("datetime").timedelta(days=age_days_threshold)

    for node in flow.get("nodes", []):
        addr = node.get("address", "")
        if not addr:
            continue

        score = 0
        signals = []
        nonce = node.get("nonce", 0) or 0

        # 0. Funded by known attacker — definitive negative signal
        gas_funder = (node.get("gas_funder") or "").lower()
        attacker_roles = {"attacker", "collector"}
        funder_is_attacker = False
        if gas_funder:
            for a, info in addresses.items():
                if a.lower() == gas_funder and info.get("role") in attacker_roles:
                    funder_is_attacker = True
                    break
            if not funder_is_attacker:
                for n2 in flow.get("nodes", []):
                    if n2.get("address", "").lower() == gas_funder and n2.get("role") in attacker_roles:
                        funder_is_attacker = True
                        break
        if funder_is_attacker:
            node["infra_score"] = 0
            node["infra_signals"] = [f"gas_funded_by_attacker={gas_funder[:12]}... (=0, attacker)"]
            node["attacker_funded"] = True
            if not node.get("role") or node.get("role") == "unknown":
                node["role"] = "attacker"
            continue

        # 1. High nonce (0-25 pts)
        if nonce >= nonce_threshold:
            pts = min(25, int(25 * min(nonce / (nonce_threshold * 10), 1)))
            score += pts
            signals.append(f"nonce={nonce:,} (+{pts})")

        # 2. Age — existed before threshold (0-20 pts)
        first_funded = node.get("first_funded_at", "")
        if first_funded:
            try:
                funded_dt = datetime.fromisoformat(first_funded.replace("Z", "+00:00"))
                if funded_dt < age_threshold_ts:
                    days_old = (attack_ts - funded_dt).days
                    pts = min(20, int(20 * min(days_old / 365, 1)))
                    score += pts
                    signals.append(f"age={days_old}d (+{pts})")
            except (ValueError, TypeError):
                pass

        # 3. Inbound diversity (0-20 pts)
        if rpc and rpc.is_alchemy:
            try:
                data = rpc.alchemy_get_asset_transfers(
                    to_address=addr, category=["external"],
                    max_count="0x64", order="desc", with_metadata=False,
                )
                transfers = (data or {}).get("transfers", [])
                unique_senders = len(set(
                    (t.get("from") or "").lower() for t in transfers
                ))
                if unique_senders >= 20:
                    pts = min(20, int(20 * min(unique_senders / 50, 1)))
                    score += pts
                    signals.append(f"senders={unique_senders} (+{pts})")
            except Exception:
                pass

        # 4. Is contract (0-10 pts)
        is_contract = node.get("is_contract")
        if is_contract is None:
            try:
                code = rpc._call("eth_getCode", [addr, "latest"])
                is_contract = code and code != "0x" and len(code) > 2
                node["is_contract"] = is_contract
            except Exception:
                is_contract = False
        if is_contract:
            score += 10
            signals.append("contract (+10)")

        # 5. Activity outside attack window (0-15 pts)
        if first_funded:
            try:
                funded_dt = datetime.fromisoformat(first_funded.replace("Z", "+00:00"))
                days_before = (attack_ts - funded_dt).days
                if days_before > 7 and nonce > 5:
                    score += 15
                    signals.append(f"active_before_attack (+15)")
            except (ValueError, TypeError):
                pass

        # 6. Balanced flow ratio (0-10 pts) — computed from graph edges
        edges = flow.get("edges", [])
        addr_lower = addr.lower()
        in_count = sum(1 for e in edges if e.get("to", "").lower() == addr_lower)
        out_count = sum(1 for e in edges if e.get("from", "").lower() == addr_lower)
        if in_count > 0 and out_count > 0:
            ratio = min(in_count, out_count) / max(in_count, out_count)
            if ratio > 0.3:
                pts = int(10 * ratio)
                score += pts
                signals.append(f"balanced_ratio={ratio:.1f} (+{pts})")

        node["infra_score"] = min(score, 100)
        node["infra_signals"] = signals


def _fetch_node_balances(flow: dict, rpc: RPCClient, native_token: str):
    for node in flow.get("nodes", []):
        addr = node.get("address", "")
        if not addr:
            continue

        if not node.get("balance"):
            try:
                bal_hex = rpc._call("eth_getBalance", [addr, "latest"])
                if bal_hex:
                    bal_wei = int(bal_hex, 16)
                    bal_eth = bal_wei / 1e18
                    if bal_eth >= 0.001:
                        node["balance"] = f"{bal_eth:,.4f} {native_token}"
                    else:
                        node["balance"] = f"{bal_eth:.6f} {native_token}"
            except Exception:
                pass

        if not node.get("nonce"):
            try:
                nonce_hex = rpc._call("eth_getTransactionCount", [addr, "latest"])
                if nonce_hex:
                    node["nonce"] = int(nonce_hex, 16)
            except Exception:
                pass

        if rpc.is_alchemy and not node.get("gas_funder"):
            try:
                data = rpc.alchemy_get_asset_transfers(
                    to_address=addr, category=["external"],
                    max_count="0x1", order="asc", with_metadata=True,
                )
                transfers = (data or {}).get("transfers", [])
                if transfers:
                    t = transfers[0]
                    node["gas_funder"] = (t.get("from") or "").lower()
                    node["first_funded_at"] = t.get("metadata", {}).get("blockTimestamp", "")
            except Exception:
                pass


def _enrich_flow_nodes(flow: dict, addresses: dict) -> dict:
    addr_roles = {}
    for addr, info in addresses.items():
        addr_roles[addr.lower()] = info.get("role", "unknown")

    for node in flow.get("nodes", []):
        addr = node.get("address", "").lower()
        if addr in addr_roles:
            node["role"] = addr_roles[addr]

    return flow


def _extract_analysis(case_dir: Path, evidence_data: dict,
                      addresses: dict | None = None,
                      all_evidence: dict | None = None) -> dict:
    analysis = {
        "vulnerability": None,
        "attack_walkthrough": [],
        "call_trace": None,
        "storage_diffs": [],
        "source_files": [],
    }

    for key, data in evidence_data.get("trace", {}).items():
        if isinstance(data, dict):
            analysis["call_trace"] = data
            break

    for key, data in evidence_data.get("storage", {}).items():
        if isinstance(data, dict):
            analysis["storage_diffs"].append(data)

    for key, data in evidence_data.get("source", {}).items():
        if isinstance(data, dict):
            analysis["source_files"].append(data)

    # Parse from findings/analysis.md
    analysis_md = case_dir / "findings" / "analysis.md"
    if analysis_md.exists():
        md_text = analysis_md.read_text()
        analysis["vulnerability"] = _parse_vulnerability_from_md(md_text)
        analysis["attack_walkthrough"] = _parse_walkthrough_from_md(md_text)
        analysis["contracts_involved"] = _parse_contracts_table_from_md(md_text)

    # Fallback: parse from case.json exploit_indicators
    if not analysis["vulnerability"]:
        case_json = json.loads((case_dir / "case.json").read_text())
        indicators = case_json.get("exploit_indicators", {})
        exploit_type = case_json.get("exploit_type", "")
        type_indicators = indicators.get(exploit_type, {})
        if type_indicators:
            analysis["vulnerability"] = {
                "type": exploit_type.replace("_", " ").title(),
                "subtype": type_indicators.get("oracle_manipulation") or type_indicators.get("flash_loan") or None,
                "severity": "critical",
                "root_cause": type_indicators.get("victim_protocol") or type_indicators.get("oracle_manipulation") or "",
                "confidence": case_json.get("confidence", "UNKNOWN"),
            }

    # Parse call sequence from trace for sequence diagram
    if analysis["call_trace"] and addresses:
        analysis["call_sequence"] = _parse_call_sequence(
            analysis["call_trace"], addresses, all_evidence
        )

    # Load trace annotations (structured narrative from /meat-analyze)
    annotations_file = case_dir / "evidence" / "trace_annotations.json"
    if annotations_file.exists():
        try:
            analysis["trace_annotations"] = json.loads(annotations_file.read_text())
        except (json.JSONDecodeError, IOError):
            pass

    # Resolve annotations to phase ranges for the sequence diagram
    if analysis.get("call_sequence") and analysis.get("trace_annotations"):
        ann_data = analysis["trace_annotations"]
        ann_list = ann_data.get("annotations", ann_data) if isinstance(ann_data, dict) else ann_data
        if isinstance(ann_list, list):
            phases = _resolve_phases(analysis["call_sequence"], ann_list)
            analysis["call_sequence"]["phases"] = phases

    # Extract flash loan info from exploit_indicators
    case_json = json.loads((case_dir / "case.json").read_text())
    indicators = case_json.get("exploit_indicators", {})
    exploit_type = case_json.get("exploit_type", "")
    type_indicators = indicators.get(exploit_type, {})
    if type_indicators.get("flash_loan"):
        analysis["flash_loan"] = type_indicators["flash_loan"]

    # Extract profit breakdown from attack tx net_flows
    attack_tx_hash = case_json.get("attack_tx", "")
    if attack_tx_hash:
        for key, data in evidence_data.get("tx", {}).items():
            if key.lower() == attack_tx_hash.lower() and isinstance(data, dict):
                analysis["profit_breakdown"] = data.get("net_flows")
                break

    return analysis


def _parse_vulnerability_from_md(md_text: str) -> dict | None:
    vuln = {}
    field_map = {
        "type": "type", "severity": "severity", "confidence": "confidence",
        "root cause": "root_cause", "affected contract": "affected_contract",
        "affected contracts": "affected_contract",
    }
    in_vuln_section = False
    for line in md_text.split("\n"):
        stripped = line.strip()
        if "## Vulnerability" in stripped:
            in_vuln_section = True
            continue
        if stripped.startswith("## ") and in_vuln_section and "Vulnerability" not in stripped:
            break
        if in_vuln_section and stripped.startswith("- **"):
            for label, key in field_map.items():
                if label in stripped.lower() and "**" in stripped:
                    val = stripped.split(":", 1)[-1].strip() if ":" in stripped else ""
                    val = re.sub(r"\*+", "", val).strip()
                    if val:
                        vuln[key] = val
                    break

    # Also extract from Summary section
    summary_lines = []
    in_summary = False
    for line in md_text.split("\n"):
        if line.strip().startswith("## Summary"):
            in_summary = True
            continue
        if line.strip().startswith("## ") and in_summary:
            break
        if in_summary and line.strip():
            summary_lines.append(line.strip())
    if summary_lines and "root_cause" not in vuln:
        vuln["root_cause"] = " ".join(summary_lines[:3])
    if not vuln.get("type") and summary_lines:
        vuln["type"] = "Smart Contract Exploit"
    if not vuln.get("severity"):
        vuln["severity"] = "critical"

    return vuln if vuln else None


KNOWN_SELECTORS = {
    "0x095ea7b3": "approve", "0xa9059cbb": "transfer", "0x23b872dd": "transferFrom",
    "0x70a08231": "balanceOf", "0x18160ddd": "totalSupply", "0x313ce567": "decimals",
    "0x0b4c7e4d": "add_liquidity", "0xb72df5de": "add_liquidity", "0x3df02124": "exchange",
    "0xcc2b27d7": "remove_liquidity_one_coin", "0x1a4d01d2": "remove_liquidity_one_coin",
    "0x4903b0d1": "remove_liquidity_one_coin", "0x4515cef3": "add_liquidity",
    "0x3c168eab": "remove_liquidity",
    "0xbb7b8b80": "get_virtual_price", "0x42b0b77c": "flashLoanSimple",
    "0xe0232b42": "flashLoan", "0x128acb08": "swap", "0x414bf389": "exactInputSingle",
    "0x2e1a7d4d": "withdraw", "0x5c60da1b": "implementation", "0x4efecaa5": "transferUnderlyingTo",
    "0x40c10f19": "mint", "0x79cc6790": "burnFrom", "0xfeaf968c": "latestRoundData",
    "0x31f57072": "onMorphoFlashLoan", "0x1b11d0ff": "executeOperation",
    "0x9341a475": "accountForPosition", "0xd98964f1": "getExchangeRate",
    "0x6d5433e6": "updateAccounting", "0xaa9a0912": "deposit",
    "0x4ebd0b94": "updateTotalAum", "0x62de91e9": "sync",
    "0xfa461e33": "uniswapV3SwapCallback",
    "0x5b1dac60": "getSharePrice", "0xd15e0053": "getReserveNormalizedIncome",
    "0xa1fe0e8d": "executeMintToTreasury", "0x69328dec": "withdraw",
}

NOISE_SELECTORS = {
    "0x70a08231", "0x18160ddd", "0x313ce567", "0xfeaf968c",
    "0x5c60da1b", "0x00000000",
}

NOISE_CALL_TYPES = {"STATICCALL"}


WELL_KNOWN_TOKENS = {
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": ("USDC", "Token"),
    "0xdac17f958d2ee523a2206206994597c13d831ec7": ("USDT", "Token"),
    "0x6b175474e89094c44da98b954eedeac495271d0f": ("DAI", "Token"),
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": ("WETH", "Token"),
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": ("WBTC", "Token"),
    "0x6c3f90f043a72fa612cbac8115ee7e52bde6e490": ("3CRV", "Curve"),
    "0x99d8a9c45b2eca8864373a26d1459e3dff1e17f3": ("MIM", "Abracadabra"),
    "0x0000000000000000000000000000000000000000": ("Null", "System"),
    "0xe592427a0aece92de3edee1f18e0157c05861564": ("Uniswap Router", "Uniswap"),
}


def _parse_call_sequence(trace_data: dict, addresses: dict,
                         evidence_data: dict | None = None) -> dict:
    """Extract a structured call sequence from a nested call trace."""
    addr_labels = {}
    addr_protocols = {}

    # 1. Labels from addresses.json
    for addr, info in addresses.items():
        name = ""
        if info.get("classify", {}).get("known_entity"):
            name = info["classify"]["known_entity"]
        elif info.get("labels"):
            name = info["labels"][0]
        if name:
            addr_labels[addr.lower()] = name
        role = info.get("role", "")
        if role:
            addr_protocols[addr.lower()] = role

    # 2. Labels from well-known addresses
    for addr, (name, proto) in WELL_KNOWN_TOKENS.items():
        if addr not in addr_labels:
            addr_labels[addr] = name

    # 3. Labels from tx evidence (token_transfers have token_name)
    if evidence_data:
        for key, tx_data in evidence_data.get("tx", {}).items():
            if not isinstance(tx_data, dict):
                continue
            for t in tx_data.get("token_transfers", []):
                token_addr = (t.get("token_address") or "").lower()
                if token_addr and token_addr not in addr_labels:
                    sym = t.get("token_symbol") or t.get("token_name") or ""
                    if sym:
                        addr_labels[token_addr] = sym

    # 4. Labels from evidence/source (contract_name)
    if evidence_data:
        for key, src_data in evidence_data.get("source", {}).items():
            if isinstance(src_data, dict):
                addr = (src_data.get("address") or key).lower()
                name = src_data.get("contract_name", "")
                if name and addr not in addr_labels:
                    addr_labels[addr] = name

    # 5. Labels from evidence/classify
    if evidence_data:
        for key, cls_data in evidence_data.get("classify", {}).items():
            if isinstance(cls_data, dict):
                addr = key.lower()
                if addr not in addr_labels:
                    entity = cls_data.get("known_entity")
                    if entity:
                        addr_labels[addr] = entity if isinstance(entity, str) else entity.get("label", "")
                    elif (cls_data.get("token_info") or {}).get("symbol"):
                        addr_labels[addr] = cls_data["token_info"]["symbol"]


    trace = trace_data.get("trace", trace_data)
    if not isinstance(trace, dict) or "calls" not in trace:
        return {"contracts": [], "calls": []}

    contracts = {}
    calls = []

    def _add_contract(addr):
        addr = addr.lower()
        if addr not in contracts:
            label = addr_labels.get(addr, "")
            role = addr_protocols.get(addr, "unknown")
            contracts[addr] = {
                "address": addr,
                "label": label,
                "role": role,
            }

    def _walk(call, depth, parent_from=""):
        call_type = call.get("type", "CALL")
        to_addr = (call.get("to") or "").lower()
        from_addr = (call.get("from") or parent_from).lower()
        selector = (call.get("input") or "")[:10]
        error = call.get("error", "")
        value_hex = call.get("value", "0x0")

        if call_type in NOISE_CALL_TYPES:
            for sub in call.get("calls", []):
                _walk(sub, depth, from_addr)
            return

        if call_type == "DELEGATECALL":
            for sub in call.get("calls", []):
                _walk(sub, depth, from_addr)
            return

        if selector in NOISE_SELECTORS:
            return

        func_name = KNOWN_SELECTORS.get(selector, "")
        if not func_name and selector and len(selector) >= 10:
            func_name = selector

        if func_name in ("approve", "transfer", "transferFrom") and depth > 2:
            return

        if to_addr and from_addr and func_name:
            _add_contract(from_addr)
            _add_contract(to_addr)
            try:
                val_wei = int(value_hex, 16) if value_hex.startswith("0x") else 0
            except (ValueError, TypeError):
                val_wei = 0

            calls.append({
                "from": from_addr,
                "to": to_addr,
                "function": func_name,
                "depth": depth,
                "error": error,
                "value_wei": str(val_wei) if val_wei > 0 else "",
            })

        for sub in call.get("calls", []):
            _walk(sub, depth + 1, from_addr)

    _walk(trace, 0)

    # Determine protocol groupings from labels and well-known addresses
    protocol_groups = {}

    def _detect_protocol(addr, label):
        label_lower = (label or "").lower()
        # Check well-known token table
        wk = WELL_KNOWN_TOKENS.get(addr)
        if wk and wk[1] not in ("Token", "System"):
            return wk[1]
        if "curve" in label_lower or "3pool" in label_lower or "3crv" in label_lower:
            return "Curve"
        if "mim" in label_lower and "3crv" in label_lower:
            return "Curve"
        if "machine" in label_lower or "dialectic" in label_lower or "dusd" in label_lower:
            return "Machine"
        if "morpho" in label_lower:
            return "Morpho"
        if "aave" in label_lower or label_lower.startswith("a") and "usdc" in label_lower:
            return "Aave"
        if "uniswap" in label_lower or "uni " in label_lower:
            return "Uniswap"
        return None

    for addr, info in contracts.items():
        proto = _detect_protocol(addr, info.get("label", ""))
        if proto:
            info["protocol"] = proto
            protocol_groups.setdefault(proto, [])
            if addr not in protocol_groups[proto]:
                protocol_groups[proto].append(addr)

    return {
        "contracts": contracts,
        "calls": calls,
        "protocol_groups": protocol_groups,
    }


def _normalize_func(name: str) -> str:
    return name.lower().replace("_", "")


def _func_matches(call_func: str, ann_func: str) -> bool:
    if not ann_func:
        return True
    if call_func == ann_func:
        return True
    cn = _normalize_func(call_func)
    an = _normalize_func(ann_func)
    return cn == an or cn.startswith(an) or an.startswith(cn)


def _resolve_phases(call_sequence: dict, annotations: list) -> list[dict]:
    """Resolve annotations against the call list to produce phase ranges.

    Each annotation marks the start of a phase. The phase extends from
    its matched call index to the next phase's start - 1.
    """
    calls = call_sequence.get("calls", [])
    if not calls or not annotations:
        return []

    matched = []
    claimed = set()

    for ann in annotations:
        ann_from = (ann.get("from") or "").lower()
        ann_to = (ann.get("to") or "").lower()
        ann_func = ann.get("function", "")
        occurrence = ann.get("occurrence", 1)

        if isinstance(occurrence, str) and occurrence == "all":
            hit_count = 0
            for i, c in enumerate(calls):
                if i in claimed:
                    continue
                if ann_from and not c["from"].startswith(ann_from[:10]):
                    continue
                if ann_to and not c["to"].startswith(ann_to[:10]):
                    continue
                if ann_func and not _func_matches(c.get("function", ""), ann_func):
                    continue
                hit_count += 1
                matched.append((i, {**ann, "_occurrence": hit_count}))
                claimed.add(i)
        else:
            target_n = int(occurrence) if occurrence else 1
            hit_count = 0
            for i, c in enumerate(calls):
                if i in claimed:
                    continue
                if ann_from and not c["from"].startswith(ann_from[:10]):
                    continue
                if ann_to and not c["to"].startswith(ann_to[:10]):
                    continue
                if ann_func and not _func_matches(c.get("function", ""), ann_func):
                    continue
                hit_count += 1
                if hit_count == target_n:
                    matched.append((i, ann))
                    claimed.add(i)
                    break

    if not matched:
        return []

    matched.sort(key=lambda x: x[0])

    phases = []
    for idx, (call_idx, ann) in enumerate(matched):
        if idx + 1 < len(matched):
            end_idx = matched[idx + 1][0] - 1
        else:
            end_idx = len(calls) - 1

        occ = ann.get("_occurrence", "")
        title = ann.get("title", "")
        if occ and isinstance(occ, int) and occ > 1:
            title = f"{title} (cycle {occ})"

        count = end_idx - call_idx + 1
        phases.append({
            "title": title,
            "purpose": ann.get("purpose", ""),
            "phase": ann.get("phase", ""),
            "start_index": call_idx,
            "end_index": end_idx,
            "call_count": count,
            "collapsed_default": count > 15,
        })

    # If calls exist before the first annotation, prepend an implicit phase
    if matched[0][0] > 0:
        first_start = matched[0][0]
        phases.insert(0, {
            "title": "Pre-attack Setup",
            "purpose": "",
            "phase": "setup",
            "start_index": 0,
            "end_index": first_start - 1,
            "call_count": first_start,
            "collapsed_default": first_start > 15,
        })

    return phases


def _parse_walkthrough_from_md(md_text: str) -> list[dict]:
    steps = []
    in_walkthrough = False
    current_step = None
    for line in md_text.split("\n"):
        stripped = line.strip()
        if "## Attack Walkthrough" in stripped:
            in_walkthrough = True
            continue
        if stripped.startswith("## ") and in_walkthrough and "Walkthrough" not in stripped:
            break
        if not in_walkthrough:
            continue
        if stripped.startswith("### ") or stripped.startswith("#### Step"):
            if current_step:
                steps.append(current_step)
            title = re.sub(r"^#{1,4}\s*", "", stripped)
            current_step = {"title": title, "details": []}
        elif current_step and stripped:
            if stripped.startswith("**Call**:") or stripped.startswith("**call**:"):
                current_step["call"] = stripped.split(":", 1)[-1].strip().strip("`")
            elif stripped.startswith("**Purpose**:") or stripped.startswith("**purpose**:"):
                current_step["purpose"] = stripped.split(":", 1)[-1].strip()
            elif stripped.startswith("**Source**:") or stripped.startswith("**source**:"):
                current_step["source"] = stripped.split(":", 1)[-1].strip().strip("`")
            elif stripped.startswith("**USD impact**:"):
                current_step["usd_impact"] = stripped.split(":", 1)[-1].strip()
            else:
                current_step["details"].append(stripped)
    if current_step:
        steps.append(current_step)
    return steps


def _parse_contracts_table_from_md(md_text: str) -> list[dict]:
    contracts = []
    in_table = False
    headers = []
    for line in md_text.split("\n"):
        stripped = line.strip()
        if "## Contracts Involved" in stripped:
            in_table = True
            continue
        if stripped.startswith("## ") and in_table and "Contracts" not in stripped:
            break
        if not in_table:
            continue
        if stripped.startswith("|") and stripped.endswith("|"):
            cells = [c.strip() for c in stripped.split("|")[1:-1]]
            if all(c.replace("-", "").replace(":", "").strip() == "" for c in cells):
                continue
            if not headers:
                headers = [c.lower() for c in cells]
            else:
                entry = {}
                for i, h in enumerate(headers):
                    if i < len(cells):
                        val = cells[i].strip("`").strip()
                        entry[h] = val
                if entry:
                    contracts.append(entry)
    return contracts


def _load_findings(findings_dir: Path) -> dict:
    findings = {}
    if not findings_dir.exists():
        return findings
    for f in sorted(findings_dir.glob("*.md")):
        findings[f.stem] = f.read_text()
    return findings
