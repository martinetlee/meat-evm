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
    evidence_index = _build_evidence_index(evidence_dir)
    evidence_data = _load_evidence_data(evidence_dir)

    transactions = _extract_transactions(evidence_data)
    native_token = chain_cfg.get("native_token", "ETH")
    case_created = case_json.get("created")
    rpc = None
    try:
        chain_obj = cfg.get_chain(chain_name)
        if chain_obj.has_rpc():
            rpc = RPCClient(chain_obj.rpc_url)
    except (ValueError, Exception):
        pass
    flow = _extract_flow(evidence_data, addresses, chain_name, native_token, rpc,
                         case_created)
    analysis = _extract_analysis(case_dir, evidence_data)

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


def _extract_analysis(case_dir: Path, evidence_data: dict) -> dict:
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

    return analysis


def _load_findings(findings_dir: Path) -> dict:
    findings = {}
    if not findings_dir.exists():
        return findings
    for f in sorted(findings_dir.glob("*.md")):
        findings[f.stem] = f.read_text()
    return findings
