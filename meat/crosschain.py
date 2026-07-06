"""Cross-chain fund-tracing helpers: Bitcoin (Blockstream) and THORChain (memo + Midgard).

These make the manual, error-prone parts of fund tracing DETERMINISTIC:
  - Bitcoin peel-chain following, dormancy/consolidation/OP_RETURN detection
  - THORChain depositWithExpiry memo decode (what the swap will do) + best-effort output resolution

All data comes from public JSON APIs (no HTML scraping): consistent with the "on-chain data via
configured APIs" rule. Every fetch is deterministic and suitable for write-once evidence.
"""
from __future__ import annotations

import json
from pathlib import Path

import requests

BLOCKSTREAM_BASE = "https://blockstream.info/api"
# Midgard instances (THORChain and its Maya fork share the same API + memo format)
MIDGARD_BASE = "https://midgard.ninerealms.com/v2"
MAYA_MIDGARD_BASE = "https://midgard.mayachain.info/v2"  # verified via research
MIDGARD_BY_PROTOCOL = {"thorchain": MIDGARD_BASE, "maya": MAYA_MIDGARD_BASE}
SAT = 100_000_000


class CrossChainError(Exception):
    pass


# ---------------------------------------------------------------------------
# Bitcoin (Blockstream REST — pure JSON)
# ---------------------------------------------------------------------------

def _bs_get(path: str, timeout: int = 30):
    try:
        resp = requests.get(BLOCKSTREAM_BASE + path, timeout=timeout)
        resp.raise_for_status()
    except requests.Timeout:
        raise CrossChainError(f"Blockstream timed out after {timeout}s: {path}")
    except requests.HTTPError as e:
        raise CrossChainError(f"Blockstream HTTP error {resp.status_code}: {path}")
    except requests.RequestException as e:
        raise CrossChainError(f"Blockstream request failed: {e}")
    return resp


def _decode_op_return(vout: dict) -> str | None:
    """Extract an OP_RETURN payload as text, if present."""
    if vout.get("scriptpubkey_type") != "op_return":
        return None
    asm = vout.get("scriptpubkey_asm", "")
    # asm looks like "OP_RETURN OP_PUSHBYTES_78 <hex> ..." — collect hex tokens
    hexparts = []
    for tok in asm.split():
        if tok.startswith("OP_"):
            continue
        if len(tok) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in tok):
            hexparts.append(tok)
    if not hexparts:
        return None
    try:
        raw = bytes.fromhex("".join(hexparts))
        text = raw.decode("utf-8", errors="replace")
        return text
    except ValueError:
        return None


def btc_address_summary(addr: str, timeout: int = 30) -> dict:
    """Balance + dormancy state for a Bitcoin address."""
    d = _bs_get(f"/address/{addr}", timeout).json()
    cs = d.get("chain_stats", {})
    ms = d.get("mempool_stats", {})
    funded = cs.get("funded_txo_sum", 0) + ms.get("funded_txo_sum", 0)
    spent = cs.get("spent_txo_sum", 0) + ms.get("spent_txo_sum", 0)
    tx_count = cs.get("tx_count", 0) + ms.get("tx_count", 0)
    bal = funded - spent
    return {
        "address": addr,
        "balance_sat": bal,
        "balance_btc": round(bal / SAT, 8),
        "received_sat": funded,
        "sent_sat": spent,
        "tx_count": tx_count,
        # forensic flags
        "dormant": bal > 0 and spent == 0,          # received, never spent onward
        "fully_swept": funded > 0 and bal == 0,     # emptied out
    }


def btc_tx(txid: str, timeout: int = 30) -> dict:
    """Structured inputs/outputs for a Bitcoin tx (addresses + values + OP_RETURN)."""
    d = _bs_get(f"/tx/{txid}", timeout).json()
    vin = []
    in_addrs = set()
    for v in d.get("vin", []):
        po = v.get("prevout") or {}
        a = po.get("scriptpubkey_address")
        vin.append({"address": a, "value_sat": po.get("value")})
        if a:
            in_addrs.add(a)
    vout = []
    op_returns = []
    for o in d.get("vout", []):
        if o.get("scriptpubkey_type") == "op_return":
            msg = _decode_op_return(o)
            if msg:
                op_returns.append(msg)
            vout.append({"address": None, "value_sat": o.get("value", 0), "op_return": msg})
        else:
            vout.append({"address": o.get("scriptpubkey_address"), "value_sat": o.get("value", 0)})
    return {
        "txid": txid,
        "confirmed": d.get("status", {}).get("confirmed", False),
        "block_height": d.get("status", {}).get("block_height"),
        "block_time": d.get("status", {}).get("block_time"),
        "fee_sat": d.get("fee"),
        "n_vin": len(vin),
        "n_vout": len(vout),
        "distinct_input_addresses": len(in_addrs),
        "vin": vin,
        "vout": vout,
        "op_returns": op_returns,
    }


def _address_txs(addr: str, timeout: int = 30) -> list[dict]:
    """Confirmed + mempool txs for an address (Blockstream returns up to ~25 most-recent)."""
    return _bs_get(f"/address/{addr}/txs", timeout).json()


def _load_registry(registry_path: Path | None) -> dict:
    """Flatten labels/known_addresses.json to {addr_lower: (category, name)}."""
    flat = {}
    if not registry_path or not registry_path.exists():
        return flat
    try:
        reg = json.loads(registry_path.read_text())
    except (json.JSONDecodeError, IOError):
        return flat
    for cat, v in reg.items():
        if isinstance(v, dict) and not cat.startswith("_"):
            for a, name in v.items():
                if isinstance(name, str):
                    flat[a.lower()] = (cat, name)
    return flat


def btc_trace(start: str, max_hops: int = 20, follow: str = "largest",
              min_sat: int = 10_000, max_branch: int = 3,
              registry_path: Path | None = None, timeout: int = 30) -> dict:
    """Follow BTC forward from `start`, hop by hop.

    follow="largest": peel-chain — follow only the single largest onward output per address.
    follow="all":     follow every recipient output >= min_sat, up to max_branch per address.

    Stops a branch at: a dormant/unspent endpoint, a consolidation sweep (many distinct inputs =
    likely a service), a registry-known service/CEX/mixer, an already-visited address, or max_hops.
    Returns nodes[], edges[], and endpoints[] classified by why the trail ended.
    """
    registry = _load_registry(registry_path)
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    endpoints: list[dict] = []
    op_return_hits: list[dict] = []
    visited: set[str] = set()
    # queue of (address, hops_used, amount_arriving_sat)
    queue = [(start, 0, None)]

    def note_node(addr, **extra):
        if addr not in nodes:
            summ = btc_address_summary(addr, timeout)
            reg = registry.get(addr.lower())
            if reg:
                summ["known_entity"] = {"category": reg[0], "name": reg[1]}
            nodes[addr] = summ
        nodes[addr].update({k: v for k, v in extra.items() if v is not None})
        return nodes[addr]

    while queue:
        addr, hops, arriving = queue.pop(0)
        if addr in visited:
            continue
        visited.add(addr)
        summ = note_node(addr)

        # registry hit -> custody hand-off, stop
        if summ.get("known_entity"):
            endpoints.append({"address": addr, "reason": "known_service",
                              "entity": summ["known_entity"], "balance_sat": summ["balance_sat"]})
            continue
        # dormant -> unspent endpoint, stop
        if summ["dormant"]:
            endpoints.append({"address": addr, "reason": "dormant_unspent",
                              "balance_sat": summ["balance_sat"], "balance_btc": summ["balance_btc"]})
            continue
        if hops >= max_hops:
            endpoints.append({"address": addr, "reason": "max_hops", "balance_sat": summ["balance_sat"]})
            continue

        # find outgoing spends and their onward recipients
        try:
            txs = _address_txs(addr, timeout)
        except CrossChainError:
            endpoints.append({"address": addr, "reason": "fetch_error"})
            continue

        onward = []  # (recipient, value_sat, txid)
        for tx in txs:
            in_addrs = {(v.get("prevout") or {}).get("scriptpubkey_address") for v in tx.get("vin", [])}
            if addr not in in_addrs:
                continue  # not a spend BY this address
            # capture OP_RETURN messages on any tx touching this address
            for o in tx.get("vout", []):
                if o.get("scriptpubkey_type") == "op_return":
                    msg = _decode_op_return(o)
                    if msg:
                        op_return_hits.append({"txid": tx.get("txid"), "address": addr, "message": msg})
            recipients = [o for o in tx.get("vout", [])
                          if o.get("scriptpubkey_address") and o.get("scriptpubkey_address") != addr]
            for o in recipients:
                onward.append((o["scriptpubkey_address"], o.get("value", 0), tx.get("txid")))

        if not onward:
            # spent but only to self / no external recipient, or unspendable
            endpoints.append({"address": addr, "reason": "no_onward_output", "balance_sat": summ["balance_sat"]})
            continue

        onward.sort(key=lambda x: -x[1])
        if follow == "largest":
            chosen = onward[:1]
        else:
            chosen = [o for o in onward if o[1] >= min_sat][:max_branch]

        for recip, val, txid in chosen:
            # detect consolidation: does the recipient's receiving tx merge many distinct inputs?
            try:
                rtx = btc_tx(txid, timeout)
                consolidation = rtx["distinct_input_addresses"] >= 5
            except CrossChainError:
                consolidation = False
            edges.append({"from": addr, "to": recip, "value_sat": val,
                          "value_btc": round(val / SAT, 8), "txid": txid,
                          "consolidation_sweep": consolidation})
            note_node(recip, arrived_sat=val)
            if consolidation:
                endpoints.append({"address": recip, "reason": "consolidation_sweep",
                                  "txid": txid, "note": "many distinct inputs — likely a service/exchange sweep"})
                visited.add(recip)  # don't trace into a service's commingled wallet
            else:
                queue.append((recip, hops + 1, val))

    return {
        "start": start,
        "follow": follow,
        "max_hops": max_hops,
        "nodes": nodes,
        "edges": edges,
        "endpoints": endpoints,
        "op_returns": op_return_hits,
        "summary": {
            "hops_traced": len(edges),
            "addresses_seen": len(nodes),
            "dormant_endpoints": [e for e in endpoints if e["reason"] == "dormant_unspent"],
            "service_endpoints": [e for e in endpoints if e["reason"] in ("known_service", "consolidation_sweep")],
        },
    }


# ---------------------------------------------------------------------------
# THORChain (memo decode + best-effort Midgard resolution)
# ---------------------------------------------------------------------------

# THORChain asset short-codes (common). Full "CHAIN.ASSET" passes through unchanged.
_THOR_ASSET = {
    "b": "BTC.BTC", "e": "ETH.ETH", "a": "AVAX.AVAX", "d": "DOGE.DOGE",
    "l": "LTC.LTC", "c": "BCH.BCH", "g": "GAIA.ATOM", "n": "BNB.BNB",
    "r": "THOR.RUNE", "s": "BSC.BNB",
}
_THOR_ACTION = {"=": "SWAP", "s": "SWAP", "swap": "SWAP", "add": "ADD_LIQUIDITY",
                "+": "ADD_LIQUIDITY", "-": "WITHDRAW", "wd": "WITHDRAW", "out": "OUTBOUND"}


def decode_thor_memo(memo: str) -> dict:
    """Decode a THORChain memo, e.g. '=:b:bc1q...:limit/interval/qty:affiliate:bps'.

    Purely deterministic string parse — tells you where the swap will deliver and in what asset.
    """
    parts = memo.split(":")
    action_raw = parts[0].strip().lower() if parts else ""
    out = {
        "raw": memo,
        "action": _THOR_ACTION.get(action_raw, action_raw.upper() or "UNKNOWN"),
    }
    if len(parts) > 1 and parts[1]:
        code = parts[1].strip()
        out["dest_asset"] = _THOR_ASSET.get(code.lower(), code)
    if len(parts) > 2 and parts[2]:
        out["dest_address"] = parts[2].strip()
    if len(parts) > 3 and parts[3]:
        # limit[/interval/count] for streaming swaps
        lim = parts[3].strip()
        out["limit"] = lim
        if "/" in lim:
            bits = lim.split("/")
            out["streaming"] = {"limit": bits[0], "interval": bits[1] if len(bits) > 1 else None,
                                "quantity": bits[2] if len(bits) > 2 else None}
    if len(parts) > 4 and parts[4]:
        out["affiliate"] = parts[4].strip()
    if len(parts) > 5 and parts[5]:
        out["affiliate_bps"] = parts[5].strip()
    return out


def midgard_resolve(txid: str, base_url: str = MIDGARD_BASE, timeout: int = 30) -> dict | None:
    """Best-effort: resolve a THORChain/Maya action's actual output via Midgard.

    `base_url` selects the network (THORChain or the Maya fork — same API surface). Returns None if
    Midgard doesn't index the tx (common for older/pruned actions) — the caller should degrade
    gracefully to the memo decode rather than treating None as 'no swap happened'.
    """
    txid_clean = txid[2:] if txid.startswith("0x") else txid
    for candidate in (txid_clean.upper(), txid_clean.lower()):
        try:
            resp = requests.get(f"{base_url}/actions", params={"txid": candidate},
                                headers={"x-client-id": "meat-evm"}, timeout=timeout)
            if resp.status_code != 200 or not resp.text.strip():
                continue
            data = resp.json()
        except (requests.RequestException, json.JSONDecodeError):
            continue
        actions = data.get("actions", [])
        if not actions:
            continue
        outs = []
        for a in actions:
            for o in a.get("out", []):
                outs.append({"address": o.get("address"), "coins": o.get("coins"), "txid": o.get("txID")})
        return {"status": actions[0].get("status"), "type": actions[0].get("type"),
                "pools": actions[0].get("pools"), "out": outs}
    return None


# ---------------------------------------------------------------------------
# deBridge DLN (intent cross-chain — full resolver via stats-api.dln.trade)
# ---------------------------------------------------------------------------

DLN_STATS_BASE = "https://stats-api.dln.trade/api"
# deBridge internal chain ids: EVM use real chain ids; non-EVM get custom ids.
_DLN_CHAIN = {
    "1": "Ethereum", "10": "Optimism", "56": "BNB Chain", "100": "Gnosis",
    "137": "Polygon", "146": "Sonic", "8453": "Base", "42161": "Arbitrum",
    "43114": "Avalanche", "59144": "Linea", "7565164": "Solana",
    "100000001": "Neon", "100000002": "Gnosis", "100000004": "Metis",
    "100000013": "Story", "100000014": "Sonic", "100000017": "HyperEVM",
}


def _dln_chain(cid) -> str:
    cid = str(cid)
    return _DLN_CHAIN.get(cid, f"chain:{cid}")


def _dln_offer(offer: dict) -> dict:
    """Flatten a give/take offer into {chain, token, symbol, amount_raw, amount}."""
    if not offer:
        return {}
    meta = offer.get("metadata") or {}
    dec = meta.get("decimals")
    raw = (offer.get("amount") or {}).get("bigIntegerValue")
    amount = None
    if raw is not None and dec is not None:
        try:
            amount = int(raw) / (10 ** int(dec))
        except (ValueError, TypeError):
            amount = None
    return {
        "chain": _dln_chain((offer.get("chainId") or {}).get("stringValue")),
        "token": (offer.get("tokenAddress") or {}).get("stringValue"),
        "symbol": meta.get("symbol"),
        "amount_raw": raw,
        "amount": amount,
    }


def debridge_resolve(tx_hash: str, timeout: int = 30) -> dict | None:
    """Resolve a deBridge DLN order by its source-chain creation tx hash.

    Returns the full cross-chain mapping (give side, take side, destination recipient, both tx
    hashes, state) or None if the tx isn't a DLN order. Deterministic public API — no auth.
    """
    try:
        resp = requests.get(f"{DLN_STATS_BASE}/Orders/creationTxHash/{tx_hash}", timeout=timeout)
        if resp.status_code != 200 or not resp.text.strip():
            return None
        d = resp.json()
    except (requests.RequestException, json.JSONDecodeError):
        return None
    if not d or not d.get("orderId"):
        return None
    src_tx = ((d.get("createdSrcEventMetadata") or {}).get("transactionHash") or {}).get("stringValue")
    dst_tx = ((d.get("fulfilledDstEventMetadata") or {}).get("transactionHash") or {}).get("stringValue")
    return {
        "protocol": "deBridge DLN",
        "order_id": (d.get("orderId") or {}).get("stringValue"),
        "state": d.get("state"),
        "give": _dln_offer(d.get("giveOfferWithMetadata")),
        "take": _dln_offer(d.get("takeOfferWithMetadata")),
        "receiver_dst": (d.get("receiverDst") or {}).get("stringValue"),
        "src_tx": src_tx,
        "dst_tx": dst_tx,
        "note": "dst_tx / receiver_dst are on the DESTINATION chain (give.chain -> take.chain). "
                "Switch chains and keep tracing from receiver_dst.",
    }


# ---------------------------------------------------------------------------
# Orbiter Finance (L2<->L2 — source-side confirm; dest leg not in public API)
# ---------------------------------------------------------------------------

ORBITER_API = "https://api.orbiter.finance"


def orbiter_resolve(tx_hash: str, timeout: int = 30) -> dict | None:
    """Confirm an Orbiter transfer and return its source-side facts.

    Orbiter's public /transaction/{hash} endpoint exposes the SOURCE tx (chain, sender, receiver,
    amount, symbol, status) but NOT the destination tx — Orbiter matches the paired transfer off an
    amount identification code it does not publish. So this deterministically confirms the Orbiter
    hand-off + amount/direction, but the destination leg must be found on the target chain manually.
    Returns None if the tx isn't an Orbiter transfer.
    """
    try:
        resp = requests.get(f"{ORBITER_API}/transaction/{tx_hash}", timeout=timeout)
        if resp.status_code != 200:
            return None
        d = resp.json()
    except (requests.RequestException, json.JSONDecodeError):
        return None
    if d.get("status") != "success" or not d.get("result"):
        return None
    r = d["result"]
    return {
        "protocol": "Orbiter Finance",
        "source_chain": r.get("chainId"),
        "sender": r.get("sender"),
        "receiver": r.get("receiver"),
        "amount": r.get("amount"),
        "symbol": r.get("symbol"),
        "timestamp": r.get("timestamp"),
        "status_code": r.get("status"),
        "op_status": r.get("opStatus"),
        "note": "Source-side only — Orbiter's public API does not expose the destination tx. This is "
                "a cross-chain hand-off; find the paired transfer on the target chain (an Orbiter "
                "Maker EOA pays out an equal amount, minus a small withholding fee).",
    }
