"""Deterministic analysis helpers: provenance, profit resolution, and the case
invariant checker (`meat check`).

The point of this module is to move the checks an analyst is prone to *skip* out
of "things to remember" and into code that computes them and fails loudly. The
flagship is `check_case`, whose value-conservation invariant catches the classic
error of concluding an attack without identifying who actually lost the money.
"""
from __future__ import annotations

import json
from pathlib import Path

# Exact canonical symbols of fungible USD stablecoins. Matched case-sensitively
# and exactly so that manipulated vault tokens whose symbols merely *contain*
# "USD" (vgUSDC, LVUSDC, gtUSDC, ...) are NOT counted as money — they are the
# illiquid assets an attacker injects, not realized value.
STABLE_SYMBOLS = {
    "USDC", "USDT", "DAI", "USDS", "FRAX", "TUSD", "USDP", "GUSD", "LUSD",
    "crvUSD", "PYUSD", "USDe", "USDD", "sUSD", "USDL", "USD0", "BUSD", "FDUSD",
}

# Addresses that are never "counterparties" for conservation purposes.
SYSTEM_ADDRESSES = {
    "0x0000000000000000000000000000000000000000",  # zero / mint / burn
    "0x000000000000000000000000000000000000dead",  # burn
    "0x0000000000000000000000000000000000000001",  # ecrecover precompile
}

VALUE_ROLES = {"attacker", "victim"}  # roles that require provenance


def _f(x) -> float:
    try:
        return float(x)
    except (TypeError, ValueError):
        return 0.0


def _load_envelope(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text()).get("data")
    except (json.JSONDecodeError, IOError, OSError):
        return None


# --------------------------------------------------------------------------- #
# Provenance: where did an address first get a token?
# --------------------------------------------------------------------------- #
def first_inbound_sources(transfers: list[dict], address: str,
                          token: str | None = None) -> list[dict]:
    """Given raw explorer tokentx records, return the earliest inbound source of
    each token received by `address` (optionally filtered to one token)."""
    addr = address.lower()
    tok = token.lower() if token else None

    inbound = []
    for t in transfers:
        if (t.get("to") or "").lower() != addr:
            continue
        ca = (t.get("contractAddress") or "").lower()
        if tok and ca != tok:
            continue
        inbound.append(t)

    inbound.sort(key=lambda t: (int(t.get("blockNumber", 0) or 0),
                                int(t.get("transactionIndex", 0) or 0)))

    per_token: dict[str, list[dict]] = {}
    for t in inbound:
        per_token.setdefault((t.get("contractAddress") or "").lower(), []).append(t)

    out = []
    for ca, lst in per_token.items():
        first = lst[0]
        sources: dict[str, int] = {}
        for t in lst:
            frm = (t.get("from") or "").lower()
            sources[frm] = sources.get(frm, 0) + 1
        dec = int(first.get("tokenDecimal") or 18)
        out.append({
            "token_address": ca,
            "token_symbol": first.get("tokenSymbol"),
            "inbound_count": len(lst),
            "distinct_sources": len(sources),
            "first_seen_block": int(first.get("blockNumber", 0) or 0),
            "first_from": (first.get("from") or "").lower(),
            "first_tx": first.get("hash"),
            "first_amount": _f(first.get("value", 0)) / (10 ** dec),
            "sources": [
                {"from": s, "transfers": c}
                for s, c in sorted(sources.items(), key=lambda kv: -kv[1])
            ][:10],
            "single_source": len(sources) == 1,
        })
    out.sort(key=lambda r: r["first_seen_block"])
    return out


# --------------------------------------------------------------------------- #
# Profit: which tx realizes the largest net stablecoin gain for an address?
# --------------------------------------------------------------------------- #
def per_tx_net(transfers: list[dict], address: str) -> dict[str, dict]:
    """Group tokentx records by tx hash and compute the net amount of each token
    for `address` (positive = received). Returns {hash: {...}}."""
    addr = address.lower()
    by_tx: dict[str, dict] = {}
    for t in transfers:
        frm = (t.get("from") or "").lower()
        to = (t.get("to") or "").lower()
        if addr not in (frm, to):
            continue
        h = t.get("hash")
        dec = int(t.get("tokenDecimal") or 18)
        val = _f(t.get("value", 0)) / (10 ** dec)
        sym = t.get("tokenSymbol") or (t.get("contractAddress") or "?")
        entry = by_tx.setdefault(h, {
            "hash": h,
            "block": int(t.get("blockNumber", 0) or 0),
            "net": {},
        })
        e = entry["net"].setdefault(sym, {
            "symbol": sym,
            "token": (t.get("contractAddress") or "").lower(),
            "amount": 0.0,
        })
        e["amount"] += val if to == addr else -val
    return by_tx


def rank_profit(by_tx: dict[str, dict]) -> list[dict]:
    """Value each tx's net movement by stablecoins ($1) and rank descending."""
    ranked = []
    for h, entry in by_tx.items():
        net_stable = 0.0
        for sym, e in entry["net"].items():
            if sym in STABLE_SYMBOLS:
                net_stable += e["amount"]
        gains = {s: round(e["amount"], 4) for s, e in entry["net"].items()
                 if abs(e["amount"]) > 1e-9}
        ranked.append({
            "hash": h,
            "block": entry["block"],
            "net_stablecoin_usd": round(net_stable, 2),
            "net_by_token": gains,
        })
    ranked.sort(key=lambda r: r["net_stablecoin_usd"], reverse=True)
    return ranked


# --------------------------------------------------------------------------- #
# Check: enforce case invariants. Pure + offline (safe to run in a hook).
# --------------------------------------------------------------------------- #
def _price(symbol: str, eth_price: float | None) -> float | None:
    """USD price of one unit, or None if we can't price it offline. Only exact
    stablecoin symbols and (optionally) ETH/WETH are priced; everything else —
    including manipulated vault shares — is 'unpriced' and treated as non-money."""
    if symbol in STABLE_SYMBOLS:
        return 1.0
    if eth_price and symbol in ("ETH", "WETH"):
        return eth_price
    return None


def _tx_flows(tx_data: dict) -> dict[str, dict[str, float]]:
    """Per-address, per-symbol net amount within one tx, from net_flows."""
    flows: dict[str, dict[str, float]] = {}
    for addr, tokens in (tx_data.get("net_flows") or {}).items():
        a = addr.lower()
        d = flows.setdefault(a, {})
        for sym, detail in tokens.items():
            amt = _f(detail.get("formatted") if isinstance(detail, dict) else detail)
            d[sym] = d.get(sym, 0.0) + amt
    return flows


def _priced_net(addr_flows: dict[str, float], eth_price: float | None) -> float:
    total = 0.0
    for sym, amt in addr_flows.items():
        p = _price(sym, eth_price)
        if p is not None:
            total += amt * p
    return total


def _role(labeled: dict, addr: str) -> str | None:
    info = labeled.get(addr)
    return info.get("role") if info else None


def analyze_tx_value(tx_data: dict, labeled: dict, eth_price: float | None = None,
                     min_usd: float = 100_000.0, dump_frac: float = 0.25) -> dict:
    """Attribute value movement in one tx: priced winners/losers, and who the
    attacker offloaded illiquid (unpriced) tokens onto (asset-substitution
    victims). Pure function over net_flows — the core of loss attribution."""
    flows = _tx_flows(tx_data)

    priced = {a: _priced_net(f, eth_price) for a, f in flows.items()}
    attacker_gain = sum(v for a, v in priced.items()
                        if v > 0 and _role(labeled, a) == "attacker")

    # Illiquid (unpriced) tokens an attacker sent DIRECTLY to a non-attacker are
    # assets being offloaded — the classic NAV/oracle-manipulation move. Use the
    # transfer edges (not net totals) so we only attribute value the attacker
    # actually pushed onto someone, not e.g. a protocol's own mint to a third
    # party.
    dumped: dict[str, float] = {}
    dumped_to: dict[str, dict[str, float]] = {}
    for t in tx_data.get("token_transfers") or []:
        frm = (t.get("from") or "").lower()
        to = (t.get("to") or "").lower()
        sym = t.get("token_symbol") or (t.get("token_address") or "")
        if _role(labeled, frm) != "attacker":
            continue
        if _price(sym, eth_price) is not None:
            continue  # priced asset, not an "offload"
        if to in SYSTEM_ADDRESSES or _role(labeled, to) == "attacker":
            continue
        amt = _f(t.get("amount_formatted"))
        if amt <= 0:
            raw = _f(t.get("amount_raw"))
            dec = int(t.get("token_decimals") or 18)
            amt = raw / (10 ** dec)
        dumped[sym] = dumped.get(sym, 0.0) + amt
        dumped_to.setdefault(to, {})[sym] = dumped_to.get(to, {}).get(sym, 0.0) + amt

    # Recipients that absorbed a meaningful share of a dumped token are the
    # candidates for who actually ate the loss.
    dump_receivers: dict[str, dict[str, float]] = {}
    for a, toks in dumped_to.items():
        for sym, amt in toks.items():
            if dumped.get(sym) and amt >= dump_frac * dumped[sym]:
                dump_receivers.setdefault(a, {})[sym] = amt

    return {
        "priced": priced,
        "attacker_gain": attacker_gain,
        "dumped_tokens": dumped,
        "dump_receivers": dump_receivers,
        "priced_movers": {a: v for a, v in priced.items() if abs(v) >= min_usd},
    }


def _decisive_txs(case: dict) -> list[str]:
    hashes = []
    for key in ("attack_tx", "monetization_tx", "realized_profit_tx"):
        v = case.get(key)
        if isinstance(v, str) and v.startswith("0x") and len(v) == 66:
            hashes.append(v.lower())
    # also accept a list under attack_txs
    v = case.get("attack_txs")
    if isinstance(v, list):
        for h in v:
            if isinstance(h, str) and h.startswith("0x") and len(h) == 66:
                hashes.append(h.lower())
    seen, out = set(), []
    for h in hashes:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def check_case(case_dir: Path, min_usd: float = 100_000.0) -> dict:
    """Run invariant checks over a case directory. Returns a structured report;
    `passed` is False if there are any hard violations."""
    violations: list[dict] = []
    warnings: list[dict] = []

    case_file = case_dir / "case.json"
    if not case_file.exists():
        return {"passed": False, "violations": [{"invariant": "case_exists",
                "detail": f"no case.json in {case_dir}"}], "warnings": []}
    case = json.loads(case_file.read_text())

    addr_file = case_dir / "addresses.json"
    addresses = {}
    if addr_file.exists():
        try:
            addresses = json.loads(addr_file.read_text())
        except json.JSONDecodeError:
            pass
    labeled = {k.lower(): v for k, v in addresses.items()}

    ev = case_dir / "evidence"
    prov_stems = []
    prov_dir = ev / "provenance"
    if prov_dir.exists():
        prov_stems = [p.stem.lower() for p in prov_dir.glob("*.json")]

    min_usd = float(case.get("check_min_usd", min_usd))
    eth_price = case.get("eth_price_usd")
    eth_price = float(eth_price) if eth_price else None
    decisive = _decisive_txs(case)
    victim_candidates: list[dict] = []

    # --- Invariant 1: decisive txs fetched in full -------------------------- #
    fetched: dict[str, dict] = {}
    for h in decisive:
        f = ev / "tx" / f"{h}.json"
        if not f.exists():
            violations.append({
                "invariant": "money_out_tx_fetched",
                "detail": f"decisive tx {h} is declared but not fetched to evidence/tx/. "
                          f"Run `meat tx {h}` (full, not --compact).",
            })
            continue
        data = _load_envelope(f)
        if not data:
            violations.append({"invariant": "money_out_tx_fetched",
                               "detail": f"evidence/tx/{h}.json is unreadable"})
            continue
        if not data.get("token_transfers") and not data.get("net_flows"):
            violations.append({
                "invariant": "money_out_tx_fetched",
                "detail": f"tx {h} was fetched compact (no token_transfers/net_flows). "
                          f"Re-run `meat tx {h}` without --compact.",
            })
            continue
        fetched[h] = data

    if not decisive:
        warnings.append({"invariant": "money_out_tx_fetched",
                         "detail": "no attack_tx/monetization_tx declared in case.json"})

    # --- Invariant 2: value conservation & loss attribution ----------------- #
    # For each decisive tx: (a) every large priced (stablecoin/ETH) mover must be
    # labeled; (b) recipients of tokens an attacker offloaded are victim
    # candidates and must be labeled; (c) the attacker's priced gain must be
    # accounted for by a VICTIM-role address — either a priced loss or absorbing
    # the dumped illiquid asset. This is what forces "who actually lost funds?".
    for h, data in fetched.items():
        va = analyze_tx_value(data, labeled, eth_price=eth_price, min_usd=min_usd)

        # (a) large priced movers must be labeled
        for a, net in va["priced_movers"].items():
            if a in SYSTEM_ADDRESSES or a in labeled:
                continue
            violations.append({
                "invariant": "value_conservation",
                "detail": f"unlabeled net {'winner' if net > 0 else 'loser'} {a} moved "
                          f"{net:+,.0f} USD (priced) in tx {h}. Identify and label who "
                          f"this is before concluding.",
            })

        # (b) recipients of attacker-dumped illiquid tokens = victim candidates
        for a, toks in va["dump_receivers"].items():
            desc = ", ".join(f"{amt:,.0f} {sym}" for sym, amt in toks.items())
            role = _role(labeled, a)
            victim_candidates.append({"address": a, "tx": h, "received": toks, "role": role})
            if a not in labeled:
                violations.append({
                    "invariant": "loss_attribution",
                    "detail": f"{a} received attacker-offloaded illiquid tokens ({desc}) in "
                              f"tx {h} — this is the classic NAV/oracle-drain signature and it "
                              f"is likely the VICTIM that ate the loss. Investigate and label it.",
                })

        # (c) attacker priced gain must be accounted for by a VICTIM-role address
        if va["attacker_gain"] >= min_usd:
            victim_priced_loss = -sum(
                v for a, v in va["priced"].items()
                if v < 0 and _role(labeled, a) == "victim"
            )
            victim_absorbed_dump = any(
                _role(labeled, a) == "victim" for a in va["dump_receivers"]
            )
            if victim_priced_loss < 0.5 * va["attacker_gain"] and not victim_absorbed_dump:
                cand = [a for a in va["dump_receivers"]] or [
                    a for a, v in va["priced"].items()
                    if v <= -min_usd and _role(labeled, a) != "attacker"
                ]
                cand_str = ", ".join(cand) if cand else "none found in flows — widen the tx set"
                violations.append({
                    "invariant": "loss_attribution",
                    "detail": f"in tx {h} the attacker gained ~{va['attacker_gain']:,.0f} USD but "
                              f"no address labeled 'victim' shows a matching priced loss or absorbed "
                              f"the dumped asset. WHO LOST THE MONEY? Candidates: {cand_str}. "
                              f"Label the true victim (role=victim) — do not conclude until you have.",
                })

    # --- Invariant 2b: profit tx must be a declared decisive tx ------------- #
    profit_dir = ev / "profit"
    if profit_dir.exists():
        for pf in profit_dir.glob("*.json"):
            pdata = _load_envelope(pf) or {}
            rpt = pdata.get("realized_profit_tx") or {}
            phash = (rpt.get("hash") or "").lower()
            if phash and phash not in decisive:
                violations.append({
                    "invariant": "money_out_tx_fetched",
                    "detail": f"`meat profit` identified {phash} as the largest realized-gain tx "
                              f"(~{rpt.get('net_stablecoin_usd')} USD) but it is not declared as a "
                              f"decisive tx in case.json. Add it and analyze it in full.",
                })

    # --- Invariant 3: provenance for attacker/victim ------------------------ #
    for a, info in labeled.items():
        role = info.get("role")
        if role not in VALUE_ROLES:
            continue
        has_prov = any(stem.startswith(a) for stem in prov_stems)
        if has_prov or info.get("provenance") or info.get("provenance_waived"):
            continue
        violations.append({
            "invariant": "provenance_required",
            "detail": f"address {a} labeled '{role}' has no provenance. Run "
                      f"`meat provenance {a}` (or set provenance_waived) — verify "
                      f"where its funds/tokens came from before labeling.",
        })

    # --- Invariant 4 (warn): earned negatives ------------------------------- #
    blob = json.dumps(case).lower()
    negatives = ["not a vuln", "not a smart", "not a contract", "just phishing",
                 "not an exploit", "no vulnerability"]
    if any(n in blob for n in negatives):
        findings = case_dir / "findings"
        traced = False
        if findings.exists():
            for md in findings.glob("*.md"):
                txt = md.read_text().lower()
                if "value" in txt and ("flow" in txt or "trace" in txt or "conserv" in txt):
                    traced = True
                    break
        if not traced:
            warnings.append({
                "invariant": "earned_negatives",
                "detail": "case asserts a negative ('not a vulnerability' / 'just phishing') "
                          "but no findings file documents a full value-flow trace. "
                          "Only state negatives you have traced end-to-end.",
            })

    return {
        "passed": len(violations) == 0,
        "case": case.get("name"),
        "min_usd_threshold": min_usd,
        "eth_priced": eth_price is not None,
        "decisive_txs": decisive,
        "victim_candidates": victim_candidates,
        "counts": {"violations": len(violations), "warnings": len(warnings)},
        "violations": violations,
        "warnings": warnings,
    }
