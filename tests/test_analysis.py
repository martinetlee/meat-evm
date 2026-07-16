"""Tests for the deterministic analysis helpers (provenance, profit, check gate).

These lock in the invariants that catch the "concluded an attack without finding
who lost the money" failure mode.
"""
import json

from meat import analysis


def _tt(hash, frm, to, value, symbol, contract, block=100, decimals=6, tx_index=0):
    return {
        "hash": hash, "from": frm, "to": to, "value": str(value),
        "tokenSymbol": symbol, "contractAddress": contract,
        "blockNumber": str(block), "tokenDecimal": str(decimals),
        "transactionIndex": str(tx_index),
    }


VICTIM = "0xd39d1733a03f940ce47cec8982e45e6964d29fa1"
SEED = "0xba1333333333a1ba1108e8412f11850a5c319ba9"
ATTACKER = "0x7bf716167b48cf527725722c6d79494b45b3bdca"
VG = "0x8399c8fc273bd165c346af74a02e65f10e4fd78f"
DAI = "0x6b175474e89094c44da98b954eedeac495271d0f"


def test_provenance_flags_single_source_sybil():
    transfers = [
        _tt("0xa", SEED, VICTIM, 11_000_000, "vgUSDC", VG, block=10),
        _tt("0xb", VICTIM, "0xdead", 5_000_000, "vgUSDC", VG, block=20),  # outbound ignored
    ]
    out = analysis.first_inbound_sources(transfers, VICTIM)
    assert len(out) == 1
    prov = out[0]
    assert prov["single_source"] is True
    assert prov["first_from"] == SEED
    assert prov["first_seen_block"] == 10


def test_provenance_multi_source_is_not_flagged():
    transfers = [
        _tt("0xa", SEED, VICTIM, 1, "USDC", DAI, block=10),
        _tt("0xb", "0xother", VICTIM, 1, "USDC", DAI, block=11),
    ]
    out = analysis.first_inbound_sources(transfers, VICTIM, token=DAI)
    assert out[0]["single_source"] is False
    assert out[0]["distinct_sources"] == 2


def test_profit_ranks_stablecoin_gain_and_ignores_lookalikes():
    # One tx nets +6M DAI to the attacker; a decoy tx nets vgUSDC (not money).
    transfers = [
        _tt("0xprofit", "0xpool", ATTACKER, 6_000_000_000000, "DAI", DAI, block=200, decimals=6),
        _tt("0xdecoy", "0xpool", ATTACKER, 19_000_000_000_000000, "vgUSDC", VG, block=150),
    ]
    by_tx = analysis.per_tx_net(transfers, ATTACKER)
    ranked = analysis.rank_profit(by_tx)
    assert ranked[0]["hash"] == "0xprofit"
    assert ranked[0]["net_stablecoin_usd"] == 6_000_000.0
    # vgUSDC must NOT be counted as stablecoin value
    decoy = next(r for r in ranked if r["hash"] == "0xdecoy")
    assert decoy["net_stablecoin_usd"] == 0.0


def _write_case(tmp_path, case, addresses, tx_evidence):
    (tmp_path / "case.json").write_text(json.dumps(case))
    (tmp_path / "addresses.json").write_text(json.dumps(addresses))
    txdir = tmp_path / "evidence" / "tx"
    txdir.mkdir(parents=True)
    for h, data in tx_evidence.items():
        (txdir / f"{h}.json").write_text(json.dumps({"_meta": {}, "data": data}))


def test_check_catches_unlabeled_winner_and_missing_provenance(tmp_path):
    h = "0x" + "d" * 64
    tx = {
        "token_transfers": [{"x": 1}],
        "net_flows": {
            ATTACKER: {"DAI": {"formatted": "6000000"}},
            "0xffffffffffffffffffffffffffffffffffffffff": {"USDC": {"formatted": "-6000000"}},
        },
    }
    case = {"name": "t", "attack_tx": h}
    # attacker labeled but the $6M loser is NOT labeled, and attacker lacks provenance
    addresses = {ATTACKER: {"role": "attacker"}}
    _write_case(tmp_path, case, addresses, {h: tx})

    report = analysis.check_case(tmp_path)
    assert report["passed"] is False
    invs = {v["invariant"] for v in report["violations"]}
    assert "value_conservation" in invs      # unlabeled net loser
    assert "provenance_required" in invs      # attacker without provenance


def test_check_passes_when_conserved_and_provenanced(tmp_path):
    h = "0x" + "e" * 64
    loser = "0xffffffffffffffffffffffffffffffffffffffff"
    tx = {
        "token_transfers": [{"x": 1}],
        "net_flows": {
            ATTACKER: {"DAI": {"formatted": "6000000"}},
            loser: {"USDC": {"formatted": "-6000000"}},
        },
    }
    case = {"name": "t", "attack_tx": h}
    addresses = {
        ATTACKER: {"role": "attacker", "provenance_waived": "operator"},
        loser: {"role": "victim", "provenance_waived": "known protocol vault"},
    }
    _write_case(tmp_path, case, addresses, {h: tx})

    report = analysis.check_case(tmp_path)
    assert report["passed"] is True, report["violations"]


ARK = "0x61d7063041d83c8ca3e42c39181dfd14b3bc76c2"
DRAINER = "0x0514f827c129c16418a0933e03c99a6af982fc61"


def _xfer(frm, to, amount_formatted, symbol, token):
    return {"from": frm, "to": to, "amount_formatted": str(amount_formatted),
            "token_symbol": symbol, "token_address": token, "token_decimals": 6}


def test_analyze_detects_attacker_dumped_illiquid_token():
    # Attacker (drainer) dumps 19.5B illiquid vgUSDC onto a vault ark and takes DAI.
    tx = {
        "token_transfers": [
            _xfer(DRAINER, ARK, 19_551_517_226, "vgUSDC", VG),
            _xfer("0xpool", ATTACKER, 6_000_000, "DAI", DAI),
        ],
        "net_flows": {
            DRAINER: {"vgUSDC": {"formatted": "-19551517226"}},
            ARK: {"vgUSDC": {"formatted": "19551517226"}},
            ATTACKER: {"DAI": {"formatted": "6000000"}},
        },
    }
    labeled = {ATTACKER: {"role": "attacker"}, DRAINER: {"role": "attacker"}}
    va = analysis.analyze_tx_value(tx, labeled, min_usd=100_000)
    assert "vgUSDC" in va["dumped_tokens"]
    assert ARK in va["dump_receivers"]
    # The Silo owner receiving a MINT (from zero addr) must NOT be a dump receiver:
    assert va["attacker_gain"] == 6_000_000.0


def test_check_flags_unlabeled_dump_receiver_as_victim(tmp_path):
    h = "0x" + "a" * 64
    tx = {
        "token_transfers": [
            _xfer(DRAINER, ARK, 19_551_517_226, "vgUSDC", VG),
            _xfer("0xpool", ATTACKER, 6_000_000, "DAI", DAI),
        ],
        "net_flows": {
            ATTACKER: {"DAI": {"formatted": "6000000"}},
            ARK: {"vgUSDC": {"formatted": "19551517226"}},
        },
    }
    case = {"name": "t", "monetization_tx": h}
    addresses = {
        ATTACKER: {"role": "attacker", "provenance_waived": "op"},
        DRAINER: {"role": "attacker", "provenance_waived": "contract"},
    }
    _write_case(tmp_path, case, addresses, {h: tx})

    report = analysis.check_case(tmp_path)
    assert report["passed"] is False
    invs = [v["invariant"] for v in report["violations"]]
    assert "loss_attribution" in invs
    # the ark should be surfaced as a victim candidate
    assert any(c["address"] == ARK for c in report["victim_candidates"])


def test_check_passes_when_victim_absorbs_dumped_asset(tmp_path):
    h = "0x" + "b" * 64
    tx = {
        "token_transfers": [
            _xfer(DRAINER, ARK, 19_551_517_226, "vgUSDC", VG),
            _xfer("0xpool", ATTACKER, 6_000_000, "DAI", DAI),
        ],
        "net_flows": {
            ATTACKER: {"DAI": {"formatted": "6000000"}},
            ARK: {"vgUSDC": {"formatted": "19551517226"}},
        },
    }
    case = {"name": "t", "monetization_tx": h}
    addresses = {
        ATTACKER: {"role": "attacker", "provenance_waived": "op"},
        DRAINER: {"role": "attacker", "provenance_waived": "contract"},
        ARK: {"role": "victim", "provenance_waived": "known protocol ark"},
    }
    _write_case(tmp_path, case, addresses, {h: tx})

    report = analysis.check_case(tmp_path)
    assert report["passed"] is True, report["violations"]


def test_check_fails_when_money_out_tx_not_fetched(tmp_path):
    h = "0x" + "f" * 64
    case = {"name": "t", "monetization_tx": h}
    (tmp_path / "case.json").write_text(json.dumps(case))
    (tmp_path / "addresses.json").write_text(json.dumps({}))
    (tmp_path / "evidence").mkdir()

    report = analysis.check_case(tmp_path)
    assert report["passed"] is False
    assert any(v["invariant"] == "money_out_tx_fetched" for v in report["violations"])


# --------------------------------------------------------------------------- #
# Warning invariants: label grounding, victim-set consistency, suspect prices
# --------------------------------------------------------------------------- #

UNREG = "0x1111111111111111111111111111111111111111"   # not in the registry
UNREG2 = "0x2222222222222222222222222222222222222222"
UNREG3 = "0x3333333333333333333333333333333333333333"
UNREG4 = "0x4444444444444444444444444444444444444444"
BAL_V3 = "0xba1333333333a1ba1108e8412f11850a5c319ba9"  # in labels/known_addresses.json


def _write_classify(tmp_path, addr, data):
    cdir = tmp_path / "evidence" / "classify"
    cdir.mkdir(parents=True, exist_ok=True)
    (cdir / f"{addr}.json").write_text(json.dumps({"_meta": {}, "data": data}))


def _warns(report, invariant):
    return [w for w in report["warnings"] if w["invariant"] == invariant]


def test_label_grounding_flags_null_classify_narrative_label(tmp_path):
    # The 0xba13 failure mode: classify found nothing, analyst invented a label.
    _write_case(tmp_path, {"name": "t"},
                {UNREG: {"role": "victim", "labels": ["Fake Protocol Vault"],
                         "provenance_waived": "x"}}, {})
    _write_classify(tmp_path, UNREG, {"known_entity": None, "is_token": False})

    report = analysis.check_case(tmp_path)
    warns = _warns(report, "label_grounding")
    assert len(warns) == 1
    assert UNREG in warns[0]["detail"]
    assert "Fake Protocol Vault" in warns[0]["detail"]
    # warnings must not fail the gate
    assert not any(v["invariant"] == "label_grounding" for v in report["violations"])


def test_label_grounding_exemptions(tmp_path):
    addresses = {
        # in the registry -> grounded, even with null classify
        BAL_V3: {"role": "intermediate", "labels": ["Balancer V3: Vault"]},
        # label_source records how the label was derived -> grounded
        UNREG: {"role": "victim", "labels": ["Documented Vault"],
                "label_source": "verified via createVault event in tx 0xabc"},
        # classify itself grounded the identity
        UNREG2: {"role": "victim", "labels": ["Known Proto"]},
        # a token identified by its on-chain metadata
        UNREG3: {"role": "intermediate", "labels": ["vgUSDC token"]},
        # attacker labels are operational, not entity claims
        UNREG4: {"role": "attacker", "labels": ["Attacker EOA"]},
    }
    _write_case(tmp_path, {"name": "t"}, addresses, {})
    _write_classify(tmp_path, BAL_V3, {"known_entity": None, "is_token": False})
    _write_classify(tmp_path, UNREG, {"known_entity": None, "is_token": False})
    _write_classify(tmp_path, UNREG2, {"known_entity": "Known Proto"})
    _write_classify(tmp_path, UNREG3, {"known_entity": None, "is_token": True})
    _write_classify(tmp_path, UNREG4, {"known_entity": None, "is_token": False})

    report = analysis.check_case(tmp_path)
    assert _warns(report, "label_grounding") == []


def test_label_grounding_silent_without_classify_record(tmp_path):
    # No classify evidence at all -> the invariant has nothing to contradict.
    _write_case(tmp_path, {"name": "t"},
                {UNREG: {"role": "victim", "labels": ["Unclassified Vault"]}}, {})

    report = analysis.check_case(tmp_path)
    assert _warns(report, "label_grounding") == []


def test_victim_set_consistency_flags_count_mismatch(tmp_path):
    case = {"name": "t", "summary": {"victim_addresses": 2, "attacker_addresses": 1}}
    addresses = {
        ATTACKER: {"role": "attacker", "provenance_waived": "op"},
        ARK: {"role": "victim", "provenance_waived": "vault"},  # only 1 victim, not 2
    }
    _write_case(tmp_path, case, addresses, {})

    report = analysis.check_case(tmp_path)
    warns = _warns(report, "victim_set_consistency")
    assert len(warns) == 1
    assert "victim_addresses=2" in warns[0]["detail"]


def test_victim_set_consistency_flags_unlabeled_loss_by_vault(tmp_path):
    case = {"name": "t", "summary": {"loss_by_vault": {
        f"Vault X ({UNREG})": 123456,
        f"Vault Y ({ARK})": 654321,
        "_note": "keys starting with underscore are skipped",
    }}}
    addresses = {ARK: {"role": "victim", "provenance_waived": "vault"}}
    _write_case(tmp_path, case, addresses, {})

    report = analysis.check_case(tmp_path)
    warns = _warns(report, "victim_set_consistency")
    assert len(warns) == 1          # Vault X only; Vault Y's ARK is a victim
    assert "Vault X" in warns[0]["detail"]


def test_suspect_usd_prices_unit():
    tx = {"net_flows": {
        UNREG: {
            "xUSD": {"formatted": "1000", "price_usd": 0.18},   # collapsed -> flag
            "gtUSDC": {"formatted": "1", "price_usd": 1.12},    # off-peg -> flag
            "sUSDC": {"formatted": "1", "price_usd": 1.03},     # within 5% -> ok
            "USDC": {"formatted": "1", "price_usd": 1.12},      # canonical -> exempt
            "WETH": {"formatted": "1", "price_usd": 3000.0},    # not USD-named -> exempt
            "noprice": {"formatted": "1"},                       # no price -> ok
        },
    }}
    out = analysis._suspect_usd_prices(tx)
    assert out == {"xUSD": 0.18, "gtUSDC": 1.12}


def test_check_warns_on_suspect_token_price(tmp_path):
    h = "0x" + "c" * 64
    tx = {
        "token_transfers": [{"x": 1}],
        "net_flows": {
            UNREG: {"xUSD": {"formatted": "1000", "price_usd": 0.18}},
        },
    }
    _write_case(tmp_path, {"name": "t", "attack_tx": h}, {}, {h: tx})

    report = analysis.check_case(tmp_path)
    warns = _warns(report, "suspect_token_price")
    assert len(warns) == 1
    assert "xUSD=$0.1800" in warns[0]["detail"]
