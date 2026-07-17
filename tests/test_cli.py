"""Tests for CLI-layer correctness helpers.

Locks in the evidence-grounding guard on `classify`: a free-typed / corrupted
address that never appears in fetched evidence must be flagged before its
classification is trusted.
"""
import json

from meat import cli

REAL = "0x61d7063041d83c8ca3e42c39181dfd14b3bc76c2"
BOGUS = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"


class _Cfg:
    def __init__(self, cases_dir):
        self.cases_dir = cases_dir


def _setup(tmp_path, monkeypatch, name="c1"):
    monkeypatch.setattr(cli, "get_config", lambda: _Cfg(tmp_path))
    monkeypatch.delenv("MEAT_CASE", raising=False)
    ev = tmp_path / name / "evidence"
    (ev / "tx").mkdir(parents=True)
    (ev / "tx" / "0xabc.json").write_text(json.dumps(
        {"_meta": {}, "data": {"from": REAL, "to": "0xpool"}}))
    return ev


def test_grounded_when_address_in_fetched_evidence(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    assert cli._address_grounded_in_evidence("c1", REAL) is True
    # case-insensitive: evidence is matched lowercased
    assert cli._address_grounded_in_evidence("c1", REAL.upper().replace("0X", "0x")) is True


def test_not_grounded_when_address_absent(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    assert cli._address_grounded_in_evidence("c1", BOGUS) is False


def test_classify_store_is_not_self_grounding(tmp_path, monkeypatch):
    # An address appearing ONLY in the classify store proves nothing.
    ev = _setup(tmp_path, monkeypatch)
    (ev / "tx" / "0xabc.json").unlink()
    cdir = ev / "classify"
    cdir.mkdir()
    (cdir / f"{BOGUS}.json").write_text(json.dumps(
        {"_meta": {}, "data": {"address": BOGUS}}))
    # classify files are skipped, so no other evidence exists -> None
    assert cli._address_grounded_in_evidence("c1", BOGUS) is None


def test_none_when_no_case_or_evidence(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    assert cli._address_grounded_in_evidence(None, REAL) is None       # no case
    assert cli._address_grounded_in_evidence("missing", REAL) is None  # no evidence dir
    assert cli._address_grounded_in_evidence("c1", "0x1234") is None   # malformed address


# --- deployments discovery helpers -------------------------------------------

ZERO = "0x" + "0" * 40
CHILD = "0xEBc29199c817Dc47BA12E3F86102564D640cBf99"
DEPLOYER = "0x5f259d0b76665c337c6104145894f4d1d2758b8c"


def test_creations_from_normal_picks_deploys_only():
    txs = [
        # a contract creation: to empty, contractAddress set
        {"hash": "0xa", "to": "", "contractAddress": CHILD, "blockNumber": "100",
         "timeStamp": "1678000000", "isError": "0"},
        # a normal call: to set -> not a creation
        {"hash": "0xb", "to": "0xpool", "contractAddress": "", "blockNumber": "101"},
        # a reverted deploy -> skipped
        {"hash": "0xc", "to": "", "contractAddress": "0xdead", "blockNumber": "102",
         "isError": "1"},
        # zero contractAddress -> skipped
        {"hash": "0xd", "to": "", "contractAddress": ZERO, "blockNumber": "103"},
    ]
    recs = cli._creations_from_normal(txs, DEPLOYER)
    assert [r["address"] for r in recs] == [CHILD.lower()]
    r = recs[0]
    assert r["creation_tx"] == "0xa"
    assert r["block"] == 100 and r["timestamp"] == 1678000000
    assert r["via"].startswith("direct")


def test_creations_from_internal_picks_create_types():
    txs = [
        {"hash": "0xa", "type": "create", "contractAddress": CHILD, "blockNumber": "200",
         "timeStamp": "1678000001", "isError": "0"},
        {"hash": "0xb", "type": "create2", "contractAddress": "0xAbC0000000000000000000000000000000000001",
         "blockNumber": "201"},
        # a call internal tx -> not a deploy
        {"hash": "0xc", "type": "call", "contractAddress": "", "blockNumber": "202"},
        # failed create -> skipped
        {"hash": "0xd", "type": "create", "contractAddress": "0xfeed", "blockNumber": "203",
         "isError": "1"},
    ]
    recs = cli._creations_from_internal(txs, DEPLOYER)
    addrs = [r["address"] for r in recs]
    assert CHILD.lower() in addrs
    assert "0xabc0000000000000000000000000000000000001" in addrs
    assert len(recs) == 2
    assert all(r["via"].startswith("factory") for r in recs)
