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
