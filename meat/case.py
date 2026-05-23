from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


class Case:
    def __init__(self, case_dir: Path, data: dict):
        self.case_dir = case_dir
        self.data = data

    @classmethod
    def create(cls, cases_root: Path, name: str, chain: str) -> "Case":
        case_dir = cases_root / name
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / "evidence").mkdir(exist_ok=True)
        (case_dir / "findings").mkdir(exist_ok=True)
        (case_dir / "contracts").mkdir(exist_ok=True)

        now = datetime.now(timezone.utc).isoformat()
        data = {
            "name": name,
            "created": now,
            "status": "active",
            "chain": chain,
            "last_updated": now,
            "last_monitored": None,
            "monitored_addresses": [],
            "open_questions": [],
            "summary": {
                "total_stolen": {},
                "total_recovered": {},
                "attacker_addresses": 0,
                "victim_addresses": 0,
                "attack_txs": 0,
            },
        }

        case = cls(case_dir, data)
        case.save()
        case.append_journal(f"Case created: {name} on {chain}")
        return case

    @classmethod
    def load(cls, cases_root: Path, name: str) -> "Case | None":
        case_dir = cases_root / name
        case_file = case_dir / "case.json"
        if not case_file.exists():
            return None
        try:
            data = json.loads(case_file.read_text())
            return cls(case_dir, data)
        except (json.JSONDecodeError, IOError):
            return None

    @classmethod
    def list_cases(cls, cases_root: Path) -> list[str]:
        if not cases_root.exists():
            return []
        return [
            d.name for d in sorted(cases_root.iterdir())
            if d.is_dir() and (d / "case.json").exists()
        ]

    def save(self):
        self.data["last_updated"] = datetime.now(timezone.utc).isoformat()
        case_file = self.case_dir / "case.json"
        case_file.write_text(json.dumps(self.data, indent=2, default=str))

    def update_status(self, status: str):
        self.data["status"] = status
        self.save()

    def add_address(self, address: str, role: str, confidence: str,
                    evidence: list[str], reason: str):
        addr_file = self.case_dir / "addresses.json"
        addresses = {}
        if addr_file.exists():
            try:
                addresses = json.loads(addr_file.read_text())
            except json.JSONDecodeError:
                pass

        addresses[address] = {
            "role": role,
            "confidence": confidence,
            "evidence": evidence,
            "reason": reason,
            "added_at": datetime.now(timezone.utc).isoformat(),
        }

        addr_file.write_text(json.dumps(addresses, indent=2))

    def get_addresses(self) -> dict:
        addr_file = self.case_dir / "addresses.json"
        if not addr_file.exists():
            return {}
        try:
            return json.loads(addr_file.read_text())
        except json.JSONDecodeError:
            return {}

    def add_monitored_address(self, address: str, role: str, last_block: int = 0):
        existing = [m for m in self.data["monitored_addresses"] if m["address"] != address]
        existing.append({
            "address": address,
            "role": role,
            "last_tx_block": last_block,
        })
        self.data["monitored_addresses"] = existing
        self.save()

    def append_journal(self, entry: str):
        journal_file = self.case_dir / "journal.md"
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        formatted = f"\n## {now}\n{entry}\n"

        with open(journal_file, "a") as f:
            f.write(formatted)

    @property
    def name(self) -> str:
        return self.data["name"]

    @property
    def status(self) -> str:
        return self.data["status"]

    @property
    def chain(self) -> str:
        return self.data["chain"]
