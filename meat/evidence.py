from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


class EvidenceStore:
    def __init__(self, case_dir: Path):
        self.evidence_dir = case_dir / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    def _category_dir(self, category: str) -> Path:
        d = self.evidence_dir / category
        d.mkdir(exist_ok=True)
        return d

    def _key_to_filename(self, key: str) -> str:
        return key.replace("/", "_").replace(":", "_") + ".json"

    def save(self, category: str, key: str, data: dict, chain: str | None = None) -> tuple[str, bool]:
        """Save evidence. Returns (relative_path, was_newly_written)."""
        d = self._category_dir(category)
        filename = self._key_to_filename(key)
        path = d / filename
        rel = str(path.relative_to(self.evidence_dir.parent))

        if path.exists():
            return rel, False

        envelope = {
            "_meta": {
                "category": category,
                "key": key,
                "chain": chain,
                "fetched_at": datetime.now(timezone.utc).isoformat(),
            },
            "data": data,
        }

        path.write_text(json.dumps(envelope, indent=2, default=str))
        return rel, True

    def load(self, category: str, key: str) -> dict | None:
        d = self._category_dir(category)
        filename = self._key_to_filename(key)
        path = d / filename
        if not path.exists():
            return None
        try:
            envelope = json.loads(path.read_text())
            return envelope.get("data")
        except (json.JSONDecodeError, IOError):
            return None

    def exists(self, category: str, key: str) -> bool:
        d = self.evidence_dir / category
        filename = self._key_to_filename(key)
        return (d / filename).exists()

    def list_keys(self, category: str) -> list[str]:
        d = self.evidence_dir / category
        if not d.exists():
            return []
        return [p.stem for p in d.glob("*.json")]

    def get_path(self, category: str, key: str) -> str:
        d = self._category_dir(category)
        filename = self._key_to_filename(key)
        return str((d / filename).relative_to(self.evidence_dir.parent))
