from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from dotenv import load_dotenv


@dataclass
class ChainConfig:
    name: str
    chain_id: int
    rpc_env: str
    explorer_api_env: str
    explorer_base: str
    explorer_url: str
    native_token: str
    url_patterns: list[str] = field(default_factory=list)
    trace_method: str | None = None
    trace_fallback: str | None = None

    @property
    def rpc_url(self) -> str | None:
        return os.environ.get(self.rpc_env)

    @property
    def explorer_api_key(self) -> str | None:
        return os.environ.get(self.explorer_api_env)

    def has_rpc(self) -> bool:
        url = self.rpc_url
        return url is not None and url.strip() != ""

    def has_explorer(self) -> bool:
        key = self.explorer_api_key
        return key is not None and key.strip() != ""


class Config:
    def __init__(self, project_root: Path | None = None):
        self.project_root = project_root or self._find_project_root()
        load_dotenv(self.project_root / ".env")
        self._chains: dict[str, ChainConfig] = {}
        self._rate_limit: int = 5
        self._load()

    def _find_project_root(self) -> Path:
        p = Path(__file__).resolve().parent.parent
        if (p / "chains.yaml").exists():
            return p
        return Path.cwd()

    def _load(self):
        config_path = self.project_root / "chains.yaml"
        if not config_path.exists():
            raise FileNotFoundError(f"chains.yaml not found at {config_path}")

        with open(config_path) as f:
            raw = yaml.safe_load(f)

        for name, chain_data in raw.get("chains", {}).items():
            self._chains[name] = ChainConfig(name=name, **chain_data)

        rate_cfg = raw.get("rate_limit", {})
        self._rate_limit = rate_cfg.get("requests_per_second", 5)

    def get_chain(self, name: str) -> ChainConfig:
        if name not in self._chains:
            available = ", ".join(sorted(self._chains.keys()))
            raise ValueError(f"Unknown chain '{name}'. Available: {available}")
        return self._chains[name]

    def all_chains(self) -> dict[str, ChainConfig]:
        return dict(self._chains)

    def detect_chain_from_url(self, url: str) -> str | None:
        url_lower = url.lower()
        for name, chain in self._chains.items():
            for pattern in chain.url_patterns:
                if pattern in url_lower:
                    return name
        return None

    @property
    def rate_limit(self) -> int:
        return self._rate_limit

    @property
    def cases_dir(self) -> Path:
        return self.project_root / "cases"


_config: Config | None = None


def get_config() -> Config:
    global _config
    if _config is None:
        _config = Config()
    return _config
