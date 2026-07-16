# CLAUDE.md — MEAT-EVM

## What this is
EVM exploit analysis toolkit. Python CLI for data fetching/decoding + Claude skills for analysis/reasoning.

## Quick start
```
source .venv/bin/activate
cp .env.example .env  # add your RPC URLs and explorer API keys
pip install -r requirements.txt
```

## Skills
| Skill | Purpose |
|-------|---------|
| `/meat <input>` | Analyze a tx, address, or URL. Main entry point. |
| `/meat-recon` | Expand from partial info to full picture |
| `/meat-trace` | Track where stolen funds went |
| `/meat-analyze` | Deep-dive into the vulnerability |
| `/meat-poc` | Create a Foundry PoC reproduction |
| `/meat-monitor` | Watch active cases for new activity |

## CLI tool
```
source .venv/bin/activate
python3 -m meat <command> [options]
```

Commands: `parse`, `tx`, `source`, `abi`, `classify`, `decode`

Phase 2 commands: `txlist`, `transfers`, `flow`
Phase 3 commands: `trace`, `storage`, `logs`, `block`
Correctness commands: `profit`, `provenance`, `check` — `profit <eoa> --block <blk>` finds the tx that
realizes the largest net stablecoin gain (the money-out tx is rarely the one you were handed);
`provenance <addr>` shows the earliest inbound source of each token (single-source = sybil red flag,
not a victim); `check <case>` is a hard gate that fails unless value conserves (large priced movers
labeled), **loss is attributed** (attacker gains matched by a `victim`-role address — either a priced
loss or absorbing an illiquid token the attacker dumped onto it; the gate names dump recipients as
`victim_candidates`), attacker/victim labels have provenance, and money-out txs are fetched in full.
The gate also emits **warnings** (don't fail the build, but surface skipped work): `label_grounding`
(an entity label whose `classify` evidence has `known_entity=null` and isn't in `labels/known_addresses.json`
— the null→narrative guess, e.g. mislabeling Balancer V3 as "SummerFi Vault"; clear it by adding to the
registry or setting `label_source`), `victim_set_consistency` (summary counts / `loss_by_vault` don't
reconcile with labeled roles), and `suspect_token_price` (DeFiLlama priced a USD-named non-canonical
token far off $1 — stale for impaired/collapsed tokens like xUSD; never trust its `usd_value`).
A Stop hook runs `check` automatically. Set `eth_price_usd` in case.json to value ETH/WETH too.
Cross-chain (fund tracing): `btc-trace`, `btc-tx`, `thorchain` (+`--protocol maya`), `debridge`,
`orbiter`, `intents` — deterministic Bitcoin peel-chain following (Blockstream), THORChain/Maya memo
decode + Midgard, deBridge DLN and Orbiter order resolution, and intents/bridge registry
cross-reference. Prefer these over hand-tracing explorer web pages.

## Case directory
Each analysis writes to `cases/<case-name>/`. Evidence (raw on-chain data) in `evidence/`, analysis in `findings/`.

On-chain data is immutable — evidence files are write-once, never modified.

## Chains
Configured in `chains.yaml`. Uses Etherscan V2 API (`chainid` parameter). RPC URLs and API keys come from `.env`.

## Enhanced providers
- **Alchemy RPC** — auto-detected from URL. Enables: `alchemy_getAssetTransfers` (faster fund tracing), `alchemy_getTokenBalances` (full token balance snapshot), `debug_traceTransaction` (call traces).
- **Tenderly** — optional. Set `TENDERLY_ACCESS_KEY`, `TENDERLY_ACCOUNT`, `TENDERLY_PROJECT` in `.env`. Enables decoded call traces as fallback.
- **DeFiLlama** — free, no config. Auto-fetches USD prices for token transfers in net_flows.
- **Sourcify** — free, no config. Fallback for contract verification and function signature lookup (4.7M signatures).

## Dependencies
Python: requests, eth-abi, eth-utils, eth-hash[pycryptodome], click, pyyaml, python-dotenv

System (optional): cast, forge (Foundry) for PoC reproduction

## Investigation Rules
- All analysis claims MUST cite evidence from CLI tool output — no unsourced assertions
- Do NOT reference external reports, blog posts, or news about the exploit
- Do NOT use prior knowledge to skip investigation steps — follow the evidence even if you already know the answer
- Web searches for protocol documentation or GitHub repos: ASK the user first
- Web searches about the specific exploit/incident: NEVER — use only on-chain data via configured APIs
- Report generation is presentation only — no RPC calls, no web fetches, no data synthesis

## Architecture
- `meat/cli.py` — Click CLI entry point, all commands output JSON to stdout
- `meat/config.py` — Loads chains.yaml + .env
- `meat/rpc.py` — JSON-RPC client
- `meat/explorer.py` — Etherscan V2 API client with rate limiter
- `meat/decode.py` — ABI decoding, 4byte selector lookup
- `meat/evidence.py` — Write-once evidence store
- `meat/case.py` — Case lifecycle (case.json, journal.md, addresses.json)
- `meat/classify.py` — Address classification (EOA/contract/token/proxy)
- `meat/crosschain.py` — Bitcoin (Blockstream) peel-chain tracing + THORChain memo/Midgard decode
- `meat/analysis.py` — Deterministic correctness helpers: provenance, profit resolution, and the
  `check` invariant gate (value conservation, provenance-required, money-out-fetched). Pure + offline.
- `meat/parse.py` — Input parser (tx hash, address, URL, batch)
