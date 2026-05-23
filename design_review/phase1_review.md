# Phase 1 Design Review — MVP

## What was built

Python CLI (`python3 -m meat`) with 6 commands, evidence storage, case management, and the `/meat` skill file.

### Modules implemented

| Module | LOC | Purpose | Status |
|--------|-----|---------|--------|
| `config.py` | 95 | Load chains.yaml + .env, chain config dataclass | Tested |
| `parse.py` | 140 | Input parser: tx hash, address, URL, batch/messy input | Tested |
| `rpc.py` | 80 | JSON-RPC client with error handling | Tested (via Polygon RPC) |
| `explorer.py` | 190 | Etherscan V2 API client + rate limiter | Tested |
| `decode.py` | 220 | ABI decoding, event decoding, 4byte selector lookup | Tested |
| `evidence.py` | 65 | Write-once evidence store per case | Tested |
| `case.py` | 95 | Case lifecycle: create, load, journal, addresses | Implemented |
| `classify.py` | 120 | Address classification (EOA/contract/token/proxy) | Tested |
| `cli.py` | 420 | Click CLI with parse, tx, source, abi, classify, decode | Tested |

### Test results

| Test | Result | Notes |
|------|--------|-------|
| `parse` — Etherscan URL | PASS | Extracts tx hash + chain |
| `parse` — bare tx hash | PASS | Detects type correctly |
| `parse` — bare address | PASS | |
| `parse` — Polygon URL | PASS | Chain auto-detected |
| `parse` — batch messy input (stdin) | PASS | Extracts mixed hashes + addresses from noisy text |
| `tx` — Euler hack tx | PASS | 20 token transfers decoded, status=success, gas fee computed |
| `classify` — Euler contract | PASS | Identified as verified proxy, label "Euler", implementation found |
| `source` — Euler contract | PASS | Returns contract name, compiler, proxy status |
| `decode` — approve calldata (4byte) | PASS | Found `approve(address,uint256)` from 4byte.directory |
| `decode` — transfer with ABI | PASS | Fully decoded with param names from on-chain ABI |
| Evidence storage (`--case`) | PASS | tx and receipt saved to evidence/ |
| Error: invalid tx hash | PASS | Clean JSON error |
| Error: missing chain | PASS | Lists available chains |
| Error: unknown chain | PASS | Clean JSON error (after fix) |
| Error: no source code (EOA) | PASS | Clean JSON error |

### Issues found and fixed

1. **Python 3.9 compatibility**: System Python is 3.9, which doesn't support `X | None` union syntax. Fixed by adding `from __future__ import annotations` to all modules.

2. **Etherscan V1 API deprecated**: The original V1 API (`api.etherscan.io/api`) returns deprecation notices for proxy endpoints. Migrated to V2 API (`api.etherscan.io/v2/api`) with `chainid` parameter. All chains now use the unified V2 endpoint.

3. **Unhandled ValueError for unknown chain**: `config.get_chain()` raised ValueError but the CLI didn't catch it. Fixed with try/except in `_get_chain_config()`.

4. **Missing keccak backend**: `eth-hash` requires either `pycryptodome` or `pysha3`. Added `eth-hash[pycryptodome]` to requirements.txt.

## Architecture decisions validated

- **Explorer proxy as RPC fallback**: Works well. With just an Etherscan API key (no RPC URL), we can fetch full tx details + receipts. This makes the tool usable with minimal config.

- **JSON output to stdout**: Clean separation. Claude reads JSON, errors go to stderr. Exit codes signal success/failure.

- **Rate limiter**: Token bucket at 5 req/sec works. No 429 errors during testing.

- **Evidence store**: Write-once semantics validated. Second fetch of same tx doesn't overwrite.

## Known limitations (Phase 1)

1. **No RPC for Ethereum**: Only have an Etherscan API key, not an RPC URL. Token classification (`_check_erc20`) falls back silently when no RPC available. The classify command works but token detection relies on RPC `eth_call`.

2. **Log decoding limited to target contract ABI**: Logs emitted by other contracts (e.g., token Transfer events from USDC contract in an Euler tx) are decoded as raw ERC20 transfers but not against the emitting contract's ABI. Full log decoding would require fetching ABIs for every unique log address.

3. **No tx-level token transfer fetching via explorer**: Etherscan's `tokentx` doesn't filter by tx hash directly. We rely on receipt log decoding for per-tx transfers, which works but misses token name/symbol enrichment.

4. **No `txlist`, `transfers`, `flow` commands yet**: These are Phase 2.

5. **urllib3 OpenSSL warning**: System LibreSSL 2.8.3 triggers a deprecation warning from urllib3 v2. Harmless but noisy. Suppressed with `2>/dev/null` in tests.

## Modularity assessment

- **Each module is independently importable**: No circular dependencies.
- **Config is loaded lazily**: `get_config()` singleton, not imported at module level.
- **Explorer and RPC are interchangeable**: CLI tries RPC first, falls back to explorer proxy.
- **Evidence store is decoupled from case**: Can be used standalone or with case management.
- **CLI commands are self-contained**: Each Click command handles its own error cases.

## Files created

```
.gitignore
.env.example
.env
requirements.txt
chains.yaml
CLAUDE.md
PLAN.md
meat/__init__.py
meat/__main__.py
meat/config.py
meat/parse.py
meat/rpc.py
meat/explorer.py
meat/decode.py
meat/evidence.py
meat/case.py
meat/classify.py
meat/cli.py
.claude/skills/meat.md
```
