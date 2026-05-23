# Speed & Validation Review

## 1. `meat quick` — Single-shot analysis

### What it does
One command from input to full decoded summary:
```bash
meat quick 0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d --chain ethereum
```

Outputs: tx summary + net flows + address classification for from/to + meta — all in one JSON response.

### Design decisions
- **Classify before ABI fetches**: Address classification runs before the expensive per-contract log decoding, so you get address types even when rate limited
- **Skip full log decoding**: `skip_log_decode=True` saves 10+ API calls. Output notes "use `meat tx` for full log decoding"
- **Auto chain detection**: If `--chain` is omitted, tries each configured chain's explorer until the tx is found
- **Accepts URLs**: `meat quick https://etherscan.io/tx/0x...` works — parses the URL, extracts chain + hash

### Performance
| Metric | Value |
|--------|-------|
| Time (with chain specified) | **8.4s** |
| API calls | ~10 (tx + receipt + 2x classify + token resolution) |
| Output size | ~2KB (compact format) |
| Bottleneck | Etherscan V2 rate limit (3/sec) |

### What's in the output
```
hash, from, to, value, status, fee
transfer_count, transfer_summary (per-token counts)
net_flows (per-address per-token, human-readable)
addresses (from/to classification with type, labels, balance, proxy info)
_meta (data sources, elapsed time, warnings, enrichment failures)
```

### Issues found and fixed
- **Etherscan V2 rate limit is 3/sec, not 5/sec**: Updated `chains.yaml` default
- **Rate limit errors caused silent classify failures**: Added retry logic (up to 3 retries with 1s backoff) in `explorer._request()`
- **Rate budget consumed by log decoding**: Added `skip_log_decode` parameter to `_build_tx_result`

## 2. Validation test suite

### Structure
```
tests/
├── __init__.py
├── test_parse.py           # 9 unit tests — input parsing, no API calls
├── test_decode.py          # 12 unit tests — ABI decoding, event parsing
└── test_integration.py     # 10 integration tests — live API against Euler hack
```

### Unit tests (21 total, 0.22s)
| Test | What it validates |
|------|-------------------|
| Parse bare tx hash | Correct type detection, lowercase |
| Parse bare address | Correct type detection |
| Parse Etherscan URL | Chain extraction from URL |
| Parse Polygonscan URL | Multi-chain URL support |
| Parse Basescan URL | Base chain detection |
| Parse unknown input | Graceful "unknown" type |
| Parse batch mixed | Extracts tx + 2 addresses from noisy text |
| Parse batch dedup | Same address twice → one result |
| Parse noisy markdown | Strips `**`, backticks, brackets |
| Compute selector (transfer) | `transfer(address,uint256)` → `0xa9059cbb` |
| Compute selector (approve) | `approve(address,uint256)` → `0x095ea7b3` |
| Transfer topic hash | Starts with `0xddf252ad` |
| Approval topic hash | Starts with `0x8c5be1e5` |
| Decode ERC20 Transfer | Correct from/to/amount from log |
| Decode Approval | Correct owner/spender from log |
| Decode WETH Deposit | "ETH wrapped to WETH" annotation |
| Decode WETH Withdrawal | Correct src address |
| Format value 18 decimals | 1e18 → "1.0" |
| Format value 6 decimals | 1e6 → "1.0" |
| Format value zero | 0 → "0.0" |
| Non-matching log | Returns None |

### Integration tests (10 total, 40s)
All validated against the **Euler Finance hack** (March 2023, $200M DAI):

| Test | What it validates |
|------|-------------------|
| parse euler URL | Extracts tx hash + detects ethereum chain |
| tx basic fields | from=attacker EOA, to=attacker contract, status=success, 20 transfers |
| tx has meta | `_meta` field present with data_sources |
| tx net flows DAI | DAI movements found in net_flows |
| classify attacker EOA | type=eoa, is_contract=false |
| classify Euler proxy | type=contract, is_verified=true, is_proxy=true, "Euler" in labels |
| classify Binance 14 | known_entity with category=cex, "Binance" in label |
| quick Euler | Full quick analysis: 20 transfers, both addresses classified, elapsed_seconds present |
| parse multiple chains | Ethereum + Polygon URLs parsed correctly |
| parse noisy telegram | Emoji-laden text correctly parsed |

### Running tests
```bash
# Unit tests only (fast, no API)
pytest tests/test_parse.py tests/test_decode.py -v

# Integration tests (needs ETHERSCAN_API_KEY in .env)
pytest tests/test_integration.py -v

# All tests
pytest tests/ -v
```

## Files created/modified

| File | Change |
|------|--------|
| `meat/cli.py` | Added `quick` command, `_auto_detect_chain()`, `_compact_tx()`, `skip_log_decode` param, `_resolve_chain`/`_resolve_case` helpers |
| `meat/explorer.py` | Added retry logic (3 attempts with 1s backoff) on rate limit errors |
| `chains.yaml` | Rate limit corrected: 5 → 3 req/sec |
| `tests/test_parse.py` | 9 unit tests |
| `tests/test_decode.py` | 12 unit tests |
| `tests/test_integration.py` | 10 integration tests against Euler hack |
