# Usability & Visibility Fixes Review

## Summary of changes

Three categories of fixes addressing 14 usability and visibility issues identified in the review.

## 1. `_meta` field on all CLI outputs

Every command now includes a `_meta` field showing:

```json
"_meta": {
  "data_sources": ["explorer_proxy"],
  "evidence_saved": ["evidence/tx/0xabc...json", "evidence/receipt/0xabc...json"],
  "warnings": ["No RPC for ethereum — token/admin/proxy detection unavailable"],
  "enrichment_failures": ["0xe025e3ca..."]
}
```

**What this fixes:**
- Issue #8 (no data source indication): Now shows "rpc" or "explorer_proxy"
- Issue #9 (silent enrichment failures): Lists token addresses that failed to resolve
- Issue #13 (evidence writes invisible): Shows exactly what evidence files were saved
- Issue #14 (no degraded operation warning): Warns when running without RPC
- Issue #10 (no decode coverage): Added `"decode_coverage": "39/56 logs decoded"`

## 2. Net flows now human-readable

**Before:**
```json
"0x028171bca77440...": {"Dai": "27000000000000000000000"}
"0x583c21631c48d4...": {"0xe025e3ca2be023...": "2"}
```

**After:**
```json
"0x028171bca77440...": {"Dai": "27000.0"}
"0x583c21631c48d4...": {"UNKNOWN(0xe025e3ca...)": "0.000000"}
```

- Token symbols used when resolved, `UNKNOWN(0xaddr...)` when not
- Values formatted with correct decimals (DAI = 18 decimals, USDC = 6, etc.)
- Negative values prefixed with "-" for outflows

## 3. `meat case` subcommand group

Three new commands for case management:

| Command | Purpose |
|---------|---------|
| `meat case create <name> --chain <chain>` | Create case, shows path + env var hint |
| `meat case list` | All cases with status, chain, address counts |
| `meat case show <name>` | Summary: addresses, evidence count, journal tail |

**`case create` output:**
```json
{
  "created": true,
  "name": "euler-hack",
  "chain": "ethereum",
  "path": "/path/to/cases/euler-hack",
  "hint": "Set MEAT_CASE=euler-hack MEAT_CHAIN=ethereum to avoid repeating --case and --chain"
}
```

## 4. Environment variable defaults (`MEAT_CHAIN`, `MEAT_CASE`)

Setting `MEAT_CHAIN=ethereum MEAT_CASE=euler-hack` eliminates `--chain` and `--case` from every command:

```bash
# Before: 40+ chars of boilerplate per command
python3 -m meat tx 0xabc... --chain ethereum --case euler-hack
python3 -m meat classify 0xdef... --chain ethereum --case euler-hack

# After: set once, use everywhere
export MEAT_CHAIN=ethereum MEAT_CASE=euler-hack
python3 -m meat tx 0xabc...
python3 -m meat classify 0xdef...
```

The `_resolve_chain()` and `_resolve_case()` helpers check env vars when CLI flags are omitted.

## 5. `--compact` flag on `tx` command

Produces a summary-only output: header fields + net_flows + counts. Skips raw arrays.

| Metric | Full | Compact |
|--------|------|---------|
| Output size | 26KB | 2KB |
| Token transfers | 20 raw entries | `transfer_summary: {"Dai": 7, ...}` |
| Decoded logs | 39 raw entries | `decode_coverage: "9/56"` |
| Internal txs | raw array | `internal_tx_count: 0` |

Compact output is ideal for Claude's initial scan — get the overview, then drill into full output only if needed.

## Test results

| Test | Result |
|------|--------|
| `case create` | PASS — creates case dir, case.json, journal |
| `case list` | PASS — shows all cases with metadata |
| `case show` | PASS — shows evidence count, address count, journal tail |
| `tx --compact` | PASS — 2KB vs 26KB, all summary fields present |
| `tx` full with `_meta` | PASS — data sources, evidence paths, warnings, enrichment failures |
| `MEAT_CHAIN`/`MEAT_CASE` env vars | PASS — classify works without --chain --case flags |
| Net flows formatting | PASS — human-readable values with token symbols |
| Enrichment failure tracking | PASS — 2 tokens identified as unresolvable |
| Decode coverage | PASS — "9/56 logs decoded" shown |

## Issues addressed (from review)

| # | Issue | Status |
|---|-------|--------|
| 1 | Chain/case repetition | FIXED — MEAT_CHAIN, MEAT_CASE env vars |
| 2 | Forgetting --case loses evidence | MITIGATED — evidence paths shown in _meta; env var avoids forgetting |
| 3 | Net flows use raw addresses | FIXED — token symbols + UNKNOWN(0x...) fallback |
| 4 | 22KB JSON output | FIXED — --compact flag reduces to 2KB |
| 5 | No case management CLI | FIXED — case list/show/create |
| 6 | No case summary | FIXED — case show |
| 8 | No data source indication | FIXED — _meta.data_sources |
| 9 | Silent enrichment failures | FIXED — _meta.enrichment_failures |
| 10 | No decode coverage | FIXED — decode_coverage field |
| 13 | Evidence writes invisible | FIXED — _meta.evidence_saved |
| 14 | No degraded operation warning | FIXED — _meta.warnings |
