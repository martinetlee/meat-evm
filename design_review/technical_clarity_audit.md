# Technical Clarity & Auditability Review

## Methodology

Reviewed every module for: Can a new analyst understand what the code does? Can someone verify the output is correct? Can someone trace a finding back to raw data?

---

## Issues Found

### 1. `_meta` is not on every command output (inconsistency)

**Severity: High (auditability)**

`tx` and `quick` include `_meta`. But `classify`, `txlist`, `transfers`, `flow`, `logs`, `source`, `abi`, `storage`, `calltrace`, `decode` — none of these include `_meta`. An auditor reviewing a case that used these commands can't tell what data source was used or if there were failures.

**Fix**: Every command that makes API calls should include `_meta` in its output.

### 2. `_build_tx_result` is a 180-line function doing 6 unrelated things

**Severity: Medium (clarity)**

`_build_tx_result` (lines 342-524) does:
1. Parse basic tx fields
2. Extract token transfers / approvals / WETH events
3. Resolve token info for each transfer
4. Compute net flows
5. Decode input calldata
6. Decode all logs (per-contract ABI)
7. Fetch internal transactions

This is hard to audit because a change in step 3 (token resolution) can silently affect step 4 (net flows). An auditor can't review the net flow logic without also understanding the token resolution path.

**Fix**: Break into `_extract_events()`, `_enrich_tokens()`, `_compute_net_flows()`, `_decode_calldata()`, `_decode_all_logs()`, `_fetch_internal_txs()`. Each should be independently testable.

### 3. Evidence saves raw API response, output shows transformed data — gap is unverifiable

**Severity: High (auditability)**

The evidence store saves the raw Etherscan/RPC JSON response (`tx_data`). The CLI output shows the *transformed* result (with `format_value`, token resolution, net flows). But there's nothing connecting them. An auditor sees `"Dai": "8877507.348306"` in the output but the evidence file contains `"value": "0x1e7e4171bf4d3a0000..."`. There's no documented mapping from raw → formatted.

The net flows are especially opaque: they aggregate across 20+ transfers with token resolution, decimal formatting, and sign flipping. If a net flow number is wrong, an auditor has to manually re-derive it from the raw receipt logs to verify.

**Fix**: Add a `_meta.computation_notes` or embed the derivation chain. At minimum, add raw values alongside formatted values in net_flows:
```json
"Dai": {"formatted": "8877507.348306", "raw_wei": "8877507348306697267428294", "decimals": 18}
```

### 4. Silent fallbacks hide data source

**Severity: Medium (auditability)**

Multiple functions silently fall through from one data source to another:
- `classify._get_code()`: tries RPC, falls back to explorer, returns None on both fail — caller just sees `type: error` with no explanation of what was tried
- `_build_tx_result` token resolution: tries RPC `eth_call`, falls back to explorer `get_source_code` — caller sees either a token name or nothing, no indication which path was taken
- `storage._read_slot()`: tries RPC, falls back to explorer, returns `"0x"` on both fail — indistinguishable from "slot is actually zero"

**Fix**: For `classify`, add a `checks_performed` list showing what was tried and the outcome. For `storage`, return an error or a `"source": "rpc"|"explorer"|"failed"` field so `"0x"` from a failed read isn't confused with a genuine zero slot.

### 5. `net_flows` decimal lookup is O(n*m) and fragile

**Severity: Medium (correctness risk)**

Lines 451-460 in `_build_tx_result`:
```python
for tok, val in tokens.items():
    decimals = 18
    for t_addr, info in seen_tokens.items():
        if info and info.get("symbol") == tok:
            decimals = info.get("decimals", 18)
            break
```

This scans `seen_tokens` by symbol match to find decimals. If two tokens have the same symbol (e.g., two tokens both named "USDC"), this picks the first one's decimals. It also defaults to 18 for any token whose symbol isn't in `seen_tokens` (including `UNKNOWN(...)` labels), which would format a 6-decimal token's value with 18 decimals — producing a wrong number.

**Fix**: Build a `{token_label: decimals}` map during the token labeling step, using the same label derivation logic. Don't rely on symbol matching after the fact.

### 6. `evidence.save()` silently skips if file exists

**Severity: Medium (auditability)**

`evidence.py` line 30: `if path.exists(): return`. This means re-running a command won't update evidence if it already exists. This is correct for immutable on-chain data but creates confusion:
- If the first fetch had a rate limit error (partial data), the bad data is cached forever
- There's no indication to the caller that the data came from cache vs fresh fetch
- The `_meta.evidence_saved` path is returned even for cache hits, making it look like new data was saved

**Fix**: Return a different indicator for cache hits vs new writes. Add a boolean to the return: `(path, was_written)`.

### 7. No type validation on API responses

**Severity: Low (robustness)**

Throughout the codebase, API responses are treated as trusted dicts. For example, `tx_data.get("value", "0x0")` assumes `value` is a hex string. If the API returns an unexpected format (integer, null, nested object), the code may crash with an unhelpful error or produce wrong output silently.

This is especially relevant for the V2 Etherscan API which may have slightly different response formats than V1.

**Fix**: Add response shape validation for critical fields (at minimum: tx hash, from, to, value, gasPrice, blockNumber). A simple check like "is this a hex string?" before `int(x, 16)`.

### 8. `classify` output has no version/timestamp

**Severity: Low (auditability)**

When an auditor reads `evidence/classify/0xabc.json`, there's no indication of when this classification was performed. On-chain state changes over time (e.g., owner changes, proxy upgrades). A classification from 3 months ago may be stale. The evidence envelope has `fetched_at` (from `evidence.py`), but the classify result dict itself doesn't.

### 9. `case.py` journal has no structure

**Severity: Low (auditability)**

The journal is append-only markdown, which is good. But entries are free-text strings passed by the caller. There's no structured format enforcement. An automated audit of the journal (e.g., "find all address classifications") requires parsing markdown text, not reading structured data.

**Fix**: Consider a structured journal alongside the markdown one — a JSON lines file where each entry has `timestamp`, `action`, `details`.

### 10. `_auto_detect_chain()` creates a new rate limiter per chain tried

**Severity: Low (correctness)**

Line 241: Each chain in the loop gets a fresh `RateLimiter()`. If the API key is shared across chains (Etherscan V2 uses one key for all chains), these independent rate limiters don't coordinate. The actual rate to Etherscan could be N times the intended limit, where N is the number of chains tried.

---

## What's Good

### Evidence separation is sound
Raw API responses → `evidence/`, analysis → `findings/`. The evidence envelope includes `_meta.fetched_at` and `chain`. This is a solid forensic foundation.

### Confidence tagging design is right
The `addresses.json` schema with `role`, `confidence`, `evidence` references, and `reason` is exactly what an auditor needs. The skill instructions enforce this.

### Known entity labeling is transparent
`known_addresses.json` is a flat, readable JSON file. The classify output shows both the label and the category. An auditor can verify any label by checking the file.

### Rate limit retry logic is correct
The explorer client retries rate limit errors with backoff. This is the right behavior — better to retry than to silently return partial data.

### Test suite validates against real data
The Euler hack integration tests prove the tool produces correct output for a known exploit. This is the strongest form of validation.

---

## Priority Fixes

| # | Issue | Impact | Effort |
|---|-------|--------|--------|
| 1 | `_meta` not on all commands | Auditability gap | Low — wrap each command's output |
| 3 | Net flows show formatted only, no raw | Can't verify computation | Low — add raw values |
| 5 | Decimal lookup is fragile | Wrong numbers for same-symbol tokens | Medium — refactor labeling |
| 2 | `_build_tx_result` is monolithic | Hard to audit/test | Medium — split into functions |
| 4 | Silent fallbacks | Can't tell what was tried | Medium — add checks_performed |
| 6 | Evidence cache hit indistinguishable | Misleading _meta | Low — return (path, is_new) |
