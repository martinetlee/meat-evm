# Scenario-Based Fixes Review

## Issues fixed (10 total)

### Blockers resolved

| # | Issue | Fix | Verified |
|---|-------|-----|----------|
| 7 | Token transfers missing name/symbol/decimals | Added `resolve_token_info()` in decode.py — resolves via RPC `eth_call` (name/symbol/decimals) or explorer. Token info cached per-session. `tx` command now shows `"amount_formatted": "30000000.0 Dai"` | PASS — Euler hack shows "30000000.0 Dai" |
| 8 | Log decoding uses only target ABI | `_build_tx_result` now fetches ABI for each unique `log["address"]` with a per-tx cache. Euler hack: 39 decoded logs vs ~3 before | PASS — 39 decoded logs |
| 1 | Flow graph dies at DEX swaps | `build_flow_graph()` now tracks BOTH outgoing and incoming token transfers for each address. Incoming transfers reveal swap outputs. Peers from same tx are queued for BFS expansion | PASS — 9 nodes vs 2 before |
| 9 | No internal txs in tx output | `_build_tx_result` calls `explorer.get_internal_txs_by_hash()`. Shows contract creations, internal ETH transfers, delegatecalls | PASS — 2 internal txs for Euler hack |

### Significant issues resolved

| # | Issue | Fix | Verified |
|---|-------|-----|----------|
| 2 | No time-bounded flow | `flow` command now has `--start-block` and `--end-block`. Passed through to `build_flow_graph()` and all explorer calls | PASS |
| 3 | No balance checking | `classify` now calls `explorer.get_balance()`. Shows `"balance_formatted": "3.612838 ETH"` | PASS |
| 10 | No per-tx net flow | `_build_tx_result` computes `net_flows` dict: per-address per-token net movement including native ETH. Flash loan borrow/repay cancels naturally | PASS — net flows shown for Euler hack |
| 12 | calltrace no explorer fallback | `calltrace` now falls back to `explorer.get_internal_txs_by_hash()` when RPC debug and cast are unavailable. Returns flat call list | PASS — 2 internal txs found |
| 4 | No approval tracking | `decode_approval()` added to decode.py. `tx` command extracts Approval events alongside Transfers. Shows in `"approvals"` array | PASS — 2 approvals in Euler hack |
| 5 | WETH wrap/unwrap invisible | `decode_weth_event()` added — catches `Deposit(address,uint256)` and `Withdrawal(address,uint256)`. Shows in `"weth_events"` array with `"note": "ETH wrapped to WETH"` | PASS (no WETH events in Euler test tx, but decoder verified) |

## Files modified

| File | Changes |
|------|---------|
| `meat/decode.py` | Added `WETH_DEPOSIT_TOPIC`, `WETH_WITHDRAWAL_TOPIC`, `_token_info_cache`. New functions: `decode_approval()`, `decode_weth_event()`, `resolve_token_info()` |
| `meat/cli.py` | Rewrote `_build_tx_result()`: per-contract ABI log decoding, token enrichment, approval/WETH tracking, net flows, internal txs. Updated `flow` command with `--start-block`/`--end-block`. Added `calltrace` explorer fallback |
| `meat/trace.py` | Rewrote `build_flow_graph()`: tracks both incoming AND outgoing transfers, added `start_block`/`end_block` params, extracted `_add_known_node()` helper |
| `meat/classify.py` | Added `_check_balance()`, called for both EOA and contracts |

## Before/after comparison

### `tx` command output (Euler hack)
| Field | Before | After |
|-------|--------|-------|
| token_transfers | `amount_raw` only, no token name | `amount_formatted: "30000000.0 Dai"`, name/symbol/decimals |
| decoded_logs | ~3 (only target ABI) | 39 (per-contract ABI) |
| internal_transactions | missing | 2 (contract creations) |
| approvals | missing | 2 events |
| weth_events | missing | tracked (0 in this tx) |
| net_flows | missing | per-address per-token net movement |

### `classify` command output
| Field | Before | After |
|-------|--------|-------|
| balance_wei | always null | "3612838..." |
| balance_formatted | missing | "3.612838 ETH" |

### `flow` command
| Feature | Before | After |
|---------|--------|-------|
| DEX swap tracking | loses trail | follows both directions |
| Time bounding | no filter | --start-block, --end-block |
| Euler attacker (depth 1, from block 16817990) | 2 nodes, 2 edges | 9 nodes, 14 edges |

### `calltrace` command
| Feature | Before | After |
|---------|--------|-------|
| No RPC, no cast | hard error | falls back to explorer txlistinternal |
