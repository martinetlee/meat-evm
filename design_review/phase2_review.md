# Phase 2 Design Review — Recon + Trace + Monitor

## What was built

Three new CLI commands (`txlist`, `transfers`, `flow`), a fund flow graph builder (`trace.py`), and three skill files (`meat-recon.md`, `meat-trace.md`, `meat-monitor.md`).

### Modules implemented / modified

| Module | Change | Status |
|--------|--------|--------|
| `trace.py` | New — fund flow graph builder (BFS) | Tested |
| `cli.py` | Added `txlist`, `transfers`, `flow` commands | Tested |
| `meat-recon.md` | New skill — expand from partial info | Written |
| `meat-trace.md` | New skill — fund tracing workflow | Written |
| `meat-monitor.md` | New skill — case monitoring (loop-compatible) | Written |

### Test results

| Test | Result | Notes |
|------|--------|-------|
| `txlist` — Euler attacker history | PASS | Returns 5 txs with hash, value, to address |
| `transfers` — Euler attacker tokens | PASS | Returns ERC20 transfers with token symbols |
| `flow` — depth-1 from attacker | PASS | Builds graph with 2 nodes, 2 edges, net flow summary |
| Error handling — all commands | PASS | Missing chain, invalid input handled |

### FundFlowGraph design

The `trace.py` module implements a BFS-based fund flow tracker:

```python
FundFlowGraph:
  - nodes: dict[address → {label, type, ...}]
  - edges: list[{from, to, value, token, tx_hash, block, timestamp}]
  - summary: net token flows per address (auto-computed)
```

The `build_flow_graph()` function:
1. Starts from a root address
2. Fetches normal txs and token transfers via explorer API
3. For outgoing transfers, adds edges and queues destination addresses
4. Continues BFS up to `depth` hops
5. Rate-limited by the explorer client

### Skill design decisions

1. **`/meat-recon`**: Three expansion strategies (from attacker, from victim, from single tx). Each produces concrete CLI commands for Claude to run. Includes correctness rules for address classification confidence.

2. **`/meat-trace`**: Classifies destinations as CEX/bridge/mixer/DEX/intermediate. Produces ASCII flow diagram and endpoints table. Notes bridge crossings for potential cross-chain continuation.

3. **`/meat-monitor`**: Loop-compatible. Checks each monitored address for new txs since last known block. Classifies urgency (HIGH for CEX/bridge movements). Concise output when nothing changed.

### Known limitations

1. **Flow graph rate limiting**: Each address in BFS requires 2 API calls (txlist + tokentx). At depth 2 with many intermediate addresses, this can hit rate limits. The rate limiter handles this but scanning is slow for wide graphs.

2. **No internal transaction tracking in flow**: The flow graph only follows normal txs and token transfers, not internal (CALL) transactions. A contract-to-contract ETH transfer won't be caught by `txlist`.

3. **No token enrichment in flow edges**: The flow graph stores token symbols from the explorer API but doesn't independently verify token names or add decimal formatting.

4. **Cross-chain tracing is manual**: Bridge detection requires human recognition. No automated bridge event decoding yet (Phase 4).

## Files created / modified

```
meat/trace.py (new)
meat/cli.py (modified — added txlist, transfers, flow commands)
.claude/skills/meat-recon.md (new)
.claude/skills/meat-trace.md (new)
.claude/skills/meat-monitor.md (new)
```
