---
name: meat-trace
description: |
  Track where stolen funds went after an exploit. Follows money through DEX swaps,
  bridges, mixers, and CEX deposits. Use after /meat or /meat-recon.
user_invocable: true
arguments: "Case name (optional — uses MEAT_CASE env var if set)"
---

# MEAT-TRACE: Fund Tracing

You are tracing stolen funds. Always: `source .venv/bin/activate`

## EVIDENCE RULES

**Verify `MEAT_CASE` and `MEAT_CHAIN` are set before running any command.** All data-fetching commands save evidence automatically when case is set. After each command, check `_meta.evidence_saved` to confirm persistence.

## Step 1: Load case state

```bash
python3 -m meat case show $MEAT_CASE
```

Identify attacker/collector addresses and the attack block number from case.json and addresses.json.

## Step 2: Run flow graph

For each attacker/collector address, trace outflows:

```bash
python3 -m meat flow <collector_addr> --depth 2
```

**Evidence saved**: `evidence/flow/<address>.json` — contains nodes[], edges[], summary.

The flow command:
- **Alchemy RPC**: `alchemy_getAssetTransfers` — single API call per address.
- **Explorer fallback**: 3 calls per address (txlist + internal + tokentx).
- Follows BOTH outgoing AND incoming transfers (catches DEX swap outputs).
- Auto-labels known entities (CEX, bridges, mixers, DEX routers).

## Step 3: Gas funding analysis

Identify attacker-controlled addresses via gas funding source:

```bash
python3 -m meat funder <addr1> <addr2> <addr3> ...
```

**Evidence saved**: `evidence/funder/cluster_analysis.json` — clusters addresses by common gas funder.

Addresses funded by a known attacker/collector are definitively attacker-controlled.

## Step 4: Classify and label each destination

For every new address in the flow graph:

```bash
python3 -m meat classify <addr>     # evidence/classify/<addr>.json
python3 -m meat label <addr> -r <role> -n "<name>" --source "<source>"
```

Check `known_entity` for categorization: `cex`, `mixers`, `bridges`, `dex_routers`, `lending`.

## Step 5: Check current balances

For each attacker-controlled address, `classify` output includes:
- `balance_formatted` — current native token balance
- `token_balances` — all ERC-20 balances (Alchemy)

Cross-reference to identify recovery opportunities vs already-drained addresses.

## Step 6: Cross-chain bridges

If funds crossed a bridge:
1. Note bridge contract, source tx, destination chain, recipient
2. Switch chain: `export MEAT_CHAIN=<destination_chain>`
3. Continue: `python3 -m meat flow <recipient_addr> --depth 2`

## Step 7: Update case.json

Add recovery information to case.json:

```json
{
  "summary": {
    "total_stolen": {"ETH": "100"},
    "total_stolen_usd": "~$350,000",
    "total_recovered": {},
    "total_recovered_usd": "$0",
    "potentially_recoverable_usd": "~$170,000"
  }
}
```

## Step 8: Write fund trace report

Write `cases/<case>/findings/fund-trace.md` with:
1. Flow diagram (ASCII)
2. Recovery summary table (CEX deposits, mixers, still-held, bridges)
3. Total stolen vs potentially recoverable

## Evidence Checklist

| Evidence | Command | Saved to |
|----------|---------|----------|
| Flow graph | `meat flow <addr>` | `evidence/flow/<addr>.json` |
| Gas funding clusters | `meat funder <addrs>` | `evidence/funder/cluster_analysis.json` |
| Address classifications | `meat classify <addr>` | `evidence/classify/<addr>.json` |
| Address labels | `meat label <addr>` | `addresses.json` |
| Swap tx decodes | `meat tx <hash> --compact` | `evidence/tx/<hash>.json` |
| Case summary | manual update | `case.json` |
| Findings | manual write | `findings/fund-trace.md` |

## CORRECTNESS RULES

1. **Only follow confirmed on-chain transfers.** Every edge must be a real Transfer event or ETH transfer.
2. **Use USD values.** The net_flows include DeFiLlama prices.
3. **Don't speculate about mixer outputs.** After Tornado Cash, label as "trace ends at mixer."
4. **Check `_meta.evidence_saved`** after each command to confirm data was persisted.
