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

## Step 1: Load case state

```bash
python3 -m meat case show <case-name>
```

Identify attacker addresses and the attack block number.

## Step 2: Run flow graph

For each attacker address, trace outflows starting from the attack block:

```bash
python3 -m meat flow <attacker_addr> --depth 2 --start-block <attack_block>
```

The flow command:
- **If Alchemy RPC is configured**: Uses `alchemy_getAssetTransfers` — single API call per address covering ETH + internal + ERC20 + ERC721 + ERC1155 with pre-enriched token names. Much faster than explorer.
- **Otherwise**: Uses Etherscan explorer (3 calls per address: txlist + internal + tokentx)
- Follows BOTH outgoing AND incoming token transfers (catches DEX swap outputs)
- Auto-labels known entities (CEX deposits, bridges, mixers, DEX routers)
- Check `_meta.data_sources` to see which path was used

## Step 3: Classify each destination

For every new address in the flow graph:

```bash
python3 -m meat classify <addr>
```

Check `known_entity` field for automatic categorization:
- `cex` → **CEX deposit** (Binance, Coinbase, Kraken). Law enforcement can subpoena.
- `mixers` → **Mixer** (Tornado Cash, Railgun). Tracing becomes probabilistic.
- `bridges` → **Bridge**. Note destination chain. Offer to continue tracing cross-chain.
- `dex_routers` → **DEX swap**. Check what came out:
  ```bash
  python3 -m meat tx <swap_tx_hash> --compact
  ```
  The net_flows will show what tokens the attacker received from the swap.
- `lending` → **DeFi deposit**. Funds may be parked as collateral.
- No known_entity → **Unknown address**. Likely attacker-controlled if it's an EOA.

## Step 4: Search for approval-based drains

For token approvals the attacker may have set:

```bash
python3 -m meat logs --event "Approval(address,address,uint256)" --topic2 <attacker_padded_to_32_bytes> --from-block <attack_block> --chain <chain>
```

This finds all tokens where the attacker was approved as spender.

## Step 5: Check current balances

For each attacker-controlled address:

```bash
python3 -m meat classify <addr>
```

- `balance_formatted` — current ETH balance
- `token_balances` — all ERC-20 balances (available when Alchemy RPC is configured). Shows every non-zero token the address holds — critical for knowing if stolen tokens are still there.

Cross-reference to identify:
- Addresses that still hold funds (recovery opportunity)
- Addresses that have been fully drained (already moved)

## Step 6: Cross-chain bridges

If funds crossed a bridge:
1. Note the bridge contract, source tx, destination chain, expected recipient
2. Ask the user if they want to continue tracing on the destination chain
3. If yes, switch chain:
   ```bash
   export MEAT_CHAIN=<destination_chain>
   python3 -m meat flow <recipient_addr> --depth 2
   ```

## Step 7: Write fund trace report

Write `cases/<case>/findings/fund-trace.md` with:

1. **Flow diagram** (ASCII):
```
Attacker EOA (0xDead...)
  ├─ 200 ETH ($340,000) → 0xCafe... (intermediate)
  │   ├─ 100 ETH ($170,000) → Tornado Cash (mixer) ⚠️
  │   └─ 100 ETH ($170,000) → Binance 14 (CEX deposit) ✓
  ├─ 1M USDC ($1,000,000) → Uniswap V3 (swapped to ETH)
  │   └─ 500 ETH ($850,000) → 0xBabe... (intermediate)
  └─ 50 ETH ($85,000) → remains at 0xDead...
```

2. **Recovery summary** (using USD values from net_flows):

| Category | Amount | Status |
|----------|--------|--------|
| CEX deposits | $170,000 | Potentially recoverable (contact exchange) |
| Mixers | $170,000 | Likely unrecoverable |
| Still at attacker addresses | $85,000 | Can be monitored |
| Cross-chain bridges | $1,850,000 | Continue trace on destination |

3. **Total:** $X stolen, $Y potentially recoverable

## CORRECTNESS RULES

1. **Only follow confirmed on-chain transfers.** Every edge must be a real Transfer event or ETH transfer.
2. **Use USD values.** The net_flows include DeFiLlama prices — use them for recovery prioritization.
3. **Don't speculate about mixer outputs.** After Tornado Cash, label as "trace ends at mixer."
4. **Note timestamps.** "200 ETH moved 30 minutes after attack" matters for recovery.
