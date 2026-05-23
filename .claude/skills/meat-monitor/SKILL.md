---
name: meat-monitor
description: |
  Watch active cases for new on-chain activity. Checks monitored addresses for new
  transactions. Compatible with /loop for continuous monitoring.
user_invocable: true
arguments: "Case name"
---

# MEAT-MONITOR: Case Monitoring

You are checking for new activity on a monitored case. Always: `source .venv/bin/activate`

## Step 1: Load case state

```bash
python3 -m meat case show $ARGUMENTS
```

Check: `status` (only monitor `active` or `monitoring` cases), `monitored_addresses` with their `last_tx_block`.

If status is `closed`: report "Case is closed" and stop.

## Step 2: Check each monitored address

For each address, check for new activity since the last known block:

```bash
python3 -m meat txlist <address> --start-block <last_tx_block+1> --sort asc
python3 -m meat transfers <address> --start-block <last_tx_block+1>
```

## Step 3: Analyze new activity

For any new transactions:

1. **Quick classify new destinations:**
   ```bash
   python3 -m meat classify <dest_addr>
   ```
   Check `known_entity` for automatic identification (CEX, bridge, mixer).

2. **Check current balance:**
   The classify output includes `balance_formatted`.

3. **Assess urgency:**
   - **URGENT**: Funds moving to CEX → exchange can freeze if contacted quickly
   - **URGENT**: Funds moving to bridge → about to leave this chain
   - **MEDIUM**: Funds moving to new unknown address → add to monitoring
   - **LOW**: Funds moving to mixer → already hard to trace

4. **Check for approval-based drains:**
   ```bash
   python3 -m meat logs --event "Approval(address,address,uint256)" --topic2 <attacker_padded> --from-block <last_block>
   ```

## Step 4: Update case state

- Update `last_tx_block` for each checked address
- Add new destination addresses to `monitored_addresses`
- Append journal entry

## Step 5: Report

If new activity:
```
MONITOR UPDATE — <case-name>
═══════════════════════════════
  <address> (attacker):
    Block <N>: Transferred 100 ETH ($170,000) to 0xNew... (unknown)
    Block <N>: Swapped 50 ETH for DAI on Uniswap V3

  URGENT: 100 ETH heading to unknown address — classify and monitor
═══════════════════════════════
```

If no new activity: "No new activity since block <N>." (keep it brief for loop mode)

## Loop mode

Run continuously:
```
/loop 5m /meat-monitor <case-name>
```

Keep output concise when nothing changed.
