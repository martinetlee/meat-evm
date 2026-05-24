---
name: meat-recon
description: |
  Expand from partial exploit info to full picture. Finds additional attacker addresses,
  attack transactions, and victims. Use after /meat when the picture is incomplete.
user_invocable: true
arguments: "Case name (optional — uses MEAT_CASE env var if set)"
---

# MEAT-RECON: Expand from Partial Info

You are expanding an incomplete exploit picture. Always: `source .venv/bin/activate`

Ensure MEAT_CHAIN and MEAT_CASE are set (or pass --chain/--case to each command).

## Step 1: Load case state

```bash
python3 -m meat case show <case-name>
```

Review: addresses found so far, evidence count, journal tail, open questions.

## Step 2: Choose expansion strategy

### A) From attacker address(es)

1. **Full transaction history:**
   ```bash
   python3 -m meat txlist <attacker> --sort asc
   ```

2. **Key patterns to look for:**
   - `to=null` → contract deployment (attacker-deployed contracts)
   - Transactions BEFORE the attack → test runs, preparation
   - The first incoming tx → **funding source** (Tornado Cash? CEX? Another address?)

3. **Check for related addresses via same funder:**
   If attacker was funded by address X, search X's outgoing transfers:
   ```bash
   python3 -m meat transfers <funder_address>
   ```
   Other addresses funded by X may be part of the same operation.

4. **Search for approval setup (key compromise pattern):**
   ```bash
   python3 -m meat logs --event "Approval(address,address,uint256)" --topic1 <victim_padded> --from-block <block-1000> --to-block <attack_block>
   ```

### B) From victim contract(s)

1. **Recent transaction history + anomalies:**
   ```bash
   python3 -m meat txlist <victim> --limit 200 --sort desc
   ```

2. **Large token outflows:**
   ```bash
   python3 -m meat transfers <victim> --start-block <attack_block-100> --end-block <attack_block+100>
   ```

3. **Check admin/ownership:**
   ```bash
   python3 -m meat classify <victim>
   ```
   Look at `admin_info` — who is the owner? Was ownership transferred?
   ```bash
   python3 -m meat logs --event "OwnershipTransferred(address,address)" --address <victim>
   ```

4. **Check proxy upgrades:**
   ```bash
   python3 -m meat storage <victim> --slot 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --compare-block <attack_block-1>
   ```
   This checks if the implementation address changed around the attack.

### C) From a single transaction

1. **Get the full decoded tx:**
   ```bash
   python3 -m meat tx <hash>
   ```

2. **Classify every unique address** from token_transfers, internal_transactions, decoded_logs.

3. **Search for other txs between the same parties:**
   ```bash
   python3 -m meat txlist <attacker> --start-block <attack_block-1000> --end-block <attack_block>
   ```

## Step 3: Build timeline

From gathered data, build chronological timeline:
1. When was the attacker address created/funded?
2. Were there test transactions?
3. When did the attack(s) happen?
4. What happened after — fund movements?

## Step 4: Update case

After expanding:
- Update `addresses.json` with newly discovered addresses, roles, confidence levels
- Append findings to `journal.md`
- Update `case.json` summary
- Write/update `findings/recon.md`

Add all newly discovered attacker/victim addresses to monitored_addresses.

## Evidence Checklist

| Evidence | Command | Saved to |
|----------|---------|----------|
| Tx history | `meat txlist <addr>` | `evidence/txlist/` |
| Token transfers | `meat transfers <addr>` | `evidence/transfers/` |
| Address classify | `meat classify <addr>` | `evidence/classify/` |
| Event logs | `meat logs ...` | `evidence/logs/` |
| Address labels | `meat label <addr> -r <role>` | `addresses.json` |
| New tx decodes | `meat tx <hash>` | `evidence/tx/` |
| Case updates | manual | `case.json`, `findings/recon.md` |

## CORRECTNESS RULES

1. **All commands must save evidence.** Verify `MEAT_CASE` is set. Check `_meta.evidence_saved` after each command.
2. **Attacker classification requires evidence:**
   - CONFIRMED: initiated the exploit tx, or received stolen funds directly
   - HIGH: funded by confirmed attacker, or deployed a contract used in attack
   - MEDIUM: similar behavior pattern, same funding source
3. **Victim classification requires:** funds flowed OUT during the attack (CONFIRMED), or is the target contract (CONFIRMED)
4. Everything else is "related" or "unknown" until proven
5. **Label every discovered address** with `meat label` — role, name, source, confidence.
