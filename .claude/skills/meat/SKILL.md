---
name: meat
description: |
  EVM exploit analysis. Paste a tx hash, address, or block explorer URL.
  Identifies attackers, victims, fund movements, and attack type.
  Use when: "analyze this exploit", "what happened in this tx", or a raw tx hash / explorer URL.
user_invocable: true
arguments: "Transaction hash(es), address(es), or block explorer URL(s)"
---

# MEAT: Martinet's Exploit Analysis Tool

You are analyzing an EVM exploit. Always activate the venv first: `source .venv/bin/activate`

## EVIDENCE RULES

Every CLI command MUST include `--case <case-name>` (or have `MEAT_CASE` env var set). This ensures all fetched data is saved to `cases/<case>/evidence/` automatically. After each command, verify evidence was saved by checking `_meta.evidence_saved` in the output.

Evidence is write-once (immutable) and stored as JSON envelopes with `_meta` (category, key, chain, timestamp) + `data` payload.

## Step 1: Quick analysis

```bash
python3 -m meat quick $ARGUMENTS
```

Parses input → detects chain → fetches tx + receipt → classifies from/to → computes net flows with USD. If chain isn't detected from a URL, add `--chain <chain>`.

## Step 2: Create case and set env vars

```bash
python3 -m meat case create <YYYY-MM-DD-protocol> --chain <chain>
export MEAT_CHAIN=<chain> MEAT_CASE=<case-name>
```

**All subsequent commands inherit these defaults.** Verify with `echo $MEAT_CASE $MEAT_CHAIN`.

## Step 3: Save attack transaction evidence

Re-run the attack tx with case set to save evidence:

```bash
python3 -m meat tx <hash>          # saves to evidence/tx/ and evidence/receipt/
python3 -m meat tx <hash> --compact  # same evidence, shorter output
```

**Verify**: Check `_meta.evidence_saved` lists `evidence/tx/<hash>.json`.

> ⚠️ Never analyze the money-out tx in `--compact`. The decisive tx must be read in full.

## Step 3.5: Follow the money — find where value is actually realized

The tx you were handed is usually a *mechanism* (a permit, a transfer, a flash-loan setup),
NOT where the profit lands. The money is often taken out a few txs later. Find it:

```bash
python3 -m meat profit <initiator_eoa> --block <attack_block>   # scans forward, ranks by net stablecoin gain
```

Take the `realized_profit_tx` it reports and **read it in full** (`meat tx <hash>`, not `--compact`).
That tx tells you who actually lost the money — which is the real story. Do NOT conclude from the
handed tx alone.

## Step 3.6: Verify provenance before labeling anyone

Before you call an address a victim or attacker, answer "where did its tokens come from?" A wallet
holding billions of an obscure token is a red flag, not a victim:

```bash
python3 -m meat provenance <address> [--token <token>]   # earliest inbound source per token
```

If a token came from a **single source** (flagged in output), the "holder" is likely a pre-seeded
sybil, not an independent user. This one check distinguishes phishing victims from attacker sybils.
Run it for every address you're about to label attacker/victim.

## Step 4: Classify and label ALL addresses

Label every address that appears in the attack — not just attacker/victim, but also tokens, protocols, and intermediaries. The report sequence diagram and flow graph use these labels.

**4a. Label key actors** (attacker, victim, protocols):
```bash
python3 -m meat classify <address>    # saves to evidence/classify/
python3 -m meat label <address> -r <role> -n "<name>" --note "<reason>"
```

Roles: `attacker`, `victim`, `collector`, `funder`, `exchange`, `mixer`, `bridge`, `intermediate`.

**4b. Label ALL token contracts** from the tx output:

Check `token_transfers` in the tx output. For each unique `token_address`, label it:
```bash
python3 -m meat label <token_address> -r intermediate -n "<token_symbol>" --note "Token contract"
```

Common tokens to label: USDC, USDT, DAI, WETH, any LP tokens (3CRV, MIM-3CRV), protocol-specific tokens (MachineShare, aUSDC).

**4c. Label protocol contracts** from the call trace:

If you ran `meat calltrace`, check the decoded trace for contracts that were called. Label each with its name and protocol:
```bash
python3 -m meat label <contract_addr> -r intermediate -n "<contract_name>" --note "Part of <protocol>"
```

**Verify**: `addresses.json` contains ALL interacted addresses with labels. The report sequence diagram uses these labels for column headers.

## Step 5: Attack type classification

Based on the data, classify the attack:

- **Smart contract exploit**: Complex call, flash loans, unusual function calls. Net flows show flash loan borrow/repay canceling.
- **Key compromise**: Simple transfers from victim EOA. Check `approvals` in tx output.
- **Governance attack**: Malicious proposals. `meat logs --event 'ProposalCreated(...)'`
- **Access control**: Unprotected admin functions. Check `admin_info` in classify.

## Step 6: Update case.json

After classification, update `case.json` with structured data:

```json
{
  "exploit_type": "smart_contract_exploit|key_compromise|...",
  "exploit_subtype": "oracle_manipulation|reentrancy|...",
  "confidence": "CONFIRMED|HIGH|MEDIUM|LOW",
  "attack_tx": "0x...",
  "summary": {
    "total_stolen": {"ETH": "100", "USDC": "50000"},
    "total_stolen_usd": "~$350,000",
    "attacker_addresses": 1,
    "victim_addresses": 2,
    "attack_txs": 1
  },
  "exploit_indicators": {
    "<exploit_type>": {
      "flash_loan": "...",
      "oracle_manipulation": "...",
      ...
    }
  }
}
```

**This is critical for the report generator.** Without these fields, the report shows empty data.

## Step 7: Write findings

Write `cases/<case>/findings/recon.md`. Every claim must cite evidence from `_meta.evidence_saved` paths.

## Step 7.5: GATE — run `meat check` before you conclude (MANDATORY)

```bash
python3 -m meat check <case>   # exits non-zero on violations
```

This is a hard gate, not advice. It enforces:
- **value conservation** — every large priced (stablecoin/ETH) winner/loser in a decisive tx is labeled.
- **loss attribution** — the attacker's priced gain must be accounted for by a **`victim`-role**
  address: either a matching priced loss, or absorbing an illiquid token the attacker offloaded onto
  it. If a non-attacker address receives a token the attacker dumped (the NAV/oracle-drain
  signature), the gate names it as the likely victim in `victim_candidates` and fails until you
  investigate and label it. This is what forces you to answer *"which contract actually lost funds?"*
- **provenance** — every attacker/victim label has a `meat provenance` record (or explicit waiver).
- **money-out tx fetched in full** — decisive txs exist in `evidence/tx/` (not compact); and any tx
  `meat profit` flagged as the largest realized gain must be declared decisive.
- **earned negatives** — don't assert "not a vulnerability" / "just phishing" without a traced value flow.

Set `eth_price_usd` in case.json to also value ETH/WETH flows (check is offline, so it needs the
price stated). Tune `check_min_usd` to change the threshold. Read `victim_candidates` in the output —
it points at the contracts that absorbed dumped assets.

Do not present conclusions or write the final report while `meat check` fails. A Stop hook also runs
this automatically. If a violation is a genuine false positive, resolve it explicitly (label the
address, or set `provenance_waived: true` with a reason) — don't ignore it.

## Step 8: Offer next steps

- **`/meat-trace`** — track where stolen funds went
- **`/meat-analyze`** — understand the vulnerability (call traces, source code)
- **`/meat-recon`** — expand from partial info (find more txs, addresses)
- **`/meat-poc`** — reproduce the exploit in Foundry
- **`meat report <case>`** — generate HTML report from collected evidence

## Evidence Checklist (verify before finishing)

| Evidence | Command | Saved to |
|----------|---------|----------|
| Attack tx decode | `meat tx <hash>` | `evidence/tx/<hash>.json` |
| **Money-out tx** | `meat profit <eoa> --block <blk>` → `meat tx <hash>` | `evidence/profit/`, `evidence/tx/` |
| **Provenance (victims/attackers)** | `meat provenance <addr>` | `evidence/provenance/<addr>.json` |
| Address classifications | `meat classify <addr>` | `evidence/classify/<addr>.json` |
| **Key actor labels** | `meat label <addr> -r attacker/victim` | `addresses.json` |
| **Token contract labels** | `meat label <token_addr> -r intermediate -n <symbol>` | `addresses.json` |
| **Protocol contract labels** | `meat label <addr> -r intermediate -n <name>` | `addresses.json` |
| Case metadata | manual edit | `case.json` (exploit_type, confidence, summary, attack_tx) |
| Findings | manual write | `findings/recon.md` |

**Critical**: Label ALL addresses from `token_transfers` and the call trace, not just attacker/victim. The report uses these labels for the sequence diagram and flow graph.

## READING RULES

10. **Unverified contract in the exploit path? Read its bytecode before asserting what it does.**
    Inferring behaviour from "the attack succeeded" is not evidence of mechanism — it cannot
    distinguish *no check* from *a check with a bypass*, and that distinction is usually where the
    cheap fix lives. Disassemble, find the dispatch, read the branch.
11. **A failed experiment is evidence about your instrument first.** If you cannot reproduce an
    on-chain commitment (a Merkle root, a hash, a balance), you do not yet understand the format.
    Say so. Do not fall back on a correlation and present it as a finding.
12. **Measure the victim, not the attacker.** "How much left" is a balance delta on the victim across
    the window, not a sum of the attacker's transactions. "How many contracts are affected" is a
    configuration-event replay, not a list of the ones you saw used. "Is it over" is activity since
    your newest evidence, not a config read.
13. **Gross holdings are not value at risk.** Check the liability side before quoting a number.

## CORRECTNESS RULES

1. **Never claim without evidence.** Every statement must reference specific data from CLI output.
2. **Use confidence levels.** CONFIRMED / HIGH / MEDIUM / LOW / HYPOTHESIS.
3. **Report net flows with USD.** The net_flows field already computes this — use it directly.
4. **Check `_meta.warnings`** — if it says "No RPC", token/admin detection was limited.
5. **Check `_meta.evidence_saved`** — confirm data was persisted to the case.
6. **Check `_meta.data_sources`** — tells you if data came from RPC, explorer, Alchemy, Tenderly, or Sourcify.
7. **Follow the money, not the tx.** The handed tx is a mechanism; find where value is realized (`meat profit`) and read that tx in full. A permit/transfer is HOW, not WHO lost what.
8. **Verify provenance before labeling.** `meat provenance` — a single-source "holder" is a sybil, not a victim.
9. **Value must conserve.** If someone gained $X, someone lost $X — identify and label them. `meat check` enforces this; never conclude while it fails.
