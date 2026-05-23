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

## Step 1: Quick analysis

Start with the `quick` command for an immediate overview:

```bash
python3 -m meat quick $ARGUMENTS
```

This single command: parses input → detects chain → fetches tx + receipt → classifies from/to addresses → computes net flows with USD values → returns a compact summary in ~9 seconds.

If chain isn't detected from a URL, add `--chain <chain>`.

## Step 2: Create case

```bash
python3 -m meat case create <YYYY-MM-DD-protocol> --chain <chain>
```

Then set env vars to avoid repeating flags:
```bash
export MEAT_CHAIN=<chain> MEAT_CASE=<case-name>
```

All subsequent commands will use these defaults.

## Step 3: Full transaction decode (if needed)

If the quick output needs more detail:

```bash
python3 -m meat tx <hash>          # full output: all transfers, decoded logs, internal txs
python3 -m meat tx <hash> --compact  # summary only
```

The full output includes:
- `token_transfers` with names, symbols, decimals, formatted amounts
- `approvals` — ERC20 approval events (critical for key compromise detection)
- `weth_events` — ETH wrap/unwrap events
- `net_flows` — per-address per-token net movement with USD values (DeFiLlama)
- `decoded_logs` — all logs decoded using each emitting contract's ABI
- `internal_transactions` — contract-to-contract calls
- `decode_coverage` — how many logs were successfully decoded
- `_meta` — data sources, evidence paths, enrichment failures, warnings

## Step 4: Classify additional addresses

```bash
python3 -m meat classify <address>
```

Output now includes:
- **type** (eoa/contract), **balance** (ETH), **known entity** (CEX, bridge, mixer, DEX)
- **token_balances** — all ERC-20 balances (when Alchemy RPC available). Shows every non-zero token the address holds.
- **proxy detection** — EIP-1967, UUPS, beacon, minimal proxy (EIP-1167), diamond (EIP-2535)
- **admin_info** — owner(), admin(), AccessControl roles
- **is_lp_pair** — Uniswap V2-style LP detection with token0/token1
- **checks_performed** — what was tried and what was skipped (for auditability)

## Step 5: Attack type classification

Based on the data, classify the attack:

- **Smart contract exploit**: Complex call, flash loans, unusual function calls, large token movements through DeFi protocols. Net flows show flash loan borrow/repay canceling naturally.
- **Key compromise**: Simple transfers from victim EOA. Look for `approvals` in the tx output — attacker may have set approvals before draining. Use `meat logs --event 'Approval(address,address,uint256)' --address <token> --chain <chain>` to search for suspicious approvals.
- **Governance attack**: Malicious proposals. Search with `meat logs --event 'ProposalCreated(...)' --address <governor>`.
- **Rug pull / insider**: Look at `admin_info` in classify output — who is the owner? Use `meat logs --event 'OwnershipTransferred(address,address)' --address <contract>` to check ownership history.

## Step 6: Present findings

Use the USD values from net_flows. Example:

```
RECON SUMMARY
═══════════════════════════════════════
Chain:          ethereum
Attack type:    Smart contract exploit (CONFIRMED)
Block:          16817996
Timestamp:      2023-03-13

ATTACKER(S):
  0x5f259d0b... — EOA — balance: 3.61 ETH
  0xebc29199... — contract (unverified) — exploit contract

VICTIM(S):
  0x27182842... — Euler (verified proxy → 0xec29b4c2...)

NET FUND FLOWS:
  Dai:  8,877,507 ($8,780,121) — from Euler to attacker contract

ATTACK TX(es):
  0xc310a0af... — success — 20 token transfers — fee: 0.11 ETH
═══════════════════════════════════════
```

## Step 7: Save case state

Write findings to `cases/<case>/findings/recon.md`. Every claim must cite evidence from `_meta.evidence_saved` paths.

## Step 8: Offer next steps

- **`/meat-recon`** — expand from partial info (find more txs, addresses, funding source)
- **`/meat-trace`** — track where stolen funds went (with USD values)
- **`/meat-analyze`** — understand the vulnerability (uses Tenderly traces, storage diffs, source code)
- **`/meat-poc`** — reproduce the exploit in Foundry

## CORRECTNESS RULES

1. **Never claim without evidence.** Every statement must reference specific data from CLI output.
2. **Use confidence levels.** CONFIRMED / HIGH / MEDIUM / LOW/HYPOTHESIS.
3. **Report net flows with USD.** The net_flows field already computes this — use it directly.
4. **Check `_meta.warnings`** — if it says "No RPC", token/admin detection was limited.
5. **Check `_meta.enrichment_failures`** — these tokens couldn't be resolved. Classify them separately if important.
6. **Check `_meta.data_sources`** — tells you if data came from RPC, explorer_proxy, Alchemy, Tenderly, or Sourcify.
