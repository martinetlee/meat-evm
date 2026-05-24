---
name: meat-analyze
description: |
  Deep vulnerability analysis. Fetches contract source code, call traces, and walks
  through the exploit step-by-step. Identifies vulnerability class and root cause.
  Use after /meat when you want to understand HOW the exploit works.
user_invocable: true
arguments: "Case name (optional — uses MEAT_CASE env var if set)"
---

# MEAT-ANALYZE: Exploit Analysis

You are analyzing the technical vulnerability. Always: `source .venv/bin/activate`

## EVIDENCE RULES

**Verify `MEAT_CASE` and `MEAT_CHAIN` are set.** All commands save evidence automatically. This skill produces the most critical evidence for the report's Technical tab — call traces, source code, and vulnerability details.

## Step 1: Load case state

```bash
python3 -m meat case show $MEAT_CASE
```

Identify: attack tx hash, victim contract(s), attacker contract(s), attack type from recon.

## Step 2: Fetch victim contract source code

```bash
python3 -m meat source <victim_addr>       # saves to evidence/source/
```

**Evidence saved**: `evidence/source/<addr>.json` — contract name, compiler, source code, ABI.

If proxy (check classify output `proxy_type`), also fetch implementation:
```bash
python3 -m meat source <implementation_addr>
```

## Step 3: Get the call trace

```bash
python3 -m meat calltrace <attack_tx_hash>   # saves to evidence/trace/
```

**Evidence saved**: `evidence/trace/<hash>.json` — nested call tree.

Trace methods (tried in order): `debug_traceTransaction` (Alchemy) → Tenderly → `cast run` → explorer `txlistinternal`.

Check `_meta.data_sources` to know which method was used.

## Step 4: Check state before/after attack

```bash
python3 -m meat storage <victim> --slot <slot_hex> --compare-block <attack_block-1>
```

Common slots:
- `0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc` — EIP-1967 implementation
- `0x0` — owner / initialized flag

## Step 5: Search for related events

```bash
python3 -m meat logs --address <victim> --from-block <block-100> --to-block <block+10>
```

## Step 6: Source code review

BEFORE cross-referencing with the trace, review the victim contract source independently. Look for:
- **Reentrancy**: External calls before state updates
- **Oracle manipulation**: Price feeds from DEX reserves (manipulable in one tx)
- **Access control**: Missing modifiers, unprotected functions
- **Flash loan vulnerability**: Logic assuming balance checks span multiple blocks
- **Logic errors**: Wrong conditionals, incorrect fee calculations
- **Upgrade bugs**: Uninitialized implementations, storage collisions

## Step 7: Trace walkthrough

Walk through the call trace step by step. For each call:
1. What contract? What function? What parameters?
2. Map back to source code location
3. Why does the attacker make this call at this point?
4. What state changes result?

## Step 7b: Annotate the call trace

After the trace walkthrough, save structured annotations that map your narrative to exact trace positions. This is critical for the report's sequence diagram.

```bash
python3 -m meat annotate <attack_tx_hash> @annotations.json
```

Write `annotations.json` with one entry per key step. Each annotation must reference the exact call by `from`, `to`, and `function` fields — these are matched against the actual trace data.

```json
[
  {
    "from": "0x935bfb49...",
    "to": "0xbbbbbbbb...",
    "function": "flashLoan",
    "title": "Flash Loan",
    "purpose": "Borrow 160.5M USDC from Morpho Blue",
    "phase": "setup"
  },
  {
    "from": "0x935bfb49...",
    "to": "0x32e616f4...",
    "function": "add_liquidity",
    "title": "Manipulate USDC/MachineShare pool",
    "purpose": "Deposit massive USDC to shift pool balance",
    "phase": "manipulation"
  }
]
```

**Fields:**
- `from`, `to`, `function`: exact match against trace calls — must be correct
- `title`: short step name shown in the sequence diagram
- `purpose`: explanation shown on hover
- `phase`: `setup` | `manipulation` | `extraction` | `cashout` — controls divider color

**Evidence saved**: `evidence/trace_annotations.json`

The report's sequence diagram overlays these annotations as divider bars between trace calls. No guessing — every annotation is anchored to an actual on-chain call.

## Step 7c: Label ALL contracts from the call trace

After the trace walkthrough, label every contract that appears in the call trace. This is critical for the report's sequence diagram.

For each contract in the trace:
```bash
python3 -m meat label <contract_addr> -r <role> -n "<name>" --note "<description>"
```

Include:
- **Victim contracts** (pools, vaults, oracles) — role=victim
- **Flash loan sources** (Morpho, Aave, dYdX) — role=intermediate
- **Token contracts** (USDC, WETH, LP tokens) — role=intermediate, name=symbol
- **DEX routers** (Uniswap, Curve) — role=intermediate
- **Attacker contracts** — role=attacker

The sequence diagram groups contracts by protocol. Include the protocol name in the label where applicable (e.g., "Curve MIM/3CRV pool", "Aave V3 Pool").

## Step 8: Update case.json

Update `case.json` with exploit classification:

```json
{
  "exploit_type": "smart_contract_exploit",
  "exploit_subtype": "oracle_manipulation",
  "confidence": "CONFIRMED",
  "exploit_indicators": {
    "smart_contract_exploit": {
      "flash_loan": "160M USDC from Morpho Blue",
      "oracle_manipulation": "Curve pool virtual price",
      "victim_protocol": "Machine Vault — settle() uses manipulated prices",
      "exploit_contract": "0x935b (unverified)",
      "compiler": "Vyper 0.2.8"
    }
  }
}
```

## Step 9: Write analysis report

Write `cases/<case>/findings/analysis.md` with this structure:

```markdown
# Vulnerability Analysis: <Protocol>

## Summary
<1-2 sentences>

## Vulnerability Details
- **Type**: <vulnerability class>
- **Severity**: Critical
- **Affected contracts**:
  - `<address>` — <name> — <role>
- **Root cause**: <description>
- **Confidence**: CONFIRMED

## Attack Walkthrough
### Step 1: <action>
**Call**: `<contract>.<function>(<params>)`
**Purpose**: <why>
**Source**: `<file>:<line>`

## Root Cause
<Code snippet + explanation>

## Fix Recommendation
<Specific code change>

## Contracts Involved
| Address | Name | Role |
|---------|------|------|
| `0x...` | ... | ... |
```

**This markdown format is parsed by the report generator** to populate the Technical tab's vulnerability card. The `## Vulnerability Details` section with `- **Type**:`, `- **Severity**:`, `- **Root cause**:`, `- **Confidence**:` fields are extracted automatically.

## Evidence Checklist

| Evidence | Command | Saved to |
|----------|---------|----------|
| Call trace | `meat calltrace <hash>` | `evidence/trace/<hash>.json` |
| Source code (each victim) | `meat source <addr>` | `evidence/source/<addr>.json` |
| Storage diffs | `meat storage <addr> --slot <s>` | manual |
| Event logs | `meat logs --address <addr>` | `evidence/logs/` |
| **ALL contract labels** | `meat label <addr> -r <role> -n <name>` | `addresses.json` |
| Case metadata | manual update | `case.json` (exploit_type, indicators) |
| Findings | manual write | `findings/analysis.md` |

**Critical**: The report sequence diagram shows contract names from `addresses.json`. If a contract isn't labeled, it shows as a raw address. Label every contract that appears in the trace — tokens, protocols, intermediaries, not just attacker/victim.

## CORRECTNESS RULES

1. **Read the source code.** Never describe a vulnerability without reading the actual contract.
2. **Verify against the trace.** Your hypothesis must be consistent with the call trace.
3. **Check `_meta.data_sources`** — know whether you have a full nested trace or just a flat call list.
4. **Name the exact code location.** File:line, not "somewhere in the contract."
5. **Check `_meta.evidence_saved`** — confirm all evidence was persisted.
