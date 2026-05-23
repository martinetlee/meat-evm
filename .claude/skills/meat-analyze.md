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

## Step 1: Load case state

```bash
python3 -m meat case show <case-name>
```

Identify: attack tx hash(es), victim contract(s), attacker contract(s), attack type from recon.

## Step 2: Fetch victim contract source code

```bash
python3 -m meat source <victim_addr> --save cases/<case>/contracts/
```

This tries Etherscan first, then Sourcify as fallback. Check `_meta.data_sources` to see which succeeded.

If it's a proxy (check classify output or `proxy_type` field):
```bash
python3 -m meat source <implementation_addr> --save cases/<case>/contracts/
```

Read the saved source files in `cases/<case>/contracts/<addr>/`.

## Step 3: Get the call trace

```bash
python3 -m meat calltrace <attack_tx_hash>
```

This tries (in order):
1. `debug_traceTransaction` (RPC with debug namespace) — full nested call tree. **Alchemy RPC supports this on Growth plan.**
2. **Tenderly API** — decoded traces with state diffs (if `TENDERLY_ACCESS_KEY` configured)
3. `cast run` (Foundry) — replays tx locally
4. Explorer `txlistinternal` — flat call list (fallback)

If using Alchemy RPC, `debug_traceTransaction` with `callTracer` works out of the box — this is the best trace quality.

Check `_meta.data_sources` to know which method was used. If you got `explorer_txlistinternal`, note the `_meta.warnings` about it being a flat list, not a nested trace.

## Step 4: Check state before/after attack

For critical storage slots (e.g., balances, implementation address, owner):

```bash
python3 -m meat storage <victim> --slot <slot_hex> --compare-block <attack_block-1>
```

Common slots to check:
- `0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc` — EIP-1967 implementation
- `0x0` — often the owner or initialized flag (OpenZeppelin)

## Step 5: Search for related events

```bash
# Find all interactions with the victim around the attack
python3 -m meat logs --address <victim> --from-block <block-100> --to-block <block+10> --chain <chain>

# Check for governance events
python3 -m meat logs --event "ProposalExecuted(uint256)" --address <governor>

# Check for role changes
python3 -m meat logs --event "RoleGranted(bytes32,address,address)" --address <victim>

# Check for upgrade events  
python3 -m meat logs --event "Upgraded(address)" --address <victim>
```

## Step 6: Independent source code review

BEFORE cross-referencing with the trace, review the victim contract source independently. Look for:

- **Reentrancy**: External calls before state updates, missing reentrancy guards
- **Access control**: Missing modifiers, unprotected functions. Check `classify` `admin_info` for who holds admin roles
- **Oracle manipulation**: Price feeds from DEX reserves (manipulable in one tx)
- **Flash loan vulnerability**: Logic assuming balance checks span multiple blocks
- **Integer overflow/underflow**: Unchecked arithmetic (pre-Solidity 0.8)
- **Logic errors**: Wrong conditionals, incorrect fee calculations
- **Upgrade bugs**: Uninitialized implementations, storage collisions

## Step 7: Trace walkthrough

Walk through the call trace step by step. For each call:
1. What contract? What function? What parameters?
2. Map back to source code location
3. Why does the attacker make this call at this point?
4. What state changes result?

## Step 8: Synthesize

1. **Vulnerability class**: Name the specific type
2. **Root cause**: What is the code flaw? Reference exact source file:line
3. **Attack mechanism**: Step-by-step, referencing trace data
4. **Fix recommendation**: What code change prevents this?

## Step 9: Write analysis report

Write `cases/<case>/findings/analysis.md`:

```markdown
# Vulnerability Analysis: <Protocol>

## Summary
<1-2 sentences>

## Vulnerability Details
- **Type**: <vulnerability class>
- **Severity**: Critical
- **Affected contract**: <address> (<ContractName>)
- **Root cause**: <description>
- **Confidence**: CONFIRMED (verified via [trace method] + source review)

## Attack Walkthrough
### Step 1: <action>
**Call**: `<contract>.<function>(<params>)`
**Purpose**: <why>
**Source**: `<file>:<line>`
**USD impact**: <from net_flows>

## Root Cause
<Code snippet + explanation>

## Fix Recommendation
<Specific code change>
```

## CORRECTNESS RULES

1. **Read the source code.** Never describe a vulnerability without reading the actual contract.
2. **Verify against the trace.** Your hypothesis must be consistent with the call trace.
3. **Check `_meta.data_sources`** — know whether you have a full nested trace or just a flat call list.
4. **Name the exact code location.** File:line, not "somewhere in the contract."
