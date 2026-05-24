---
name: meat-poc
description: |
  Create a Foundry PoC that reproduces an exploit. Forks mainnet at the block before
  the attack, replays the attack sequence, and verifies the outcome.
  Use after /meat-analyze when the vulnerability is understood.
user_invocable: true
arguments: "Case name (optional — uses MEAT_CASE env var if set)"
---

# MEAT-POC: Foundry Proof of Concept

You are creating a Foundry test that reproduces an exploit. Always: `source .venv/bin/activate`

## Prerequisites

```bash
which forge && forge --version
```

If not installed: `curl -L https://foundry.paradigm.xyz | bash && foundryup`

## Step 1: Load analysis

Read `cases/<case>/findings/analysis.md` for:
- The vulnerability and attack sequence
- The victim contract address
- The block number (from evidence)

Get the USD impact from the tx output's `net_flows` — include it in the test's assertions/logs.

## Step 2: Set up Foundry

Check `foundry/foundry.toml` exists. If forge-std isn't installed:
```bash
cd foundry && forge install foundry-rs/forge-std --no-commit
```

## Step 3: Get the call trace (if not already in analysis)

```bash
python3 -m meat calltrace <attack_tx_hash>
```

Tenderly traces (check `_meta.data_sources`) include decoded function calls with parameter values — use these directly in the PoC.

## Step 4: Check pre-attack state

```bash
python3 -m meat storage <victim> --slot <key_slot> --block <attack_block-1>
```

This confirms the initial state the PoC should expect when forking.

## Step 5: Write the PoC

Create `foundry/test/Exploit_<CaseName>.t.sol`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IVictim {
    // Only the functions called in the attack
}

contract Exploit_<CaseName> is Test {
    address constant VICTIM = <victim_address>;

    function setUp() public {
        vm.createSelectFork("mainnet", <block_number - 1>);
    }

    function test_Exploit() public {
        uint256 balanceBefore = ...;

        // Attack sequence from analysis

        uint256 balanceAfter = ...;
        assertGt(balanceAfter, balanceBefore);
        emit log_named_uint("Profit (wei)", balanceAfter - balanceBefore);
        // Log USD value from DeFiLlama price data
    }
}
```

## Step 6: Run

```bash
cd foundry && forge test --match-test test_Exploit -vvv
```

Iterate up to 3 times if it fails. Read the error output carefully — common issues:
- Wrong fork block (must be block N-1)
- Missing `vm.prank()` to act as attacker
- Token approvals needed before transfers
- Gas limits

## Step 7: Document

Write `cases/<case>/findings/poc.md` with run instructions and test output.

## Evidence Checklist

Ensure these exist BEFORE writing the PoC (from earlier `/meat-analyze`):

| Evidence | Source | Location |
|----------|--------|----------|
| Call trace | `meat calltrace <hash>` | `evidence/trace/<hash>.json` |
| Source code | `meat source <addr>` | `evidence/source/<addr>.json` |
| Analysis | `/meat-analyze` | `findings/analysis.md` |
| Attack tx | `meat tx <hash>` | `evidence/tx/<hash>.json` |

The PoC itself is saved to `foundry/test/` and documented in `findings/poc.md`.

## CORRECTNESS RULES

1. **The test must pass.** A failing PoC is not a PoC.
2. **Fork at block N-1.** Pre-attack state.
3. **Assert profit > 0**, not exact amounts (state may vary slightly).
4. **Use minimal interfaces.** Only define functions you actually call.
5. **Verify `MEAT_CASE` is set** when running calltrace/storage commands to save evidence.
