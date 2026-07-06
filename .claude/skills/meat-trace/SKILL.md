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

## Step 3: Gas funding analysis (clustering)

Identify attacker-controlled addresses via gas funding source:

```bash
python3 -m meat funder <addr1> <addr2> <addr3> ...
```

**Evidence saved**: `evidence/funder/cluster_analysis.json` — clusters addresses by common gas funder.

Addresses funded by a known attacker/collector are definitively attacker-controlled.

## Step 3b: Trace the funding source UPSTREAM (deanonymization) — ALWAYS DO THIS

Fund tracing is **bidirectional**. Downstream (Steps 2/6) shows where the loot *went*;
upstream shows where the attacker's **gas/setup capital came from** — the best lead to a CEX
and therefore an identity. **Do not skip this even when the user only says "where did funds go."**

Recurse `meat funder` backward from the attacker until you hit a **CEX**, a **mixer** (dead end),
or run out of hops:

```bash
python3 -m meat funder <attacker>          # -> funder F1
python3 -m meat classify <F1>              # CEX? contract? EOA?
python3 -m meat funder <F1>                # -> F2 ... repeat
python3 -m meat flow <Fn> --depth 1        # inspect a funder's in/out pattern
```

At each hop record: `classify.known_entity` (category `cex` = jackpot), balance, and the
in/out **fan pattern**.

**Critical caveat — distinguish a real CEX link from a shared gas service.** A funder that
receives from **many** senders and pays out to **many** recipients (e.g. 40+ in / 40+ out) is a
**shared disperser / gas-funding service**, NOT the attacker's wallet. A CEX feeding such a hub
does **not** deanonymize the attacker (they're one of hundreds of users). Only a **direct**
CEX→attacker (or CEX→dedicated-relay→attacker, low fan-out) transfer is a clean identity lead.
Quantify the CEX's share of the hub's inflow before claiming attribution.

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

## Step 6: Cross-chain bridges — USE THE DETERMINISTIC COMMANDS, DO NOT HAND-TRACE

Hand-tracing Bitcoin/THORChain/NEAR by eyeballing explorer web pages is where fund traces go wrong
(missed legs, mis-attributed addresses). The CLI now does these deterministically from JSON APIs and
auto-saves evidence. **Prefer these over WebFetch.**

**EVM → EVM bridge:**
1. Note bridge contract, source tx, destination chain, recipient.
2. `export MEAT_CHAIN=<destination_chain>` then `python3 -m meat flow <recipient_addr> --depth 2`.

**THORChain (ETH↔BTC/other) — decode what the swap does:**
```bash
python3 -m meat thorchain <eth_deposit_tx_hash>     # decodes the depositWithExpiry memo:
                                                     # dest chain/asset/address + streaming/affiliate,
                                                     # + best-effort Midgard output resolution
```
The memo's `dest_address` is your next hop on the destination chain. (Midgard often can't resolve
older swaps — the memo decode alone still tells you where it's headed; degrade gracefully, don't
treat an empty Midgard as "no swap.")

**Bitcoin — follow it forward automatically:**
```bash
python3 -m meat btc-trace <btc_address> --follow all --min-sat 5000000   # trace every branch
python3 -m meat btc-trace <btc_address>                                  # peel-chain (largest only)
python3 -m meat btc-tx <txid>                                            # one tx: in/out/OP_RETURN
```

**Intent / bridge legs — resolve the far side deterministically:**
```bash
python3 -m meat debridge <src_tx>    # deBridge DLN: full src->dst chain/asset/amount + dst tx
python3 -m meat orbiter <src_tx>     # Orbiter: source-side confirm (dest not in public API)
python3 -m meat intents <addr>       # registry flag + manual cross-ref URL (NEAR etc.)
```
`btc-trace` follows hop-by-hop and **auto-classifies every endpoint**: `dormant_unspent` (a live,
possibly-recoverable stash — report it), `consolidation_sweep` / `known_service` (a custody
hand-off — see 6b), `max_hops`, `no_onward_output`. It also surfaces OP_RETURN messages (whitehat
notices, protocol memos) and cross-references the label registry. Read `summary.dormant_endpoints`
and `summary.service_endpoints` first.

## Step 6b: Custody hand-off & cross-chain "fly-off" check — DO NOT SKIP

Funds can leave the chain through a service with **no on-chain link** on either side: the
coins commingle in the solver/bridge pool while the *value* re-emerges on another chain/asset
from the service's own inventory. Same-chain tracing CANNOT see this. Two failure modes to avoid:

- **Treating a CEX/service label as a destination.** Reaching a Binance-labelled (or any service)
  address is a **custody hand-off, not a cash-out.** The account may belong to the subject OR to a
  **nested service** (a swap/solver that banks at the CEX) — a deposit address that aggregates
  **many** inputs is the service's, and your subject is one pass-through depositor. A label answers
  *whose address*, never *where the money went next*.
- **Concluding a destination at a commingling point.** Mixer, CEX, and cross-chain solver look
  identical at entry. On-chain you cannot distinguish them or follow through them.

**Procedure.** At every **custody hand-off** (a fresh/dedicated address forwarding into a service)
and every **address you can't otherwise identify**:

1. **Registry check (deterministic):** run `python3 -m meat intents <addr>` on every hand-off
   address (and every `service_endpoint` that `btc-trace` flags). It checks
   `labels/known_addresses.json` for a known solver/bridge/mixer (`resolved: true` means funds
   **flew off** here — look up the intent) and emits the explorer URL for the manual step. Equivalent
   for EVM contracts: `meat classify <addr>` → `category: intents_solvers | bridges | mixers`.
2. **Order-book cross-reference (protocol-agnostic, NOT symmetry-based):** search the hand-off
   address against **publishing** intents/bridge order books — regardless of what the actor used
   earlier. The registry (`labels/known_addresses.json`, categories `intents_solvers` / `bridges` /
   `no_kyc_swap` / `mixers`) covers the common rails so `classify` / `intents` / `btc-trace`
   auto-flag them. When one is a **fly-off point**, resolve the far side:

   - **RESOLVABLE with a CLI command (auto-jumps to the destination leg):**
     - THORChain → `meat thorchain <tx>`; **Maya** → `meat thorchain <tx> --protocol maya`
     - **deBridge DLN → `meat debridge <tx>`** (returns give/take chain+asset+amount, dest recipient, dst tx)
     - **Orbiter → `meat orbiter <tx>`** (source-side confirm + amount; dest leg not in public API — find on target chain)
   - **RESOLVABLE via API (no command yet):** CoW → `api.cow.fi/mainnet/api/v1/trades?txHash=` ·
     SideShift → `sideshift.ai/api/v2/shifts/{id}` · Across → across.to API
   - **OPAQUE (publish nothing / gated)** — stop honestly, report *"unresolved / possible off-chain
     exit"*: **eXch** and most no-KYC swappers (FixedFloat/ChangeNOW/SimpleSwap — API is key-gated),
     **Chainflip** (no public REST — scan.chainflip.io only), **NEAR Intents** (auth-gated SPA —
     `meat intents` gives the manual URL). Also watch LI.FI, Socket/Bungee, Symbiosis, Meson,
     Synapse, Celer, Squid/Axelar, UniswapX, 1inch Fusion, Railgun.
3. **When you resolve a new solver/settlement address, add it to `labels/known_addresses.json`
   `intents_solvers`/`bridges`** so the registry check catches it next time.

**Epistemic rule (this is what actually prevents the mistake):**
- A **hit** resolves the cross-chain leg.
- A **miss is NOT a clearance.** "Checked my list, not found" ≠ "didn't fly off" — the list is always
  incomplete, and opaque rails (mixers, private solvers) publish nothing. Downgrade to
  **"unresolved / possible off-chain exit"**, never a fabricated destination.
- Only claim a destination the chain actually supports. At a service boundary the honest output is
  *"trail hands off here; cash-out vs mix vs cross-chain swap is on-chain-indistinguishable;
  resolvable only via the service's off-chain records."*

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
| Bitcoin forward trace | `meat btc-trace <addr>` | `evidence/btc_trace/<addr>.json` |
| Bitcoin single tx | `meat btc-tx <txid>` | `evidence/btc_tx/<txid>.json` |
| THORChain memo/output | `meat thorchain <tx>` | `evidence/thorchain/<tx>.json` |
| Intents/bridge crossref | `meat intents <addr>` | (prints URL; no fetch) |
| Case summary | manual update | `case.json` |
| Findings | manual write | `findings/fund-trace.md` |

## CORRECTNESS RULES

1. **Only follow confirmed on-chain transfers.** Every edge must be a real Transfer event or ETH transfer.
2. **Use USD values.** The net_flows include DeFiLlama prices.
3. **Don't speculate about mixer outputs.** After Tornado Cash, label as "trace ends at mixer."
4. **Check `_meta.evidence_saved`** after each command to confirm data was persisted.
