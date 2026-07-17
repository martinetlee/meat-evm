---
name: meat-contain
description: |
  Decide whether an exploit is STILL ONGOING (more funds reachable / sibling contracts share
  the flaw) and, assuming the client holds the protocol's privileged roles, produce a concrete
  ordered plan of which address must send which transaction to stop further losses.
  Use after /meat + /meat-analyze once the vulnerability and exploited contract are known.
user_invocable: true
arguments: "Case name (optional — uses MEAT_CASE env var if set)"
---

# MEAT-CONTAIN: Is it ongoing, and how do we stop it?

You are answering two questions for a protocol that is being (or was just) attacked:

1. **Is the incident ONGOING** — is there more to hack? (funds still reachable via the same
   vulnerable path, or **sibling contracts** deployed by the same protocol that share the flaw and
   still hold value)
2. **How do we stop it safely** — the client has access to the protocol's **privileged roles**.
   Produce a concrete, ordered plan: *which address sends which transaction to which contract*,
   with ready-to-verify `cast` templates.

Always: `source .venv/bin/activate`. Ensure `MEAT_CHAIN` and `MEAT_CASE` are set (or pass
`--chain`/`--case` to each command). All data-fetching commands auto-save evidence when the case is
set — check `_meta.evidence_saved` after each.

> **This skill is analysis + planning only.** It never broadcasts a transaction. The output is a
> plan the client's key-holders / multisig execute themselves, *after simulating*. Time matters in a
> live incident, but a wrong or mis-ordered privileged tx can make things worse — every action below
> is presented with the safest reversible option first.

## Step 0: Load what's already known

```bash
python3 -m meat case show $MEAT_CASE
```

You need from prior `/meat` + `/meat-analyze`: the **exploited contract**, the **attacker
address(es)**, the **attack block**, and the **vulnerability class / vulnerable function**. If the
vuln isn't yet understood, run `/meat-analyze` first — you cannot judge "still exploitable" without
knowing *what* was exploited.

## Step 1: Map the protocol's FULL contract surface ("what else could be hacked")

A single exploited contract is rarely the whole protocol. Find every contract the protocol deployed.

### 1a. Find the deployer(s)

The exploited contract's creator is the primary deployer:

```bash
python3 -m meat classify <exploited_contract>        # -> creation_tx, admin_info (owner/admin/proxy_admin)
python3 -m meat tx <creation_tx>                     # `from` of the creation tx = the DEPLOYER
```

Also treat these as candidate deployers/controllers (from `admin_info`): `owner`, `admin`,
`proxy_admin`, `default_admin_role` holder, `guardian`. Protocols often deploy from the same EOA or
a factory that these roles point at.

### 1b. Enumerate everything the deployer deployed

```bash
python3 -m meat deployments <deployer> --enrich --depth 2
```

- Scans the deployer's normal txlist (direct deploys) **and** internal txlist (factory
  CREATE/CREATE2), following discovered contracts as factories `--depth 2` levels deep.
- `--enrich` classifies each contract → `holds_value`, `is_verified`, `is_proxy`,
  `implementation`, `admin_info`, `emergency_controls.paused`, `native_balance`,
  `nonzero_token_count`.
- Read the summary buckets — every one is a contract **still holding funds**:
  `summary.live_pausable_with_value` (has a `pause()` lever to flip — **priority stop targets**),
  `summary.live_no_pause_switch_with_value` (holds funds but **no direct pause** — contain via its
  parent/admin/upgrade), and `summary.paused_with_value` (already halted — verify it stays that way).
- Evidence: `evidence/deployments/<deployer>.json`.
- If `_meta.warnings` says a txlist "hit page limit", the deployer is prolific — raise `--limit` or
  narrow `--start-block/--end-block` and re-run; do not report a truncated surface as complete.

Repeat 1a→1b for every **additional deployer** you discover (a factory child that is itself a
deployer, a second admin EOA, etc.) until no new deployers appear.

### 1c. Find deployers the on-chain graph misses (docs)

Some protocol contracts are deployed by addresses not reachable from the first deployer (separate
deployer per product, a CREATE2 vanity deployer, a governance-deployed periphery). The protocol's
**docs / GitHub deployments file** list official addresses.

> **Investigation rule:** web searches for protocol **documentation or GitHub** require asking the
> user first. Web searches about the **specific exploit/incident are never allowed** — use only
> on-chain data. So: **ASK the user** "may I fetch <protocol> docs/deployments to complete the
> contract inventory?" before any web fetch. If declined, proceed with on-chain discovery only and
> **state the inventory may be incomplete**.

Every address the docs list → `classify` it, and if it's a new deployer, run `deployments` on it.

## Step 2: Verdict — ONGOING or CONTAINED?

Decide per at-risk contract, then for the incident overall. Center the judgment on the two primary
signals (plus the value baseline):

**Baseline — value still reachable.** From `deployments --enrich`, list every protocol contract with
`holds_value: true`. A contract with zero balance and zero token holdings is not a live target
(note it, move on).

**Signal A — the vulnerable code path is still live.** For each value-holding contract:
- `emergency_controls.paused` — if `false` (or absent), the contract is **not paused**: the attacker
  can transact against it right now.
- Is the exact function that was exploited still callable? Confirm the implementation is unchanged
  since the attack:
  ```bash
  python3 -m meat storage <proxy> --slot 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --compare-block <attack_block-1>
  ```
  Same implementation as at the attack block ⇒ the patched code is **not** deployed; path is live.
- For a proxy, `classify` automatically follows through to the **implementation** and scans its ABI
  too — `emergency_controls.functions` tags each lever with `source: "proxy"` vs
  `"implementation"` (the real `pause`/`emergencyWithdraw`/vulnerable entrypoints live on the
  implementation), and `abi_sources` records which ABIs were read. For a **beacon proxy**, classify
  resolves the beacon → logic (the `beacon` field holds the beacon address, `implementation` the
  resolved logic) and scans the beacon's own ABI too — its `upgradeTo` (`source: "beacon"`) is the
  key containment lever: one call repoints **every** proxy behind that beacon at patched logic. If
  `emergency_controls.implementation_abi_unverified: true`, the implementation isn't verified, so the
  lever set couldn't be enumerated — fetch its source another way (`meat source <impl>`) before
  concluding a contract has no pause switch.

**Signal B — sibling contracts share the flaw.** The exploited contract is often one instance of a
template (a vault per asset, a pool per pair). A sibling shares the flaw when:
- It is a proxy pointing at the **same `implementation`** as the exploited contract (exact same
  code) — the strongest signal; compare `implementation` fields across the `deployments` output.
- Or it is verified with the **same `ContractName`** and deployed by the same deployer (compare via
  `classify`; confirm by bytecode if unverified: `meat classify` reports code, or compare
  `creation` bytecode).

  A sibling that shares the implementation/code **and** `holds_value` **and** is not paused is an
  **imminent next target** — treat the incident as ongoing even if the originally-hit contract is
  now empty.

**Verdict:**
- **ONGOING** if any value-holding contract has the vulnerable path live (Signal A) **or** any
  unpatched sibling shares the flaw and holds value (Signal B).
- **CONTAINED** only if every value-holding contract is paused/patched AND no unpatched sibling holds
  value. State the evidence for whichever you conclude — do not assert "contained" unearned.

Also worth a quick note (secondary, not the deciding factor): standing victim **approvals** to the
exploited contract and whether the **attacker still holds roles/approvals** — surface these if seen,
because they feed the Step 4 plan, but the verdict rests on Signals A/B + value.

## Step 3: Enumerate privileged roles and WHO holds them

For every contract you'll act on (each at-risk contract, and its proxy admin / implementation):

```bash
python3 -m meat classify <contract>     # admin_info: owner, admin, proxy_admin, access_control,
                                        #   default_admin_role, guardian; emergency_controls.functions
```

AccessControl contracts don't expose holders via a getter — enumerate from events:

```bash
python3 -m meat logs --event "RoleGranted(bytes32,address,address)" --address <contract> --from-block <deploy_block> --to-block latest
python3 -m meat logs --event "RoleRevoked(bytes32,address,address)" --address <contract> --from-block <deploy_block> --to-block latest
```

Match role hashes: `DEFAULT_ADMIN_ROLE` = `0x00..00`; named roles are `keccak256("PAUSER_ROLE")` etc.
Reconcile grants minus revokes to get the **current** holder set per role.

Build a role map: for each contract → which addresses hold `owner` / `proxy_admin` /
`DEFAULT_ADMIN_ROLE` / `PAUSER_ROLE` / `guardian` / upgrade rights. Cross-check against the
addresses the **client controls** — the plan can only use levers the client actually holds. Flag any
critical lever (e.g. the only pauser) that the client does **not** control.

## Step 4: Build the containment action plan

Pull `emergency_controls.functions` from each contract's `classify` (and its implementation) to see
which levers exist. Order actions **safest-and-fastest first**:

1. **PAUSE / FREEZE everything reachable** (reversible, stops the bleed immediately) — `pause()`,
   `setPaused(true)`, `freeze()`, `shutdown()`, guardian halt. Pause the exploited contract **and
   every unpatched sibling that holds value**, not just the one already hit.
2. **Revoke the attacker's standing power** — `revokeRole(role, attacker)`, revoke approvals the
   attacker relies on, remove a malicious module/operator.
3. **Rescue / patch** — upgrade the proxy to a **patched implementation** (`upgradeTo` /
   `upgradeToAndCall` via the proxy admin), or `emergencyWithdraw` / `sweep` funds to a **safe
   multisig the client controls**. These are higher-risk and slower — do them after the bleed is
   paused.
4. **Cut victim exposure** — advise still-exposed victims to revoke ERC-20 approvals to the
   exploited contract.

Present it as an **ordered table**, one row per transaction:

| # | Priority | Role-holder (sender) | Target contract | Function(args) | Effect | Lever held? |
|---|----------|----------------------|-----------------|----------------|--------|-------------|
| 1 | STOP     | `0x…pauser`          | `0x…vault`      | `pause()`      | Halts deposits/borrows on the live vault | ✅ PAUSER_ROLE |
| 2 | STOP     | `0x…pauser`          | `0x…siblingVault` | `pause()`    | Halts the unpatched sibling before it's hit | ✅ |
| 3 | REVOKE   | `0x…admin`           | `0x…vault`      | `revokeRole(OPERATOR_ROLE, 0x…attacker)` | Removes attacker's module | ✅ DEFAULT_ADMIN |
| 4 | RESCUE   | `0x…proxyAdmin`      | `0x…proxy`      | `upgradeTo(0x…patched)` | Deploys fixed code | ⚠ verify admin |

Then give **ready-to-verify `cast` templates** (the client fills the RPC/key and **simulates
first**):

```bash
# 1. SIMULATE before broadcasting (no state change) — must succeed & come from the real role-holder:
cast call <target> "pause()" --from <role_holder> --rpc-url $RPC

# 2. Broadcast (client's signer / multisig only — this tool never does this):
cast send <target> "pause()" --from <role_holder> --rpc-url $RPC   # add signing per the client's setup
```

For a multisig role-holder (Gnosis Safe etc.), the row is a **Safe transaction proposal** to
`target` with that calldata — encode with `cast calldata "pause()"` and hand the calldata + target
to the signers; do not imply a single EOA can send it.

**Execution guardrails to state in the plan:**
- **Simulate every tx** (`cast call` / Tenderly) from the exact role-holder before broadcasting.
- **Order matters** — pause before upgrade/rescue; never `renounceOwnership`/`revokeRole` on your own
  admin before the rescue txs are done (you'd lock yourself out).
- Use the **current** role-holder from Step 3 (roles may have been transferred, incl. by the
  attacker).
- Confirm each `cast` target/selector against the contract's verified ABI (`meat abi <contract>`) —
  a wrong selector wastes the one clean shot.

## Step 5: Record

- Write `cases/<case>/findings/containment.md`:
  1. **Verdict** (ONGOING / CONTAINED) with the per-contract evidence table.
  2. **Contract inventory** — every protocol contract, deployer, value held, paused state, shares-flaw?
  3. **At-risk total** — sum of value in live, unpaused, flaw-sharing contracts.
  4. **Role map** — contract → role → current holder → client-controlled?
  5. **Action plan** — the ordered table + `cast` templates + guardrails.
- Update `case.json` — the report reads these exact keys to render the verdict banner + Containment
  tab, so use them verbatim:
  ```json
  { "summary": { "incident_status": "ongoing", "at_risk_usd": "~$…", "containment_ready": true },
    "monitored_addresses": ["…all at-risk contracts and the attacker…"] }
  ```
  `incident_status` must be exactly `"ongoing"` or `"contained"`. `meat report` then shows a red
  ONGOING (or green CONTAINED) banner on the Overview and a dedicated **Containment tab** (placed
  right after Overview, alert-styled while ongoing) that renders `findings/containment.md` in full —
  so a responder reaches the who-sends-what plan in one click.
- Add every at-risk contract and the attacker to `monitored_addresses` so `/meat-monitor` catches a
  renewed attempt while the client executes the plan.

## Evidence Checklist

| Evidence | Command | Saved to |
|----------|---------|----------|
| Protocol contract surface | `meat deployments <deployer> --enrich --depth 2` | `evidence/deployments/<deployer>.json` |
| Contract classification (admin/roles/pause) | `meat classify <contract>` | `evidence/classify/<addr>.json` |
| Creation tx → deployer | `meat tx <creation_tx>` | `evidence/tx/<hash>.json` |
| Implementation-change check | `meat storage <proxy> --slot <impl> --compare-block …` | `evidence/storage/` |
| Role holders | `meat logs --event "RoleGranted(...)" --address <contract>` | `evidence/logs/` |
| Contract ABI (verify selectors) | `meat abi <contract>` | `evidence/abi/` |
| Verdict + plan | manual write | `findings/containment.md`, `case.json` |

## CORRECTNESS RULES

1. **Every claim cites tool output.** "Still exploitable" needs `paused=false` **and** an unchanged
   implementation (or a live reachable function) — not a guess.
2. **Don't call it CONTAINED unearned.** Contained requires *evidence* that every value-holding
   contract is paused/patched and no unpatched sibling holds value.
3. **Inventory completeness is a claim too.** If you couldn't fetch docs (Step 1c), say the surface
   may be incomplete; a missed sibling is a missed next-target.
4. **The plan uses only levers the client holds** (Step 3). Flag any critical lever the client lacks.
5. **This tool never broadcasts.** Output templates + simulation instructions; the client executes.
6. **Safest reversible action first** (pause) before irreversible ones (renounce, sweep, upgrade).
