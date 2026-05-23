# MEAT-EVM: Martinet's Exploit Analysis Tool

## Context

Build a Claude Code skill-based workflow + Python CLI for analyzing EVM exploits in real-time. The tool handles the full lifecycle: from an incomplete set of inputs (a tx hash, an address, a URL), it expands into a full picture of who attacked whom, how, and where the funds went. Two main branches after recon: **fund tracing** (follow the money) and **exploit analysis** (understand the vulnerability, reproduce it).

Key challenge: inputs are always incomplete. One tx hash might be one of many attack txs. One attacker address might be one of many. The recon phase must systematically expand.

## Architecture

**Python CLI** (`python3 -m meat <command>`) provides data fetching, decoding, and classification. **Claude Code skills** (`/meat`, `/meat-recon`, `/meat-trace`, `/meat-analyze`, `/meat-poc`) orchestrate the analysis — Claude does the reasoning, the CLI provides the data.

Communication between skills happens via the **case directory** on disk (`cases/<case-name>/`), which holds recon findings, address registries, analysis reports, and cached API responses.

## Repository Structure

```
meat-evm/
├── CLAUDE.md
├── chains.yaml                     # Multi-chain config
├── .env.example
├── .gitignore
├── requirements.txt                # requests, eth-abi, eth-utils, click, pyyaml, python-dotenv
├── meat/
│   ├── __init__.py
│   ├── cli.py                      # Click CLI entry point
│   ├── config.py                   # Load chains.yaml + .env
│   ├── evidence.py                 # Evidence store: write raw data to evidence/, never modify
│   ├── parse.py                    # Input parser: URL, tx hash, address detection
│   ├── rpc.py                      # JSON-RPC client (requests-based)
│   ├── explorer.py                 # Etherscan-compatible API client + rate limiter
│   ├── decode.py                   # ABI decoding, 4byte selector lookup
│   ├── classify.py                 # Address classification (EOA/contract/token/proxy)
│   ├── case.py                     # Case lifecycle: create, load, update case.json + journal
│   └── trace.py                    # Fund flow graph builder (BFS from address)
├── .claude/
│   └── skills/
│       ├── meat.md                 # /meat — main entry point
│       ├── meat-recon.md           # /meat-recon — expand from partial info
│       ├── meat-trace.md           # /meat-trace — fund tracing
│       ├── meat-analyze.md         # /meat-analyze — exploit analysis
│       ├── meat-poc.md             # /meat-poc — Foundry PoC crafting
│       └── meat-monitor.md         # /meat-monitor — watch active cases
├── foundry/                        # Foundry workspace for PoC reproduction
│   ├── foundry.toml
│   └── test/
├── cases/                          # Per-case output (gitignored)
│   └── .gitkeep
└── labels/                         # Known address labels (CEX, bridges, mixers)
    └── known_addresses.json
```

## chains.yaml Schema

```yaml
chains:
  ethereum:
    chain_id: 1
    rpc_env: ETH_RPC_URL                    # env var name (not the URL itself)
    explorer_api_env: ETHERSCAN_API_KEY      # env var name
    explorer_base: "https://api.etherscan.io/api"
    explorer_url: "https://etherscan.io"
    native_token: ETH
    url_patterns: ["etherscan.io"]           # for auto-detecting chain from pasted URLs
    trace_method: debug_traceTransaction     # null if RPC doesn't support it
    trace_fallback: cast_run                 # use `cast run` as fallback
  # polygon, base, arbitrum, bsc, optimism, etc.
```

RPC URLs and API keys are **never** stored in chains.yaml — only env var names. Secrets come from `.env`.

## CLI Commands

All commands output **JSON to stdout** (for Claude to parse). The `--chain` flag identifies the network; if omitted for tx hashes, the CLI tries each configured chain.

| Command | Purpose |
|---------|---------|
| `meat parse <input>` | Detect type (tx_hash/address/url), extract chain from URL |
| `meat tx <hash> --chain <c>` | Full tx + receipt + decoded input + token transfers |
| `meat trace <hash> --chain <c>` | Call trace (debug_traceTransaction → cast run fallback) |
| `meat txlist <addr> --chain <c>` | Transaction history for an address (via explorer API) |
| `meat source <addr> --chain <c> [--save dir]` | Verified source code from explorer |
| `meat abi <addr> --chain <c>` | ABI from explorer (handles proxy detection) |
| `meat classify <addr> --chain <c>` | EOA vs contract, token info, proxy detection, labels |
| `meat transfers <hash_or_addr> --chain <c>` | ERC20/721/1155 transfers with decoded amounts |
| `meat decode calldata <hex> [--abi file]` | Decode calldata (ABI or 4byte.directory fallback) |
| `meat flow <addr> --chain <c> --depth N` | Fund flow graph (BFS, classify each hop) |

## Skills

### `/meat <input>` — Main Entry Point

1. Parse input (tx hash, address, or block explorer URL)
2. If chain unknown, ask user or auto-detect
3. Fetch tx details, decode function calls and events, extract token transfers
4. Quick-classify all addresses (attacker vs victim vs protocol vs unknown)
5. Present summary: who, what, how much, when
6. Create case directory, save `recon.md` + `addresses.json`
7. Offer next steps: `/meat-recon`, `/meat-trace`, `/meat-analyze`

### `/meat-recon` — Expand from Partial Info

The core problem: inputs are incomplete. This skill systematically expands.

**From an attacker address:**
- Fetch all their txs → find attack txs, contract deployments, fund movements
- Check funding source (where did gas money come from? Same funder = same attacker)
- Find related addresses via same funding pattern

**From a victim contract:**
- Fetch source code for security review
- Check recent unusual interactions via txlist
- Find the attack tx(s) by looking for large outflows

**From a single tx:**
- Extract every address from the call trace
- Classify each (protocol, attacker-deployed, victim, neutral)
- Look for other txs between the same attacker and victim

**Output:** Updated `recon.md` with complete address map, timeline, and fund quantification.

### `/meat-trace` — Fund Tracing

1. Start from attacker address(es) in `addresses.json`
2. Run `meat flow` to get the transfer graph
3. At each hop, classify the destination:
   - **CEX deposit** → note exchange name, end of on-chain trace
   - **Bridge** → note bridge + destination chain, offer to continue tracing cross-chain
   - **Mixer** (Tornado Cash etc.) → note, tracing becomes probabilistic
   - **DEX swap** → track what came out the other side
   - **Intermediate address** → expand trace from here
4. Build fund flow diagram and summary table
5. Write `fund-trace.md`

### `/meat-analyze` — Exploit Analysis

1. Fetch victim contract source code → save to `cases/<case>/contracts/`
2. Fetch full call trace of attack tx
3. Two parallel analyses:
   - **Trace walkthrough**: Step through the call trace, explain what each call does
   - **Source code review**: Review victim contracts for vulnerabilities independent of the trace
4. Synthesize: identify vulnerability class (reentrancy, oracle manipulation, access control, etc.)
5. WebSearch for existing audits, post-mortems, similar exploits
6. Write `analysis.md` with vulnerability description, step-by-step walkthrough, root cause, fix recommendation

### `/meat-poc` — Foundry PoC

1. Read `analysis.md` for vulnerability details
2. Write a Foundry test at `foundry/test/Exploit_<Case>.t.sol` that:
   - Forks mainnet at the block before the attack
   - Reproduces the attack sequence
   - Asserts the expected outcome (fund transfer)
3. Run `forge test --match-test test_Exploit -vvv`
4. Iterate up to 3 times if test fails
5. Write `poc.md` documenting how to run it

## Correctness Guardrails

Claude can hallucinate. In exploit analysis, a wrong conclusion (misidentifying an attacker, fabricating a vulnerability) can mislead an entire incident response. Three layers of defense:

### Layer 1: Evidence separation

Strict separation between **evidence** (raw on-chain data, immutable, machine-fetched) and **findings** (Claude's analysis). Evidence is stored in `evidence/` and never modified. Findings in `findings/` must cite specific evidence files.

```
cases/<case>/
├── evidence/                # GROUND TRUTH — raw on-chain data, never edited
│   ├── tx_<hash>.json       # includes: chain, block, timestamp, raw response
│   ├── receipt_<hash>.json
│   ├── trace_<hash>.json
│   ├── source_<addr>.json
│   ├── abi_<addr>.json
│   └── txlist_<addr>_<page>.json
├── findings/                # ANALYSIS — each claim cites evidence
│   ├── recon.md
│   ├── analysis.md
│   ├── fund-trace.md
│   └── poc.md
```

The CLI tool writes to `evidence/` automatically when fetching data. Skills write to `findings/` and must reference evidence paths. This means anyone can verify any claim by checking the cited evidence file.

### Layer 2: Confidence tagging

Every classification and conclusion gets a confidence level:

- **CONFIRMED**: Directly proven by on-chain data (e.g., "This address initiated the exploit tx")
- **HIGH**: Strong evidence, consistent across multiple data points (e.g., "Funded from same source as confirmed attacker")
- **MEDIUM**: Reasonable inference but not directly proven (e.g., "Likely attacker-controlled based on fund flow pattern")
- **LOW/HYPOTHESIS**: Speculation that needs further investigation (e.g., "May be related based on deployment timing")

The `addresses.json` registry carries confidence per address:
```json
{
  "0xDead...": {
    "role": "attacker",
    "confidence": "CONFIRMED",
    "evidence": ["evidence/tx_0xabc.json"],
    "reason": "Initiated exploit transaction"
  }
}
```

### Layer 3: Cross-validation rules

Skills include verification steps before finalizing conclusions:
- **Vulnerability claim** → verify the call trace actually exercises that code path
- **Fund flow claim** → verify the transfer events match the claimed amounts
- **Address classification** → verify from multiple angles (funding source, behavior pattern, on-chain interactions)
- **PoC** → the Foundry test must actually pass — this is the ultimate verification

Skills are instructed: "If you cannot cite evidence for a claim, label it as HYPOTHESIS. Never present unverified analysis as fact."

## Case Lifecycle & Monitoring

Cases are not one-shot — exploits develop in real-time. The attacker moves funds, new victims appear, the community discovers related incidents.

### Case state (`case.json`)

```json
{
  "name": "euler-hack",
  "created": "2024-03-13T14:30:00Z",
  "status": "active",
  "chain": "ethereum",
  "last_updated": "2024-03-13T16:45:00Z",
  "last_monitored": "2024-03-13T16:45:00Z",
  "monitored_addresses": [
    {"address": "0xDead...", "role": "attacker", "last_tx_block": 18234567},
    {"address": "0xBeef...", "role": "victim", "last_tx_block": 18234500}
  ],
  "open_questions": [
    "Are there additional attacker addresses funded from the same source?",
    "Where did the 500 ETH sent to 0xCafe... end up?"
  ],
  "summary": {
    "total_stolen": {"ETH": "450", "USDC": "2300000"},
    "total_recovered": {},
    "attacker_addresses": 3,
    "victim_addresses": 1,
    "attack_txs": 2
  }
}
```

Status transitions: `active` → `monitoring` → `closed`

### Case journal (`journal.md`)

Append-only timestamped log. Every skill invocation adds an entry:

```markdown
## 2024-03-13 14:30 — Initial recon (/meat)
- Input: tx 0xabc...
- Identified attacker: 0xDead... (CONFIRMED)
- Identified victim: 0xBeef... (Euler LendingPool) (CONFIRMED)
- Estimated loss: ~$2.3M USDC + 450 ETH

## 2024-03-13 15:00 — Expanded recon (/meat-recon)
- Found 2 additional attack txs from same attacker
- Found attacker was funded via Tornado Cash 2h before attack
- Updated total loss: $3.1M

## 2024-03-13 16:45 — Monitor check (/meat-monitor)
- Attacker moved 200 ETH to new address 0xCafe... (block 18234600)
- 0xCafe... swapped 200 ETH → DAI on Uniswap V3
- Updated fund-trace.md
```

### `/meat-monitor` — Case Monitoring Skill

New skill for watching active cases:

1. Read `case.json` to get monitored addresses and their last-known block numbers
2. For each address, fetch new transactions since `last_tx_block`
3. If new activity found:
   - Classify the new transactions (fund movement, swap, bridge, etc.)
   - Update `case.json` with new last_tx_block
   - Append to `journal.md`
   - Update `fund-trace.md` if new fund movements detected
   - Alert the user with a summary of new activity
4. If no new activity, record the check in journal and move on

Can be run on a loop for active incidents:
```
/loop 5m /meat-monitor euler-hack
```

Or scheduled for longer-term monitoring:
```
/schedule "0 */6 * * *" /meat-monitor euler-hack
```

### `/meat` on existing case — Incremental updates

When `/meat` is invoked and a matching case already exists:
1. Load `case.json` — show current status and summary
2. Ask: resume investigation, run monitor check, or start fresh?
3. If resuming: load existing `addresses.json` and `journal.md`, continue from where we left off
4. All new data goes to `evidence/`, new analysis updates `findings/`
5. Journal is appended, never overwritten

## Case Directory Structure

```
cases/<case-name>/
├── case.json             # Case metadata, status, monitored addresses
├── journal.md            # Append-only investigation log
├── addresses.json        # Address registry with roles + confidence + evidence refs
├── evidence/             # Raw on-chain data — ground truth, never modified after write
│   ├── tx_<hash>.json
│   ├── receipt_<hash>.json
│   ├── trace_<hash>.json
│   ├── source_<addr>.json
│   ├── abi_<addr>.json
│   └── txlist_<addr>_<page>.json
├── findings/             # Analysis outputs — each cites evidence
│   ├── recon.md
│   ├── analysis.md
│   ├── fund-trace.md
│   └── poc.md
├── contracts/            # Downloaded source code (by address)
│   ├── 0xVictim/
│   └── 0xAttacker/
└── poc/                  # Foundry PoC for this case
    └── Exploit.t.sol
```

## Key Technical Decisions

- **requests + eth-abi** instead of web3.py: lighter, more control over caching, we only need raw RPC calls + ABI decoding
- **Evidence store (not cache)**: raw on-chain data goes to `evidence/` and is never modified after write. This is the ground truth that all analysis references. Conceptually different from a performance cache — it's the forensic record.
- **`cast run` as trace fallback**: free-tier RPC providers don't expose `debug_traceTransaction`, but `cast run` replays the tx locally against archive state — works universally
- **Per-case evidence** over global: keeps cases self-contained and forensically clean. Each case has its own evidence directory that can be handed to another analyst.
- **Rate limiter** in explorer.py: token bucket at 5 req/sec (Etherscan free tier limit)
- **Confidence-tagged address registry**: `addresses.json` carries confidence levels (CONFIRMED/HIGH/MEDIUM/LOW) with evidence references. Prevents cascading errors from misclassification.
- **Append-only journal**: investigation history is never rewritten. If a finding is later corrected, the correction is a new journal entry, not an edit of the old one.

## Additional Design Decisions from Review

### Attack type classification (Phase 1 — in `/meat` entry point)

Not all exploits are smart contract vulnerabilities. `/meat` classifies early because it changes the entire downstream path:

- **Smart contract exploit**: unusual function calls, flash loans, complex call traces → `/meat-analyze` does source review + trace walkthrough
- **Key compromise**: simple transfers from victim EOA, authorized-looking multisig calls, no exploit contract → analysis focuses on when the key started being used maliciously, approval patterns, multisig signer identification
- **Governance attack**: malicious proposals, vote manipulation → analyze proposal content and voting patterns
- **Rug pull / insider**: deployer draining liquidity, admin key abuse → analyze privileged function calls

### Net flow calculation (skill-level, not CLI)

Profit calculation uses **net token flows per address** across the full transaction — flash loan borrow/repay pairs cancel naturally. Skills should:
- Report net profit, not gross volume
- Label flash loan usage for understanding the mechanism (which provider, what amount leveraged)
- This is a presentation concern in skill instructions, not special CLI logic

### Additional CLI commands (Phase 1-2)

| Command | Phase | Purpose |
|---------|-------|---------|
| `meat storage <addr> --slot N --chain <c>` | 2 | Read contract state before/after attack |
| `meat logs --address <a> --topic <t> --chain <c>` | 2 | Event search via eth_getLogs |
| `meat block <number> --chain <c>` | 2 | Block info + all txs (multi-tx same-block attacks) |

### Batch + messy input parsing (Phase 1)

`meat parse` accepts multiline/multi-item input (stdin or multiple args). Strips markdown formatting, surrounding text noise, URL parameters. Returns an array of parsed items. Handles real-world input from Telegram, Twitter, Discord.

### Cross-chain bridge linking (Phase 4+, data structures now)

Store bridge crossings in `case.json` with: source tx hash, bridge name, destination chain, expected recipient. Automated linking (decoding bridge-specific events) is Phase 4+. Manual linking supported from day one — user provides the destination tx hash.

### Deferred capabilities

- **Unverified contract decompilation**: Bytecode fetch + disassembly for attacker contracts. For now, call trace + victim source is usually sufficient for root cause analysis.
- **Rescue/whitehack tx crafting** (`/meat-rescue`): Forge scripts to exploit the same vulnerability for fund recovery. Design later with appropriate guardrails.

## Phased Implementation

### Phase 1: MVP — paste a tx hash, get a decoded analysis
1. Project scaffolding: `CLAUDE.md`, `chains.yaml`, `.env.example`, `.gitignore`, `requirements.txt`
2. `meat/config.py` — load chains.yaml + .env
3. `meat/parse.py` — input parser (tx hash, address, URL detection + chain extraction)
4. `meat/rpc.py` — JSON-RPC client
5. `meat/explorer.py` — Etherscan API client + rate limiter
6. `meat/decode.py` — ABI decoding + 4byte selector lookup
7. `meat/evidence.py` — evidence store (write-once raw data)
8. `meat/case.py` — case lifecycle (create case.json, append journal)
9. `meat/classify.py` — EOA vs contract, ERC20 detection, proxy detection
10. `meat/cli.py` — Click CLI with `parse`, `tx`, `source`, `abi`, `classify`, `decode` commands
11. `.claude/skills/meat.md` — main entry point skill (with existing-case detection)

### Phase 2: Recon + Trace + Monitor
1. CLI commands: `txlist`, `transfers`, `flow`
2. `meat/trace.py` — fund flow graph builder
3. `.claude/skills/meat-recon.md`
4. `.claude/skills/meat-trace.md`
5. `.claude/skills/meat-monitor.md` — case monitoring (loop-compatible)
6. Expand `chains.yaml` with all major EVM chains

### Phase 3: Deep Analysis + PoC
1. CLI command: `trace` (call traces via debug_traceTransaction / cast run)
2. `.claude/skills/meat-analyze.md`
3. `.claude/skills/meat-poc.md`
4. Foundry project scaffolding

### Phase 4: Polish
1. Known address labels database (CEX deposits, bridges, mixers)
2. Cross-chain bridge detection and continuation
3. Proxy contract handling (EIP-1967, EIP-1822, diamond, minimal)
4. Consolidated report generation
5. Multicall unwrapping, flash loan pattern detection

## Verification

After Phase 1:
- `python3 -m meat parse "https://etherscan.io/tx/0x..."` returns `{type: "tx_hash", chain: "ethereum", value: "0x..."}`
- `python3 -m meat tx <known_exploit_tx> --chain ethereum` returns decoded tx with transfers
- `/meat <tx_hash>` interactively analyzes the transaction and creates a case directory

After Phase 2:
- `/meat-recon` expands from a single attacker address to find all related txs and addresses
- `/meat-trace` produces a fund flow diagram from attacker addresses

After Phase 3:
- `/meat-analyze` explains the vulnerability from source code + call trace
- `/meat-poc` produces a working Foundry test that reproduces the exploit
