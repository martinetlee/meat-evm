# MEAT-EVM

**Martinet's Exploit Analysis Tool for EVM**

A Claude Code skill-based toolkit for investigating EVM exploits in real-time. Paste a transaction hash, get a decoded analysis with USD values in under 10 seconds. Then trace funds, analyze vulnerabilities, and reproduce exploits.

```
$ meat quick https://etherscan.io/tx/0xc310a0af...

Euler Hack — Quick Analysis
Status:    success   Fee: 0.110796 ETH
Transfers: 20

ADDRESSES:
  0x5f259d0b...   eoa       bal=3.612838 ETH
  0xebc29199...   contract  bal=0.0001 ETH

NET FLOWS:
  0x028171bc...     27,000.0 ($26,703.81) Dai
  0xebc29199...  8,877,507.3 ($8,780,121.09) Dai
  0x27182842...  -8,904,507.3 (-$8,806,824.90) Dai

Time: 8.7s
```

---

## Quick Start

```bash
# 1. Clone and setup
git clone <repo> && cd meat-evm
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Configure API keys
cp .env.example .env
# Edit .env — at minimum, add ETHERSCAN_API_KEY
# For best experience, add an Alchemy RPC URL (free tier works)

# 3. Run your first analysis
source .venv/bin/activate
python3 -m meat quick <tx_hash_or_explorer_url> --chain ethereum
```

### Minimal config (explorer only)
```env
ETHERSCAN_API_KEY=your_key_here
```

### Recommended config (full capabilities)
```env
ETHERSCAN_API_KEY=your_key_here
ETH_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/your_key
POLYGON_RPC_URL=https://polygon-mainnet.g.alchemy.com/v2/your_key
```

### Investigation workflow
```bash
# Quick analysis — one command, full picture
python3 -m meat quick 0xabc123...

# Create a case to track the investigation
python3 -m meat case create 2024-03-13-euler --chain ethereum
export MEAT_CHAIN=ethereum MEAT_CASE=2024-03-13-euler

# Deep dive
python3 -m meat tx 0xabc123...           # full tx decode with all logs
python3 -m meat classify 0xAttacker...   # address type, admin, proxy, balances
python3 -m meat flow 0xAttacker...       # fund flow graph
python3 -m meat source 0xVictim...       # contract source code

# Follow the money & gate the conclusion (correctness)
python3 -m meat profit 0xAttacker... --block 25471345   # find the real money-out tx
python3 -m meat provenance 0xHolder...                  # single-source = sybil, not a victim
python3 -m meat check 2024-03-13-euler                  # value conservation + loss attribution (exits non-zero on failure)

# Or use the Claude Code skills
/meat 0xabc123...          # guided analysis
/meat-recon                # expand from partial info
/meat-trace                # follow the money
/meat-analyze              # vulnerability deep-dive
/meat-poc                  # Foundry PoC reproduction
/meat-monitor euler-hack   # watch for new activity
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Claude Code Skills                       │
│  /meat  /meat-recon  /meat-trace  /meat-analyze  /meat-poc   │
│                     /meat-monitor                            │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │ Orchestration: Claude reads CLI output, reasons about   │ │
│  │ exploits, writes findings to case directory             │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────────────────┬──────────────────────────────────┘
                           │ invokes via bash
┌──────────────────────────▼──────────────────────────────────┐
│                     CLI Layer (cli.py)                        │
│                                                              │
│  quick · tx · classify · calltrace · source · abi · decode   │
│  txlist · transfers · flow · funder · logs · storage · block │
│  profit · provenance · check      ← correctness gate         │
│  btc-tx · btc-trace · thorchain · debridge · orbiter         │
│  intents · case · label · annotate · report · trace-addresses│
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐ │
│  │ _meta    │  │ compact  │  │ evidence │  │ MEAT_CHAIN  │ │
│  │ on every │  │ mode     │  │ auto-    │  │ MEAT_CASE   │ │
│  │ output   │  │ (2KB vs  │  │ save     │  │ env var     │ │
│  │          │  │  26KB)   │  │          │  │ defaults    │ │
│  └──────────┘  └──────────┘  └──────────┘  └─────────────┘ │
└──────────┬────────────┬────────────┬────────────┬───────────┘
           │            │            │            │
┌──────────▼──┐ ┌───────▼────┐ ┌─────▼──────┐ ┌──▼──────────┐
│  Data Layer │ │  Decode    │ │  Analysis  │ │  External   │
│             │ │  Layer     │ │  Layer     │ │  APIs       │
│ rpc.py      │ │            │ │            │ │             │
│ ┌─────────┐ │ │ decode.py  │ │classify.py │ │external.py  │
│ │Standard │ │ │ ·ABI decode│ │ ·EOA/      │ │ ·DeFiLlama │
│ │JSON-RPC │ │ │ ·ERC20    │ │  contract  │ │  (USD price)│
│ │         │ │ │  Transfer │ │ ·Proxy     │ │ ·Sourcify   │
│ │Alchemy  │ │ │ ·Approval │ │  (5 types) │ │  (sigs+src) │
│ │Enhanced:│ │ │ ·WETH wrap│ │ ·Admin/    │ │ ·Tenderly   │
│ │·getAsset│ │ │ ·4byte +  │ │  roles     │ │  (traces)   │
│ │ Transf. │ │ │  Sourcify │ │ ·LP pair   │ │             │
│ │·getToken│ │ │ ·Token    │ │ ·Labels    │ │             │
│ │ Balance │ │ │  enrichmt │ │ ·Balances  │ │             │
│ │·debug   │ │ │ ·Net flow │ │ ·Token     │ │             │
│ │ trace   │ │ │  compute  │ │  balances  │ │             │
│ └─────────┘ │ └────────────┘ │ (Alchemy) │ │             │
│             │                └────────────┘ │             │
│explorer.py  │                               │             │
│ ·Etherscan  │                               │             │
│  V2 API     │  trace.py                     │             │
│ ·Rate limit │  ·Fund flow BFS               │             │
│  + retry    │  ·Alchemy fast path            │             │
│ ·Proxy RPC  │  ·Explorer fallback            │             │
│  fallback   │  ·Known entity labels          │             │
└─────────────┘  └─────────────────────────────┘ └───────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                    Case Directory                            │
│                                                              │
│  cases/<name>/                                               │
│  ├── case.json          Status, monitored addresses, summary │
│  ├── journal.md         Append-only investigation log        │
│  ├── addresses.json     Roles + confidence + evidence refs   │
│  ├── evidence/          Raw on-chain data (write-once)       │
│  │   ├── tx/          Transaction data                       │
│  │   ├── receipt/     Transaction receipts                   │
│  │   ├── trace/       Call traces                            │
│  │   ├── source/      Verified source code                   │
│  │   ├── classify/    Address classifications                │
│  │   ├── provenance/  Token origin (sybil check)             │
│  │   └── profit/      Money-out tx resolution                │
│  ├── findings/          Analysis outputs (cite evidence)     │
│  │   ├── recon.md         Who attacked whom, how much        │
│  │   ├── fund-trace.md    Where the money went               │
│  │   ├── analysis.md      Vulnerability deep-dive            │
│  │   └── poc.md           PoC reproduction docs              │
│  └── contracts/         Downloaded source code by address    │
└─────────────────────────────────────────────────────────────┘
```

### Data flow for a typical investigation

```
Input (tx hash / URL / address)
  │
  ▼
Parse ──→ detect type (tx_hash/address) + chain (from URL)
  │
  ▼
Quick ──→ fetch tx + receipt ──→ decode transfers + events
  │         │                       │
  │         ▼                       ▼
  │    classify from/to        compute net flows
  │    (type, proxy, admin,    (per-address per-token,
  │     labels, balances)       with USD via DeFiLlama)
  │
  ▼
Evidence ──→ raw API responses saved to cases/<name>/evidence/
  │
  ▼
Analysis ──→ Claude reasons about the data
  │           │
  │           ├─ /meat-recon:  expand (txlist, logs, classify more addrs)
  │           ├─ /meat-trace:  fund flow graph (BFS, Alchemy or explorer)
  │           ├─ /meat-analyze: source review + call trace walkthrough
  │           └─ /meat-poc:    Foundry test reproduction
  │
  ▼
Findings ──→ written to cases/<name>/findings/ (cites evidence)
```

---

## CLI Commands (29 total)

**Core analysis**
| Command | Purpose |
|---------|---------|
| `quick` | **One-shot analysis**: tx hash or URL → decoded summary with USD in ~9 seconds |
| `tx` | Full tx decode: transfers, approvals, WETH events, net flows, decoded logs, internal txs |
| `classify` | Address classification: EOA/contract, proxy type, admin roles, LP pair, token balances |
| `calltrace` | Call trace: debug RPC → Tenderly → cast → explorer fallback chain |
| `source` | Verified source code (Etherscan → Sourcify fallback) |
| `abi` | Contract ABI with proxy resolution |
| `decode` | Decode calldata or function selector |

**History & fund tracing**
| Command | Purpose |
|---------|---------|
| `txlist` | Transaction history for an address |
| `transfers` | ERC20 token transfers for an address |
| `flow` | Fund flow graph (BFS): follows money through swaps, bridges, mixers. Alchemy fast path |
| `funder` | First gas-funding source(s) — sybil clustering |
| `logs` | Event log search by signature or topic |
| `storage` | Storage slot read with `--compare-block` for before/after diffs |
| `block` | Block info with transaction list |

**Correctness gate** — *don't conclude an exploit without finding who lost the money*
| Command | Purpose |
|---------|---------|
| `profit` | Find the tx that realizes the largest net stablecoin gain — **the money-out tx is rarely the one you were handed** |
| `provenance` | Earliest inbound source of each token — a single-source "holder" is a sybil red flag, not a victim |
| `check` | Hard gate (non-zero exit): value conservation, **loss attribution**, provenance, money-out-tx-fetched. Runs from a Stop hook |

**Cross-chain fund tracing**
| Command | Purpose |
|---------|---------|
| `btc-tx` / `btc-trace` | Bitcoin tx + deterministic peel-chain following (Blockstream) |
| `thorchain` | THORChain/Maya memo decode + Midgard (`--protocol maya`) |
| `debridge` / `orbiter` | deBridge DLN / Orbiter cross-chain order resolution |
| `intents` | Cross-reference an address against known bridge/intent registries |

**Case management**
| Command | Purpose |
|---------|---------|
| `case` | Case lifecycle: `create`, `list`, `show` |
| `label` | Assign role / name / confidence to an address |
| `annotate` | Attach phase + purpose notes to call-trace nodes |
| `report` | Generate an HTML report from collected evidence |
| `trace-addresses` | Extract all unique addresses from a saved call trace |

### Output features

Every command includes `_meta`:
```json
"_meta": {
  "data_sources": ["explorer_proxy"],
  "evidence_saved": ["evidence/tx/0x...json (new)"],
  "warnings": ["No RPC — token/admin detection limited"],
  "enrichment_failures": ["0xe025e3ca..."]
}
```

Use `--compact` on `tx` for 2KB summary instead of 26KB full output.

Set `MEAT_CHAIN` and `MEAT_CASE` env vars to skip `--chain` and `--case` flags.

---

## Enhanced Provider Support

| Provider | Auto-detected | What it enables |
|----------|--------------|-----------------|
| **Alchemy RPC** | URL contains `alchemy.com` | `getAssetTransfers` (fast fund tracing), `getTokenBalances` (full token snapshot), `debug_traceTransaction` (call traces) |
| **Tenderly** | `TENDERLY_ACCESS_KEY` set | Decoded call traces with state diffs as calltrace fallback |
| **DeFiLlama** | Always (free, no auth) | USD prices in net_flows via historical price API |
| **Sourcify** | Always (free, no auth) | 4.7M function signatures + contract source fallback |
| **Etherscan V2** | `ETHERSCAN_API_KEY` set | Core data layer: tx, receipts, source code, logs, internal txs |

---

## Correctness Guardrails

**Evidence separation** — Raw API responses in `evidence/` (write-once, never modified). Analysis in `findings/` must cite evidence paths.

**Confidence tagging** — Every address classification carries a level:
- CONFIRMED: directly proven by on-chain data
- HIGH: strong multi-source evidence
- MEDIUM: reasonable inference
- LOW/HYPOTHESIS: speculation needing investigation

**Auditability** — Every output includes `_meta` showing data sources, evidence file paths (new vs cached), enrichment failures, and capability warnings. `classify` includes `checks_performed` listing what was tried.

**Net flows** include both raw wei values and formatted amounts with USD, so computations are verifiable:
```json
"Dai": {"raw": "8877507348306697267428294", "formatted": "8877507.348306", "decimals": 18, "usd_value": "$8,780,121.09"}
```

### Correctness gate (`meat check`)

The most common way an exploit analysis goes wrong is concluding *what happened* without proving *who
lost the money* — mistaking a mechanism (a permit, a transfer) for the theft, or stopping at the tx
you were handed instead of the tx where value is realized. `meat check` turns that discipline into a
deterministic gate that **exits non-zero** and blocks the conclusion until it holds. It runs
automatically from a Stop hook, so a wrong write-up fails a gate rather than a memory check.

Invariants enforced, per declared attack/monetization tx:
- **Value conservation** — every address with a large net *priced* (stablecoin/ETH) swing must be labeled.
- **Loss attribution** — the attacker's gain must be accounted for by a `victim`-role address: either a
  matching priced loss, or **absorbing an illiquid token the attacker offloaded onto it** (the classic
  NAV/oracle-drain signature). Dump recipients are surfaced as `victim_candidates` and the gate fails
  until the true victim is investigated and labeled.
- **Provenance** — every attacker/victim label has a `meat provenance` record (or an explicit waiver).
- **Money-out fetched** — decisive txs exist in `evidence/tx/` in full (not `--compact`), and any tx
  `meat profit` flagged as the largest realized gain is declared decisive.

Supporting commands: `meat profit` finds the real money-out tx; `meat provenance` distinguishes
sybils (single-source token holders) from genuine victims. The `/meat` skill wires all three into its
workflow (find the payout → verify provenance → gate before writing findings).

---

## Supported Chains

Configured in `chains.yaml`. All use Etherscan V2 unified API:

| Chain | Chain ID | Explorer |
|-------|----------|----------|
| Ethereum | 1 | etherscan.io |
| Polygon | 137 | polygonscan.com |
| Base | 8453 | basescan.org |
| Arbitrum | 42161 | arbiscan.io |
| BSC | 56 | bscscan.com |
| Optimism | 10 | optimistic.etherscan.io |

Add new EVM chains by adding an entry to `chains.yaml`.

---

## Tests

```bash
# Unit tests (no API calls, <1s)
python3 -m pytest tests/test_parse.py tests/test_decode.py -v

# Integration tests (live API, ~45s, needs ETHERSCAN_API_KEY)
python3 -m pytest tests/test_integration.py -v

# All tests
python3 -m pytest tests/ -v
```

40 tests, mostly validating against the Euler Finance hack ($200M, March 2023):
- Input parsing (URLs, addresses, noisy text)
- ABI decoding (selectors, Transfer/Approval/WETH events)
- Transaction decode (token transfers, net flows, DAI movements)
- Address classification (EOA, verified proxy, known CEX)
- Quick analysis pipeline (end-to-end in one command)
- Correctness gate (offline): provenance/sybil detection, profit ranking, and the `check`
  loss-attribution invariants (unlabeled dump-recipient → fail; victim absorbs dumped asset → pass)

---

## Project Structure

```
meat-evm/
├── meat/                    Python CLI package
│   ├── cli.py                 All 29 commands + helpers (~2400 LOC)
│   ├── config.py              Chain config + env loading
│   ├── rpc.py                 JSON-RPC + Alchemy enhanced methods
│   ├── explorer.py            Etherscan V2 API + rate limiter + retry
│   ├── external.py            DeFiLlama + Sourcify + Tenderly
│   ├── decode.py              ABI/event decoding + Sourcify signatures
│   ├── classify.py            Address classification (proxy, admin, LP, balance)
│   ├── trace.py               Fund flow graph (Alchemy fast path + explorer)
│   ├── analysis.py            Correctness gate: provenance, profit, check (pure + offline)
│   ├── crosschain.py          Bitcoin peel-chain + THORChain/deBridge/Orbiter tracing
│   ├── report.py              HTML report generator
│   ├── evidence.py            Write-once evidence store
│   ├── case.py                Case lifecycle management
│   └── parse.py               Input parsing (URLs, hashes, batch, noisy text)
├── .claude/
│   ├── skills/               Claude Code skills (each a dir with SKILL.md)
│   │   ├── meat/               Main entry point
│   │   ├── meat-recon/         Expand from partial info
│   │   ├── meat-trace/         Fund tracing
│   │   ├── meat-analyze/       Vulnerability analysis
│   │   ├── meat-poc/           Foundry PoC
│   │   └── meat-monitor/       Case monitoring
│   └── hooks/                Stop hook that runs `meat check` at wrap-up
├── chains.yaml              Multi-chain configuration
├── labels/                  Known address database
├── foundry/                 Foundry workspace for PoC reproduction
├── cases/                   Per-case investigation data (gitignored)
├── tests/                   Unit + integration tests (incl. offline gate tests)
└── design_review/           Architecture decision records
```
