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
│  quick · tx · classify · flow · calltrace · source · abi     │
│  txlist · transfers · logs · storage · block · decode        │
│  case create · case list · case show                         │
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
│  │   ├── tx/              Transaction data                   │
│  │   ├── receipt/         Transaction receipts               │
│  │   ├── trace/           Call traces                        │
│  │   ├── source/          Verified source code               │
│  │   └── classify/        Address classifications            │
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

## CLI Commands (14 total)

| Command | Purpose |
|---------|---------|
| `quick` | **One-shot analysis**: tx hash or URL → decoded summary with USD in ~9 seconds |
| `tx` | Full tx decode: transfers, approvals, WETH events, net flows, decoded logs, internal txs |
| `classify` | Address classification: EOA/contract, proxy type, admin roles, LP pair, token balances |
| `flow` | Fund flow graph (BFS): follows money through swaps, bridges, mixers. Alchemy fast path |
| `calltrace` | Call trace: debug RPC → Tenderly → cast → explorer fallback chain |
| `source` | Verified source code (Etherscan → Sourcify fallback) |
| `abi` | Contract ABI with proxy resolution |
| `txlist` | Transaction history for an address |
| `transfers` | ERC20 token transfers for an address |
| `logs` | Event log search by signature or topic |
| `storage` | Storage slot read with `--compare-block` for before/after diffs |
| `block` | Block info with transaction list |
| `decode` | Decode calldata or function selector |
| `case` | Case management: `create`, `list`, `show` |

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

31 tests validate against the Euler Finance hack ($200M, March 2023):
- Input parsing (URLs, addresses, noisy text)
- ABI decoding (selectors, Transfer/Approval/WETH events)
- Transaction decode (token transfers, net flows, DAI movements)
- Address classification (EOA, verified proxy, known CEX)
- Quick analysis pipeline (end-to-end in one command)

---

## Project Structure

```
meat-evm/
├── meat/                    Python CLI package
│   ├── cli.py                 All 14 commands + helpers (~1100 LOC)
│   ├── config.py              Chain config + env loading
│   ├── rpc.py                 JSON-RPC + Alchemy enhanced methods
│   ├── explorer.py            Etherscan V2 API + rate limiter + retry
│   ├── external.py            DeFiLlama + Sourcify + Tenderly
│   ├── decode.py              ABI/event decoding + Sourcify signatures
│   ├── classify.py            Address classification (proxy, admin, LP, balance)
│   ├── trace.py               Fund flow graph (Alchemy fast path + explorer)
│   ├── evidence.py            Write-once evidence store
│   ├── case.py                Case lifecycle management
│   └── parse.py               Input parsing (URLs, hashes, batch, noisy text)
├── .claude/skills/          Claude Code skill files
│   ├── meat.md                Main entry point
│   ├── meat-recon.md          Expand from partial info
│   ├── meat-trace.md          Fund tracing
│   ├── meat-analyze.md        Vulnerability analysis
│   ├── meat-poc.md            Foundry PoC
│   └── meat-monitor.md       Case monitoring
├── chains.yaml              Multi-chain configuration
├── labels/                  Known address database (50+ entities)
├── foundry/                 Foundry workspace for PoC reproduction
├── cases/                   Per-case investigation data (gitignored)
├── tests/                   Unit + integration tests
└── design_review/           Architecture decision records
```
