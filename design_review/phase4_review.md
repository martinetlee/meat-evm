# Phase 4 Design Review — Polish

## What was built

Known address labels database, label integration into `classify` and `flow` commands, and Foundry workspace improvements.

### Changes

| Component | Change | Status |
|-----------|--------|--------|
| `labels/known_addresses.json` | 50+ addresses: CEX deposits, bridges, mixers, DEX routers, lending | Created |
| `classify.py` | Integrated label lookup — adds `known_entity` field to results | Tested |
| `trace.py` | Flow graph nodes auto-labeled from known addresses | Tested |

### Test results

| Test | Result | Notes |
|------|--------|-------|
| Classify Binance 14 | PASS | `type: eoa, known_entity: {label: "Binance 14", category: "cex"}` |
| Classify Tornado Cash Router | PASS | `type: contract, known_entity: {label: "Tornado Cash: Router", category: "mixers"}` |
| Flow graph label propagation | PASS | Nodes auto-labeled when matching known addresses |
| Label file loading (lazy) | PASS | Loaded once, cached globally |

### Known address categories

| Category | Count | Purpose |
|----------|-------|---------|
| `cex` | 15 | Exchange deposit addresses (Binance, Coinbase, Kraken, OKX, Crypto.com) |
| `bridges` | 9 | Cross-chain bridges (Wormhole, Optimism, Arbitrum, Base, Polygon, Across, Hop, Stargate) |
| `mixers` | 5 | Privacy protocols (Tornado Cash pools, Railgun) |
| `dex_routers` | 6 | DEX aggregators (Uniswap V2/V3, 0x, 1inch, Kyber) |
| `lending` | 4 | Lending protocols (Aave V2/V3, Compound, Maker) |

### What was deferred from Phase 4 plan

1. **Cross-chain bridge event decoding**: Detecting bridge crossings from event logs and linking source→destination transactions. This requires bridge-specific ABI knowledge and is complex. Data structures support it (bridge crossings in case.json), but automated detection is not implemented.

2. **Advanced proxy handling**: EIP-1822 (UUPS), diamond proxy (EIP-2535), minimal proxy (EIP-1167). Current implementation handles EIP-1967 proxies and Etherscan's proxy detection. More exotic patterns deferred.

3. **Multicall unwrapping**: Decoding multicall/batch transactions to reveal the individual calls inside. Would improve analysis of complex DeFi interactions.

4. **Consolidated report generation**: A single `/meat-report` that synthesizes all findings into one shareable document. Currently each skill writes its own findings file.

## Architecture summary (all phases complete)

### CLI commands (10 total)

| Command | Phase | Category |
|---------|-------|----------|
| `parse` | 1 | Input handling |
| `tx` | 1 | Data fetching |
| `source` | 1 | Data fetching |
| `abi` | 1 | Data fetching |
| `classify` | 1 | Analysis |
| `decode` | 1 | Analysis |
| `txlist` | 2 | Data fetching |
| `transfers` | 2 | Data fetching |
| `flow` | 2 | Analysis |
| `calltrace` | 3 | Data fetching |
| `storage` | 3 | Data fetching |
| `block` | 3 | Data fetching |

### Skills (6 total)

| Skill | Phase | Purpose |
|-------|-------|---------|
| `/meat` | 1 | Main entry point — parse, fetch, classify, summarize |
| `/meat-recon` | 2 | Expand from partial info to full picture |
| `/meat-trace` | 2 | Track where stolen funds went |
| `/meat-monitor` | 2 | Watch active cases for new activity |
| `/meat-analyze` | 3 | Deep vulnerability analysis |
| `/meat-poc` | 3 | Foundry PoC reproduction |

### Python modules (10 total)

```
meat/
├── __init__.py
├── __main__.py
├── cli.py        (~600 LOC) — All CLI commands
├── config.py     (~95 LOC)  — Chain config + env loading
├── parse.py      (~140 LOC) — Input parser
├── rpc.py        (~80 LOC)  — JSON-RPC client
├── explorer.py   (~190 LOC) — Etherscan V2 API + rate limiter
├── decode.py     (~220 LOC) — ABI + 4byte decoding
├── evidence.py   (~65 LOC)  — Write-once evidence store
├── case.py       (~95 LOC)  — Case lifecycle management
├── classify.py   (~150 LOC) — Address classification + labels
└── trace.py      (~140 LOC) — Fund flow graph builder
```

### Correctness guarantees

1. **Evidence separation**: Raw on-chain data in `evidence/` (write-once), analysis in `findings/`
2. **Confidence tagging**: CONFIRMED/HIGH/MEDIUM/LOW on all classifications
3. **Known entity labels**: 50+ addresses auto-identified (CEX, bridges, mixers)
4. **Cross-validation**: Skills instruct Claude to verify claims against evidence
5. **Append-only journal**: Investigation history never rewritten
