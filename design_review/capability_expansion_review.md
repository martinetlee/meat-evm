# Capability Expansion Review

## What was built

5 new capabilities addressing gaps found during scenario-based review.

## 1. Event log searching (`meat logs`)

**What it does**: Searches event logs via explorer `getLogs` API or RPC `eth_getLogs`. Supports filtering by contract address, event signature (auto-computes topic0 hash), and indexed parameters (topic1-3). Decodes matched logs using per-contract ABI.

**Test results**:
| Test | Result |
|------|--------|
| Search Approval events on DAI by event signature | PASS — 7 events found, decoded with params (src, guy, wad) |
| Auto topic0 computation from event string | PASS — `Approval(address,address,uint256)` → correct keccak hash |
| Block range filtering | PASS |
| Log decoding with per-contract ABI | PASS |

**Use cases unlocked**:
- Find all approvals granted to a phishing address
- Find all `Upgraded` events on a proxy contract
- Find all `RoleGranted` events for AccessControl contracts
- Find governance `ProposalCreated` / `VoteCast` events

## 2. Owner/admin role detection

**What it does**: `classify` now detects three admin patterns:
- **Ownable**: Calls `owner()` — returns the current owner address
- **admin()**: Calls `admin()` — returns proxy admin or custom admin
- **AccessControl (OZ)**: Checks `supportsInterface(0x7965db0b)`, queries `DEFAULT_ADMIN_ROLE()`, and suggests using `meat logs --event 'RoleGranted(bytes32,address,address)'` to enumerate role holders

**Test results**:
| Test | Result |
|------|--------|
| Polygon contract admin detection | PASS (requires RPC) |
| AccessControl interface detection | PASS (checked via supportsInterface) |
| Proxy admin slot read | PASS (EIP-1967 admin slot) |

**Output format**:
```json
"admin_info": {
  "owner": "0x...",
  "proxy_admin": "0x...",
  "access_control": true,
  "default_admin_role": "0x00...00",
  "note": "Use meat logs --event 'RoleGranted(...)' to find role holders"
}
```

## 3. Historical storage reads + compare-block

**What it does**: `storage` command now:
- Falls back to explorer `proxy_get_storage_at` when no RPC available
- Supports `--compare-block` to show before/after values at two blocks
- Reports `"changed": true/false` for quick state diff

**Test results**:
| Test | Result |
|------|--------|
| Storage read via RPC (Polygon) | PASS |
| Storage compare-block (same value) | PASS — shows before/after + changed=false |
| Explorer fallback for storage | PASS — added `proxy_get_storage_at` to explorer client |

**Use cases**: Check if implementation address changed, verify state before/after attack, detect unauthorized storage modifications.

## 4. Expanded proxy detection

**What it does**: `classify` now detects 5 proxy patterns:

| Pattern | Detection method |
|---------|-----------------|
| EIP-1967 transparent proxy | Implementation slot + admin slot both non-zero |
| EIP-1967 UUPS | Implementation slot non-zero, admin slot zero |
| EIP-1967 beacon proxy | Beacon slot non-zero |
| EIP-1822 UUPS (legacy) | Legacy UUPS implementation slot |
| EIP-1167 minimal proxy | Bytecode prefix pattern (`363d3d373d3d3d363d73...`) |
| EIP-2535 diamond | `supportsInterface(0x48e2b093)` |
| Explorer-detected | Etherscan proxy flag (fallback when no RPC) |

**Test results**:
| Test | Result |
|------|--------|
| Euler contract (explorer only, no RPC) | PASS — `proxy_type: explorer-detected`, implementation found |
| EIP-1167 minimal proxy detection | Implemented (bytecode pattern matching) |
| Diamond proxy detection | Implemented (ERC-165 interface check) |

**Output format**: New `proxy_type` field distinguishes proxy types:
```json
"is_proxy": true,
"proxy_type": "EIP-1967 transparent proxy",
"implementation": "0x..."
```

## 5. Liquidity position detection

**What it does**: `classify` detects Uniswap V2-style LP pairs by calling `factory()`, `token0()`, `token1()`. If all three return valid addresses, the contract is identified as an LP pair.

**Test results**:
| Test | Result |
|------|--------|
| Quickswap WMATIC/USDC pair on Polygon | PASS — `is_lp_pair: true`, factory + token0 + token1 identified |
| Non-LP contract | PASS — `is_lp_pair: false` |

**Output format**:
```json
"is_lp_pair": true,
"lp_info": {
  "factory": "0x5757371414417b8c6caad45baef941abc7d3ab32",
  "token0": "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270",
  "token1": "0x2791bca1f2de4661ed88a30c99a7a9449aa84174"
}
```

## CLI command summary (now 13 commands)

| Command | Category | Added |
|---------|----------|-------|
| `parse` | Input | Phase 1 |
| `tx` | Data fetch | Phase 1 |
| `source` | Data fetch | Phase 1 |
| `abi` | Data fetch | Phase 1 |
| `classify` | Analysis | Phase 1, expanded here |
| `decode` | Analysis | Phase 1 |
| `txlist` | Data fetch | Phase 2 |
| `transfers` | Data fetch | Phase 2 |
| `flow` | Analysis | Phase 2, expanded here |
| `calltrace` | Data fetch | Phase 3, expanded here |
| `storage` | Data fetch | Phase 3, expanded here |
| `block` | Data fetch | Phase 3 |
| **`logs`** | **Data fetch** | **New** |

## Files modified

| File | Changes |
|------|---------|
| `meat/classify.py` | Full rewrite: added admin detection (Ownable, AccessControl), 5 proxy patterns, LP pair detection, merged verified+proxy checks |
| `meat/cli.py` | Added `logs` command, expanded `storage` with explorer fallback + `--compare-block` |
| `meat/explorer.py` | Added `get_logs()` and `proxy_get_storage_at()` methods |
