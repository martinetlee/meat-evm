# Phase 3 Design Review — Deep Analysis + PoC

## What was built

Three new CLI commands (`calltrace`, `storage`, `block`), two skill files (`meat-analyze.md`, `meat-poc.md`), and Foundry project scaffolding.

### Modules implemented / modified

| Module | Change | Status |
|--------|--------|--------|
| `cli.py` | Added `calltrace`, `storage`, `block` commands | Tested |
| `meat-analyze.md` | New skill — vulnerability analysis workflow | Written |
| `meat-poc.md` | New skill — Foundry PoC creation | Written |
| `foundry/` | Foundry project scaffolding | Created |

### Test results

| Test | Result | Notes |
|------|--------|-------|
| `calltrace` — no RPC available | PASS | Graceful failure with clear error message |
| `calltrace` — cast fallback | PARTIAL | `cast` found but RPC is explorer URL (fixed) |
| `storage` — Polygon USDC slot 0 | PASS | Returns hex value and decimal |
| `block` — Polygon block 50M | PASS | 564 txs, timestamp decoded |
| Error handling | PASS | Missing RPC, invalid hash handled cleanly |

### calltrace command design

Three fallback strategies, tried in order:
1. `debug_traceTransaction` with `callTracer` (fastest, needs debug RPC namespace)
2. `trace_transaction` (Parity trace API, some nodes support this)
3. `cast run` (Foundry — replays locally against archive node, works with any RPC)

If none available, returns a clear error explaining what's needed.

**Fix applied:** The fallback previously passed the explorer API URL to `cast run`, which doesn't work (explorer URL ≠ RPC URL). Now `cast run` only activates when an actual RPC URL is configured.

### Skill design decisions

**`/meat-analyze` workflow:**
1. Fetch victim source code and save to `contracts/`
2. Independent source code review (before looking at trace) — prevents confirmation bias
3. Call trace walkthrough — step-by-step with source code cross-references
4. Synthesis — vulnerability class, root cause, fix recommendation
5. WebSearch for prior art (audits, existing writeups)
6. Structured report with evidence citations

**`/meat-poc` workflow:**
1. Load analysis findings
2. Set up Foundry project (or verify existing)
3. Write test that forks mainnet at block N-1
4. Run test with `forge test -vvv`
5. Iterate up to 3 times on failures
6. Document with run instructions and output

### Foundry project structure

```
foundry/
├── foundry.toml    # All chain RPCs configured via env vars
├── src/            # Attacker contracts for PoC
├── test/           # PoC test files (Exploit_*.t.sol)
└── lib/            # Dependencies (forge-std)
```

`forge-std` is not installed yet — will be added when the first PoC is created via `forge install foundry-rs/forge-std`.

### Known limitations

1. **calltrace requires RPC with debug namespace**: Most free-tier providers don't support `debug_traceTransaction`. Alchemy supports it on paid plans. Cast fallback requires Foundry installed + archive RPC access.

2. **No automatic internal tx trace without RPC**: When only explorer API is available, we can get internal transactions via `txlistinternal` but not the full nested call trace.

3. **Forge-std not pre-installed**: The first PoC run will need `cd foundry && forge install foundry-rs/forge-std`. This is intentional — avoids pulling deps until needed.

4. **PoC iteration is manual**: The skill guides Claude through up to 3 fix attempts, but there's no automated retry loop.

### Error handling improvements made

- `calltrace` no longer passes explorer URL to `cast run`
- Clear error messages for missing RPC, missing Foundry
- Timeout handling for `cast run` (120s limit)

## Files created / modified

```
meat/cli.py (modified — added calltrace, storage, block commands)
.claude/skills/meat-analyze.md (new)
.claude/skills/meat-poc.md (new)
foundry/foundry.toml (new)
foundry/src/.gitkeep (new)
foundry/test/.gitkeep (new)
foundry/lib/ (new, empty)
```
