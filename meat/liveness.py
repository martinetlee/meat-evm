"""Live (on-chain) invariants for the `check` gate.

`meat/analysis.py` is pure and offline on purpose: it validates the post-mortem
you wrote. Everything in there is retrospective — conservation *within a
declared tx*, provenance *for a label*, money-out tx *fetched*. None of it can
answer "is this still happening", "is that balance actually yours", or "did you
find all of the outflow", because those are questions about the chain right now,
not about files on disk.

That gap is not hypothetical. In the 2026-09-15 Safe module case the offline gate
passed clean while the analysis (a) called a still-running exploit contained,
(b) quoted a victim's gross collateral as value-at-risk when it was a leveraged
position worth ~18x less, and (c) accounted for 2 of the 17 transactions that
actually drained the victim.

These checks exist so none of that depends on anyone remembering to look. They
degrade to a warning when there is no RPC, and never hard-fail on a network
error — a flaky node must not be able to fake a passing gate, but it also must
not be able to fake a failing one.
"""

from __future__ import annotations

import time

from eth_abi import decode as abi_decode, encode as abi_encode
from eth_utils import keccak

TRANSFER_TOPIC = "0x" + keccak(text="Transfer(address,address,uint256)").hex()

# Aave-family receipt tokens. A borrower holds the debt token as an ERC20, so a
# plain balance scan already contains the liability — it just has to be read.
DEBT_PREFIXES = ("variabledebt", "stabledebt", "debt")
COLLATERAL_PREFIXES = ("aeth", "a", "c", "s")  # weak; only used to explain, never to decide

# A gate runs on every Stop, so it must stay cheap or it gets disabled.
MAX_WATCHED = 40
MAX_TOKENS_PER_ADDRESS = 60


def _past(deadline: float | None) -> bool:
    return deadline is not None and time.monotonic() > deadline


def _pad(addr: str) -> str:
    return "0x" + "0" * 24 + addr.lower().replace("0x", "")


def _call(rpc, to: str, sig: str, types=None, args=None, rets=None, block="latest"):
    data = "0x" + (keccak(text=sig)[:4] + (abi_encode(types, args) if types else b"")).hex()
    try:
        out = rpc.eth_call({"to": to, "data": data}, block)
    except Exception:
        return None
    if not out or out == "0x":
        return None
    try:
        return abi_decode(rets, bytes.fromhex(out[2:])) if rets else out
    except Exception:
        return None


def _logs(rpc, params: dict) -> list | None:
    try:
        return rpc._rpc_call("eth_getLogs", [params]) if hasattr(rpc, "_rpc_call") else None
    except Exception:
        return None


def _get_logs(rpc, params: dict) -> list | None:
    """rpc clients differ; try the documented helper, then a raw call."""
    for name in ("get_logs", "eth_get_logs"):
        fn = getattr(rpc, name, None)
        if fn:
            try:
                return fn(params)
            except Exception:
                return None
    import requests
    url = getattr(rpc, "url", None) or getattr(rpc, "rpc_url", None)
    if not url:
        return None
    try:
        r = requests.post(url, json={"jsonrpc": "2.0", "id": 1,
                                     "method": "eth_getLogs", "params": [params]}, timeout=45)
        return r.json().get("result")
    except Exception:
        return None


def _balance_of(rpc, token: str, holder: str, block="latest") -> int | None:
    r = _call(rpc, token, "balanceOf(address)", ["address"], [holder], ["uint256"], block)
    return r[0] if r else None


_META_CACHE: dict[str, tuple[str, int]] = {}


def _meta(rpc, token: str) -> tuple[str, int]:
    key = token.lower()
    if key not in _META_CACHE:
        s = _call(rpc, token, "symbol()", rets=["string"])
        d = _call(rpc, token, "decimals()", rets=["uint8"])
        _META_CACHE[key] = ((s[0] if s else "?"), (d[0] if d else 18))
    return _META_CACHE[key]


# --------------------------------------------------------------------------- #
# Invariant L1: is the incident over?
# --------------------------------------------------------------------------- #

def check_liveness(rpc, labeled: dict, exploit_path: list[str], accounted: dict,
                   latest_decisive_block: int | None,
                   deadline: float | None = None) -> tuple[list, list]:
    """Fail if anything on the exploit path moved after the newest evidence.

    This is the invariant whose absence let a live exploit be reported as
    contained. Both probes are address-indexed so it stays cheap enough that
    there is never a reason to skip it:

      1. logs emitted BY each watched address since the last decisive block —
         catches Safe module executions, which is how this class of exploit
         actually presents;
      2. balanceOf for each token the case says was drained, then vs now — a
         drop after your newest evidence means value is still leaving.

    An unfiltered `Transfer` topic sweep would be more thorough and is far too
    slow to run on every Stop; it belongs in an explicit investigation, not a gate.
    """
    violations, warnings = [], []
    if latest_decisive_block is None:
        return violations, warnings

    watched = [a for a, i in labeled.items() if i.get("role") == "victim"]
    watched += [a.lower() for a in exploit_path]
    watched = list(dict.fromkeys(watched))
    if not watched:
        return violations, warnings

    # Bound the window. A gate that can issue an unbounded historical query is a
    # gate someone will turn off.
    frm = hex(latest_decisive_block + 1)
    if len(watched) > MAX_WATCHED:
        warnings.append({
            "invariant": "incident_liveness",
            "detail": (f"{len(watched)} addresses qualify for the liveness sweep; only the first "
                       f"{MAX_WATCHED} were checked. Narrow the labels or sweep manually."),
        })
        watched = watched[:MAX_WATCHED]
    for a in watched:
        if _past(deadline):
            warnings.append({"invariant": "live_checks_budget",
                             "detail": "liveness sweep hit its time budget; not every watched "
                                       "address was checked. Raise --live-budget or narrow the labels."})
            break
        logs = _get_logs(rpc, {"address": a, "fromBlock": frm, "toBlock": "latest"})
        if logs:
            newest = int(logs[-1]["blockNumber"], 16)
            role = (labeled.get(a) or {}).get("role") or "exploit-path contract"
            violations.append({
                "invariant": "incident_liveness",
                "detail": (f"{a} ({role}) emitted {len(logs)} event(s) after block "
                           f"{latest_decisive_block}, newest at block {newest}. The incident is "
                           f"NOT over — your evidence stops before the chain does. Extend the "
                           f"decisive-tx set, or record why this activity is benign."),
            })

    # Value still leaving a victim, measured rather than inferred.
    for victim, tokens in (accounted or {}).items():
        if (labeled.get(victim.lower()) or {}).get("role") != "victim":
            continue
        for token in tokens:
            then = _balance_of(rpc, token, victim, hex(latest_decisive_block))
            now = _balance_of(rpc, token, victim, "latest")
            if then is None or now is None or now >= then:
                continue
            sym, dec = _meta(rpc, token)
            violations.append({
                "invariant": "incident_liveness",
                "detail": (f"{victim} has lost a further {(then - now) / 10 ** dec:,.6f} {sym} "
                           f"since block {latest_decisive_block}, which is the newest block in "
                           f"your evidence. The drain did not stop where your analysis stops."),
            })
    return violations, warnings


# --------------------------------------------------------------------------- #
# Invariant L2: is that balance actually theirs?
# --------------------------------------------------------------------------- #

def check_net_of_debt(rpc, labeled: dict, deadline: float | None = None) -> tuple[list, list]:
    """Warn when a watched address holds debt tokens alongside its holdings.

    A borrower holds `variableDebt*` as a plain ERC20, so the liability is
    already in any balance listing. Quoting gross collateral as value-at-risk is
    then a pure failure to read a line that was on the screen.
    """
    violations, warnings = [], []
    getter = getattr(rpc, "alchemy_get_token_balances", None)
    if not getter:
        return violations, warnings

    for a, info in labeled.items():
        if info.get("role") != "victim":
            continue
        if _past(deadline):
            break
        try:
            bal = getter(a)
        except Exception:
            continue
        debts, assets = [], 0
        rows = [r for r in ((bal or {}).get("tokenBalances", []) or [])][:MAX_TOKENS_PER_ADDRESS]
        for row in rows:
            try:
                v = int(row["tokenBalance"], 16)
            except (KeyError, TypeError, ValueError):
                continue
            if v == 0:
                continue
            assets += 1
            sym, dec = _meta(rpc, row["contractAddress"])
            low = (sym or "").lower()
            if any(low.startswith(p) for p in DEBT_PREFIXES):
                debts.append(f"{sym} {v / 10 ** dec:,.4f}")
        if debts:
            warnings.append({
                "invariant": "net_of_debt",
                "detail": (f"{a} (role={info.get('role')}) holds debt token(s): {'; '.join(debts)}. "
                           f"Its position is LEVERAGED — gross holdings are not value at risk, and "
                           f"quoting them overstates exposure (in the 2026-09-15 case, by ~18x). "
                           f"Report collateral, debt and net equity separately."),
            })
    return violations, warnings


# --------------------------------------------------------------------------- #
# Invariant L3: did you find all of the outflow?
# --------------------------------------------------------------------------- #

def check_drain_completeness(rpc, labeled: dict, accounted: dict,
                             first_block: int | None, last_block: int | None,
                             tol: float = 0.01,
                             deadline: float | None = None) -> tuple[list, list]:
    """Compare the victim's real balance delta to what the analysis accounted for.

    `accounted` is {victim: {token_addr: outflow_raw}} summed from the decisive
    txs. This is what turns "I found some transfers" into "I found all of them":
    the chain states the total, so an incomplete tx set cannot pass silently.
    """
    violations, warnings = [], []
    if first_block is None or last_block is None:
        return violations, warnings

    pre, post = hex(max(first_block - 1, 0)), hex(last_block)
    for victim, tokens in (accounted or {}).items():
        if (labeled.get(victim.lower()) or {}).get("role") != "victim":
            continue
        for token, claimed in tokens.items():
            if _past(deadline):
                break
            b0 = _balance_of(rpc, token, victim, pre)
            b1 = _balance_of(rpc, token, victim, post)
            if b0 is None or b1 is None:
                continue
            actual = b0 - b1
            if actual <= 0:
                continue
            claimed = int(claimed or 0)
            if claimed >= actual * (1 - tol):
                continue
            sym, dec = _meta(rpc, token)
            missing = (actual - claimed) / 10 ** dec
            violations.append({
                "invariant": "drain_completeness",
                "detail": (f"{victim} lost {actual / 10 ** dec:,.6f} {sym} between blocks "
                           f"{first_block - 1} and {last_block}, but your decisive txs only "
                           f"account for {claimed / 10 ** dec:,.6f}. {missing:,.6f} {sym} left "
                           f"in transactions you have not found. Sweep outbound Transfer logs "
                           f"for {victim} across that range — do not stop at the attacker's txs."),
            })
    return violations, warnings


# --------------------------------------------------------------------------- #
# entry point
# --------------------------------------------------------------------------- #

def live_checks(rpc, labeled: dict, exploit_path: list[str], accounted: dict,
                first_block: int | None, last_block: int | None,
                budget_s: float = 90.0) -> tuple[list, list]:
    """Run every live invariant. Never hard-fails on a network problem."""
    if rpc is None:
        return [], [{
            "invariant": "live_checks_skipped",
            "detail": ("no RPC configured for this chain, so the live invariants "
                       "(incident_liveness, net_of_debt, drain_completeness) did not run. "
                       "The offline gate cannot tell you whether the incident is still "
                       "ongoing."),
        }]

    deadline = time.monotonic() + budget_s
    violations, warnings = [], []
    for fn, args in (
        # Ordered by value: liveness first, so a tight budget still answers the
        # question that matters most — is this still happening?
        (check_liveness, (rpc, labeled, exploit_path, accounted, last_block, deadline)),
        (check_drain_completeness, (rpc, labeled, accounted, first_block, last_block, 0.01, deadline)),
        (check_net_of_debt, (rpc, labeled, deadline)),
    ):
        try:
            v, w = fn(*args)
            violations += v
            warnings += w
        except Exception as e:  # a broken node must not fake either verdict
            warnings.append({
                "invariant": "live_checks_error",
                "detail": f"{fn.__name__} could not complete: {type(e).__name__}: {e}",
            })
    return violations, warnings
