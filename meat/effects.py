from __future__ import annotations


EFFECT_TEMPLATES = {
    "deposit": "Deposit {amount} into the pool",
    "withdraw": "Withdraw {amount} from the pool",
    "transfer": "Transfer {value} to {to}",
    "approve": "Approve {spender} to spend tokens",
    "mint": "Mint {amount} (borrow against collateral)",
    "flashLoan": "Flash loan {amount} from the pool",
    "flashLoanSimple": "Flash loan {amount} of {asset}",
    "swap": "Swap tokens via the pool",
    "exchange": "Exchange tokens in the pool",
    "donateToReserves": "Donate {amount} to protocol reserves",
    "repay": "Repay {amount} of debt",
    "liquidate": "Liquidate underwater position",
    "transferFrom": "Transfer {value} from {from} to {to}",
    "balanceOf": "Check balance of {owner}",
    "add_liquidity": "Add liquidity to the pool",
    "remove_liquidity_one_coin": "Remove liquidity as single coin",
    "remove_liquidity": "Remove liquidity from the pool",
    "exactInputSingle": "Swap exact input amount via Uniswap V3",
    "executeOperation": "Execute flash loan callback",
    "onMorphoFlashLoan": "Execute Morpho flash loan callback",
    "burn": "Burn {amount} tokens",
    "totalSupply": "Query total token supply",
    "decimals": "Query token decimals",
    "dispatch": "Dispatch call to module",
    "getPrice": "Query price from oracle",
    "computeLiquidity": "Compute account liquidity",
    "requireLiquidity": "Verify account meets liquidity requirements",
    "checkLiquidation": "Check if position is liquidatable",
    "updateTotalAum": "Update total assets under management",
    "accountForPosition": "Re-value position at current prices",
    "getSharePrice": "Query share price from oracle",
}

AMOUNT_PARAM_NAMES = {
    "amount", "_amount", "amounts", "value", "_value",
    "assets", "shares", "wad", "rawAmount",
}

ADDRESS_PARAM_NAMES = {
    "to", "_to", "from", "_from", "sender", "_sender",
    "receiver", "_receiver", "recipient", "spender", "_spender",
    "owner", "_owner", "account", "holder", "asset",
}


def format_params_human(params: dict, token_decimals: dict | None = None) -> dict:
    if not params or not isinstance(params, dict):
        return params or {}
    formatted = {}
    amount_names = {n.lstrip("_").lower() for n in AMOUNT_PARAM_NAMES}
    for key, val in params.items():
        name = key.lstrip("_").lower()
        # Convert string numbers to int for formatting
        num_val = None
        if isinstance(val, int):
            num_val = val
        elif isinstance(val, str) and val.isdigit() and len(val) > 0:
            num_val = int(val)

        if num_val is not None:
            if name in amount_names and num_val > 10**15:
                formatted[key] = _format_big_int(num_val, 18)
            elif num_val > 10**12:
                formatted[key] = f"{num_val:,}"
            else:
                formatted[key] = str(num_val)
        elif isinstance(val, str) and val.startswith("0x") and len(val) == 42:
            formatted[key] = val
        elif isinstance(val, str) and len(val) > 100:
            formatted[key] = val[:66] + "..."
        elif isinstance(val, (list, tuple)):
            formatted[key] = str(val)[:200]
        else:
            formatted[key] = str(val) if val is not None else ""
    return formatted


def _format_big_int(val: int, decimals: int = 18) -> str:
    if decimals == 0:
        return f"{val:,}"
    whole = val // (10 ** decimals)
    frac = val % (10 ** decimals)
    frac_str = str(frac).zfill(decimals)[:4].rstrip("0") or "0"
    return f"{whole:,}.{frac_str}"


def format_effect(func_name: str, params: dict | None = None,
                  addr_labels: dict | None = None) -> str:
    template = EFFECT_TEMPLATES.get(func_name, "")
    if not template:
        return ""
    if not params:
        return template.replace("{", "").replace("}", "")

    labels = addr_labels or {}

    def _resolve(key: str) -> str:
        val = None
        for k in [key, f"_{key}", key.lower(), f"_{key.lower()}"]:
            if k in params:
                val = params[k]
                break
        if val is None:
            return key
        if isinstance(val, str) and val.startswith("0x") and len(val) == 42:
            return labels.get(val.lower(), val[:10] + "...")
        return str(val)

    import re
    result = re.sub(r"\{(\w+)\}", lambda m: _resolve(m.group(1)), template)
    return result
