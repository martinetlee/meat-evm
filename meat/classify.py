from __future__ import annotations

import json
from pathlib import Path

from meat.rpc import RPCClient, RPCError
from meat.explorer import ExplorerClient, ExplorerError


ERC20_NAME_SIG = "0x06fdde03"
ERC20_SYMBOL_SIG = "0x95d89b41"
ERC20_DECIMALS_SIG = "0x313ce567"

OWNER_SIG = "0x8da5cb5b"  # owner()
ADMIN_SIG = "0xf851a440"  # admin()
DEFAULT_ADMIN_ROLE_SIG = "0xa217fddf"  # DEFAULT_ADMIN_ROLE()
GET_ROLE_ADMIN_SIG = "0x248a9ca3"  # getRoleAdmin(bytes32)
HAS_ROLE_SIG = "0x91d14854"  # hasRole(bytes32,address)
PAUSED_SIG = "0x5c975abb"  # paused() -> bool (OpenZeppelin Pausable)
GUARDIAN_SIG = "0x452a9320"  # guardian() -> address
BEACON_IMPL_SIG = "0x5c60da1b"  # implementation() -> address (UpgradeableBeacon)

# Substrings that mark a function as an emergency / kill / access-control switch.
# Curated to catch the levers a privileged holder would pull to stop an active
# incident, without dragging in unrelated business logic ("unlock" staking etc.).
_EMERGENCY_FN_KEYWORDS = (
    "pause", "unpause", "freeze", "unfreeze", "shutdown", "halt",
    "emergency", "guardian", "kill", "setpaused", "togglepause",
    "disabledeposit", "disablewithdraw", "stopmint", "blacklist",
    "revokerole", "renounceownership", "transferownership",
    "grantrole", "upgradeto", "setimplementation", "sweep",
)
SUPPORTS_INTERFACE_SIG = "0x01ffc9a7"  # supportsInterface(bytes4)

# Proxy storage slots
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
EIP1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
EIP1822_IMPL_SLOT = "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7"

# EIP-1167 minimal proxy bytecode prefix
MINIMAL_PROXY_PREFIX = "363d3d373d3d3d363d73"
MINIMAL_PROXY_SUFFIX = "5af43d82803e903d91602b57fd5bf3"

# Uniswap V2 pair interface
FACTORY_SIG = "0xc45a0155"  # factory()
TOKEN0_SIG = "0x0dfe1681"  # token0()
TOKEN1_SIG = "0xd21220a7"  # token1()

# AccessControl interface ID (ERC-165)
ACCESS_CONTROL_INTERFACE_ID = "0x7965db0b"

_known_addresses: dict | None = None


def _load_known_addresses() -> dict:
    global _known_addresses
    if _known_addresses is not None:
        return _known_addresses

    labels_file = Path(__file__).parent.parent / "labels" / "known_addresses.json"
    if labels_file.exists():
        try:
            raw = json.loads(labels_file.read_text())
            flat = {}
            for category, addrs in raw.items():
                if category.startswith("_"):
                    continue
                if isinstance(addrs, dict):
                    for addr, label in addrs.items():
                        if addr.startswith("_"):
                            continue
                        flat[addr.lower()] = {"label": label, "category": category}
            _known_addresses = flat
        except (json.JSONDecodeError, IOError):
            _known_addresses = {}
    else:
        _known_addresses = {}
    return _known_addresses


def classify_address(address: str, rpc: RPCClient | None = None,
                     explorer: ExplorerClient | None = None) -> dict:
    result = {
        "address": address,
        "type": "unknown",
        "is_contract": False,
        "is_token": False,
        "token_info": None,
        "is_proxy": False,
        "proxy_type": None,
        "implementation": None,
        "beacon": None,
        "is_verified": False,
        "labels": [],
        "known_entity": None,
        "admin_info": None,
        "is_lp_pair": False,
        "lp_info": None,
        "creation_tx": None,
        "balance_wei": None,
        "emergency_controls": None,
        "checks_performed": [],
    }

    checks = result["checks_performed"]

    known = _load_known_addresses()
    addr_lower = address.lower()
    if addr_lower in known:
        entry = known[addr_lower]
        result["known_entity"] = entry
        result["labels"].append(entry["label"])

    code = _get_code(address, rpc, explorer, checks)

    if code is None:
        result["type"] = "error"
        checks.append("get_code: FAILED (no RPC or explorer available)")
        return result

    if code == "0x" or code == "0x0" or len(code) <= 2:
        result["type"] = "eoa"
        _check_balance(result, address, explorer)
        return result

    result["type"] = "contract"
    result["is_contract"] = True

    if rpc:
        _check_erc20(result, address, rpc)
        checks.append(f"erc20: {'yes — ' + result['token_info']['symbol'] if result['is_token'] else 'no'}")
        _check_proxy_all(result, address, rpc, code)
        checks.append(f"proxy: {result['proxy_type'] or 'none detected'}")
        _check_admin(result, address, rpc)
        checks.append(f"admin: {list(result['admin_info'].keys()) if result.get('admin_info') else 'none detected'}")
        _check_lp_pair(result, address, rpc)
        if result["is_lp_pair"]:
            checks.append("lp_pair: yes")
    else:
        checks.append("erc20/proxy/admin/lp: SKIPPED (no RPC)")

    if explorer:
        _check_verified_and_proxy(result, address, explorer)
        checks.append(f"verified: {result['is_verified']}")
        _check_creation(result, address, explorer)
        _check_emergency_controls(result, address, rpc, explorer)
        if result.get("emergency_controls"):
            ec = result["emergency_controls"]
            checks.append(
                f"emergency_controls: {len(ec.get('functions', []))} fn(s), "
                f"paused={ec.get('paused')}"
            )
    else:
        checks.append("verified/creation: SKIPPED (no explorer)")

    _check_balance(result, address, explorer)

    if rpc and rpc.is_alchemy:
        _check_token_balances_alchemy(result, address, rpc)
        checks.append("token_balances: via Alchemy")

    return result


def _get_code(address: str, rpc: RPCClient | None, explorer: ExplorerClient | None,
              checks: list | None = None) -> str | None:
    if rpc:
        try:
            code = rpc.get_code(address)
            if checks is not None:
                checks.append("get_code: via RPC")
            return code
        except RPCError as e:
            if checks is not None:
                checks.append(f"get_code: RPC failed ({e})")
    if explorer:
        try:
            code = explorer.proxy_get_code(address)
            if checks is not None:
                checks.append("get_code: via explorer proxy")
            return code
        except ExplorerError as e:
            if checks is not None:
                checks.append(f"get_code: explorer failed ({e})")
    return None


def _check_erc20(result: dict, address: str, rpc: RPCClient):
    try:
        name_hex = rpc.eth_call({"to": address, "data": ERC20_NAME_SIG})
        symbol_hex = rpc.eth_call({"to": address, "data": ERC20_SYMBOL_SIG})
        decimals_hex = rpc.eth_call({"to": address, "data": ERC20_DECIMALS_SIG})

        if name_hex and name_hex != "0x" and symbol_hex and symbol_hex != "0x":
            result["is_token"] = True
            result["token_info"] = {
                "name": _decode_string(name_hex),
                "symbol": _decode_string(symbol_hex),
                "decimals": int(decimals_hex, 16) if decimals_hex and decimals_hex != "0x" else 18,
            }
    except (RPCError, ValueError, Exception):
        pass


def _check_proxy_all(result: dict, address: str, rpc: RPCClient, code: str):
    code_hex = code[2:].lower() if code.startswith("0x") else code.lower()

    # EIP-1167 minimal proxy: check bytecode pattern
    if code_hex.startswith(MINIMAL_PROXY_PREFIX):
        impl_hex = code_hex[len(MINIMAL_PROXY_PREFIX):len(MINIMAL_PROXY_PREFIX) + 40]
        if len(impl_hex) == 40:
            result["is_proxy"] = True
            result["proxy_type"] = "EIP-1167 minimal proxy"
            result["implementation"] = "0x" + impl_hex
            return

    # EIP-1967 implementation slot (covers TransparentUpgradeableProxy + UUPS)
    try:
        impl_raw = rpc.get_storage_at(address, EIP1967_IMPL_SLOT)
        if _is_nonzero_address(impl_raw):
            result["is_proxy"] = True
            result["implementation"] = "0x" + impl_raw[-40:]

            admin_raw = rpc.get_storage_at(address, EIP1967_ADMIN_SLOT)
            if _is_nonzero_address(admin_raw):
                result["proxy_type"] = "EIP-1967 transparent proxy"
                if result["admin_info"] is None:
                    result["admin_info"] = {}
                result["admin_info"]["proxy_admin"] = "0x" + admin_raw[-40:]
            else:
                result["proxy_type"] = "EIP-1967 (likely UUPS)"
            return
    except RPCError:
        pass

    # EIP-1967 beacon slot
    try:
        beacon_raw = rpc.get_storage_at(address, EIP1967_BEACON_SLOT)
        if _is_nonzero_address(beacon_raw):
            beacon_addr = "0x" + beacon_raw[-40:]
            result["is_proxy"] = True
            result["proxy_type"] = "EIP-1967 beacon proxy"
            result["beacon"] = beacon_addr
            # The slot holds the *beacon*, not the logic. Resolve one more hop via
            # the beacon's implementation() so `implementation` is the actual code
            # (where pause/emergency levers live); fall back to the beacon address.
            logic = None
            try:
                logic_hex = rpc.eth_call({"to": beacon_addr, "data": BEACON_IMPL_SIG})
                if logic_hex and logic_hex != "0x" and _is_nonzero_address(logic_hex):
                    logic = "0x" + logic_hex[-40:]
            except (RPCError, ValueError, Exception):
                pass
            result["implementation"] = logic or beacon_addr
            return
    except RPCError:
        pass

    # EIP-1822 UUPS (older slot)
    try:
        impl_raw = rpc.get_storage_at(address, EIP1822_IMPL_SLOT)
        if _is_nonzero_address(impl_raw):
            result["is_proxy"] = True
            result["proxy_type"] = "EIP-1822 UUPS"
            result["implementation"] = "0x" + impl_raw[-40:]
            return
    except RPCError:
        pass

    # EIP-2535 Diamond: check if it implements diamondCut interface
    # Diamond interface ID: 0x48e2b093
    try:
        resp = rpc.eth_call({"to": address, "data": SUPPORTS_INTERFACE_SIG + "48e2b093" + "0" * 56})
        if resp and len(resp) >= 66 and resp[-1] == "1":
            result["is_proxy"] = True
            result["proxy_type"] = "EIP-2535 diamond"
            return
    except (RPCError, Exception):
        pass


def _check_admin(result: dict, address: str, rpc: RPCClient):
    admin_info = result.get("admin_info") or {}

    # Check Ownable: owner()
    try:
        owner_hex = rpc.eth_call({"to": address, "data": OWNER_SIG})
        if owner_hex and owner_hex != "0x" and _is_nonzero_address(owner_hex):
            admin_info["owner"] = "0x" + owner_hex[-40:]
    except (RPCError, Exception):
        pass

    # Check admin()
    try:
        admin_hex = rpc.eth_call({"to": address, "data": ADMIN_SIG})
        if admin_hex and admin_hex != "0x" and _is_nonzero_address(admin_hex):
            admin_info["admin"] = "0x" + admin_hex[-40:]
    except (RPCError, Exception):
        pass

    # Check AccessControl: supportsInterface(0x7965db0b)
    has_access_control = False
    try:
        resp = rpc.eth_call({
            "to": address,
            "data": SUPPORTS_INTERFACE_SIG + ACCESS_CONTROL_INTERFACE_ID[2:] + "0" * 56
        })
        if resp and len(resp) >= 66 and resp[-1] == "1":
            has_access_control = True
    except (RPCError, Exception):
        pass

    if has_access_control:
        admin_info["access_control"] = True

        # Get DEFAULT_ADMIN_ROLE (should be 0x00)
        try:
            role_hex = rpc.eth_call({"to": address, "data": DEFAULT_ADMIN_ROLE_SIG})
            default_role = role_hex if role_hex else "0x" + "0" * 64
            admin_info["default_admin_role"] = default_role

            # Check who has the default admin role — try common admin addresses
            # We can't enumerate all holders without events, but we can check known addresses
            admin_info["note"] = "Use `meat logs --event 'RoleGranted(bytes32,address,address)' --address <contract> --chain <chain>` to find all role holders"
        except (RPCError, Exception):
            pass

    if admin_info:
        result["admin_info"] = admin_info


def _check_lp_pair(result: dict, address: str, rpc: RPCClient):
    try:
        factory_hex = rpc.eth_call({"to": address, "data": FACTORY_SIG})
        token0_hex = rpc.eth_call({"to": address, "data": TOKEN0_SIG})
        token1_hex = rpc.eth_call({"to": address, "data": TOKEN1_SIG})

        if (factory_hex and _is_nonzero_address(factory_hex) and
                token0_hex and _is_nonzero_address(token0_hex) and
                token1_hex and _is_nonzero_address(token1_hex)):
            result["is_lp_pair"] = True
            result["lp_info"] = {
                "factory": "0x" + factory_hex[-40:],
                "token0": "0x" + token0_hex[-40:],
                "token1": "0x" + token1_hex[-40:],
            }
    except (RPCError, Exception):
        pass


def _check_verified_and_proxy(result: dict, address: str, explorer: ExplorerClient):
    try:
        source = explorer.get_source_code(address)
        if not source:
            return
        if source.get("SourceCode"):
            result["is_verified"] = True
            contract_name = source.get("ContractName", "")
            if contract_name:
                result["labels"].append(contract_name)
        if not result["is_proxy"] and source.get("Proxy") == "1" and source.get("Implementation"):
            result["is_proxy"] = True
            result["proxy_type"] = result.get("proxy_type") or "explorer-detected"
            result["implementation"] = source["Implementation"]
    except ExplorerError:
        pass


def _check_creation(result: dict, address: str, explorer: ExplorerClient):
    try:
        creation = explorer.get_contract_creation([address])
        if creation:
            result["creation_tx"] = creation[0].get("txHash")
    except ExplorerError:
        pass


def _check_emergency_controls(result: dict, address: str, rpc: RPCClient | None,
                              explorer: ExplorerClient):
    """Detect the emergency / access-control levers this contract exposes and,
    when possible, whether it is currently paused. Serves the containment
    question 'can this be stopped, and is the vulnerable path still live?'.

    Reads the verified ABI (function *names* — robust to setPaused/togglePause
    variants that a fixed selector list would miss) and, if RPC is available,
    calls paused() for the live state. Additive + best-effort; never raises.

    Proxies are the common case: the proxy's own ABI only exposes upgrade
    plumbing, while the real pause/emergencyWithdraw/vulnerable entrypoints live
    on the **implementation**. So when this contract is a proxy we also fetch and
    scan the implementation ABI, tagging each function with its `source`."""
    ec: dict = {}
    fns: list[dict] = []
    abi_sources: list[str] = []

    # The proxy's own ABI, then the implementation's (where the logic lives), and
    # for a beacon proxy also the beacon itself (its upgradeTo is a containment
    # lever that repoints every proxy behind it at patched logic).
    scan_targets = [(address, "proxy" if result.get("is_proxy") else "self")]
    impl = result.get("implementation")
    if result.get("is_proxy") and impl and _is_nonzero_address(impl):
        scan_targets.append((impl, "implementation"))
    beacon = result.get("beacon")
    if beacon and _is_nonzero_address(beacon) and beacon.lower() != (impl or "").lower():
        scan_targets.append((beacon, "beacon"))

    for target_addr, source in scan_targets:
        try:
            abi_json = explorer.get_abi(target_addr)
        except (ExplorerError, Exception):
            abi_json = None
        if not abi_json:
            # Unverified / unreadable ABI. For the implementation this is
            # actionable: the levers exist but we can't enumerate them.
            if source == "implementation":
                ec["implementation_abi_unverified"] = True
            continue
        try:
            abi = json.loads(abi_json)
        except (json.JSONDecodeError, TypeError):
            continue
        abi_sources.append(f"{source}:{target_addr.lower()}")
        for item in abi:
            if item.get("type") != "function":
                continue
            name = item.get("name", "")
            low = name.lower()
            if any(kw in low for kw in _EMERGENCY_FN_KEYWORDS):
                fns.append({
                    "name": name,
                    "inputs": [i.get("type", "") for i in item.get("inputs", [])],
                    "stateMutability": item.get("stateMutability", ""),
                    "source": source,
                })

    if fns:
        ec["functions"] = fns
    if abi_sources:
        ec["abi_sources"] = abi_sources

    # Live paused() state — call on `address` (resolves through delegatecall for
    # a proxy). Only meaningful when the switch exists.
    if rpc:
        try:
            paused_hex = rpc.eth_call({"to": address, "data": PAUSED_SIG})
            if paused_hex and paused_hex != "0x":
                ec["paused"] = int(paused_hex, 16) != 0
        except (RPCError, ValueError, Exception):
            pass
        try:
            guardian_hex = rpc.eth_call({"to": address, "data": GUARDIAN_SIG})
            if guardian_hex and guardian_hex != "0x" and _is_nonzero_address(guardian_hex):
                ec["guardian"] = "0x" + guardian_hex[-40:]
        except (RPCError, ValueError, Exception):
            pass

    if ec:
        result["emergency_controls"] = ec


def _check_balance(result: dict, address: str, explorer: ExplorerClient | None):
    if not explorer:
        return
    try:
        balance = explorer.get_balance(address)
        result["balance_wei"] = str(balance)
        from meat.decode import format_value
        result["balance_formatted"] = format_value(balance, 18) + " ETH"
    except ExplorerError:
        pass


def _check_token_balances_alchemy(result: dict, address: str, rpc: RPCClient):
    try:
        data = rpc.alchemy_get_token_balances(address)
        if not data:
            return
        balances = data.get("tokenBalances", [])
        non_zero = []
        for b in balances:
            bal = b.get("tokenBalance", "0x0")
            if bal and bal != "0x0" and bal != "0x" and int(bal, 16) > 0:
                non_zero.append({
                    "token_address": b.get("contractAddress", ""),
                    "balance_raw": str(int(bal, 16)),
                })
        if non_zero:
            result["token_balances"] = non_zero[:50]
    except (RPCError, ValueError, Exception):
        pass


def _is_nonzero_address(hex_val: str) -> bool:
    if not hex_val or hex_val == "0x":
        return False
    stripped = hex_val.replace("0x", "").lstrip("0")
    return len(stripped) > 0


def _decode_string(hex_data: str) -> str:
    if not hex_data or hex_data == "0x":
        return ""
    try:
        raw = bytes.fromhex(hex_data[2:])
        if len(raw) >= 64:
            length = int.from_bytes(raw[32:64], "big")
            if 0 < length < len(raw) - 64 + 1:
                return raw[64:64 + length].decode("utf-8", errors="replace").strip("\x00")
        decoded = raw.rstrip(b"\x00").decode("utf-8", errors="replace").strip()
        if decoded and all(c.isprintable() or c.isspace() for c in decoded):
            return decoded
    except Exception:
        pass
    return hex_data[:20] + "..."
