from __future__ import annotations

from collections import defaultdict

from meat.explorer import ExplorerClient, ExplorerError


class FundFlowGraph:
    def __init__(self):
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []

    def add_node(self, address: str, label: str | None = None,
                 node_type: str = "unknown", **kwargs):
        addr = address.lower()
        if addr not in self.nodes:
            self.nodes[addr] = {"address": addr, "label": label, "type": node_type}
        if label:
            self.nodes[addr]["label"] = label
        if node_type != "unknown":
            self.nodes[addr]["type"] = node_type
        self.nodes[addr].update(kwargs)

    def add_edge(self, from_addr: str, to_addr: str, value: str,
                 token: str | None = None, tx_hash: str | None = None,
                 block: int | None = None, timestamp: str | None = None):
        self.edges.append({
            "from": from_addr.lower(),
            "to": to_addr.lower(),
            "value": value,
            "token": token,
            "tx_hash": tx_hash,
            "block": block,
            "timestamp": timestamp,
        })

    def to_dict(self) -> dict:
        return {
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
            "summary": self._summarize(),
        }

    def _summarize(self) -> dict:
        net_flows: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for edge in self.edges:
            token = edge.get("token", "ETH") or "ETH"
            try:
                val = int(edge["value"])
            except (ValueError, TypeError):
                continue
            net_flows[edge["from"]][token] -= val
            net_flows[edge["to"]][token] += val

        summary = {}
        for addr, tokens in net_flows.items():
            non_zero = {t: v for t, v in tokens.items() if v != 0}
            if non_zero:
                summary[addr] = {t: str(v) for t, v in non_zero.items()}
        return summary


def build_flow_graph(root_address: str, explorer: ExplorerClient, chain: str,
                     depth: int = 2, min_value_wei: int = 0,
                     start_block: int = 0, end_block: int = 99999999,
                     rpc=None) -> FundFlowGraph:
    from meat.classify import _load_known_addresses
    known = _load_known_addresses()

    if rpc and rpc.is_alchemy:
        return _build_flow_alchemy(root_address, rpc, known, depth,
                                   start_block, end_block)

    return _build_flow_explorer(root_address, explorer, known, depth,
                                start_block, end_block, min_value_wei)


def _build_flow_alchemy(root_address: str, rpc, known: dict,
                        depth: int, start_block: int, end_block: int) -> FundFlowGraph:
    """Single call per address via alchemy_getAssetTransfers — covers ETH + internal
    + ERC20 + ERC721 + ERC1155 with pre-enriched token metadata."""
    graph = FundFlowGraph()
    visited = set()
    queue = [(root_address.lower(), 0)]
    graph.add_node(root_address, node_type="root")

    from_blk = hex(start_block) if start_block else "0x0"
    to_blk = hex(end_block) if end_block < 99999999 else "latest"

    while queue:
        addr, current_depth = queue.pop(0)
        if addr in visited or current_depth >= depth:
            continue
        visited.add(addr)

        peers = set()

        for direction in ("from", "to"):
            try:
                kwargs = {"from_block": from_blk, "to_block": to_blk,
                          "max_count": "0xC8", "order": "asc"}
                if direction == "from":
                    kwargs["from_address"] = addr
                else:
                    kwargs["to_address"] = addr

                data = rpc.alchemy_get_asset_transfers(**kwargs)
            except Exception:
                continue

            if not data:
                continue

            for t in data.get("transfers", []):
                from_a = (t.get("from") or "").lower()
                to_a = (t.get("to") or "").lower()
                if not from_a or not to_a:
                    continue

                raw_value = t.get("rawContract", {}).get("value", "0x0")
                try:
                    raw_int = int(raw_value, 16) if isinstance(raw_value, str) and raw_value.startswith("0x") else int(raw_value or 0)
                except (ValueError, TypeError):
                    raw_int = 0

                asset = t.get("asset") or t.get("rawContract", {}).get("address", "ETH")
                block_num = t.get("blockNum", "0x0")
                try:
                    block_int = int(block_num, 16) if isinstance(block_num, str) else int(block_num or 0)
                except (ValueError, TypeError):
                    block_int = 0

                peer = to_a if direction == "from" else from_a
                _add_known_node(graph, peer, known)
                graph.add_edge(
                    from_a, to_a, value=str(raw_int),
                    token=asset, tx_hash=t.get("hash"),
                    block=block_int,
                    timestamp=t.get("metadata", {}).get("blockTimestamp"),
                )
                if peer not in visited:
                    peers.add(peer)

        for peer in peers:
            queue.append((peer, current_depth + 1))

    return graph


def _build_flow_explorer(root_address: str, explorer: ExplorerClient, known: dict,
                         depth: int, start_block: int, end_block: int,
                         min_value_wei: int) -> FundFlowGraph:
    """Build flow graph using Etherscan-compatible explorer API (3 calls per address)."""
    graph = FundFlowGraph()
    visited = set()
    queue = [(root_address.lower(), 0)]
    graph.add_node(root_address, node_type="root")

    while queue:
        addr, current_depth = queue.pop(0)
        if addr in visited or current_depth >= depth:
            continue
        visited.add(addr)

        try:
            txs = explorer.get_tx_list(addr, start_block=start_block,
                                       end_block=end_block, page=1, offset=100, sort="asc")
        except ExplorerError:
            continue

        for tx in txs:
            value_wei = int(tx.get("value", "0"))
            from_addr = tx.get("from", "").lower()
            to_addr = tx.get("to", "").lower()

            if not to_addr or value_wei < min_value_wei:
                continue

            if from_addr == addr and value_wei > 0:
                _add_known_node(graph, to_addr, known)
                graph.add_edge(from_addr, to_addr, value=str(value_wei), token="ETH",
                               tx_hash=tx.get("hash"), block=int(tx.get("blockNumber", 0)),
                               timestamp=tx.get("timeStamp"))
                if to_addr not in visited:
                    queue.append((to_addr, current_depth + 1))

        try:
            token_txs = explorer.get_token_transfers(
                address=addr, start_block=start_block, end_block=end_block,
                page=1, offset=100, sort="asc")
        except ExplorerError:
            continue

        per_tx_peers: dict[str, set] = defaultdict(set)

        for ttx in token_txs:
            from_addr_t = ttx.get("from", "").lower()
            to_addr_t = ttx.get("to", "").lower()
            token_name = ttx.get("tokenSymbol", "") or ttx.get("contractAddress", "")
            tx_h = ttx.get("hash", "")

            if from_addr_t == addr:
                _add_known_node(graph, to_addr_t, known)
                graph.add_edge(from_addr_t, to_addr_t, value=ttx.get("value", "0"),
                               token=token_name, tx_hash=tx_h,
                               block=int(ttx.get("blockNumber", 0)),
                               timestamp=ttx.get("timeStamp"))
                if to_addr_t not in visited:
                    per_tx_peers[tx_h].add(to_addr_t)

            elif to_addr_t == addr:
                _add_known_node(graph, from_addr_t, known)
                graph.add_edge(from_addr_t, to_addr_t, value=ttx.get("value", "0"),
                               token=token_name, tx_hash=tx_h,
                               block=int(ttx.get("blockNumber", 0)),
                               timestamp=ttx.get("timeStamp"))
                if from_addr_t not in visited:
                    per_tx_peers[tx_h].add(from_addr_t)

        for tx_h, peers in per_tx_peers.items():
            for peer in peers:
                if peer not in visited:
                    queue.append((peer, current_depth + 1))

    return graph


def _add_known_node(graph: FundFlowGraph, addr: str, known: dict):
    k = known.get(addr)
    node_type = k["category"] if k else "unknown"
    label = k["label"] if k else None
    graph.add_node(addr, label=label, node_type=node_type)
