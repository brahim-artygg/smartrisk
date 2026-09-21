from __future__ import annotations

from collections import defaultdict
from typing import Any

from .ledger import TransferEvent, TransferLedger


class LedgerAnalytics:
    def __init__(self, ledger: TransferLedger):
        self.ledger = ledger

    def holder_concentration(self, token_address: str, top_n: int = 10) -> float | None:
        balances = self.ledger.holder_snapshot(token_address)
        positive = sorted((value for value in balances.values() if value > 0), reverse=True)
        total = sum(positive)
        return sum(positive[:top_n]) / total if total else None

    def holder_churn(self, token_address: str, split_block: int) -> dict[str, Any]:
        before = self._balances(token_address, lambda event: event.block_number <= split_block)
        after = self._balances(token_address, lambda event: event.block_number > split_block)
        addresses = set(before) | set(after)
        changed = sum(1 for address in addresses if (before.get(address, 0) > 0) != (after.get(address, 0) > 0))
        return {"changed_holders": changed, "holder_count_before": sum(value > 0 for value in before.values()), "holder_count_after": sum(value > 0 for value in after.values())}

    def velocity(self, token_address: str, from_block: int, to_block: int) -> dict[str, Any]:
        events = [event for event in self.ledger.events.values() if event.token_address.lower() == token_address.lower() and from_block <= event.block_number <= to_block]
        volume = sum(event.amount for event in events)
        return {"transfer_count": len(events), "token_volume": volume, "blocks": max(1, to_block - from_block + 1), "volume_per_block": volume / max(1, to_block - from_block + 1)}

    def counterparty_graph(self, token_address: str) -> dict[str, set[str]]:
        graph: dict[str, set[str]] = defaultdict(set)
        for event in self.ledger.events.values():
            if event.token_address.lower() == token_address.lower():
                graph[event.from_address].add(event.to_address)
                graph[event.to_address].add(event.from_address)
        return dict(graph)

    def deployer_flows(self, token_address: str, deployer: str) -> dict[str, int]:
        inflow = outflow = 0
        for event in self.ledger.events.values():
            if event.token_address.lower() != token_address.lower():
                continue
            if event.to_address.lower() == deployer.lower():
                inflow += event.amount
            if event.from_address.lower() == deployer.lower():
                outflow += event.amount
        return {"deployer_inflow": inflow, "deployer_outflow": outflow, "net": inflow - outflow}

    def _balances(self, token_address: str, predicate) -> dict[str, int]:
        result: dict[str, int] = defaultdict(int)
        zero = "0x" + "0" * 40
        for event in sorted(self.ledger.events.values(), key=lambda item: (item.block_number, item.log_index)):
            if event.token_address.lower() != token_address.lower() or not predicate(event):
                continue
            if event.from_address != zero:
                result[event.from_address] -= event.amount
            if event.to_address != zero:
                result[event.to_address] += event.amount
        return dict(result)
