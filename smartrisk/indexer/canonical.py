from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .ledger import TransferLedger


@dataclass
class CanonicalBlock:
    number: int
    block_hash: str
    parent_hash: str | None
    logs: list[dict[str, Any]] = field(default_factory=list)


class CanonicalChain:
    """Maintains a canonical block path and rebuilds the ledger on reorg."""

    def __init__(self, chain_id: str, ledger: TransferLedger | None = None):
        self.chain_id = chain_id
        self.ledger = ledger or TransferLedger()
        self.blocks: dict[str, CanonicalBlock] = {}
        self.head: str | None = None

    def ingest_block(self, block: CanonicalBlock) -> dict[str, Any]:
        self.blocks[block.block_hash] = block
        if self.head is None:
            self.head = block.block_hash
            return {"reorg": False, "head": self.head, "replayed": self.rebuild()}
        current = self.blocks[self.head]
        if block.parent_hash == self.head and block.number == current.number + 1:
            self.head = block.block_hash
            return {"reorg": False, "head": self.head, "replayed": self.rebuild()}
        if block.number < current.number:
            return {"reorg": False, "head": self.head, "ignored": True}
        ancestor = self._find_common_ancestor(block)
        if ancestor is None:
            raise ValueError("cannot find common ancestor for reorg")
        self.head = block.block_hash
        return {"reorg": True, "common_ancestor": ancestor, "head": self.head, "replayed": self.rebuild()}

    def rebuild(self) -> dict[str, int]:
        path: list[CanonicalBlock] = []
        cursor = self.head
        while cursor:
            block = self.blocks[cursor]
            path.append(block)
            cursor = block.parent_hash
        path.reverse()
        logs = [log for block in path for log in block.logs]
        return self.ledger.replay(self.chain_id, logs)

    def _find_common_ancestor(self, candidate: CanonicalBlock) -> str | None:
        current_hash = self.head
        candidate_hash = candidate.parent_hash
        ancestors = set()
        while current_hash:
            ancestors.add(current_hash)
            current = self.blocks.get(current_hash)
            current_hash = current.parent_hash if current else None
        while candidate_hash:
            if candidate_hash in ancestors:
                return candidate_hash
            current = self.blocks.get(candidate_hash)
            candidate_hash = current.parent_hash if current else None
        return None
