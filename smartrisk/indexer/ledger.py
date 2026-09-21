from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55aebf1e8b5b"


@dataclass(frozen=True)
class TransferEvent:
    key: str
    chain_id: str
    token_address: str
    from_address: str
    to_address: str
    amount: int
    block_number: int
    block_hash: str
    transaction_hash: str
    log_index: int
    removed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class TransferLedger:
    """Canonical in-memory ERC-20 ledger; replayable from raw logs."""

    def __init__(self):
        self.events: dict[str, TransferEvent] = {}
        self.raw_logs: dict[str, dict[str, Any]] = {}
        self.removed_keys: set[str] = set()

    def ingest_logs(self, chain_id: str, logs: list[dict[str, Any]]) -> dict[str, int]:
        accepted = duplicate = removed = malformed = 0
        for log in logs:
            try:
                event = self.decode_transfer(chain_id, log)
            except ValueError:
                malformed += 1
                continue
            if event.removed:
                if event.key in self.events:
                    del self.events[event.key]
                self.removed_keys.add(event.key)
                self.raw_logs.pop(event.key, None)
                removed += 1
                continue
            if event.key in self.events:
                duplicate += 1
                continue
            self.events[event.key] = event
            self.raw_logs[event.key] = dict(log)
            accepted += 1
        return {"accepted": accepted, "duplicate": duplicate, "removed": removed, "malformed": malformed}

    def replay(self, chain_id: str, logs: list[dict[str, Any]]) -> dict[str, int]:
        self.events.clear()
        self.raw_logs.clear()
        self.removed_keys.clear()
        return self.ingest_logs(chain_id, logs)

    def holder_snapshot(self, token_address: str) -> dict[str, int]:
        balances: dict[str, int] = {}
        token_address = token_address.lower()
        for event in sorted(self.events.values(), key=lambda item: (item.block_number, item.log_index)):
            if event.token_address.lower() != token_address:
                continue
            if event.from_address != "0x" + "0" * 40:
                balances[event.from_address] = balances.get(event.from_address, 0) - event.amount
            if event.to_address != "0x" + "0" * 40:
                balances[event.to_address] = balances.get(event.to_address, 0) + event.amount
        return {address: amount for address, amount in balances.items() if amount != 0}

    @staticmethod
    def decode_transfer(chain_id: str, log: dict[str, Any]) -> TransferEvent:
        topics = log.get("topics") or []
        if len(topics) < 3 or str(topics[0]).lower() != TRANSFER_TOPIC:
            raise ValueError("not a canonical ERC-20 Transfer log")
        try:
            from_address = "0x" + str(topics[1])[-40:].lower()
            to_address = "0x" + str(topics[2])[-40:].lower()
            amount = int(str(log.get("data", "0x0")), 16)
            block_number = int(str(log["blockNumber"]), 16) if isinstance(log["blockNumber"], str) else int(log["blockNumber"])
            log_index = int(str(log["logIndex"]), 16) if isinstance(log["logIndex"], str) else int(log["logIndex"])
            block_hash = str(log["blockHash"])
            transaction_hash = str(log["transactionHash"])
            token_address = str(log["address"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"malformed Transfer log: {exc}") from exc
        key = f"{chain_id}:{block_hash}:{transaction_hash}:{log_index}"
        return TransferEvent(key, chain_id, token_address, from_address, to_address, amount, block_number, block_hash, transaction_hash, log_index, bool(log.get("removed", False)))
