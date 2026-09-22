from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field, replace
from typing import Any, Mapping

from .dex_discovery import DexPair
from .models import SimulationScenario
from ..core.keccak import ethereum_selector
from ..core.networks import try_get_network

UINT256_MAX = (1 << 256) - 1


@dataclass(frozen=True)
class DexRouteConfig:
    """Explicit local router knowledge; no external router registry is queried."""

    chain_id: str
    dex_id: str
    router_address: str
    wrapped_native: str
    style: str = "uniswap-v2"
    supports_fee_on_transfer: bool = True
    native_in: bool = True
    native_out: bool = True
    native_asset_is_erc20: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TradeExecutionPlan:
    token_address: str
    pair: DexPair
    route: DexRouteConfig | None
    executable: bool
    reason: str | None = None
    buy: SimulationScenario | None = None
    approve: SimulationScenario | None = None
    pre_buy_approve: SimulationScenario | None = None
    sell_templates: dict[str, dict[str, Any]] = field(default_factory=dict)
    scenarios: list[SimulationScenario] = field(default_factory=list)

    @property
    def sell_template(self) -> dict[str, Any] | None:
        return self.sell_templates.get("sell_all") or self.sell_templates.get("baseline")

    def to_dict(self) -> dict[str, Any]:
        return {
            "token_address": self.token_address,
            "pair": self.pair.to_dict(),
            "route": self.route.to_dict() if self.route else None,
            "executable": self.executable,
            "reason": self.reason,
            "buy": self.buy.to_dict() if self.buy else None,
            "approve": self.approve.to_dict() if self.approve else None,
            "pre_buy_approve": self.pre_buy_approve.to_dict() if self.pre_buy_approve else None,
            "sell_templates": self.sell_templates,
            "scenarios": [scenario.to_dict() for scenario in self.scenarios],
        }


class DexRouteRegistry:
    def __init__(self, routes: list[DexRouteConfig] | None = None, include_defaults: bool = True):
        self._routes: dict[tuple[str, str], DexRouteConfig] = {}
        if include_defaults:
            for route in default_uniswap_v2_routes():
                self.register(route)
        for route in routes or []:
            self.register(route)

    def register(self, route: DexRouteConfig) -> None:
        _validate_address(route.router_address, "router_address")
        _validate_address(route.wrapped_native, "wrapped_native")
        profile = try_get_network(route.chain_id)
        normalized = replace(route, chain_id=profile.chain_id if profile else route.chain_id.lower())
        self._routes[(normalized.chain_id, normalized.dex_id.lower())] = normalized

    def resolve(self, chain_id: str, dex_id: str) -> DexRouteConfig | None:
        profile = try_get_network(chain_id)
        canonical = profile.chain_id if profile else str(chain_id).lower()
        return self._routes.get((canonical, dex_id.lower()))

    @classmethod
    def from_env(cls, env_var: str = "SMARTRISK_DEX_ROUTES") -> "DexRouteRegistry":
        raw = os.getenv(env_var)
        if not raw:
            return cls()
        payload = json.loads(raw)
        items = payload.get("routes", payload) if isinstance(payload, dict) else payload
        if not isinstance(items, list):
            raise ValueError(f"{env_var} must contain a JSON array or {{\"routes\": [...]}}")
        return cls([DexRouteConfig(**item) for item in items], include_defaults=True)

    def to_dict(self) -> list[dict[str, Any]]:
        return [route.to_dict() for route in self._routes.values()]


def default_uniswap_v2_routes() -> list[DexRouteConfig]:
    """Built-in, local protocol deployment knowledge; no runtime provider lookup.

    Addresses are pinned from official Uniswap v2 deployment documentation.
    Unsupported chains/DEX ids remain explicitly unknown.
    """
    return [
        # Ethereum
        DexRouteConfig("1", "uniswap", "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "uniswap-v2"),
        DexRouteConfig("1", "sushiswap", "0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F", "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "sushiswap-v2"),
        # BNB Smart Chain
        DexRouteConfig("56", "pancakeswap", "0x10ED43C718714eb63d5aA57B78B54704E256024E", "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c", "pancakeswap-v2"),
        DexRouteConfig("56", "uniswap", "0x4752ba5dbc23f44d87826276bf6fd6b1c372ad24", "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c", "uniswap-v2"),
        DexRouteConfig("56", "sushiswap", "0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506", "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c", "sushiswap-v2"),
        # Base
        DexRouteConfig("8453", "uniswap", "0x4752ba5dbc23f44d87826276bf6fd6b1c372ad24", "0x4200000000000000000000000000000000000006", "uniswap-v2"),
        DexRouteConfig("8453", "sushiswap", "0x6BDED42c6DA8FBf0d2bA55B2fa120C5e0c8D7891", "0x4200000000000000000000000000000000000006", "sushiswap-v2"),
        # Arbitrum One
        DexRouteConfig("42161", "uniswap", "0x4752ba5dbc23f44d87826276bf6fd6b1c372ad24", "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1", "uniswap-v2"),
        DexRouteConfig("42161", "sushiswap", "0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506", "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1", "sushiswap-v2"),
        # Polygon
        DexRouteConfig("137", "uniswap", "0xedf6066a2b290C185783862C7F4776A2C8077AD1", "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270", "uniswap-v2"),
        DexRouteConfig("137", "sushiswap", "0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506", "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270", "sushiswap-v2"),
        # Optimism
        DexRouteConfig("10", "uniswap", "0x4A7b5Da61326A6379179b40d00F57E5bbDC962c2", "0x4200000000000000000000000000000000000006", "uniswap-v2"),
        # Avalanche C-Chain
        DexRouteConfig("43114", "uniswap", "0x4752ba5dbc23f44d87826276bf6fd6b1c372ad24", "0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7", "uniswap-v2"),
        DexRouteConfig("43114", "traderjoe", "0x60aE616a2155Ee3d9A68541Ba4544862310933d4", "0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7", "uniswap-v2"),
        DexRouteConfig("43114", "sushiswap", "0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506", "0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7", "sushiswap-v2"),
        # Gnosis
        DexRouteConfig("100", "sushiswap", "0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506", "0x6A023CCD1ff6F2045C3309768eAd9E68F978f6e1", "sushiswap-v2"),
        DexRouteConfig("100", "honeyswap", "0x1C232F01118CB8B424793ae03F870aa7D0ac7f77", "0x6A023CCD1ff6F2045C3309768eAd9E68F978f6e1", "uniswap-v2"),
        # Celo — CELO is an ERC-20/native asset; the route remains V2-compatible.
        DexRouteConfig(
            "42220",
            "sushiswap",
            "0x1421bDe4B10e8dd459b3BCb598810B1337D56842",
            "0x471EcE3750Da237f93B8E339c536989b8978a438",
            "celo-sushiswap-v2",
            native_in=False,
            native_out=False,
            native_asset_is_erc20=True,
        ),
        # Unichain
        DexRouteConfig("130", "uniswap", "0x284f11109359a7e1306c3e447ef14d38400063ff", "0x4200000000000000000000000000000000000006", "uniswap-v2"),
    ]


class UniswapV2ScenarioBuilder:
    """Builds auditable native buy -> approve -> dynamic sell plans.

    Actual sell amount is deliberately left dynamic: the executor uses the
    observed buy token delta instead of guessing an output amount.
    """

    def __init__(self, registry: DexRouteRegistry | None = None):
        self.registry = registry or DexRouteRegistry.from_env()

    def build_native_plan(
        self,
        pair: DexPair,
        token_address: str,
        trader: str,
        buy_amount_wei: int,
        deadline: int,
    ) -> TradeExecutionPlan:
        route = self.registry.resolve(pair.chain_id, pair.dex_id)
        if route is None:
            return TradeExecutionPlan(token_address, pair, None, False, "no local router configuration for this chain/dex")
        if route.style.lower() in {"celo-sushiswap-v2"}:
            return self._build_erc20_native_plan(pair, token_address, trader, buy_amount_wei, deadline, route)
        if route.style.lower() not in {"uniswap-v2", "pancakeswap-v2", "sushiswap-v2"}:
            return TradeExecutionPlan(token_address, pair, route, False, f"unsupported route style: {route.style}")
        if not route.native_in or not route.native_out:
            return TradeExecutionPlan(token_address, pair, route, False, "route does not support native input/output")
        if buy_amount_wei <= 0:
            return TradeExecutionPlan(token_address, pair, route, False, "buy amount must be positive")
        if pair.token_side(token_address) is None:
            return TradeExecutionPlan(token_address, pair, route, False, "target token is not part of selected pair")
        if pair.base_address.lower() != route.wrapped_native.lower() and (pair.quote_address or "").lower() != route.wrapped_native.lower():
            return TradeExecutionPlan(token_address, pair, route, False, "selected pair is not a wrapped-native route")

        path = [route.wrapped_native, token_address]
        buy_data = encode_swap_exact_eth_for_tokens_native(path, trader, deadline)
        buy = SimulationScenario(
            scenario_id="trade:buy:native-v2",
            from_address=trader,
            to_address=route.router_address,
            data=buy_data,
            value_wei=buy_amount_wei,
            gas_limit=900_000,
            description=f"native buy on {pair.dex_id} {pair.pair_address}",
            observed_tokens=(token_address, route.wrapped_native),
            observed_pairs=(pair.pair_address,),
            category="trading",
            risk_tags=("trading", "buy", "honeypot"),
        )
        approve = SimulationScenario(
            scenario_id="trade:approve:router",
            from_address=trader,
            to_address=token_address,
            data=encode_approve(route.router_address, UINT256_MAX),
            gas_limit=150_000,
            description="approve router to spend bought token",
            observed_tokens=(token_address,),
            observed_pairs=(pair.pair_address,),
            category="token_transfer",
            risk_tags=("approve", "honeypot"),
        )
        sell_templates = {
            "baseline": self._sell_template(pair, token_address, trader, path, deadline, 10_000),
            "micro_sell": self._sell_template(pair, token_address, trader, path, deadline, 1_000),
            "small_sell": self._sell_template(pair, token_address, trader, path, deadline, 2_500),
            "partial_sell": self._sell_template(pair, token_address, trader, path, deadline, 5_000),
            "sell_all": self._sell_template(pair, token_address, trader, path, deadline, 10_000),
            "transfer": {"method": "transfer", "token": token_address, "recipient": pair.pair_address, "trader": trader, "amount_in": "BUY_TOKEN_DELTA"},
        }
        return TradeExecutionPlan(
            token_address,
            pair,
            route,
            True,
            buy=buy,
            approve=approve,
            sell_templates=sell_templates,
            scenarios=[buy, approve],
        )

    def _build_erc20_native_plan(
        self,
        pair: DexPair,
        token_address: str,
        trader: str,
        buy_amount_wei: int,
        deadline: int,
        route: DexRouteConfig,
    ) -> TradeExecutionPlan:
        if not route.native_asset_is_erc20:
            return TradeExecutionPlan(token_address, pair, route, False, "route is not marked as an ERC-20 native-asset route")
        if buy_amount_wei <= 0:
            return TradeExecutionPlan(token_address, pair, route, False, "buy amount must be positive")
        if pair.token_side(token_address) is None:
            return TradeExecutionPlan(token_address, pair, route, False, "target token is not part of selected pair")
        if pair.base_address.lower() != route.wrapped_native.lower() and (pair.quote_address or "").lower() != route.wrapped_native.lower():
            return TradeExecutionPlan(token_address, pair, route, False, "selected pair is not an ERC-20 native-asset route")

        path = [route.wrapped_native, token_address]
        pre_buy_approve = SimulationScenario(
            scenario_id="trade:approve:native-asset",
            from_address=trader,
            to_address=route.wrapped_native,
            data=encode_approve(route.router_address, UINT256_MAX),
            gas_limit=150_000,
            description="approve router to spend ERC-20 native asset before buy",
            observed_tokens=(route.wrapped_native,),
            observed_allowances=((route.wrapped_native, route.router_address),),
            observed_pairs=(pair.pair_address,),
            category="token_transfer",
            risk_tags=("approve", "buy", "honeypot"),
        )
        buy = SimulationScenario(
            scenario_id="trade:buy:erc20-native-v2",
            from_address=trader,
            to_address=route.router_address,
            data=encode_swap_exact_tokens_for_tokens(buy_amount_wei, path, trader, deadline),
            value_wei=0,
            gas_limit=900_000,
            description=f"ERC-20 native-asset buy on {pair.dex_id} {pair.pair_address}",
            observed_tokens=(token_address, route.wrapped_native),
            observed_allowances=((route.wrapped_native, route.router_address),),
            observed_pairs=(pair.pair_address,),
            category="trading",
            risk_tags=("trading", "buy", "honeypot"),
        )
        approve = SimulationScenario(
            scenario_id="trade:approve:router",
            from_address=trader,
            to_address=token_address,
            data=encode_approve(route.router_address, UINT256_MAX),
            gas_limit=150_000,
            description="approve router to spend bought token",
            observed_tokens=(token_address,),
            observed_allowances=((token_address, route.router_address),),
            observed_pairs=(pair.pair_address,),
            category="token_transfer",
            risk_tags=("approve", "honeypot"),
        )
        sell_templates = {
            "baseline": self._sell_template(pair, token_address, trader, path, deadline, 10_000, erc20_output=True),
            "micro_sell": self._sell_template(pair, token_address, trader, path, deadline, 1_000, erc20_output=True),
            "small_sell": self._sell_template(pair, token_address, trader, path, deadline, 2_500, erc20_output=True),
            "partial_sell": self._sell_template(pair, token_address, trader, path, deadline, 5_000, erc20_output=True),
            "sell_all": self._sell_template(pair, token_address, trader, path, deadline, 10_000, erc20_output=True),
            "transfer": {"method": "transfer", "token": token_address, "recipient": pair.pair_address, "trader": trader, "amount_in": "BUY_TOKEN_DELTA"},
        }
        return TradeExecutionPlan(
            token_address,
            pair,
            route,
            True,
            buy=buy,
            approve=approve,
            pre_buy_approve=pre_buy_approve,
            sell_templates=sell_templates,
            scenarios=[pre_buy_approve, buy, approve],
        )

    @staticmethod
    def _sell_template(pair: DexPair, token_address: str, trader: str, path: list[str], deadline: int, fraction_bps: int, erc20_output: bool = False) -> dict[str, Any]:
        return {
            "method": "swapExactTokensForTokensSupportingFeeOnTransferTokens" if erc20_output else "swapExactTokensForETHSupportingFeeOnTransferTokens",
            "router": None,
            "pair": pair.pair_address,
            "token": token_address,
            "path": list(reversed(path)),
            "trader": trader,
            "deadline": deadline,
            "amount_in": "BUY_TOKEN_DELTA",
            "fraction_bps": fraction_bps,
            "amount_out_min": 0,
        }



def encode_approve(spender: str, amount: int) -> str:
    return encode_static_call("approve(address,uint256)", [_address_word(spender), _uint_word(amount)])


def encode_swap_exact_eth_for_tokens_native(path: list[str], recipient: str, deadline: int) -> str:
    selector = ethereum_selector("swapExactETHForTokensSupportingFeeOnTransferTokens(uint256,address[],address,uint256)")
    head = b"".join([
        (0).to_bytes(32, "big"),
        (128).to_bytes(32, "big"),
        bytes.fromhex(_address_word(recipient)),
        _uint_word_bytes(deadline),
    ])
    return "0x" + selector + (head + _encode_dynamic_address_array(path)).hex()


def encode_swap_exact_tokens_for_eth(token_amount: int, path: list[str], recipient: str, deadline: int) -> str:
    selector = ethereum_selector("swapExactTokensForETHSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)")
    return _encode_v2_five_arg(selector, [
        _uint_word_bytes(token_amount),
        _uint_word_bytes(0),
        _encode_dynamic_address_array(path),
        bytes.fromhex(_address_word(recipient)),
        _uint_word_bytes(deadline),
    ])


def encode_swap_exact_tokens_for_tokens(token_amount: int, path: list[str], recipient: str, deadline: int) -> str:
    selector = ethereum_selector("swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)")
    return _encode_v2_five_arg(selector, [
        _uint_word_bytes(token_amount),
        _uint_word_bytes(0),
        _encode_dynamic_address_array(path),
        bytes.fromhex(_address_word(recipient)),
        _uint_word_bytes(deadline),
    ])


def encode_sell_from_template(template: Mapping[str, Any], amount_in: int) -> str:
    fraction_bps = int(template.get("fraction_bps", 10_000))
    effective_amount = amount_in * fraction_bps // 10_000
    if effective_amount <= 0:
        raise ValueError("dynamic sell amount rounded to zero")
    path = list(template["path"])
    if str(template.get("method")) == "swapExactTokensForTokensSupportingFeeOnTransferTokens":
        return encode_swap_exact_tokens_for_tokens(effective_amount, path, str(template["trader"]), int(template["deadline"]))
    return encode_swap_exact_tokens_for_eth(effective_amount, path, str(template["trader"]), int(template["deadline"]))


def scenario_from_sell_template(template: Mapping[str, Any], amount_in: int, route_address: str, pair_address: str, mode: str | None = None) -> SimulationScenario:
    amount = amount_in * int(template.get("fraction_bps", 10_000)) // 10_000
    if amount <= 0:
        raise ValueError("dynamic sell amount rounded to zero")
    method = str(template.get("method"))
    data = (
        encode_swap_exact_tokens_for_tokens(amount, list(template["path"]), str(template["trader"]), int(template["deadline"]))
        if method == "swapExactTokensForTokensSupportingFeeOnTransferTokens"
        else encode_swap_exact_tokens_for_eth(amount, list(template["path"]), str(template["trader"]), int(template["deadline"]))
    )
    return SimulationScenario(
        scenario_id=f"trade:sell:{mode or ('partial' if int(template.get('fraction_bps', 10000)) < 10000 else 'all')}",
        from_address=str(template["trader"]),
        to_address=route_address,
        data=data,
        gas_limit=900_000,
        description=f"dynamic sell amount={amount}",
        observed_tokens=(str(template["token"]), str(template["path"][-1])),
        observed_pairs=(pair_address,),
        category="trading",
        risk_tags=("trading", "sell", "honeypot"),
    )



def scenario_from_transfer_template(template: Mapping[str, Any], amount_in: int, pair_address: str) -> SimulationScenario:
    if amount_in <= 0:
        raise ValueError("dynamic transfer amount must be positive")
    return SimulationScenario(
        scenario_id="trade:transfer:only",
        from_address=str(template["trader"]),
        to_address=str(template["token"]),
        data=encode_static_call("transfer(address,uint256)", [_address_word(pair_address), _uint_word(amount_in)]),
        gas_limit=250_000,
        description=f"direct token transfer amount={amount_in}",
        observed_tokens=(str(template["token"]),),
        observed_pairs=(pair_address,),
        category="token_transfer",
        risk_tags=("transfer_only", "honeypot"),
    )

def encode_static_call(signature: str, words: list[str]) -> str:
    return "0x" + ethereum_selector(signature) + "".join(words)


def _encode_v2_five_arg(selector: str, args: list[bytes]) -> str:
    if len(args) != 5 or not any(len(value) != 32 for value in args):
        raise ValueError("V2 five-argument encoding expects exactly one dynamic argument")
    dynamic_index = next(i for i, value in enumerate(args) if len(value) != 32)
    head_size = 32 * len(args)
    dynamic_value = args[dynamic_index]
    head: list[bytes] = []
    for index, value in enumerate(args):
        head.append(head_size.to_bytes(32, "big") if index == dynamic_index else value)
    return "0x" + selector + b"".join(head + [dynamic_value]).hex()


def _encode_dynamic_address_array(addresses: list[str]) -> bytes:
    if len(addresses) < 2:
        raise ValueError("V2 path must contain at least two addresses")
    encoded_addresses = b"".join(bytes.fromhex(_address_word(address)) for address in addresses)
    return len(addresses).to_bytes(32, "big") + encoded_addresses


def _address_word(address: str) -> str:
    raw = str(address).lower().removeprefix("0x")
    if len(raw) != 40 or any(ch not in "0123456789abcdef" for ch in raw):
        raise ValueError(f"invalid EVM address: {address}")
    return raw.rjust(64, "0")


def _validate_address(address: str, name: str) -> None:
    try:
        _address_word(address)
    except ValueError as exc:
        raise ValueError(f"invalid {name}: {address}") from exc


def _uint_word(value: int) -> str:
    return _uint_word_bytes(value).hex()


def _uint_word_bytes(value: int) -> bytes:
    if value < 0 or value >= 1 << 256:
        raise ValueError("uint256 out of range")
    return value.to_bytes(32, "big")
