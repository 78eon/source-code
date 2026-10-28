"""Literal scope checks without DNS, local-interface enumeration or sockets."""

import ipaddress
from dataclasses import dataclass
from datetime import datetime

from rlredteam.knowledge import validation as v

from .protocols import Capability


class ScopeViolation(v.ModelError):
    pass


@dataclass(frozen=True, slots=True, kw_only=True)
class ObservationScope:
    scope_id: str
    name: str
    description: str = ""
    permitted_networks: tuple[str, ...] = ()
    permitted_assets: tuple[str, ...] = ()
    excluded_networks: tuple[str, ...] = ()
    excluded_assets: tuple[str, ...] = ()
    capability_allowlist: tuple[Capability, ...] = ()
    max_hosts: int = 16
    max_duration_seconds: int = 60
    max_requests_per_asset: int = 8
    live_enabled: bool = False
    authorization_reference: str | None = None
    expires_at: str | None = None

    def __post_init__(self):
        v.validate_fields(self)
        v.stable_id(self.scope_id)
        v.text(self.name, "scope name")
        for name in ("permitted_networks", "excluded_networks"):
            try:
                networks = tuple(
                    sorted(
                        {
                            str(ipaddress.ip_network(item, strict=True))
                            for item in getattr(self, name)
                        }
                    )
                )
            except ValueError as exc:
                raise ScopeViolation("invalid scope network") from exc
            object.__setattr__(self, name, networks)
        for name in ("permitted_assets", "excluded_assets"):
            normalized = []
            for item in getattr(self, name):
                v.stable_id(item)
                try:
                    item = str(ipaddress.ip_address(item))
                except ValueError:
                    pass
                normalized.append(item)
            object.__setattr__(self, name, tuple(sorted(set(normalized))))
        object.__setattr__(
            self, "capability_allowlist", tuple(sorted(set(self.capability_allowlist)))
        )
        for name in ("max_hosts", "max_duration_seconds", "max_requests_per_asset"):
            if getattr(self, name) <= 0:
                raise ScopeViolation("scope limits must be positive")
        v.time_field(self, "expires_at", optional=True)
        if self.authorization_reference is not None:
            v.text(self.authorization_reference, "authorization reference")
        if self.live_enabled and not self.authorization_reference:
            raise ScopeViolation(
                "live_enabled requires an authorization reference; live execution remains disabled"
            )

    def is_address_permitted(self, target):
        if not isinstance(target, str):
            return False
        try:
            address = ipaddress.ip_address(target)
        except (ValueError, TypeError):
            return False
        if str(address) in self.excluded_assets:
            return False
        if any(
            address.version == network.version and address in network
            for network in map(ipaddress.ip_network, self.excluded_networks)
        ):
            return False
        return str(address) in self.permitted_assets or any(
            address.version == network.version and address in network
            for network in map(ipaddress.ip_network, self.permitted_networks)
        )

    def is_network_permitted(self, target):
        if not isinstance(target, str):
            return False
        try:
            network = ipaddress.ip_network(target, strict=True)
        except (ValueError, TypeError):
            return False
        if network.num_addresses > self.max_hosts:
            return False
        for excluded in map(ipaddress.ip_network, self.excluded_networks):
            if network.version == excluded.version and network.overlaps(excluded):
                return False
        for value in self.excluded_assets:
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if address.version == network.version and address in network:
                return False
        return any(
            network.version == allowed.version and network.subnet_of(allowed)
            for allowed in map(ipaddress.ip_network, self.permitted_networks)
        ) or (
            network.num_addresses == 1 and self.is_address_permitted(str(network.network_address))
        )

    def is_capability_permitted(self, capability):
        return isinstance(capability, Capability) and capability in self.capability_allowlist

    def validate_target(self, target, capability, *, at):
        now = datetime.fromisoformat(v.timestamp(at))
        if self.expires_at and now >= datetime.fromisoformat(self.expires_at):
            raise ScopeViolation("scope has expired")
        if not self.is_capability_permitted(capability):
            raise ScopeViolation("capability is not explicitly permitted")
        if not isinstance(target, str) or not target or target in self.excluded_assets:
            raise ScopeViolation("target is missing or excluded")
        try:
            ipaddress.ip_address(target)
        except ValueError:
            permitted = (
                self.is_network_permitted(target)
                if "/" in target
                else target in self.permitted_assets
            )
        else:
            permitted = self.is_address_permitted(target)
        if not permitted:
            raise ScopeViolation("target is outside explicit scope")
        return target
