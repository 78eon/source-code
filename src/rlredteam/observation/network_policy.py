"""Phase 4B activation, literal endpoint validation and bounded execution policy.

Authorization metadata is not proof of supervisor/ethics approval. No networking
is performed here. The runtime gate is rechecked by the transport at every use.
"""

import ipaddress
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime

from rlredteam.knowledge import validation as v

from .protocols import (
    AuthorizationRequiredError,
    Capability,
    CapabilityDeniedError,
    LiveObservationDisabledError,
    ObservationBudgetExceededError,
    ObservationMode,
    OutOfScopeTargetError,
)
from .scope import ScopeViolation
from .session import Budget, BudgetExhaustedError, BudgetLimits

SUPPORTED = frozenset(
    (
        Capability.TCP_SERVICE_OBSERVATION,
        Capability.SERVICE_BANNER,
        Capability.TLS_METADATA,
        Capability.HTTP_METADATA,
    )
)


def utc_now():
    return datetime.now(UTC).isoformat()


def canonical_target(target):
    if not isinstance(target, str) or not target or len(target) > 253:
        raise OutOfScopeTargetError("an explicit IP or ASCII hostname is required")
    if any(char in target for char in "/%\\@[]"):
        raise OutOfScopeTargetError("no CIDRs, URLs, zone identifiers or credentials")
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        if not all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in target.split(".")
        ):
            raise OutOfScopeTargetError("invalid hostname") from None
        # Reject legacy inet_aton forms rather than allowing alternate IP syntax.
        if all(c in "0123456789." for c in target):
            raise OutOfScopeTargetError("noncanonical IP address") from None
        return target.lower()


def require_loopback(address):
    ip = ipaddress.ip_address(address)
    if not ((ip.version == 4 and ip in ipaddress.ip_network("127.0.0.0/8")) or str(ip) == "::1"):
        raise OutOfScopeTargetError("LOOPBACK_TEST permits only 127/8 and ::1")


@dataclass(frozen=True, slots=True)
class NetworkGate:
    session: object
    scope: object
    authorization: object = None
    enable_live_lab: bool = False

    def check(self, target, capability, *, at=None):
        at = at or utc_now()
        target = canonical_target(target)
        session, scope = self.session, self.scope
        if session.scope_id != scope.scope_id:
            raise OutOfScopeTargetError("session/scope mismatch")
        if session.status.value not in ("CREATED", "RUNNING"):
            raise LiveObservationDisabledError("session is not executable")
        if (
            capability not in SUPPORTED
            or not isinstance(capability, Capability)
            or capability not in session.permitted_capabilities
            or not scope.is_capability_permitted(capability)
        ):
            raise CapabilityDeniedError("capability is not explicitly supported and permitted")
        if session.mode == ObservationMode.LIVE_LAB:
            if self.enable_live_lab is not True or scope.live_enabled is not True:
                raise LiveObservationDisabledError("LIVE_LAB requires explicit runtime activation")
            if (
                self.authorization is None
                or session.authorization_id != self.authorization.authorization_id
            ):
                raise AuthorizationRequiredError("matching AuthorizationRecord required")
            try:
                self.authorization.validate(scope, at=at)
            except ValueError as exc:
                raise AuthorizationRequiredError(str(exc)) from exc
        elif session.mode == ObservationMode.LOOPBACK_TEST:
            try:
                ipaddress.ip_address(target)
            except ValueError:
                # Never send external DNS traffic in development mode.
                if target != "localhost":
                    raise OutOfScopeTargetError("loopback hostname must be localhost") from None
            else:
                require_loopback(target)
        else:
            raise LiveObservationDisabledError("offline modes cannot open connections")
        try:
            scope.validate_target(target, capability, at=at)
        except ScopeViolation as exc:
            raise OutOfScopeTargetError(str(exc)) from exc
        return target


@dataclass(frozen=True, slots=True, kw_only=True)
class NetworkLimits:
    max_targets: int = 1
    max_ports_per_target: int = 8
    max_ports_per_session: int = 8
    max_connections: int = 32
    per_target_connections: int = 32
    concurrency: int = 2
    connect_timeout: float = 2.0
    read_timeout: float = 1.0
    max_response_bytes: int = 4096
    max_banner_lines: int = 4
    max_redirects: int = 0
    session_seconds: int = 30

    def __post_init__(self):
        v.validate_fields(self)
        for name, maximum in (
            ("max_targets", 8),
            ("max_ports_per_target", 16),
            ("max_ports_per_session", 32),
            ("max_connections", 128),
            ("per_target_connections", 64),
            ("concurrency", 4),
            ("max_response_bytes", 16384),
            ("max_banner_lines", 16),
            ("session_seconds", 120),
        ):
            if not 1 <= getattr(self, name) <= maximum:
                raise ValueError(f"{name} must be between 1 and {maximum}")
        for name in ("connect_timeout", "read_timeout"):
            if not 0 < getattr(self, name) <= 5:
                raise ValueError(f"{name} must be finite, positive and at most 5 seconds")
        if self.max_redirects != 0:
            raise ValueError("Phase 4B records redirects but never follows them")


class NetworkBudget:
    def __init__(self, limits, scope):
        self.limits = limits
        self.started = time.monotonic()
        self.duration = min(limits.session_seconds, scope.max_duration_seconds)
        self.ports = {}
        self.addresses = set()
        self.counter = Budget(
            BudgetLimits(
                max_targets=min(limits.max_targets, scope.max_hosts),
                max_operations=limits.max_connections,
                max_duration_seconds=self.duration,
                per_asset_requests=min(limits.per_target_connections, scope.max_requests_per_asset),
                concurrency_limit=limits.concurrency,
            )
        )

    def remaining(self):
        remaining = self.duration - (time.monotonic() - self.started)
        if remaining <= 0:
            raise ObservationBudgetExceededError("session deadline exhausted")
        return remaining

    def approve_ports(self, target, ports):
        ports = tuple(ports)
        if not ports or any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
            raise ValueError("supply explicit valid TCP ports")
        if len(set(ports)) != len(ports):
            raise ValueError("duplicate ports are not permitted")
        merged = self.ports.get(target, set()) | set(ports)
        total = sum(len(values) for key, values in self.ports.items() if key != target) + len(
            merged
        )
        if (
            len(merged) > self.limits.max_ports_per_target
            or total > self.limits.max_ports_per_session
            or (target not in self.ports and len(self.ports) >= self.counter.limits.max_targets)
        ):
            raise ObservationBudgetExceededError("target/port limit exceeded")
        self.remaining()
        self.ports[target] = merged
        return ports

    def reserve(self, target):
        self.remaining()
        try:
            return self.counter.reserve(target, elapsed_seconds=time.monotonic() - self.started)
        except BudgetExhaustedError as exc:
            raise ObservationBudgetExceededError(str(exc)) from exc

    def approve_address(self, address):
        if address not in self.addresses and len(self.addresses) >= self.counter.limits.max_targets:
            raise ObservationBudgetExceededError("resolved address target limit exceeded")
        self.addresses.add(address)
