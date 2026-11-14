"""Explicit exact-host Nmap acquisition only. No normalization or graph logic."""

import ipaddress
import os
import secrets
import selectors
import signal
import subprocess
import time
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from threading import Lock

from rlredteam.enterprise.live import NmapLabRunner
from rlredteam.knowledge.serialization import digest

from .lab_scope_bridge import project_lab_scope
from .protocols import Capability

PROFILE = "tcp_connect_inventory"


@dataclass(frozen=True, kw_only=True)
class CollectionBudget:
    max_targets: int
    max_runtime_seconds: int
    max_retries: int
    max_concurrency: int
    max_ports: int
    max_artifact_bytes: int
    allowed_ports: tuple[int, ...]
    execution_enabled: bool = False

    def __post_init__(self):
        ports = tuple(self.allowed_ports)
        if (
            not ports
            or len(ports) > 128
            or len(set(ports)) != len(ports)
            or any(type(p) is not int or not 1 <= p <= 65535 for p in ports)
        ):
            raise ValueError("explicit backend-approved ports required")
        object.__setattr__(self, "allowed_ports", tuple(sorted(ports)))
        for name, maximum in (
            ("max_targets", 1),
            ("max_runtime_seconds", 120),
            ("max_concurrency", 4),
            ("max_ports", 128),
            ("max_artifact_bytes", 1024 * 1024),
        ):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError("invalid collection budget: " + name)
        if type(self.max_retries) is not int or not 0 <= self.max_retries <= 1:
            raise ValueError("invalid retry budget")
        if type(self.execution_enabled) is not bool:
            raise ValueError("execution_enabled must be boolean")


def execute_bounded(argv, budget, cancelled, deadline):
    """Bound both streams while running; terminate the process group on any failure."""
    if cancelled() or time.monotonic() >= deadline:
        raise InterruptedError("collection cancelled or deadline expired")
    with subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        env={"PATH": os.environ.get("PATH", ""), "LANG": "C"},
    ) as process:
        try:
            outputs = {"stdout": bytearray(), "stderr": bytearray()}
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, "stdout")
                selector.register(process.stderr, selectors.EVENT_READ, "stderr")
                while selector.get_map() or process.poll() is None:
                    if cancelled():
                        raise InterruptedError("collection cancelled")
                    if time.monotonic() >= deadline:
                        raise TimeoutError("collection deadline expired")
                    for key, _ in selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                        else:
                            outputs[key.data].extend(chunk)
                            if sum(map(len, outputs.values())) > budget.max_artifact_bytes:
                                raise ValueError("collector output exceeds budget")
            if process.wait() != 0:
                raise RuntimeError("collector failed; stderr intentionally not exposed")
            return bytes(outputs["stdout"])
        finally:
            # Kill descendants too, including on cancellation/timeouts/output overflow.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


class ControlledNmapCollector:
    def __init__(self, approvals, budget, *, execute=None, binary="nmap", context=None,
                 validate_context=lambda: None):
        self.approvals, self.budget, self.execute, self.binary = (
            dict(approvals),
            budget,
            execute if execute is not None else execute_bounded,
            binary,
        )
        self.lock = Lock()
        self.plan_lock = Lock()
        self.pending = None
        self.context_digest = digest(context if context is not None else secrets.token_hex(32))
        self.configuration_digest = (
            digest(context.get("workspace", {})) if isinstance(context, dict) else None
        )
        self.knowledge_digest = context.get("knowledge") if isinstance(context, dict) else None
        self.validate_context = validate_context

    def plan(self, *, scope_id, authorization_id, target, ports, profile):
        self.validate_context()
        if not self.budget.execution_enabled:
            raise ValueError("collector execution disabled")
        if scope_id not in self.approvals:
            raise ValueError("missing approved scope")
        scope, authorization = self.approvals[scope_id]
        at = datetime.now(UTC).isoformat()
        authorization.validate(scope, at=at)
        if not scope.live_enabled or authorization.authorization_id != authorization_id:
            raise ValueError("live authorization disabled or mismatched")
        if profile != PROFILE:
            raise ValueError("unsupported collection profile")
        # Reject names, CIDRs, special addresses and non-private destinations before execution.
        address = ipaddress.ip_address(target)
        if (
            not address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved
        ):
            raise ValueError("private routed literal target required")
        ports = tuple(ports)
        if (
            not ports
            or len(set(ports)) != len(ports)
            or any(type(p) is not int or not 1 <= p <= 65535 for p in ports)
        ):
            raise ValueError("explicit unique ports required")
        budget = self.budget
        if (
            budget.max_targets > scope.max_hosts
            or budget.max_runtime_seconds > scope.max_duration_seconds
            or budget.max_ports * (budget.max_retries + 1) > scope.max_requests_per_asset
            or budget.max_concurrency > budget.max_ports
            or len(ports) > budget.max_ports
            or not set(ports) <= set(budget.allowed_ports)
        ):
            raise ValueError("collector budget exceeds approved scope")
        for capability in (Capability.ADDRESS_OBSERVATION, Capability.TCP_SERVICE_OBSERVATION):
            scope.validate_target(str(address), capability, at=at)
        projected = project_lab_scope(
            scope, authorization, (str(address),), Capability.TCP_SERVICE_OBSERVATION, at=at
        )
        # Enabled only after canonical activation/auth/budget checks, not by frontend scope data.
        runner = NmapLabRunner(replace(projected, execution_enabled=True), binary=self.binary)
        argv = runner.plan_tcp_inventory(
            str(address),
            ports,
            seconds=budget.max_runtime_seconds,
            retries=budget.max_retries,
            concurrency=budget.max_concurrency,
        )
        payload = dict(
            scope_id=scope_id,
            authorization_id=authorization_id,
            target=str(address),
            ports=sorted(ports),
            profile=profile,
            budget=asdict(budget),
            authorization_digest=authorization.digest,
            scope_digest=digest(scope),
            context_digest=self.context_digest,
        )
        key = digest(payload)
        with self.plan_lock:
            if self.pending is None or self.pending[0] != key:
                self.pending = (key, secrets.token_hex(32))
            payload["plan_nonce"] = self.pending[1]
        return {
            **payload,
            "plan_digest": digest(payload),
            "argv": argv,
            "scope_validated": True,
            "approval_required": True,
        }

    def collect(
        self, values, *, plan_digest, operator_approved, cancelled=lambda: False, deadline=None
    ):
        plan = self.plan(**values)  # Revalidate immediately before execution.
        if operator_approved is not True or plan_digest != plan["plan_digest"]:
            raise ValueError("explicit approval of this exact backend plan required")
        deadline = min(
            deadline if deadline is not None else float("inf"),
            time.monotonic() + self.budget.max_runtime_seconds,
        )
        scope, authorization = self.approvals[values["scope_id"]]
        now = datetime.now(UTC)
        for expiry in (scope.expires_at, authorization.valid_until):
            if expiry:
                deadline = min(
                    deadline,
                    time.monotonic() + (datetime.fromisoformat(expiry) - now).total_seconds(),
                )
        if cancelled():
            raise InterruptedError("collection cancelled")
        if time.monotonic() >= deadline:
            raise TimeoutError("collection deadline expired")
        if not self.lock.acquire(blocking=False):
            raise ValueError("a collection is already active")
        try:
            self.validate_context()
            with self.plan_lock:
                if self.pending is None or self.pending[1] != plan["plan_nonce"]:
                    raise ValueError("plan was superseded or already consumed; request a new plan")
                self.pending = None
            artifact = self.execute(plan["argv"], self.budget, cancelled, deadline)
        finally:
            self.lock.release()
        if cancelled():
            raise InterruptedError("collection cancelled")
        if time.monotonic() >= deadline:
            raise TimeoutError("collection deadline expired")
        if not isinstance(artifact, bytes) or len(artifact) > self.budget.max_artifact_bytes:
            raise ValueError("invalid or excessive acquisition artifact")
        return artifact, plan
