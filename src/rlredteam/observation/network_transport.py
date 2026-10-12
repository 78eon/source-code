"""Native read-only TCP metadata. No scanner, shell, login or redirect execution."""

import asyncio
import hashlib
import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from rlredteam.knowledge.serialization import digest

from .audit import AuditKind, AuditTrail
from .models import (
    SCHEMA_VERSION,
    RawHttpObservation,
    RawServiceObservation,
    RawStatus,
    RawTlsObservation,
)
from .network_policy import NetworkBudget, NetworkLimits, canonical_target, utc_now
from .protocols import Capability, LiveObservationDisabledError, OutOfScopeTargetError
from .provenance import ObservationProvenance

COLLECTOR = "native-readonly-tcp-v1"


def provenance(session_id, value, at):
    return ObservationProvenance(
        source_id="native:" + session_id,
        collector=COLLECTOR,
        software_version="4B.1",
        schema_version=SCHEMA_VERSION,
        timestamp=at,
        input_digest=digest(value),
    )


@dataclass(frozen=True, slots=True)
class Resolution:
    supplied_target: str
    addresses: tuple[str, ...]
    resolver_source: str
    timestamp: str

    def fields(self):
        return {
            "supplied_target": self.supplied_target,
            "resolved_addresses": self.addresses,
            "resolver_source": self.resolver_source,
            "resolved_at": self.timestamp,
            "resolution_digest": digest(self),
        }


class AsyncTcpObservationTransport:
    def __init__(self, gate, *, limits=None, budget=None, ca_file=None):
        self.gate = gate
        self.limits = limits or NetworkLimits()
        self.budget = budget or NetworkBudget(self.limits, gate.scope)
        if self.budget.limits != self.limits:
            raise ValueError("transport and budget limits differ")
        self.ca_file = ca_file
        self.audit = AuditTrail(session_id=gate.session.session_id)
        self.observations = []
        self._asset_keys = {}

    def record(self, kind, **fields):
        self.audit = self.audit.append(kind, utc_now(), **fields)

    def check(self, target, capability):
        try:
            target = self.gate.check(target, capability)
        except ValueError as exc:
            self.record(AuditKind.LIVE_GATE_CHECKED, allowed=False, reason=type(exc).__name__)
            self.record(AuditKind.TARGET_REJECTED, reason=type(exc).__name__)
            raise
        self.record(AuditKind.LIVE_GATE_CHECKED, allowed=True, mode=self.gate.session.mode.value)
        self.record(AuditKind.TARGET_ALLOWED, target=target, capability=capability.value)
        return target

    async def resolve(self, target, capability):
        target = self.check(target, capability)  # BEFORE DNS
        self.budget.remaining()
        try:
            address = ipaddress.ip_address(target)
        except ValueError:
            if self.gate.session.mode.value == "LOOPBACK_TEST":
                addresses, source = ("127.0.0.1", "::1"), "static-loopback-localhost-v1"
            else:
                async with asyncio.timeout(
                    min(self.limits.connect_timeout, self.budget.remaining())
                ):
                    entries = await asyncio.get_running_loop().getaddrinfo(
                        target, None, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
                    )
                addresses = tuple(
                    sorted({str(ipaddress.ip_address(entry[4][0])) for entry in entries})
                )
                source = "system-getaddrinfo"
        else:
            addresses, source = (str(address),), "literal-address"
        if not addresses or len(addresses) > 16:
            raise OutOfScopeTargetError("empty or excessive resolver answer")
        # Every answer is checked, not merely whichever address connects first.
        for address in addresses:
            self.check(address, capability)
        resolution = Resolution(target, addresses, source, utc_now())
        self.record(AuditKind.TARGET_RESOLVED, **resolution.fields())
        return resolution

    async def observe(self, target, port, capability, *, use_tls=False):
        target = self.check(target, capability)
        if type(use_tls) is not bool:
            raise ValueError("use_tls must be boolean")
        if use_tls:
            self.check(target, Capability.TLS_METADATA)
        self.budget.approve_ports(target, (port,))
        token = self.budget.reserve(target)  # Includes resolution failures and concurrency.
        self.record(AuditKind.BUDGET_CONSUMED, operation=token, target=target)
        writer, sock = None, None
        fields = {
            "port": port,
            "protocol": "tcp",
            "transport": "tcp",
            "reachable": False,
            "error_class": None,
            "service_key": f"tcp:{port}",
        }
        began = time.monotonic()
        resolution = None
        denied = None
        try:
            async with asyncio.timeout(self.budget.remaining()):
                resolution = await self.resolve(target, capability)
                # No automatic failover; chosen literal is pinned for the connection.
                address = resolution.addresses[0]
                self.budget.approve_address(address)
                fields.update(resolution.fields())
                fields["address"] = address
                if target != address:
                    fields["hostname"] = target
                self.check(target, capability)
                self.check(address, capability)  # Immediately BEFORE connect
                if use_tls or capability == Capability.TLS_METADATA:
                    self.check(address, Capability.TLS_METADATA)
                context = None
                if use_tls or capability == Capability.TLS_METADATA:
                    context = ssl.create_default_context(cafile=self.ca_file)
                    # No injectable SSLContext or insecure bypass flag.
                    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
                self.check(target, capability)
                self.check(address, capability)
                if context:
                    self.check(target, Capability.TLS_METADATA)
                    self.check(address, Capability.TLS_METADATA)
                self.record(AuditKind.CONNECTION_ATTEMPTED, address=address, port=port)
                sock = socket.socket(
                    socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM
                )
                sock.setblocking(False)
                async with asyncio.timeout(
                    min(self.limits.connect_timeout, self.budget.remaining())
                ):
                    await asyncio.get_running_loop().sock_connect(sock, (address, port))
                    reader, writer = await asyncio.open_connection(
                        sock=sock,
                        ssl=context,
                        server_hostname=target if context else None,
                        limit=self.limits.max_response_bytes,
                        **(
                            {
                                "ssl_handshake_timeout": self.limits.connect_timeout,
                                "ssl_shutdown_timeout": 0.1,
                            }
                            if context
                            else {}
                        ),
                    )
                    sock = None  # Stream now owns the socket.
                fields["reachable"] = True
                fields["connect_seconds"] = time.monotonic() - began
                self.record(AuditKind.CONNECTION_SUCCEEDED, address=address, port=port)
                if context:
                    tls = writer.get_extra_info("ssl_object")
                    cert = tls.getpeercert()
                    fields.update(
                        tls=True,
                        tls_metadata={
                            "protocol": tls.version(),
                            "cipher": tls.cipher(),
                            "subject": cert.get("subject"),
                            "issuer": cert.get("issuer"),
                            "san": cert.get("subjectAltName"),
                            "not_before": cert.get("notBefore"),
                            "not_after": cert.get("notAfter"),
                            "certificate_sha256": hashlib.sha256(
                                tls.getpeercert(binary_form=True)
                            ).hexdigest(),
                            "certificate_verified": True,
                        },
                    )
                if capability == Capability.SERVICE_BANNER:
                    await self._banner(reader, fields)
                elif capability == Capability.HTTP_METADATA:
                    await self._http(reader, writer, target, port, capability, fields)
        except (OSError, TimeoutError, ValueError) as exc:
            self.record(AuditKind.CONNECTION_FAILED, port=port, reason=type(exc).__name__)
            if isinstance(exc, LiveObservationDisabledError):
                denied = exc
            fields["error_class"] = type(exc).__name__
        finally:
            if writer is not None:
                writer.close()
                try:
                    async with asyncio.timeout(0.2):
                        await writer.wait_closed()
                except (OSError, TimeoutError):
                    pass
            if sock is not None:
                sock.close()
            self.budget.counter.release(token)
        # Resolution/gate failures never manufacture an address.
        subject = fields.get("address", target)
        from uuid import uuid4

        if subject not in self._asset_keys:
            self._asset_keys[subject] = "observation-asset:" + str(uuid4())
        fields["asset_key"] = self._asset_keys[subject]
        fields["elapsed_seconds"] = time.monotonic() - began
        fields["mode"] = self.gate.session.mode.value
        at = utc_now()
        kind = {
            Capability.TLS_METADATA: RawTlsObservation,
            Capability.HTTP_METADATA: RawHttpObservation,
        }.get(capability, RawServiceObservation)
        raw = kind(
            observation_id=f"raw:{self.gate.session.session_id}:{token}",
            session_id=self.gate.session.session_id,
            capability=capability,
            subject_hint=subject,
            collected_at=at,
            raw_fields=fields,
            collector=COLLECTOR,
            provenance=provenance(self.gate.session.session_id, fields, at),
            status=RawStatus.FAILED if fields["error_class"] else RawStatus.SUPPLIED,
        )
        self.observations.append(raw)
        self.record(
            AuditKind.RAW_OBSERVATION_CREATED,
            observation_id=raw.observation_id,
            input_digest=raw.provenance.input_digest,
        )
        if denied is not None:
            raise denied
        return raw

    async def _banner(self, reader, fields):
        data = bytearray()
        try:
            async with asyncio.timeout(min(self.limits.read_timeout, self.budget.remaining())):
                while len(data) < self.limits.max_response_bytes:
                    chunk = await reader.read(min(256, self.limits.max_response_bytes - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
                    if data.count(b"\n") >= self.limits.max_banner_lines:
                        break
        except TimeoutError:
            fields["banner_read_timed_out"] = True
            if not data:
                raise
        lines = bytes(data).splitlines(keepends=True)[: self.limits.max_banner_lines]
        retained = b"".join(lines)
        fields.update(
            banner=retained.decode("utf-8", errors="replace"),
            banner_hex=retained.hex(),
            response_bytes=len(data),
            response_limit_reached=len(data) >= self.limits.max_response_bytes,
            banner_line_limit_reached=data.count(b"\n") >= self.limits.max_banner_lines,
        )

    async def _http(self, reader, writer, target, port, capability, fields):
        host = f"[{target}]" if ":" in target else target
        request = f"HEAD / HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
        writer.write(request.encode("ascii"))
        data = bytearray()
        async with asyncio.timeout(min(self.limits.read_timeout, self.budget.remaining())):
            await writer.drain()
            while b"\r\n\r\n" not in data and len(data) < self.limits.max_response_bytes:
                chunk = await reader.read(min(256, self.limits.max_response_bytes - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
        fields["response_bytes"] = len(data)
        fields["response_limit_reached"] = len(data) >= self.limits.max_response_bytes
        if b"\r\n\r\n" not in data:
            raise ValueError("incomplete or excessive HTTP headers")
        lines = bytes(data).split(b"\r\n\r\n", 1)[0].decode("iso-8859-1").split("\r\n")
        parts = lines[0].split(" ")
        if (
            len(parts) < 2
            or parts[0] not in ("HTTP/1.0", "HTTP/1.1")
            or not parts[1].isdigit()
            or not 100 <= int(parts[1]) <= 599
        ):
            raise ValueError("invalid HTTP status")
        selected = {}
        for line in lines[1:]:
            if ":" not in line or line.startswith((" ", "\t")):
                raise ValueError("invalid HTTP header")
            key, value = line.split(":", 1)
            if key.lower() in ("server", "content-type", "location", "content-length"):
                if key.lower() in selected:
                    raise ValueError("ambiguous selected header")
                selected[key.lower()] = value.strip()
        fields.update(
            http=True,
            http_method="HEAD",
            http_status=int(parts[1]),
            http_headers=selected,
            redirect_followed=False,
        )
        if "location" in selected:
            location = selected["location"]
            if any(ord(char) < 32 for char in location) or "\\" in location:
                raise OutOfScopeTargetError("unsafe redirect location")
            endpoint = urlsplit(location)
            if (
                endpoint.username
                or endpoint.password
                or endpoint.scheme not in ("", "http", "https")
            ):
                raise OutOfScopeTargetError("unsupported redirect endpoint")
            if endpoint.hostname:
                destination = canonical_target(endpoint.hostname)
                self.check(destination, capability)
                # Revalidate every answer even though following is disabled.
                await self.resolve(destination, capability)
            fields["redirect_policy"] = "validated-not-followed-v1"
        # No GET fallback: unsupported HEAD is recorded as supplied status, not retried.
