"""Synthetic servers: loopback/ephemeral only; listeners and clients always closed."""

import asyncio
from contextlib import asynccontextmanager

from rlredteam.observation.network_policy import NetworkGate, utc_now
from rlredteam.observation.network_transport import provenance
from rlredteam.observation.protocols import Capability, ObservationMode
from rlredteam.observation.provenance import AuthorizationRecord
from rlredteam.observation.scope import ObservationScope
from rlredteam.observation.session import create_session

CAPS = (
    Capability.TCP_SERVICE_OBSERVATION,
    Capability.SERVICE_BANNER,
    Capability.TLS_METADATA,
    Capability.HTTP_METADATA,
)


def gate(*, live=False, capabilities=CAPS):
    scope = ObservationScope(
        scope_id="scope:native-test",
        name="Synthetic local services",
        permitted_networks=("127.0.0.0/8", "::1/128"),
        permitted_assets=("localhost", "fixture.example"),
        capability_allowlist=capabilities,
        live_enabled=live,
        authorization_reference="synthetic:test" if live else None,
        max_requests_per_asset=64,
    )
    auth = (
        AuthorizationRecord(
            authorization_id="auth:synthetic",
            scope_id=scope.scope_id,
            owner="synthetic",
            authorized_by="unit-test-only",
            valid_from="2020-01-01T00:00:00Z",
            valid_until="2100-01-01T00:00:00Z",
            permitted_purpose="gate validation only, no live execution",
            authorization_reference="synthetic:test",
        )
        if live
        else None
    )
    at = utc_now()
    session = create_session(
        scope=scope,
        authorization=auth,
        enable_live_lab=live,
        session_id="session:native-test",
        created_at=at,
        mode=ObservationMode.LIVE_LAB if live else ObservationMode.LOOPBACK_TEST,
        host_identity="synthetic",
        collector_version="test",
        requested_capabilities=capabilities,
        provenance=provenance("test", {}, at),
    )
    return NetworkGate(session, scope, auth, live)


@asynccontextmanager
async def fixture_server(
    *, greeting=b"SSH-2.0-OpenSSH_9.6p1\r\n", http=None, tls=None, stall=False
):
    tasks, requests, peers = set(), [], []

    async def serve(reader, writer):
        task = asyncio.current_task()
        tasks.add(task)
        peers.append(writer.get_extra_info("peername"))
        try:
            if stall:
                await reader.read(1)
            elif http is not None:
                request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
                requests.append(request)
                writer.write(http)
                await writer.drain()
            else:
                writer.write(greeting)
                await writer.drain()
        except (OSError, asyncio.IncompleteReadError, TimeoutError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            tasks.discard(task)

    server = await asyncio.start_server(serve, "127.0.0.1", 0, ssl=tls)
    port = server.sockets[0].getsockname()[1]
    try:
        yield port, requests, peers
    finally:
        server.close()
        await server.wait_closed()
        for task in tuple(tasks):
            task.cancel()
        if tasks:
            await asyncio.gather(*tuple(tasks), return_exceptions=True)
