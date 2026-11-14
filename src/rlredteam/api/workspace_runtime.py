"""Opt-in composition from operator-owned files; no migrations, scans or training.

    SECURITY_RL_WORKSPACE_CONFIG=<private-file> uvicorn \
      rlredteam.api.workspace_runtime:create_configured_app --factory

Bind the server to loopback and configure the existing API token mechanism.
The desktop-owned backend also recognizes this explicit configuration variable.
"""

import json
import os
import secrets
import stat
from contextlib import ExitStack, asynccontextmanager
from hashlib import sha256
from pathlib import Path

from rlredteam.application.assessment_jobs import OfflineAssessmentRunner
from rlredteam.application.canonical_workspace import CanonicalWorkspace
from rlredteam.application.lab_input import LabInputService
from rlredteam.knowledge.serialization import _constant, _pairs
from rlredteam.observation.provenance import AuthorizationRecord
from rlredteam.observation.repository import JsonObservationRepository
from rlredteam.observation.scope import ObservationScope
from rlredteam.observation.serialization import loads as observation_loads


def private_read(path, *, limit=8 * 1024 * 1024):
    path = Path(path).absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("workspace configuration must not traverse symlinks")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or info.st_size > limit
        ):
            raise ValueError("workspace files require owner-only permissions and bounded size")
        content = stream.read(limit + 1)
        if len(content) > limit:
            raise ValueError("workspace file limit exceeded")
        return content.decode("utf-8")


def load_approvals(document):
    approvals = {}
    from datetime import UTC, datetime

    for entry in document:
        if set(entry) != {"scope_file", "authorization_file"}:
            raise ValueError("invalid backend approval file selection")
        scope = observation_loads(private_read(entry["scope_file"]))
        authorization = observation_loads(private_read(entry["authorization_file"]))
        if not isinstance(scope, ObservationScope) or not isinstance(
            authorization, AuthorizationRecord
        ):
            raise ValueError("typed canonical scope and authorization required")
        authorization.validate(scope, at=datetime.now(UTC).isoformat())
        if scope.scope_id in approvals:
            raise ValueError("duplicate approved scope")
        approvals[scope.scope_id] = (scope, authorization)
    return approvals


def configuration_document(selected):
    document = json.loads(
        private_read(selected), object_pairs_hook=_pairs, parse_constant=_constant
    )
    allowed = {
        "version",
        "approvals",
        "offline_processing_enabled",
        "state_directory",
        "vulnerability_snapshot",
        "attack_snapshot",
        "neo4j_projection_enabled",
        "collection_budget",
    }
    if (
        not isinstance(document, dict)
        or set(document) - allowed
        or type(document.get("version")) is not int
        or document.get("version") != 1
        or not isinstance(document.get("approvals", []), list)
        or type(document.get("offline_processing_enabled", False)) is not bool
        or type(document.get("neo4j_projection_enabled", False)) is not bool
    ):
        raise ValueError("invalid workspace runtime configuration")
    return document


def configuration_guard(selected, document):
    paths = [selected, document["vulnerability_snapshot"]]
    paths.extend(entry[key] for entry in document["approvals"]
                 for key in ("scope_file", "authorization_file"))
    if document.get("attack_snapshot"):
        paths.append(document["attack_snapshot"])
    expected = {path: sha256(private_read(path).encode()).hexdigest() for path in paths}

    def validate():
        for path, checksum in expected.items():
            if sha256(private_read(path).encode()).hexdigest() != checksum:
                raise ValueError("workspace configuration changed; restart and request a new plan")

    return expected, validate


def create_configured_app():
    from .app import create_app

    selected = os.environ.get("SECURITY_RL_WORKSPACE_CONFIG")
    if not selected:
        return create_app()
    document = configuration_document(selected)
    approvals = load_approvals(document.get("approvals", ()))
    attack = None
    if document.get("attack_snapshot"):
        from rlredteam.knowledge.external.models import MAX_SNAPSHOT_BYTES, loads

        attack = loads(private_read(document["attack_snapshot"], limit=MAX_SNAPSHOT_BYTES))
        if not attack.artifacts[0].dataset.startswith("attack-"):
            raise ValueError("ATT&CK snapshot required for ATT&CK workspace")
    workspace = CanonicalWorkspace(attack_snapshot=attack)
    if not document.get("offline_processing_enabled", False):
        return create_app(lab_input_service=LabInputService(approvals), workspace_service=workspace)
    if not approvals:
        raise ValueError("offline processing requires explicit backend approvals")
    from rlredteam.knowledge.vulnerabilities.importers import load_local

    knowledge = load_local(
        document["vulnerability_snapshot"], created_at=next(iter(approvals.values()))[1].valid_from
    )
    root = Path(document["state_directory"]).absolute()
    if any((p / ".git").exists() for p in (root, *root.parents)):
        raise ValueError("operational state must be outside Git checkouts")
    if any(p.is_symlink() for p in (root, *root.parents)):
        raise ValueError("operational state must not traverse symlinks")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("operational state requires owner-only directory permissions")
    # JsonObservationRepository enforces no-follow and protected-path checks.
    observations = JsonObservationRepository(root / "observations")
    collector = None
    if document.get("collection_budget") is not None:
        from rlredteam.observation.controlled_collection import (
            CollectionBudget,
            ControlledNmapCollector,
        )

        identities, validate = configuration_guard(selected, document)
        if (configuration_document(selected) != document
                or load_approvals(document["approvals"]) != approvals):
            raise ValueError("workspace configuration changed during startup")
        collector = ControlledNmapCollector(
            approvals, CollectionBudget(**document["collection_budget"]),
            context={"workspace": document, "knowledge": knowledge.canonical_digest,
                     "generation": secrets.token_hex(32), "input_digests": identities},
            validate_context=validate,
        )

    from .workspace_lifecycle import state_journal

    resources = ExitStack()
    journal = resources.enter_context(state_journal(root))

    # Connections are created lazily per job, never at configuration/GET time.
    class Runner:
        def __init__(self):
            self.journal = journal
            self.observation_repository = observations
            self.collector = collector

        def run(self, values):
            return self._run(values)

        def run_live(self, values, *, cancelled=lambda: False):
            if self.collector is None:
                raise ValueError("live collection not configured")
            return self._run(values, live=True, cancelled=cancelled)

        def _run(self, values, *, live=False, cancelled=lambda: False):
            import psycopg

            from rlredteam.storage.correlation_store import InventoryCorrelationStore
            from rlredteam.storage.postgres_logger import connection_string

            graph_store = None
            try:
                if document.get("neo4j_projection_enabled", False):
                    from rlredteam.storage.twin_graph_store import TwinInventoryGraphStore

                    graph_store = TwinInventoryGraphStore.connect()
                with psycopg.connect(connection_string(), autocommit=True) as connection:
                    store = InventoryCorrelationStore(connection)
                    lab = LabInputService(
                        approvals,
                        observation_repository=observations,
                        evidence_repository=store.twins.entities.evidence,
                    )
                    return OfflineAssessmentRunner(
                        lab, store, journal, knowledge, graph_store=graph_store
                    ).run(values, collector=self.collector if live else None, cancelled=cancelled)
            finally:
                if graph_store is not None:
                    graph_store.driver.close()

    @asynccontextmanager
    async def lifespan(app):
        try:
            yield
        finally:
            resources.close()

    try:
        app = create_app(
            lab_input_service=LabInputService(approvals),
            workspace_service=workspace,
            assessment_runner=Runner(),
        )
    except BaseException:
        resources.close()
        raise
    app.router.lifespan_context = lifespan
    return app
