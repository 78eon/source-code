"""READ-ONLY OBSERVATION ONLY. Real lab use requires separate scope/ethics approval."""

import argparse
import asyncio
from pathlib import Path
from uuid import uuid4

from rlredteam.observation.engine import ObservationEngine
from rlredteam.observation.network_policy import utc_now
from rlredteam.observation.network_transport import provenance
from rlredteam.observation.protocols import Capability, ObservationMode
from rlredteam.observation.provenance import AuthorizationRecord
from rlredteam.observation.repository import JsonObservationRepository
from rlredteam.observation.scope import ObservationScope
from rlredteam.observation.serialization import dumps, loads
from rlredteam.observation.session import create_session


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=("loopback-test", "live-lab"))
    parser.add_argument("--target", required=True)
    parser.add_argument("--ports", required=True, type=int, nargs="+")
    parser.add_argument(
        "--capabilities", nargs="+", choices=["tcp", "banner", "tls", "http"], default=["tcp"]
    )
    parser.add_argument("--tls-ports", type=int, nargs="*", default=[])
    parser.add_argument("--enable-live-lab", action="store_true")
    parser.add_argument("--scope-file", type=Path)
    parser.add_argument("--authorization-file", type=Path)
    parser.add_argument("--output-directory", type=Path)
    parser.add_argument(
        "--fingerprints",
        action="store_true",
        help="Print evidence-backed native fingerprint analysis",
    )
    parser.add_argument(
        "--assess-vulnerabilities",
        action="store_true",
        help="Assess retained software evidence against the local frozen catalogue only",
    )
    parser.add_argument(
        "--vulnerability-knowledge",
        type=Path,
        help="Explicit local enriched snapshot/JSON directory; never a default",
    )
    parser.add_argument(
        "--vulnerability-knowledge-snapshot",
        type=Path,
        help="Explicit prebuilt enriched snapshot; never auto-builds or loads raw sources",
    )
    args = parser.parse_args(argv)
    if args.vulnerability_knowledge and not args.assess_vulnerabilities:
        parser.error("--vulnerability-knowledge requires --assess-vulnerabilities")
    if args.vulnerability_knowledge_snapshot and not args.assess_vulnerabilities:
        parser.error("--vulnerability-knowledge-snapshot requires --assess-vulnerabilities")
    if args.vulnerability_knowledge_snapshot and args.vulnerability_knowledge:
        parser.error("select one explicit knowledge input")
    caps = tuple(
        {
            "tcp": Capability.TCP_SERVICE_OBSERVATION,
            "banner": Capability.SERVICE_BANNER,
            "tls": Capability.TLS_METADATA,
            "http": Capability.HTTP_METADATA,
        }[c]
        for c in args.capabilities
    )
    mode = (
        ObservationMode.LOOPBACK_TEST if args.mode == "loopback-test" else ObservationMode.LIVE_LAB
    )
    try:
        enriched_snapshot = None
        if args.vulnerability_knowledge_snapshot:
            from rlredteam.knowledge.vulnerabilities.builder import load_snapshot

            enriched_snapshot = load_snapshot(args.vulnerability_knowledge_snapshot)
        if args.vulnerability_knowledge:
            from rlredteam.knowledge.vulnerabilities.importers import load_local

            enriched_snapshot = load_local(args.vulnerability_knowledge, created_at=utc_now())
        auth = None
        if mode == ObservationMode.LIVE_LAB:
            if not args.enable_live_lab or not args.scope_file or not args.authorization_file:
                parser.error(
                    "LIVE_LAB requires --enable-live-lab, --scope-file and --authorization-file"
                )

            def read_model(path):
                with path.open("rb") as source:
                    data = source.read(8 * 1024 * 1024 + 1)
                if len(data) > 8 * 1024 * 1024:
                    raise ValueError("input exceeds size limit")
                return loads(data.decode("utf-8"))

            scope, auth = read_model(args.scope_file), read_model(args.authorization_file)
            if not isinstance(scope, ObservationScope) or not isinstance(auth, AuthorizationRecord):
                raise ValueError("scope/authorization model required")
        else:
            scope = ObservationScope(
                scope_id="scope:loopback-cli",
                name="Local fixture only",
                permitted_networks=("127.0.0.0/8", "::1/128"),
                permitted_assets=("localhost",),
                capability_allowlist=caps,
                max_hosts=1,
                max_requests_per_asset=32,
            )
        sid, at = "session:" + str(uuid4()), utc_now()
        session = create_session(
            scope=scope,
            authorization=auth,
            enable_live_lab=args.enable_live_lab,
            session_id=sid,
            created_at=at,
            mode=mode,
            collector_version="4B.1",
            host_identity="operator-supplied-cli",
            requested_capabilities=caps,
            provenance=provenance(sid, {"target": args.target, "ports": args.ports}, at),
        )
        repository = (
            JsonObservationRepository(args.output_directory) if args.output_directory else None
        )
        result = asyncio.run(
            ObservationEngine(
                session,
                scope,
                authorization=auth,
                enable_live_lab=args.enable_live_lab,
                repository=repository,
                fingerprint_inference=args.fingerprints or args.assess_vulnerabilities,
            ).run(args.target, args.ports, caps, tls_ports=args.tls_ports)
        )
        print(dumps(result.bundle))
        print(dumps(result.audit))
        if result.analysis is not None:
            print(dumps(result.analysis))
        if args.assess_vulnerabilities:
            from rlredteam.vulnerability.applicability import ApplicabilityEngine
            from rlredteam.vulnerability.knowledge import import_frozen_vulnerabilities
            from rlredteam.vulnerability.serialization import dumps as assessment_json

            at = result.bundle.provenance.timestamp
            if enriched_snapshot is not None:
                from rlredteam.knowledge.registry import KnowledgeRegistry
                from rlredteam.knowledge.vulnerabilities.serialization import dumps as snapshot_json

                snapshot = enriched_snapshot
                print(snapshot_json(snapshot))
                applicability = ApplicabilityEngine(
                    analysis=result.analysis,
                    evidence=result.evidence,
                    knowledge=KnowledgeRegistry(),
                    enriched_knowledge=snapshot.registry(),
                )
            else:
                knowledge, vulnerabilities = import_frozen_vulnerabilities(imported_at=at)
                applicability = ApplicabilityEngine(
                    analysis=result.analysis,
                    evidence=result.evidence,
                    knowledge=knowledge,
                    vulnerabilities=vulnerabilities,
                )
            assessments = applicability.evaluate(created_at=at)
            for assessment in assessments.list():
                print(assessment_json(assessment))
        return 0
    except (ValueError, OSError) as exc:
        parser.exit(2, f"Observation denied/failed: {type(exc).__name__}: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
