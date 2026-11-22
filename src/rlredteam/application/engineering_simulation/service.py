"""Explicit synthetic creation, offline execution and canonical publication."""

from datetime import datetime, timezone
import uuid
import json
from rlredteam.storage.analytical_identity import digest, build_analytical_report
from .models import SimulationSpec, DISCLAIMER, DECISION_ENGINE
from .repository import SimulationRepository


class SimulationService:
    def __init__(self, root):
        self.repository = SimulationRepository(root)

    def preview(self, spec):
        from .topology import preview

        return preview(spec)

    def create(self, spec):
        from .topology import generate, catalogue_metadata
        from .examples import example_provenance

        origin = example_provenance(spec)

        with self.repository.locked():
            if len(self.repository.list()) >= 100:
                raise ValueError("Saved simulation limit reached")
            catalogue = (
                catalogue_metadata() if spec.vulnerabilities.mode == "catalogue_metadata" else None
            )
            topology, assignments, catalogue_hash = generate(spec, catalogue)
            identifier = "engineering-" + uuid.uuid4().hex
            record = {
                "simulation_id": identifier,
                "specification": spec.model_dump(),
                "specification_sha256": digest(spec.model_dump()),
                "topology": topology.to_dict(),
                "topology_sha256": digest(topology.to_dict()),
                "vulnerability_assignments": assignments,
                "catalogue_snapshot_sha256": catalogue_hash,
                "catalogue_records": catalogue[0] if catalogue else [],
                "seed": spec.seed,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "evidence_class": "engineering_simulation",
                "research_status": "not_registered",
                "disclaimer": DISCLAIMER,
                "policy_id": spec.policy_id,
                "policy_checkpoint_sha256": None,
                "decision_engine": DECISION_ENGINE,
                "ppo_compatibility": "Not evaluated",
                "example_provenance": origin,
            }
            record = json.loads(json.dumps(record))
            self.repository.save(identifier, "specification", record)
            return record

    def list(self):
        return {
            "items": [
                {
                    "simulation_id": r["simulation_id"],
                    "name": r["specification"]["name"],
                    "seed": r["seed"],
                    "created_at": r["created_at"],
                    "topology_sha256": r["topology_sha256"],
                    "completed": self.repository.path(r["simulation_id"], "result").is_file(),
                }
                for r in self.repository.list()
            ]
        }

    def get(self, identifier):
        record = self.repository.load(identifier, "specification")
        if (
            record["evidence_class"] != "engineering_simulation"
            or record["research_status"] != "not_registered"
        ):
            raise ValueError("Research evidence cannot enter the simulation workspace")
        if (
            digest(record["specification"]) != record["specification_sha256"]
            or digest(record["topology"]) != record["topology_sha256"]
        ):
            raise ValueError("Simulation provenance mismatch")
        return record

    def run(self, identifier):
        from .topology import generate
        from .execution import execute

        with self.repository.locked():
            record = self.get(identifier)
            if self.repository.path(identifier, "result").exists():
                return self.repository.load(identifier, "result")
            spec = SimulationSpec.model_validate(record["specification"])
            catalogue = (
                (record["catalogue_records"], record["catalogue_snapshot_sha256"])
                if record["catalogue_snapshot_sha256"]
                else None
            )
            topology, assignments, _ = generate(spec, catalogue)
            if digest(topology.to_dict()) != record["topology_sha256"]:
                raise ValueError("Topology generator version drift; create a new simulation")
            result = execute(spec, topology, assignments, identifier)
            result.update(
                simulation_id=identifier,
                specification_sha256=record["specification_sha256"],
                topology_sha256=record["topology_sha256"],
                catalogue_snapshot_sha256=record["catalogue_snapshot_sha256"],
            )
            result = json.loads(json.dumps(result))
            self.repository.save(identifier, "result", result)
            return result

    def result(self, identifier):
        record = self.get(identifier)
        result = self.repository.load(identifier, "result")
        if (
            result["specification_sha256"] != record["specification_sha256"]
            or result["topology_sha256"] != record["topology_sha256"]
            or result["source_sha256"] != digest(result["episodes"])
        ):
            raise ValueError("Result provenance mismatch")
        return result

    def published_topology(self, graph_id, report_id):
        """Join a displayed projection to its sealed engineering publication."""
        for path in sorted(self.repository.root.glob("engineering-*/publication.json")):
            identifier = path.parent.name
            publication = self.repository.load(identifier, "publication")
            if (publication["graph_id"], publication["report_id"]) != (graph_id, report_id):
                continue
            result = self.result(identifier)
            if (result["graph_id"], result["report_id"]) != (graph_id, report_id):
                raise ValueError("Publication and episode identity mismatch")
            record = self.get(identifier)
            from ..graph_presentation import build_presentation

            return {"topology": record["topology"], "specification": record["specification"],
                    "episodes": result["episodes"],
                    "presentation": build_presentation(record["topology"]),
                    "identity": {"simulation_id": identifier, "report_id": report_id,
                                 "graph_id": graph_id, "topology_sha256": record["topology_sha256"],
                                 "runs": result["lineage"]}}
        return None

    def publish(self, identifier):
        """Explicit user action, canonical layers only. Never auto-approve research."""
        from rlredteam.causal_graph import build_causal_graph
        from rlredteam.storage.analytical_store import AnalyticalStore
        from rlredteam.storage.analytical_lineage import rebuild_report
        from rlredteam.storage.neo4j_projection import Neo4jProjectionStore
        from rlredteam.application.data.repository import ConnectionSettings
        from rlredteam.application.runtime_readiness import inspect_stores
        import os, psycopg

        with self.repository.locked():
            record = self.get(identifier)
            result = self.result(identifier)
            report, prepared, lineage = build_analytical_report(
                result["episodes"], experiment_id=identifier
            )
            graph = build_causal_graph(report.to_dict(), prepared)
            if graph.graph_id != result["graph_id"] or report.report_id != result["report_id"]:
                raise ValueError("Stored analytical identity mismatch")
            settings = ConnectionSettings.from_env()
            neo = Neo4jProjectionStore.connect(wait_seconds=0)
            try:
                with psycopg.connect(
                    host=settings.host,
                    port=settings.port,
                    user=settings.user,
                    password=settings.password,
                    dbname=settings.dbname,
                    sslmode=os.environ.get("POSTGRES_SSLMODE", "prefer"),
                    connect_timeout=4,
                    autocommit=True,
                ) as c:
                    store = AnalyticalStore(c)
                    store.ingest(
                        report,
                        graph,
                        lineage,
                        source_sha256=result["source_sha256"],
                        protocol_sha256=digest(
                            {
                                "engineering_simulation": record["specification_sha256"],
                                "research_status": "not_registered",
                            }
                        ),
                    )
                    if not store.is_approved(report.report_id):
                        store.approve(
                            report.report_id,
                            approver_label="engineering simulation operator",
                            reason="Explicit publication of unregistered synthetic simulation",
                            source="engineering_simulation",
                        )
                    rebuilt = rebuild_report(c, neo, report.report_id, graph.graph_id)
                    status = inspect_stores(c, neo, [report.report_id], True)
            finally:
                neo.close()
            publication = {
                "state": status["state"],
                "report_id": report.report_id,
                "graph_id": graph.graph_id,
                "evidence_class": "engineering_simulation",
                "research_status": "not_registered",
            }
            self.repository.save(identifier, "publication", publication)
            return {**publication, "assessment": record["specification"]["name"],
                    "freshness": status.get("freshness", "UNKNOWN"), "counts": rebuilt["counts"],
                    "projected_at": datetime.now(timezone.utc).isoformat(),
                    "projection_hash": rebuilt["projection_hash"]}
