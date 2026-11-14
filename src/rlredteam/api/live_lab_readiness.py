"""Read-only LIVE_LAB checks. Never instantiates an API, lease or scanner process."""

import hashlib
import ipaddress
import json
import os
import socket
import struct
from pathlib import Path

from rlredteam.knowledge.serialization import digest
from rlredteam.observation.controlled_collection import CollectionBudget, ControlledNmapCollector

from .workspace_runtime import configuration_document, load_approvals, private_read


def configuration_check(path, request):
    document = configuration_document(path)
    if document.get("offline_processing_enabled") is not True:
        raise ValueError("canonical processing must be explicitly enabled")
    approvals = load_approvals(document.get("approvals", []))
    if request.get("operator_approved", False) is not False:
        raise ValueError("preflight requires operator approval not yet granted")
    values = {
        key: request[key] for key in ("scope_id", "authorization_id", "target", "ports", "profile")
    }
    if set(request) - {*values, "operator_approved"}:
        raise ValueError("unsupported preflight request field")
    budget = CollectionBudget(**document["collection_budget"])
    collector = ControlledNmapCollector(approvals, budget, context={"configuration": document})
    plan = collector.plan(**values)  # Plan only: no execution or persisted approval.
    private_read(document["vulnerability_snapshot"])
    from rlredteam.knowledge.vulnerabilities.importers import load_local

    knowledge = load_local(
        document["vulnerability_snapshot"], created_at=next(iter(approvals.values()))[1].valid_from
    )
    root = Path(document["state_directory"])
    if (
        not root.is_absolute()
        or any(p.is_symlink() for p in (root, *root.parents))
        or not root.is_dir()
        or root.stat().st_uid != os.getuid()
        or root.stat().st_mode & 0o077
        or not root.stat().st_mode & 0o200
        or not os.access(root, os.W_OK | os.X_OK)
    ):
        raise ValueError("private writable operational state required")
    if any((p / ".git").exists() for p in (root, *root.parents)):
        raise ValueError("operational state cannot be in a Git checkout")
    return {
        "scope": approvals[values["scope_id"]][0],
        "plan": plan,
        "knowledge_digest": knowledge.canonical_digest,
        "configuration_digest": digest(document),
        "neo4j_required": document.get("neo4j_projection_enabled", False),
    }


def topology_reasons(evidence, target):
    """Operator attestations are evidence, not a substitute for live introspection."""
    reasons = []
    try:
        if evidence["version"] != 1 or evidence["source"] != "operator-supplied":
            return ["Unsupported routing evidence provenance"]
        kali, router, web = (evidence[k] for k in ("kali", "router", "web"))
        if evidence.get("live_introspection_available") is not True:
            reasons.append("Live VM introspection unavailable; topology is operator-supplied only")
        attacker = ipaddress.ip_interface(kali["address"])
        front = ipaddress.ip_interface(router["attacker_address"])
        back = ipaddress.ip_interface(router["internal_address"])
        server = ipaddress.ip_interface(web["address"])
        if (
            attacker.network != front.network
            or back.network != server.network
            or front.network.overlaps(back.network)
        ):
            reasons.append("Attacker and target network separation not established")
        if (
            str(server.ip) != target
            or kali["route_network"] != str(server.network)
            or kali["route_via"] != str(front.ip)
            or web["default_via"] != str(back.ip)
        ):
            reasons.append("Operator routing evidence does not establish the selected target path")
        if router.get("ipv4_forwarding") is not True:
            reasons.append("Router IPv4 forwarding unverified")
        if (
            kali.get("external_egress_blocked") is not True
            or router.get("external_egress_blocked") is not True
        ):
            reasons.append("No-external-egress evidence missing for collector/router")
    except (KeyError, TypeError, ValueError):
        reasons.append("Incomplete or invalid operator topology evidence")
    return reasons


def route_snapshot(path=Path("/proc/net/route")):
    rows = []
    for line in path.read_text().splitlines()[1:]:
        fields = line.split()
        destination, gateway, mask = (
            socket.inet_ntoa(struct.pack("<I", int(fields[i], 16))) for i in (1, 2, 7)
        )
        if int(fields[3], 16) & 1:
            rows.append(
                {
                    "interface": fields[0],
                    "network": str(ipaddress.ip_network(destination + "/" + mask)),
                    "gateway": gateway,
                }
            )
    return rows


def route_reasons(rows, target, topology):
    if any(ipaddress.ip_network(r["network"]).prefixlen == 0 for r in rows):
        return ["Collector namespace has a default route; external isolation is unproven"]
    address = ipaddress.ip_address(target)
    matches = [r for r in rows if address in ipaddress.ip_network(r["network"])]
    if not matches:
        return ["Selected collector namespace has no route to the authorized target"]
    route = max(matches, key=lambda r: ipaddress.ip_network(r["network"]).prefixlen)
    if route["gateway"] != topology["kali"]["route_via"]:
        return ["Collector route gateway differs from supplied isolated router"]
    return []


def database_reasons(neo4j_required=False):
    reasons = []
    try:
        import psycopg

        from rlredteam.storage import (
            analytical_migrations,
            correlation_migrations,
            entity_migrations,
            evidence_migrations,
            twin_migrations,
        )
        from rlredteam.storage.postgres_logger import connection_string

        with psycopg.connect(
            connection_string(),
            autocommit=True,
            connect_timeout=3,
            options="-c default_transaction_read_only=on -c statement_timeout=3000",
        ) as connection:
            for module, table in (
                (analytical_migrations, "analytical_schema_migrations"),
                (evidence_migrations, "normalized_evidence.evidence_schema_migrations"),
                (entity_migrations, "entity_reconciliation.schema_migrations"),
                (twin_migrations, "digital_twin_state.schema_migrations"),
                (correlation_migrations, "vulnerability_correlation.schema_migrations"),
            ):
                source = Path(module.__file__).with_suffix(".sql")
                if module is analytical_migrations:
                    source = source.with_name("analytical_migration.sql")
                    expected = hashlib.sha256(source.read_bytes()).hexdigest()
                else:
                    source = module.MIGRATION_PATH
                    expected = digest(source.read_text())
                actual = connection.execute(
                    "SELECT checksum FROM " + table + " WHERE version=%s", (module.VERSION,)
                ).fetchone()
                if actual != (expected,):
                    reasons.append(
                        "Workspace migration missing or checksum invalid: " + module.VERSION
                    )
    except Exception:
        reasons.append("PostgreSQL unavailable or workspace migrations incomplete")
    if neo4j_required:
        try:
            from rlredteam.storage.neo4j_projection import Neo4jProjectionStore

            store = Neo4jProjectionStore.connect(wait_seconds=0)
            store.close()
        except Exception:
            reasons.append("Required Neo4j projection service unavailable")
    return reasons


def api_reasons(expected=None):
    from urllib.request import ProxyHandler, Request, build_opener

    try:
        token = os.environ.get("SECURITY_RL_API_TOKEN", "")
        if len(token) < 32:
            return ["API token not configured"]
        opener = build_opener(ProxyHandler({}))
        for path in ("health", "workspace/live/configuration"):
            request = Request(
                "http://127.0.0.1:8765/api/" + path, headers={"Authorization": "Bearer " + token}
            )
            with opener.open(request, timeout=3) as response:
                document = json.load(response)
            if path.endswith("configuration") and document.get("enabled") is not True:
                return ["Running API has no enabled canonical live collector"]
            if path.endswith("configuration") and expected is not None:
                plan = expected["plan"]
                scope = next((s for s in document.get("scopes", [])
                              if s["scope_id"] == plan["scope_id"]), {})
                if (scope.get("scope_digest") != plan["scope_digest"]
                        or scope.get("authorization_digest") != plan["authorization_digest"]
                        or document.get("budget") != json.loads(json.dumps(plan["budget"]))
                        or document.get("configuration_digest") != expected["configuration_digest"]
                        or document.get("knowledge_digest") != expected["knowledge_digest"]):
                    return ["Running API identity/budget differs from selected configuration"]
        return []
    except Exception:
        return ["Configured loopback API unavailable or authentication rejected"]


def main():
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("configuration", "dependencies", "route"))
    parser.add_argument("--request", required=True)
    parser.add_argument("--topology", required=True)
    args = parser.parse_args()
    reasons = []
    try:
        request = json.loads(private_read(args.request))
        topology = json.loads(private_read(args.topology))
        if args.mode == "configuration":
            configuration_check(os.environ["SECURITY_RL_WORKSPACE_CONFIG"], request)
            reasons.extend(topology_reasons(topology, request["target"]))
        elif args.mode == "dependencies":
            document = configuration_document(os.environ["SECURITY_RL_WORKSPACE_CONFIG"])
            reasons.extend(database_reasons(document.get("neo4j_projection_enabled", False)))
            expected = configuration_check(os.environ["SECURITY_RL_WORKSPACE_CONFIG"], request)
            reasons.extend(api_reasons(expected))
        else:
            reasons.extend(route_reasons(route_snapshot(), request["target"], topology))
    except Exception:
        reasons.append(
            "Invalid private configuration/request or unavailable read-only prerequisite"
        )
    print(json.dumps({"status": "BLOCKED" if reasons else "READY", "reasons": reasons}))
    return bool(reasons)


if __name__ == "__main__":
    raise SystemExit(main())
