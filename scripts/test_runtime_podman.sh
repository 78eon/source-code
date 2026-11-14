#!/usr/bin/env bash
# Disposable, no-egress Phase 6 runtime validation. Never consumes .env/research services.
set -euo pipefail
phase5_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
phase5_pg="rlrt-phase6-test-pg-$$"
phase5_neo="rlrt-phase6-test-neo-$$"
phase5_image="localhost/security-rl-desktop-api:dev"
phase6_network="rlrt-phase6-network-$$"
phase6_volume="rlrt-phase6-output-$$"
phase5_cleanup() {
    # Shared-network dependents must be removed before the namespace owner.
    podman rm -f -v "$phase5_neo" >/dev/null 2>&1 || true
    podman rm -f -v "$phase5_pg" >/dev/null 2>&1 || true
    podman network rm "$phase6_network" >/dev/null 2>&1 || true
    podman volume rm "$phase6_volume" >/dev/null 2>&1 || true
}
trap phase5_cleanup EXIT INT TERM
podman image exists "$phase5_image"
podman network create --internal "$phase6_network" >/dev/null
podman volume create "$phase6_volume" >/dev/null
podman run --rm --network none --user 0:0 --cap-drop ALL \
    -v "$phase6_volume:/runtime:rw" -v "$phase5_root:/app:ro" \
    "$phase5_image" python -B -c 'from pathlib import Path; p=Path("/runtime/permission-check"); p.write_text("temporary test only"); assert p.read_text()=="temporary test only"; lines=Path("/proc/self/mountinfo").read_text().splitlines(); assert any(x.split()[4]=="/app" and "ro" in x.split()[5].split(",") for x in lines); print("ROOTLESS_NAMED_VOLUME_AND_RO_SOURCE PASS")'
podman run -d --pull never --name "$phase5_pg" --network "$phase6_network" \
    --tmpfs /var/lib/postgresql/data:rw \
    -e POSTGRES_USER=phase5_test -e POSTGRES_PASSWORD=disposable-phase5-only \
    -e POSTGRES_DB=rlrt_phase5_test docker.io/library/postgres:16-alpine >/dev/null
for phase5_try in {1..30}; do
    if podman exec "$phase5_pg" pg_isready -U phase5_test -d rlrt_phase5_test >/dev/null; then
        break
    fi
    sleep 1
done
podman exec "$phase5_pg" pg_isready -U phase5_test -d rlrt_phase5_test
podman exec "$phase5_pg" postgres --version
# hostname localhost avoids Java hostname resolution failure in the shared,
# DNS-free network namespace. No service is published to host/LAN.
podman run -d --pull never --name "$phase5_neo" --hostname localhost \
    --network "container:$phase5_pg" --user 7474:7474 --cap-drop ALL \
    --security-opt no-new-privileges --tmpfs /data:rw,mode=1777 \
    --tmpfs /logs:rw,mode=1777 --memory 1g --stop-timeout 30 \
    -e NEO4J_AUTH=neo4j/disposable-phase5-only \
    -e NEO4J_server_memory_heap_initial__size=128m \
    -e NEO4J_server_memory_heap_max__size=256m \
    -e NEO4J_server_memory_pagecache_size=128m \
    docker.io/library/neo4j:5.26.0-community >/dev/null
for phase5_try in {1..45}; do
    if podman exec "$phase5_neo" wget -q -O /dev/null http://localhost:7474; then
        break
    fi
    sleep 1
done
podman exec "$phase5_neo" wget -q -O /dev/null http://localhost:7474
podman run --rm --pull never --network "container:$phase5_pg" \
    --cap-drop ALL --security-opt no-new-privileges --memory 4g --pids-limit 512 \
    -e PYTHONPATH=/app/src:/app -e PYTHONDONTWRITEBYTECODE=1 \
    -e OPENBLAS_NUM_THREADS=1 -e OMP_NUM_THREADS=1 -e MKL_NUM_THREADS=1 \
    -e NEO4J_URI=bolt://127.0.0.1:7687 -e NEO4J_USER=neo4j \
    -e NEO4J_PASSWORD=disposable-phase5-only \
    -e RLRT_PHASE5_TEST_ONLY=1 \
    -e POSTGRES_HOST=127.0.0.1 -e POSTGRES_PORT=5432 \
    -e POSTGRES_USER=phase5_test -e POSTGRES_PASSWORD=disposable-phase5-only \
    -e POSTGRES_DB=rlrt_phase5_test \
    -v "$phase5_root:/app:ro" -w /app "$phase5_image" \
    python -B -m pytest -q -s -m "not slow" -p no:cacheprovider \
    -p rlredteam.application.analytical_test_guard \
    tests/test_runtime_readiness.py tests/test_runtime_integration.py \
    tests/test_compose_network.py tests/test_analyst_api.py \
    tests/test_analytical_lineage.py tests/test_analytical_database.py

# A real pg_dump/restore using matching PostgreSQL16 tools inside the disposable
# server. No host DB, credential file, or production target is accepted.
podman run --rm --network "container:$phase5_pg" \
    -e PYTHONPATH=/app/src -e POSTGRES_HOST=127.0.0.1 -e POSTGRES_PORT=5432 \
    -e POSTGRES_USER=phase5_test -e POSTGRES_PASSWORD=disposable-phase5-only \
    -e POSTGRES_DB=rlrt_phase5_test -v "$phase5_root:/app:ro" -w /app "$phase5_image" \
    python -B -c 'import psycopg; from rlredteam.storage.postgres_logger import ensure_schema,connection_string; from rlredteam.storage.analytical_migrations import migrate; from rlredteam.application.analytical_fixture import fixture_bundle; from rlredteam.storage.analytical_store import AnalyticalStore; from rlredteam.storage.analytical_identity import digest; c=psycopg.connect(connection_string(),autocommit=True); ensure_schema(c); migrate(c); d,r,g,e=fixture_bundle(); AnalyticalStore(c).ingest(r,g,e,source_sha256=digest(d),protocol_sha256=digest({"fixture":"not_registered"})); c.close()'
podman exec "$phase5_pg" sh -ec '
  pg_dump -U phase5_test -d rlrt_phase5_test --no-owner --no-acl > /tmp/phase6-backup.sql
  dropdb -U phase5_test rlrt_phase5_test
  createdb -U phase5_test rlrt_phase5_test
  psql -U phase5_test -d rlrt_phase5_test -v ON_ERROR_STOP=1 -f /tmp/phase6-backup.sql >/dev/null
'
podman run --rm --network "container:$phase5_pg" \
    -e PYTHONPATH=/app/src -e POSTGRES_HOST=127.0.0.1 -e POSTGRES_PORT=5432 \
    -e POSTGRES_USER=phase5_test -e POSTGRES_PASSWORD=disposable-phase5-only \
    -e POSTGRES_DB=rlrt_phase5_test -v "$phase5_root:/app:ro" -w /app "$phase5_image" \
    python -B -c 'import psycopg; from rlredteam.storage.postgres_logger import connection_string; from rlredteam.application.analytical_fixture import fixture_bundle; from rlredteam.storage.causal_store import CausalGraphStore; c=psycopg.connect(connection_string()); d,r,g,e=fixture_bundle(); assert CausalGraphStore(c).load(g.graph_id).to_dict()==g.to_dict(); assert c.execute("SELECT report_id FROM analytical_report_lineage").fetchone()[0]==r.report_id; print("POSTGRES_BACKUP_RESTORE PASS"); c.close()'
