#!/usr/bin/env bash
# Disposable, no-egress Phase 5 DB validation. Never consumes .env/research services.
set -euo pipefail
phase5_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
phase5_pg="rlrt-phase5-test-pg-$$"
phase5_neo="rlrt-phase5-test-neo-$$"
phase5_image="localhost/security-rl-neo4j-client:latest"
phase5_cleanup() {
    # Shared-network dependents must be removed before the namespace owner.
    podman rm -f -v "$phase5_neo" >/dev/null 2>&1 || true
    podman rm -f -v "$phase5_pg" >/dev/null 2>&1 || true
}
trap phase5_cleanup EXIT INT TERM
podman image exists "$phase5_image"
podman run -d --pull never --name "$phase5_pg" --network none \
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
    -e RLRT_PHASE5_TEST_ONLY=1 \
    -e POSTGRES_HOST=127.0.0.1 -e POSTGRES_PORT=5432 \
    -e POSTGRES_USER=phase5_test -e POSTGRES_PASSWORD=disposable-phase5-only \
    -e POSTGRES_DB=rlrt_phase5_test \
    -v "$phase5_root:/app:ro" -w /app "$phase5_image" \
    python -B -m pytest -q -s -m "not slow" -p no:cacheprovider \
    -p rlredteam.application.analytical_test_guard \
    tests/test_analytical_lineage.py tests/test_analytical_database.py \
    tests/test_attack_path_report.py tests/test_causal_graph.py \
    tests/test_neo4j_projection.py tests/test_causal_store.py
