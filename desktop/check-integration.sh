#!/usr/bin/env bash
# Disposable development fixtures only. No host ports, research volumes or egress.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
containers=()
cleanup() {
  status=$?
  if ((status != 0)); then
    for container in "${containers[@]}"; do
      podman logs --tail 40 "$container" >&2 || true
    done
  fi
  for ((i=${#containers[@]}-1; i>=0; i--)); do
    podman rm -f -v "${containers[$i]}" >/dev/null
  done
}
trap cleanup EXIT
api_image=localhost/security-rl-desktop-api:dev
builder_image=localhost/security-rl-desktop-builder:dev
podman image exists "$api_image"
podman image exists "$builder_image"
pg=$(podman run -d --network none --memory 512m --tmpfs /var/lib/postgresql/data \
  -e POSTGRES_USER=desktop_fixture -e POSTGRES_PASSWORD=isolated-desktop-fixture \
  -e POSTGRES_DB=desktop_fixture \
  -v "$repo/src/rlredteam/storage/schema.sql:/docker-entrypoint-initdb.d/schema.sql:ro,z" \
  docker.io/library/postgres:16-alpine)
containers+=("$pg")
neo=$(podman run -d --hostname localhost --network "container:$pg" --memory 2g --cpus 2 \
  --tmpfs /data:rw,mode=777 -e NEO4J_AUTH=neo4j/isolated-desktop-fixture \
  -e NEO4J_server_default__listen__address=127.0.0.1 \
  -e NEO4J_server_memory_heap_initial__size=256m -e NEO4J_server_memory_heap_max__size=512m \
  -e NEO4J_server_memory_pagecache_size=256m -e NEO4J_dbms_usage__report_enabled=false \
  docker.io/library/neo4j:5.26.0-community)
containers+=("$neo")
for attempt in {1..30}; do
  if podman exec "$pg" pg_isready -U desktop_fixture -d desktop_fixture >/dev/null; then break; fi
  sleep 1
done
common=(--network "container:$pg" -e PYTHONDONTWRITEBYTECODE=1 -e PYTHONPATH=/app/src:/app
  -e POSTGRES_HOST=127.0.0.1 -e POSTGRES_PORT=5432 -e POSTGRES_USER=desktop_fixture
  -e POSTGRES_PASSWORD=isolated-desktop-fixture -e POSTGRES_DB=desktop_fixture
  -e NEO4J_URI=bolt://127.0.0.1:7687 -e NEO4J_USER=neo4j -e NEO4J_PASSWORD=isolated-desktop-fixture
  -v "$repo:/app:ro,z" -w /app)
# Service startup is separate from assertions. Allow bounded cold JVM startup
# on a busy host, while retaining the tests' existing connection timeout.
podman run --rm "${common[@]}" "$api_image" python -c \
  'from rlredteam.storage.neo4j_projection import Neo4jProjectionStore; store = Neo4jProjectionStore.connect(wait_seconds=120); store.close()'
podman run --rm "${common[@]}" -e SECURITY_RL_DESKTOP_INTEGRATION=1 "$api_image" \
  pytest -q -s -p no:cacheprovider tests/test_desktop_persisted_integration.py
api=$(podman run -d "${common[@]}" \
  -e SECURITY_RL_API_TOKEN=desktop-integration-fixture-token-0001 \
  -e SECURITY_RL_ANALYST_REPORT_IDS=0495f97d405d0c1c65af83919b16f4410c3ddb05a3c71c72de462c1693cedc63 \
  -e SECURITY_RL_TWIN_SNAPSHOT=/tmp/twin.json "$api_image" sh -c \
  'python -c "from tests.digital_twin_fixtures import build; from rlredteam.digital_twin.serialization import dumps; from pathlib import Path; Path(\"/tmp/twin.json\").write_text(dumps(build()))" && exec uvicorn rlredteam.api.app:app --host 127.0.0.1 --port 8765 --no-access-log')
containers+=("$api")
if [[ "${SECURITY_RL_PACKAGE_TEST:-0}" == 1 ]]; then
  package=$(printf '%s\n' "$repo"/desktop/src-tauri/target/release/bundle/deb/*.deb)
  test -f "$package"
  for attempt in {1..50}; do
    if podman exec "$api" test -f /tmp/twin.json; then break; fi
    sleep .1
  done
  podman exec "$api" cat /tmp/twin.json | podman run --rm -i --network "container:$pg" \
    -v "$package:/installer/analyst.deb:ro,z" \
    -v "$repo/desktop/packaging/packaged-data-smoke.sh:/verification/data-smoke.sh:ro,z" \
    localhost/security-rl-desktop-clean-test:dev bash -c \
    'set -e; cat > /tmp/demo-twin.json; chmod 644 /tmp/demo-twin.json; dpkg -i /installer/analyst.deb; runuser -u analyst -- dbus-run-session -- bash /verification/data-smoke.sh'
fi
podman run --rm --network "container:$pg" --cpus 2 --memory 4g \
  -v "$repo/desktop:/app/desktop:rw,z" -w /app/desktop "$builder_image" npx playwright test
