#!/usr/bin/env bash
# Disposable fixture database namespace only. No repository is mounted here.
set -euo pipefail
export XDG_CONFIG_HOME="$HOME/.config" XDG_DATA_HOME="$HOME/.local/share"
export XDG_RUNTIME_DIR="/tmp/analyst-data-$(id -u)"
mkdir -m 700 "$XDG_RUNTIME_DIR"
runtime=$(dpkg -L security-rl-analyst | awk '/\/security-rl-api\/security-rl-api$/ {print; exit}')
eval "$(printf '%s' isolated-test-keyring-password | gnome-keyring-daemon --unlock --components=secrets)"
printf '%s' '{"settings":{"version":1,"profile":"demo","postgres":{"host":"127.0.0.1","port":5432,"database":"desktop_fixture","user":"desktop_fixture","sslmode":"disable"},"neo4j":{"uri":"bolt://127.0.0.1:7687","database":"neo4j","user":"neo4j"},"report_ids":["0495f97d405d0c1c65af83919b16f4410c3ddb05a3c71c72de462c1693cedc63"],"twin_snapshot":"/tmp/demo-twin.json"},"passwords":{"postgres":"isolated-desktop-fixture","neo4j":"isolated-desktop-fixture"}}' |
  "$runtime" --config save | jq -e '.configured == true' >/dev/null
"$runtime" --config check | jq -e '(.checks.postgres | startswith("CONNECTED")) and (.checks.neo4j | startswith("CONNECTED"))' >/dev/null
coproc API { exec "$runtime"; }
api_pid=$API_PID; api_in=${API[1]}; api_out=${API[0]}
read -r -t 20 reply <&"$api_out"
origin=$(jq -er .origin <<<"$reply"); token=$(jq -er .token <<<"$reply")
for attempt in {1..50}; do
  if curl -sf "$origin/api/health" >/dev/null; then break; fi
  sleep .1
done
get() { curl --silent --fail -H "Authorization: Bearer $token" "$origin/api/$1"; }
get assets | jq -e 'length == 4' >/dev/null
get graph/topology | jq -e '(.nodes | length) == 4 and (.edges | length) == 6' >/dev/null
get attack-paths | jq -e 'length == 1' >/dev/null
get reports | jq -e 'length == 1' >/dev/null
get digital-twin/summary | jq -e '.counts.assets == 4' >/dev/null
get digital-twin/entities | jq -e 'length > 4' >/dev/null
get simulations | jq -e '.items[0].path_available == true' >/dev/null
exec {api_in}>&-
wait "$api_pid"
echo 'PACKAGED_DATA_PASS: external PostgreSQL and Neo4j, graph, reports, persisted Twin and simulation replay; real OS keyring; no repository mounted'
