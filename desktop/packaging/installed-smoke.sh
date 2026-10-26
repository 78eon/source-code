#!/usr/bin/env bash
# Runs as an unprivileged user in a clean Podman container, under Xvfb + D-Bus.
set -euo pipefail
export XDG_CONFIG_HOME="$HOME/.config" XDG_DATA_HOME="$HOME/.local/share"
export XDG_RUNTIME_DIR="/tmp/analyst-runtime-$(id -u)"
mkdir -p "$XDG_RUNTIME_DIR"
chmod 700 "$XDG_RUNTIME_DIR"
unset PYTHONPATH PYTHONHOME SECURITY_RL_BACKEND_PYTHON
for tool in python3 node cargo; do
  if command -v "$tool" >/dev/null; then echo "Unexpected system tool: $tool" >&2; exit 1; fi
done
runtime=$(dpkg -L security-rl-analyst | awk '/\/security-rl-api\/security-rl-api$/ {print; exit}')
test -x "$runtime"
"$runtime" --config get | jq -e '.configured == false' >/dev/null
fluxbox >/tmp/desktop-window-manager.log 2>&1 &
wm_pid=$!
cleanup() {
  result=$?
  if ((result != 0)); then
    cat /tmp/first-start.log /tmp/native-start.log 2>/dev/null || true
  fi
  kill "$wm_pid" 2>/dev/null || true
  exit "$result"
}
trap cleanup EXIT
window_ready() {
  for attempt in {1..120}; do
    if wmctrl -l 2>/dev/null | grep -q 'Security-RL Analyst'; then return; fi
    sleep .25
  done
  echo 'Native window did not appear' >&2; return 1
}
close_app() {
  wmctrl -c 'Security-RL Analyst'
  for attempt in {1..100}; do
    if ! kill -0 "$app_pid" 2>/dev/null; then wait "$app_pid"; return; fi
    sleep .1
  done
  echo 'Native application did not stop gracefully' >&2; return 1
}
# First install must open without environment variables or a developer checkout.
security-rl-desktop >/tmp/first-start.log 2>&1 & app_pid=$!
window_ready
sleep 2
close_app
echo FIRST_RUN_PASS
printf '%s' '{"settings":{"version":1,"profile":"demo","postgres":null,"neo4j":null,"report_ids":[],"twin_snapshot":null}}' |
  "$runtime" --config save | jq -e '.configured == true' >/dev/null
test "$(stat -c %a "$XDG_CONFIG_HOME/org.securityrl.analyst/settings.json")" = 600
"$runtime" --config check | jq -e '.offline == true' >/dev/null
# Standalone bundled API startup, authenticated read, and stdin-EOF shutdown.
coproc API { exec "$runtime"; }
api_pid=$API_PID; api_in=${API[1]}; api_out=${API[0]}
read -r -t 20 handshake <&"$api_out"
origin=$(jq -er '.origin' <<<"$handshake")
token=$(jq -er '.token' <<<"$handshake")
[[ "$origin" == http://127.0.0.1:* ]]
for attempt in {1..50}; do
  if curl --silent --fail "$origin/api/health" >/tmp/health.json; then break; fi
  sleep .1
done
jq -e '.read_only == true' /tmp/health.json >/dev/null
test "$(curl -s -o /dev/null -w '%{http_code}' "$origin/api/assets")" = 401
curl --silent --fail -H "Authorization: Bearer $token" "$origin/api/digital-twin/summary" |
  jq -e '.status == "UNAVAILABLE"' >/dev/null
exec {api_in}>&-
wait "$api_pid"
unset token handshake
echo BUNDLED_API_PASS
# Real OS keyring, not a fake or plaintext keyring implementation.
eval "$(printf '%s' 'isolated-test-keyring-password' | gnome-keyring-daemon --unlock --components=secrets)"
printf '%s' '{"settings":{"version":1,"profile":"analyst","postgres":{"host":"127.0.0.1","port":5432,"database":"external_demo","user":"readonly","sslmode":"disable"},"neo4j":null,"report_ids":[],"twin_snapshot":null},"passwords":{"postgres":"vault-only-test-secret"}}' |
  "$runtime" --config save | jq -e '.configured == true' >/dev/null
! grep -q 'vault-only-test-secret' "$XDG_CONFIG_HOME/org.securityrl.analyst/settings.json"
if grep -R -a -q 'vault-only-test-secret' "$XDG_DATA_HOME/keyrings"; then
  echo 'Keyring persisted an unencrypted test secret' >&2; exit 1
fi
"$runtime" --config get | jq -e '.settings.postgres.database == "external_demo" and (.settings | has("password") | not)' >/dev/null
"$runtime" --config check | jq -e '.checks.postgres | startswith("UNAVAILABLE:")' >/dev/null
echo SECRET_SERVICE_PASS
# Return to offline demo; repeat native startup and prove its owned child exits.
printf '%s' '{"settings":{"version":1,"profile":"demo","postgres":null,"neo4j":null,"report_ids":[],"twin_snapshot":null}}' | "$runtime" --config save >/dev/null
for cycle in 1 2; do
  security-rl-desktop >/tmp/native-start.log 2>&1 & app_pid=$!
  window_ready
  for attempt in {1..100}; do
    if ps -C security-rl-api -o args= | grep -v -- '--config' | grep -q 'security-rl-api'; then break; fi
    sleep .2
  done
  test "$(ps -C security-rl-api -o args= | grep -v -- '--config' | grep -c 'security-rl-api')" = 1
  close_app
  ! pgrep -x security-rl-api >/dev/null
done
echo 'CLEAN_INSTALL_PASS: first run, offline profile, authenticated bundled API, real OS keyring, native start/stop twice; no host Python/Node/Rust, no repository mount'
