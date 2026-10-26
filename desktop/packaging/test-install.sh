#!/usr/bin/env bash
set -euo pipefail
desktop=$(cd "$(dirname "$0")/.." && pwd)
package=$(printf '%s\n' "$desktop"/src-tauri/target/release/bundle/deb/*.deb)
test -f "$package"
# Only an installer and verification script enter this container. No repository.
podman run --rm --network none --cpus 2 --memory 4g \
  -v "$package:/installer/analyst.deb:ro,z" \
  -v "$desktop/packaging/installed-smoke.sh:/verification/installed-smoke.sh:ro,z" \
  localhost/security-rl-desktop-clean-test:dev bash -c '
    set -euo pipefail
    dpkg -i /installer/analyst.deb
    runuser -u analyst -- xvfb-run -a dbus-run-session -- bash /verification/installed-smoke.sh
    dpkg -r security-rl-analyst
    test ! -e /usr/bin/security-rl-desktop
    echo CLEAN_UNINSTALL_PASS
  '
