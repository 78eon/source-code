# Security-RL Analyst desktop (local development)

This worktree is separate from the frozen campaign checkout. Do not run campaign
commands here. No training, scanning, exploitation or final-test UI is exposed.

## Podman workflow

From this worktree:
1. `make api-image desktop-image desktop-install`
2. Set PostgreSQL/Neo4j variables only for an approved analyst database.
   Use dedicated read-only database accounts. Do not attach campaign database volumes.
   Set `SECURITY_RL_ANALYST_REPORT_IDS` to comma-separated approved report IDs.
   No reports, graph projections or simulations are browsed by default.
   Optionally set `SECURITY_RL_TWIN_SNAPSHOT` to an existing validated Digital Twin
   JSON export; it is mounted read-only without converting or regenerating it.
3. Native mode starts its own Python API; do not start a separate API for it.
4. `make desktop-build` builds the native debug executable.
5. `make desktop-dev` opens the Tauri development shell (X11/XWayland).
   Requires a valid DISPLAY and XAUTHORITY cookie; no broad xhost access is granted.
   The native shell obtains a fresh API token through a private process pipe.
   The token is held in memory and is never embedded in frontend assets.

`make desktop-check` checks TypeScript, graph contracts, production assets and Rust.
Tauri starts one owned backend, waits up to 20 seconds for its matching health
response, and closes its stdin pipe on exit. The backend binds an ephemeral
127.0.0.1 port. A runtime lock rejects duplicate desktop-owned backends; cleanup
targets only the owned child. Python runtime packaging for distribution is pending;
the Podman development image supplies the runtime today.
Frontend dependencies are locked in package-lock.json; Rust dependencies in Cargo.lock.
Container builds need registry access; tests can run network-disabled after installation.
No dependencies are installed on the host.

For browser development only, set a session-only `SECURITY_RL_API_TOKEN` (32+
random characters), run `make api-dev`, and enter the token in the connection bar.
This separate API binds **127.0.0.1:8765 only**.

`make desktop-integration` creates disposable PostgreSQL/Neo4j containers without
egress or published ports, projects deterministic development evidence through
the existing store, and runs the real API/Sigma browser test. It removes its own
containers afterwards. `make desktop-native-smoke` checks actual native startup,
owned backend health and shutdown inside network-disabled Podman.

## Persisted readers and boundaries

PostgreSQL remains authoritative for stored causal evidence and reports.
Neo4j is the graph projection/analysis database; Sigma and Graphology only render
its DTO. They do not discover hosts, compute attack paths or connect to databases.

Assets currently list recorded graph nodes, not a live network inventory.
Findings expose recorded vulnerability identifiers with UNKNOWN applicability
until a recorded applicability result can be joined safely. No CVSS is invented.
Digital Twin reads the existing validated snapshot JSON format. With no configured
snapshot it shows "No persisted Digital Twin available". Simulation replay reads
selected persisted Phase 14 report facts and stored causal paths; absent run metadata
and episode outcomes stay unknown. No simulator is constructed or executed.
Reports and attack paths use explicitly selected stored backend records only.

The graph uses a deterministic circular layout, not a claim about physical topology.
Status is source-specific: CONNECTED means the selected endpoint returned data;
DEGRADED means API reachable but data/authentication/integration unavailable.
OFFLINE means the local API could not be reached.

## Audit and migration

Non-Qt backend, models, repository and evidence readers moved from gui/ into
src/rlredteam/application/. Research readers are retained for compatibility but
not exposed by the presentation API. The non-Qt TrainRequest remains unexposed.
Qt presentation, Qt workers, dependencies and targets were removed after extraction
tests passed. Mixed GUI tests keep their backend/evidence assertions.
`gui/` contains no frontend code. Its sole remaining file,
`gui/data/evidence/discovery_count_audit.json`, is retained unchanged as historical
evidence referenced by a compatibility reader. The frontend is React/TypeScript,
Tauri, Sigma.js and Graphology under `desktop/`; Python supplies backend services.

Tauri uses Linux WebKitGTK prerequisites:
https://v2.tauri.app/start/prerequisites/
Sigma interaction contract:
https://www.sigmajs.org/reference/events/
