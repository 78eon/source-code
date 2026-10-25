# Security-RL Analyst desktop (local development)

This worktree is separate from the frozen campaign checkout. Do not run campaign
commands here. No training, scanning, exploitation or final-test UI is exposed.

## Podman workflow

From this worktree:
1. `make api-image desktop-image desktop-install`
2. Set a session-only `SECURITY_RL_API_TOKEN` of at least 32 random characters.
   Set PostgreSQL/Neo4j variables only for an approved analyst database.
   Use dedicated read-only database accounts. Do not attach campaign database volumes.
3. `make api-dev` publishes **127.0.0.1:8765 only**.
4. `make desktop-build` builds the native debug executable.
5. `make desktop-dev` opens the Tauri development shell (X11/XWayland).
   Requires a valid DISPLAY and XAUTHORITY cookie; no broad xhost access is granted.
   Enter the API token in the connection bar; it is held in memory only.

`make desktop-check` checks TypeScript, graph contracts, production assets and Rust.
The backend lifecycle is explicit: Tauri does not launch or stop the API yet.
Frontend dependencies are locked in package-lock.json; Rust dependencies in Cargo.lock.
Container builds need registry access; tests can run network-disabled after installation.
No dependencies are installed on the host.

## Boundaries and incomplete readers

PostgreSQL remains authoritative for stored causal evidence and reports.
Neo4j is the graph projection/analysis database; Sigma and Graphology only render
its DTO. They do not discover hosts, compute attack paths or connect to databases.

Assets currently list recorded graph nodes, not a live network inventory.
Findings expose recorded vulnerability identifiers with UNKNOWN applicability
until a recorded applicability result can be joined safely. No CVSS is invented.
Digital Twin persistence and dedicated simulation browsing are explicitly
UNAVAILABLE. Reports and attack paths use stored backend records only.

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
gui/data/evidence/discovery_count_audit.json is retained unchanged as historical evidence.

Tauri uses Linux WebKitGTK prerequisites:
https://v2.tauri.app/start/prerequisites/
Sigma interaction contract:
https://www.sigmajs.org/reference/events/
