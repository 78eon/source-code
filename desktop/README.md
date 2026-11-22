# Security-RL Analyst desktop (local development)

This worktree is separate from the frozen campaign checkout. Do not run campaign
commands here. Research browsing is read-only. Lab collection controls require
backend authorization and explicit approval; no training or final-test execution UI is exposed.

## Podman workflow

From this worktree:
1. `make api-image desktop-image desktop-install`
2. Native first-run setup asks for a Demo or Analyst profile. Configure only approved
   external databases with dedicated read-only accounts; do not attach campaign volumes.
   Select explicit report IDs and, optionally, a validated Digital Twin snapshot path.
   Nothing is browsed by default. The Demo profile can run offline, with explicit
   empty/unavailable views; it does not invent evidence or bundle research results.
3. Native mode starts its own Python API; do not start a separate API for it.
4. `make desktop-build` builds the native debug executable.
5. `make desktop-dev` opens the Tauri development shell (X11/XWayland).
   Requires a valid DISPLAY and XAUTHORITY cookie; no broad xhost access is granted.
   The native shell obtains a fresh API token through a private process pipe.
   The token is held in memory and is never embedded in frontend assets.
   `desktop-dev` merges `src-tauri/tauri.dev.conf.json` to omit packaged resources
   during development. It uses the builder's `SECURITY_RL_BACKEND_PYTHON`; no
   `src-tauri/runtime/security-rl-api` directory is required. Release packaging
   uses the base configuration and still requires the real PyInstaller runtime.
   Development must run with rootless Podman in your desktop session. The launcher
   forwards `DBUS_SESSION_BUS_ADDRESS` and `XDG_RUNTIME_DIR`, mounts only the session
   bus socket read-only, and creates a private mode-0700 runtime directory. It expects
   `DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus`.
   Container UID 0 maps to the launching host user; `--user 1000:1000` would map
   to a subordinate host UID. A development-only `SECURITY_RL_DBUS_AUTH_UID`
   supplies the launching host UID for Jeepney EXTERNAL authentication; the host
   bus still validates it against kernel peer credentials. No `keep-id` mapping,
   host keyring files, or plaintext credential fallback is used. Installed/frozen
   builds ignore this adapter. The host keyring must still be unlocked, and its
   normal permission prompts may appear. The forwarded bus grants access to that
   user's session services; use only the trusted development image.

`make desktop-check` checks TypeScript, graph contracts, production assets and Rust.
Tauri starts one owned backend, waits up to 20 seconds for its matching health
response, and closes its stdin pipe on exit. The backend binds an ephemeral
127.0.0.1 port. A runtime lock rejects duplicate desktop-owned backends; cleanup
targets only the owned child. Release builds use the bundled Python/FastAPI executable;
development builds can use the Podman Python executable. Installed releases ignore
the development executable override and do not require a checkout or host Python.
Frontend dependencies are locked in package-lock.json; Rust dependencies in Cargo.lock.
Container builds need registry access; tests can run network-disabled after installation.
No dependencies are installed on the host.

For browser development only, set a session-only `SECURITY_RL_API_TOKEN` (32+
random characters), run `make api-dev`, and enter the token in the connection bar.
This separate API binds **127.0.0.1:8765 only**.
Browser/API development continues to accept PostgreSQL/Neo4j environment variables,
`SECURITY_RL_ANALYST_REPORT_IDS` and `SECURITY_RL_TWIN_SNAPSHOT`. Native mode uses its
explicit saved settings and clears inherited database/campaign settings.

## Installable package (build and test only inside Podman)

`make desktop-package-image` builds the pinned packaging environment.
`make desktop-package` freezes the allowlisted API runtime, audits its archive and
builds the release Linux x86-64 Debian package under `src-tauri/target/release/bundle/deb/`.
The required Python interpreter, Python packages and MITRE catalogue are included.
The system WebKitGTK/GTK libraries are declared Debian dependencies. PostgreSQL and
Neo4j servers are not bundled. No Qt/PySide6, models, checkpoints, research configs,
campaign evidence, documentation directories or repository checkout is included.

`make desktop-package-test` installs the artifact in a disposable Podman container
with no system Python/Node/Rust executable and no repository mount. It exercises
first run, real Secret Service storage, bundled API authentication, repeated native
start/stop and uninstall. It never installs anything on the host.

Public settings are stored at `$XDG_CONFIG_HOME/org.securityrl.analyst/settings.json`
(or `~/.config/...`) with mode 0600 inside an owner-only 0700 directory. Passwords
are stored only in Linux Secret Service, keyed to each connection identity. A locked
or unavailable keyring produces an actionable error; there is no plaintext fallback.
The package recommends `gnome-keyring`; another compatible OS Secret Service also
works. Removing a connection does not delete its old OS-keyring item; manage retained
credentials through the operating system's password manager.

Settings validates structure, ports, report scope, snapshot integrity and TLS.
Remote PostgreSQL requires `verify-full`; remote Neo4j requires a `+s` URI.
"Save and check connections" performs bounded read-only connection checks. A service
outage is reported without disclosing passwords or raw database exceptions. Database
services remain administrator-managed and are never started by the desktop.

Uninstall removes the application/runtime; user settings and keyring entries are
retained deliberately. Package builds are local and unsigned; no publication or push
is performed by these targets.

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

## Registered Research view

`GET /api/research/registered-results` is authenticated and read-only. It reads
protocol/training manifests and validation summaries, never checkpoints or held-out
evaluations. The view preserves each policy separately, including failed reward-rise
and convergence diagnostics. Missing metrics remain unavailable; a stored
`final_test_evaluated: false` displays “Pending / Not Evaluated”.

Source runs default to the archive identified by `scripts/verify_registered_boundary.py`.
`make api-dev`, `make desktop-dev`, and the workspace launcher mount that archive
read-only without relabeling it when present. Set `SECURITY_RL_REGISTERED_CAMPAIGN`
to override its host directory. For an installed backend, set this variable to an
accessible external archive directory before launching the application. Releases
include the reader but do not bundle campaign evidence. An absent archive produces
an explicit unavailable state; it does not fall back to demo results.

The contract includes source file SHA256 values and checks manifest self-hashes and
training/validation identity agreement. This is metadata consistency checking, not
an independent attestation of checkpoint contents or a replacement for the registered
boundary verifier. No pooled research statistics or inferred held-out results are returned.

## Development database connections

`desktop-dev` shares only `org.securityrl.analyst` from the host's
`${XDG_CONFIG_HOME:-$HOME/.config}` with the development container. This is the
public settings JSON, not a password store; credentials remain in Secret Service.
The container uses `XDG_CONFIG_HOME=/app/desktop-config`, so setup and subsequent
launches read the same settings file the host operator inspects.

The host-network launch default is `DESKTOP_NEO4J_URI=bolt://127.0.0.1:7687`.
Override that Make variable for a different published development endpoint; the
Compose hostname in an inherited `NEO4J_URI` is not forwarded as the default.
Submitted setup values are saved first and then checked. Saved settings and
connection-specific keyring credentials are authoritative for the native backend:
inherited `POSTGRES_*`, `NEO4J_*` and libpq `PG*` settings are cleared before activation.
Changing a connection identity requires re-entering its password; credentials are
not silently reused across different addresses/users/databases.

A nonblank password replaces the matching keyring entry and is read back before
settings are reported saved. A blank password keeps the existing entry. Connection
checks distinguish keyring, authentication/rate-limit, address, database, TLS and
permission failures using fixed messages, with no raw driver exceptions or secrets.
One database's missing credential does not hide the other database's result.
An authentication failure requires the current working database password in the UI;
it does not authorize a database password reset. Wait for any authentication-rate
limit to expire before retrying with the correct credential.

## Engineering simulations (development only)

The development desktop enables a dedicated `engineering-simulations` state volume.
Choose **New Simulation** for the ten-step brief, network, inventory, services,
vulnerabilities, identity, controls, objectives, settings and review wizard.
Preview does not save a simulation. **Create Simulation** seals the specification
and deterministic topology; **Run Simulation** explicitly executes bounded,
in-memory `EnterpriseCyberEnv` episodes. Saved runs reopen without rerunning them.

The reviewed adapter uses existing V2 observed-knowledge reasoning and masked
fallback actions, **not a PPO checkpoint**. Bounds are 40 hosts, 8 subnets,
4 service definitions, 3 episodes and 200 steps per episode. Reserved research
seeds are rejected. Identity labels, monitoring and service accessibility remain
descriptive where the base environment cannot enforce them; the wizard/review
discloses these limitations. Catalogue CVEs are attributed metadata annotations,
not assertions that real products are exploitable. Synthetic risk scores are
kept separate from CVSS.

Playback, canonical attack/provenance graph filters, recorded explanations and
the assessment summary use stored evidence. HTML, paginated PDF and JSON exports
include `SIMULATED SECURITY ASSESSMENT — NOT A LIVE PENETRATION TEST`, provenance
and limitations. PDF uses built-in Latin-1 fonts; JSON/HTML retain Unicode.
Execution is synchronous and playback begins after completion, rather than
pretending to stream simulated events in real time.

Every record is marked `engineering_simulation` / `not_registered`. No registered
checkpoint, campaign result or held-out evaluation enters this path. Explicit
**Publish canonical evidence and Neo4j projection** uses `AnalyticalStore`, approval
and `rebuild_report`; it does not silently change the selected workspace report.
The existing database role needs write permissions for this explicit publication.
The frozen research view and release packaging remain separate; packaged simulation
execution is disabled until it has its own reviewed runtime distribution.

`make development-fixture` explicitly imports/approves only the built-in engineering
fixture and rebuilds its projection. It prints the report ID for selection in
Settings. It never imports a registered result merely to pass readiness.

Run `make desktop-engineering-check` with the existing desktop builder image and
installed frontend dependencies. It runs Chromium against an ephemeral loopback
API inside `--network none`, exercises wizard → run → graph → explanation → all
three downloads, and reloads the saved assessment without rerunning it. No database,
host keyring or research configuration is forwarded to that runner.

## Synthetic examples and engine identity

**Simulations → Example Scenarios** loads eight versioned development templates.
**Load example scenario** is also available on the first wizard step. Loading is
read-only: it copies editable fields and template provenance into the wizard;
only **Create Simulation** persists a new engineering record. Review calculates
the edited topology hash separately from the original template hashes.

| Example | Devices | Subnets | Segmentation / focus |
|---|---:|---:|---|
| Small Office | 10 | 2 | Balanced; workstations, web and critical files |
| Healthcare Enterprise | 24 | 5 | Clinical/admin separation, MFA-like control |
| Financial Services | 28 | 6 | DMZ, restricted management, partial patching |
| University / Education | 36 | 5 | Broad campus/research reachability |
| Manufacturing / OT-like | 24 | 4 | Abstract production-support repository; no ICS interaction |
| Hardened Enterprise | 22 | 4 | Strict segmentation, fully patched, isolated objective |
| Vulnerable Training Lab | 12 | 2 | Weak segmentation, two synthetic assignments per host |
| Large Enterprise — bounded 40-device demo | 40 | 6 | Current validated device limit; no 50–60-device claim |

Template definitions live in `configs/engineering_simulations/examples.json` and
are exposed through authenticated `GET /api/engineering-simulations/examples` only
when the engineering runtime is enabled. Each response includes ID, version, seed,
expanded specification hash and generated topology hash. Saved records preserve
the original hashes plus whether the specification was edited. These templates
use synthetic scores and simulator applicability rules, not invented CVEs/CVSS.
The existing catalogue-selection wizard can add attributable CVE metadata explicitly.
Configured assignments, observed vulnerability findings and informational service
observations remain distinct. Outcomes depend on the seed, specification and step
budget; a template is not a promise of compromise.

All examples use **Engineering V2 Reasoner / masked heuristic**. PPO compatibility
is **Not evaluated**; no checkpoint is attached. The Registered Research panel
separately explains the frozen protocol's actual MaskablePPO algorithm and
metadata-verified checkpoint/policy binding. It never loads policies or starts
training/evaluation. The registered environment is labelled by its recorded
enterprise source, not assumed to be NASim. Reports identify the recorded
engineering engine and never advertise an unbound run as PPO-controlled.

## Registered Research → PPO Trajectories

This separate read-only section reconstructs **recorded** PPO validation actions.
Select a training seed/policy, validation topology and evaluation episode seed.
The selected episode shows its raw action indices, names/categories, targets,
rewards, flags, prerequisite/outcome tokens and original MITRE mappings, alongside
policy/checkpoint/topology identities and source file hashes/line numbers.

The timeline's arrows mean **next recorded step only**. They do not establish
host-to-host connectivity, access-state transitions or causal dependency. Missing
source hosts, observations, masks, snapshots, logits and alternatives display
**Not recorded**. No such fields are inferred from the checkpoint or topology.
The summary is a deterministic description of stored events, not a generated
explanation of why the policy selected an action. Historical `SYN-*` identifiers
and their scores remain synthetic context, not empirical CVEs/CVSS.

**Generate Research Trajectory Report** enables HTML, PDF and JSON downloads for
that episode. Exports carry **REGISTERED PPO VALIDATION EVIDENCE — READ-ONLY
RECONSTRUCTION**, technical steps, limitations and provenance. PDF uses built-in
WinAnsi fonts; HTML/JSON retain full Unicode. No report is published into an
engineering database or saved back into the campaign.

Authenticated GET-only routes:

- `/api/research/ppo-trajectories`
- `/api/research/ppo-trajectories/{training_seed}/{topology_seed}/{evaluation_seed}`
- The same episode path plus `/export/{html|pdf|json}`

The reader uses `SECURITY_RL_REGISTERED_CAMPAIGN`, matching the existing research
results reader. It validates manifest bindings, registered validation membership,
episode identities, step order, reward totals, failure counts, terminal flags and
available completion hashes. It reads no checkpoint contents, imports no PPO or
simulator code, calls no database, and provides no mutation/execution endpoint.
A missing/invalid source produces an unavailable state with no substitute data.

`make desktop-research-trajectories-check` runs the browser acceptance example
(seed 42 / topology 1001 / evaluation seed 19001) with the archive mounted read-only
inside `--network none`. The runner forwards no database, keyring or engineering
state configuration. It selects additional episodes, checks the 77-step/184.37
acceptance record and downloads all three formats using GET requests only.

### Verify report saving in the Linux desktop

Start the development desktop with `make desktop-dev`. The save dialog opens in
`~/Downloads/Security-RL`, a dedicated host directory mounted into Podman.
Use a new filename with the suggested extension. Existing files are preserved.

1. Open Registered Research → PPO Trajectories and select a recorded episode.
   Choose Generate Research Trajectory Report.
2. Click Download PDF and cancel the GTK dialog. Confirm no new file appears.
   Repeat and select Save. Check the displayed destination in the host file manager.
3. Save HTML and JSON. Open the HTML offline, open the PDF, and compare the episode
   seeds, step count and objective outcome with the selection. In JSON, compare
   `identity`, `summary`, `journey` and `steps`.
4. Open a completed assessment under Saved Simulations → Report. Repeat all three
   exports. Check its engineering classification and simulation ID.
5. Try saving over one of the files. Confirm the application asks for a new name
   and the original file remains readable. A packaged Linux desktop uses the native
   chooser without the development container's shared-folder restriction.
