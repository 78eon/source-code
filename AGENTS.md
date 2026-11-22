# Agent Instructions

Make small, scoped, reviewable changes. Keep registered research evidence separate from later engineering work.

## Core Rules

1. Do only the assigned task, in the assigned module.
2. Read the existing code and tests before editing.
3. Make the smallest coherent change. No unrelated refactors.
4. Every behavior change needs tests.
5. Never commit, push, merge, rebase, reset history, force-push, or delete branches unless the operator explicitly says so.
6. Never delete a file just because it looks unused. Prove it is obsolete first.
7. Never add secrets, tokens, credentials, or private keys.
8. Never modify tests to hide a real failure.

## Research Integrity

Registered historical evidence is immutable: frozen experiment outputs, held-out evaluation artifacts, registered protocol records, and anything the repo's verification tooling marks as protected.

- Find protected paths from the repo's verification tooling or manifests. Do not assume them.
- If a task requires changing protected evidence: stop that part, explain why, and propose a post-registration alternative.
- Never silently regenerate or overwrite historical evidence.

## Live-Lab Safety

Live-lab code runs only in authorized, isolated environments. Always preserve:

- explicit, operator-supplied network scope
- private routed ranges only
- explicit execution enablement
- operator approval before any live scan
- maximum-address limits
- rejection of out-of-scope targets
- no automatic authorization expansion

Discovery is dynamic. Authorization is independent. A newly discovered host, IP, route, or subnet is never authorized automatically.

Do not add exploit execution to the live-lab backend unless a separate, explicitly approved research task requires it.

## No Hardcoding

- Production code must not embed specific hosts, IPs, subnets, ports, service names, or topology.
- Environment-specific values belong in runtime input, operator config, fixtures, tests, or generated evidence.
- The system learns from evidence, not from a predefined inventory:

  unknown → host discovered → host enumerated → service discovered → application identified → evidence added to knowledge graph → next permitted action selected

- Do not invent knowledge the observations do not support.

## Module Boundaries

Locate modules by reading the repo layout, not by assuming paths. Stay inside the module you were assigned.

- **Environment**: semantics, observable state, action validity, transitions.
- **Attacker intelligence**: belief, knowledge, decision reasoning, action selection.
- **Live lab**: authorized discovery, service inventory, evidence ingestion, knowledge-graph construction.
- **Attack graph and reasoning**: evidence-derived relationships, graph construction, reporting.

For cross-module changes: justify the need, state the contract between modules, touch only necessary files, and add integration tests.

## Testing

1. Run the narrowest relevant tests first.
2. Run broader tests if the change crosses modules.
3. Report failures honestly.
4. Use the repo's supported container workflow (for example Podman targets) where one exists. Discover targets from the build files rather than guessing.

## Completion Report

End every implementation task with:

- **Changed**: files created, modified, deleted
- **Why**: reason for each change
- **Validation**: commands and tests run
- **Results**: what passed, what failed
- **Limitations**: anything incomplete or needing human review
- **Git**: current branch and `git diff --stat`
