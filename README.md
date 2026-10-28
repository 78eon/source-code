<div align="center">

# 🛡️ Security-RL

### Reinforcement Learning for Autonomous Attack-Path Discovery in Simulated Enterprise Networks

**MSc Research Project · RLRedTeam · Simulation-First · Evidence-Driven**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![RL](https://img.shields.io/badge/RL-PPO-8A2BE2)](#reinforcement-learning)
[![Simulator](https://img.shields.io/badge/Simulator-NASim-0A66C2)](#research-architecture)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Evidence-336791?logo=postgresql&logoColor=white)](#evidence-and-reproducibility)
[![Neo4j](https://img.shields.io/badge/Neo4j-Derived_Graph-4581C3?logo=neo4j&logoColor=white)](#analyst-workspace)
[![Tauri](https://img.shields.io/badge/Desktop-Tauri-FFC131?logo=tauri&logoColor=black)](#analyst-workspace)
[![React](https://img.shields.io/badge/React-TypeScript-61DAFB?logo=react&logoColor=black)](#analyst-workspace)
[![Research](https://img.shields.io/badge/Status-MSc_Research-orange)](#project-status)
[![License](https://img.shields.io/badge/Use-Research_%26_Education-lightgrey)](#responsible-use)

**Attack-path discovery · partial observability · CVE/CVSS reward shaping · MITRE ATT&CK semantics · reproducible experiments · analyst-facing evidence**

[Overview](#overview) ·
[Architecture](#research-architecture) ·
[Experiments](#research-work) ·
[Desktop](#analyst-workspace) ·
[Quick Start](#quick-start) ·
[Limitations](#known-limitations)

</div>

---

> [!IMPORTANT]
> **Security-RL is a research system, not an autonomous live penetration-testing product.**
>
> The registered research experiments operate in simulated environments. Simulator exploit, privilege-escalation and lateral-movement actions modify simulated state; they do not execute real exploits against production infrastructure.

---

## Overview

Security-RL explores a research question:

> **Can a reinforcement-learning agent learn useful attack-path behaviour across generated enterprise network topologies while remaining reproducible, partially observable and evidence-driven?**

The project combines:

- reinforcement learning with **PPO**;
- generated enterprise attack environments through **NASim**;
- **CVE/CVSS-informed reward signals**;
- **MITRE ATT&CK-aligned semantic events**;
- partial-observation and agent-knowledge controls;
- reproducible experiment registration and provenance;
- PostgreSQL-backed experimental evidence;
- derived causal attack-path analysis;
- an analyst-facing Tauri + React desktop application.

The focus is not simply whether an agent reaches a target.

The research also examines **how the policy behaves, what evidence it observes, how attack paths are reconstructed, how results generalise, and whether the experiment can be independently reproduced.**

---

## What makes this project different?

Security-RL is intentionally positioned between an RL research environment and a security-analysis platform.

| Area | Security-RL approach |
|---|---|
| Learning | PPO policies trained on simulated enterprise attack environments |
| Observation | Agent receives discovered knowledge rather than unrestricted hidden topology |
| Vulnerability context | CVE/CVSS metadata informs experimental reward and analysis |
| ATT&CK context | Security actions are translated into semantic ATT&CK-aligned events |
| Generalisation | Registered evaluation across generated/unseen topology instances |
| Evidence | Episode, checkpoint, configuration and provenance records are retained |
| Attack paths | Successful trajectories can be reconstructed into evidence-backed paths |
| Graph analysis | PostgreSQL-authoritative evidence can be projected into Neo4j |
| Analyst interface | Desktop workspace presents persisted evidence without controlling research training |
| Safety boundary | Registered experimentation remains simulation-first |

---

## Research architecture

```text
               ┌───────────────────────────┐
               │ Generated Enterprise Model│
               │        / NASim            │
               └─────────────┬─────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ True Environment│
                    │      State      │
                    └────────┬────────┘
                             │
                    legitimate discovery
                             │
                             ▼
                    ┌─────────────────┐
                    │ Agent Knowledge │
                    └────────┬────────┘
                             │
                             ▼
               ┌───────────────────────────┐
               │ Observation + Action Mask │
               └─────────────┬─────────────┘
                             │
                             ▼
                       ┌──────────┐
                       │   PPO    │
                       │  Policy  │
                       └────┬─────┘
                            │ action
                            ▼
                  ┌─────────────────────┐
                  │ Simulator Transition│
                  └─────────┬───────────┘
                            │
              ┌─────────────┼──────────────┐
              ▼             ▼              ▼
        CVE/CVSS       MITRE Events    Episode Evidence
        Rewarding       & Semantics       PostgreSQL
                                             │
                                             ▼
                                   Attack-Path Analysis
                                             │
                                    ┌────────┴────────┐
                                    ▼                 ▼
                                  Neo4j          Analyst Desktop
```

A core research constraint is:

```text
True topology
    ↓
environment
    ↓
legitimate discovery
    ↓
AgentKnowledge
    ↓
policy observation
```

The PPO policy is not intended to receive unrestricted hidden topology information.

---

## Research work

The repository contains several stages of research development.

### 🧠 Reinforcement learning

The primary registered research path uses PPO with deterministic experiment configuration, seeded topology generation and persistent evidence.

The repository also contains historical and exploratory work involving:

- reward shaping;
- fixed-budget evaluation;
- recurrent policies;
- curriculum learning;
- graph-oriented policies;
- transfer learning;
- hierarchical policies;
- multi-agent experiments;
- simulator adapters.

These phases are preserved for research traceability, but they should not all be interpreted as equal parts of the final registered MSc experiment.

---

### 🌐 Multi-topology generalisation

The current registered campaign evaluates whether a trained PPO policy can operate across generated topology instances outside its training set.

The protocol separates:

```text
Training topology seeds
        ↓
Validation topology seeds
        ↓
Final held-out topology seeds
```

Training-reward convergence and zero-shot task performance are deliberately treated as different measurements.

A policy may therefore show:

```text
reward-rise diagnostic: FAIL
validation performance: PASS
```

without that seed being removed, retuned or replaced.

That behaviour is retained as an experimental result rather than hidden through post-hoc tuning.

---

## CVE and reward model

Security-RL uses vulnerability metadata as part of the experimental representation and reward model.

```text
CVE metadata
    ↓
CVSS severity
    ↓
experimental weight
    ↓
security action / outcome
    ↓
reward contribution
```

Important distinction:

> A CVSS-derived weight is an experimental reward signal. It is **not** interpreted as the probability that a real exploit will succeed.

The CVE catalogue stores vulnerability metadata rather than exploit code.

---

## MITRE ATT&CK semantics

Simulator-native actions and research semantics are kept conceptually separate.

```text
Simulator action
      ↓
Semantic security event
      ↓
MITRE ATT&CK mapping
      ↓
trajectory / report / graph evidence
```

This allows attack trajectories to be analysed in security language without pretending that simulator actions are identical to real-world exploitation.

---

## Evidence and reproducibility

Reproducibility is treated as a first-class project component.

Experimental evidence can include:

- topology configuration hashes;
- topology seeds;
- training seeds;
- CVE catalogue provenance;
- protocol hashes;
- source commit hashes;
- checkpoint hashes;
- episode records;
- PPO diagnostic records;
- validation outcomes;
- policy immutability checks;
- registered completion records.

PostgreSQL acts as the primary structured evidence store for supported experiment workflows.

Derived systems such as Neo4j and MLflow do not replace the canonical experimental evidence.

---

## Attack-path analysis

Successful trajectories can be transformed into evidence-backed attack-path representations.

Rather than inventing edges directly from hidden topology, the analysis is designed around recorded events and observed knowledge changes.

Example conceptual path:

```text
Initial foothold
      ↓
Service discovery
      ↓
Vulnerability-related action
      ↓
Privilege transition
      ↓
Lateral movement
      ↓
Crown-jewel access
```

Path nodes and transitions can retain provenance back to the original episode and step evidence.

---

## Analyst workspace

The project includes a separate analyst-facing desktop application built with:

```text
Tauri
  +
React
  +
TypeScript
  +
FastAPI
  +
PostgreSQL
  +
Neo4j
  +
Sigma.js
```

The desktop application is an **engineering and presentation artefact**.

Its role is to inspect persisted evidence—not to alter registered PPO training.

Typical analyst views include:

- experiment runs;
- assets;
- vulnerabilities;
- attack paths;
- network graphs;
- evidence summaries;
- persisted reports.

The desktop and research campaign are deliberately separated so UI development cannot silently influence registered experimental outcomes.

---

## Simulator adapters

Security-RL has evolved beyond a single simulator abstraction.

The repository contains research integrations for:

| Backend | Role |
|---|---|
| **NASim** | Primary experimental control |
| **CyberBattleSim** | Additional simulator adapter research |
| **CybORG** | Additional controlled simulator integration |

Simulator-specific identifiers are not automatically presented as real CVEs unless appropriate evidence supports that mapping.

---

## Quick start

### Clone

```bash
git clone https://github.com/78eon/source-code.git
cd source-code
```

### Build the research environment

```bash
make build
```

### Start PostgreSQL

```bash
make db-up
```

### Reproducibility checks

```bash
make reproducibility-check
```

### Run a basic rollout

```bash
make rollout
```

> Long-running or registered experiment targets should only be executed after checking their corresponding protocol and documentation.

---

## Repository map

```text
source-code/
│
├── src/rlredteam/
│   ├── enterprise/          enterprise simulation + research controls
│   ├── storage/             PostgreSQL-backed evidence
│   ├── nasim_adapter.py     NASim integration
│   ├── cyberbattle_adapter.py
│   ├── cyborg_adapter.py
│   ├── reward.py            reward model
│   ├── catalogue.py         CVE catalogue access
│   ├── train.py             PPO training
│   └── ...
│
├── configs/
│   ├── experiments/         research protocols
│   └── ...
│
├── scripts/                 experiment/evaluation tooling
├── tests/                   automated verification
├── desktop/                 Tauri + React analyst application
├── docs/                    architecture, evidence and research documentation
├── data/                    controlled research datasets
└── runs/                    local experiment outputs — not published by default
```

---

## Project status

Security-RL is an active MSc research project.

Current work is centred on:

- completing the registered multi-topology generalisation campaign;
- preserving frozen experimental controls;
- validating zero-shot performance;
- maintaining policy/checkpoint provenance;
- producing final research evidence;
- consolidating the analyst desktop;
- reconciling implementation with the final dissertation scope.

The project should therefore be read as a **research artefact under active evaluation**, not as a finished commercial penetration-testing platform.

---

## What this project is not

Security-RL is **not** currently:

- an unrestricted penetration-testing agent;
- an autonomous live exploit framework;
- an EDR replacement;
- a vulnerability scanner replacement;
- a production attack-surface-management platform;
- a commercial breach-and-attack simulation platform;
- proof that simulated exploit success transfers directly to real infrastructure.

Those distinctions are intentional and important to the research validity of the project.

---

## Known limitations

Current limitations include:

- simulated CVE/service relationships may not represent real exploitability;
- CVSS-derived reward weights are not exploit-success probabilities;
- the registered research environment does not establish production-network attack capability;
- real enterprise identity, cloud, endpoint and security-control complexity is only partially represented;
- experimental sample sizes remain constrained by MSc compute/time limits;
- Neo4j and analyst visualisations are derived from canonical evidence rather than experimental ground truth;
- commercial deployment concerns such as HA, enterprise RBAC, SSO, secrets management and SIEM/SOAR integrations remain outside the registered experiment.

These limitations are documented rather than hidden because they define the boundary between a research prototype and an operational security product.

---

## Responsible use

This repository is intended for:

- cybersecurity research;
- reinforcement-learning research;
- controlled simulation;
- academic evaluation;
- authorised lab environments.

Do not use project components against systems without explicit permission.

Registered research results should not be interpreted as authorization or evidence that the same behaviour is safe or effective on real enterprise networks.

Policy checkpoints and other dual-use artefacts are not published automatically.

---

## Research philosophy

Security-RL follows three principles:

```text
Reproducibility over impressive demos
Evidence over assumptions
Explicit limitations over inflated claims
```

The goal is not to build an agent that merely *looks autonomous*.

The goal is to investigate whether attack-path learning can be made **measurable, reproducible, explainable and useful to a security analyst**.

---

<div align="center">

### Security-RL / RLRedTeam

**Reinforcement Learning · Cybersecurity · Attack-Path Research · Enterprise Simulation**

Built as part of an MSc cybersecurity research project.

[Back to top](#-security-rl)

</div>