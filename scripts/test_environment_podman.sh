#!/usr/bin/env bash
# Phase 7 only: fixed test allowlist, collection guard, no network, read-only source.
set -euo pipefail
if (( $# )); then
    echo 'This bounded runner accepts no arguments.' >&2
    exit 2
fi
phase7_root='/home/god/Desktop/sem 4/source-code-merge'
cd "$phase7_root"
exec podman run --rm --pull never --network none --cap-drop ALL \
    --security-opt no-new-privileges \
    -e PYTHONPATH=/app/src:/app -e PYTHONDONTWRITEBYTECODE=1 \
    -e OPENBLAS_NUM_THREADS=1 -e OMP_NUM_THREADS=1 -e MKL_NUM_THREADS=1 \
    -v "$phase7_root:/app:ro" -w /app \
    localhost/security-rl-desktop-api:dev \
    python -B -m pytest -q -p no:cacheprovider \
    -p rlredteam.application.analytical_test_guard \
    tests/test_phase7_environment_contract.py \
    tests/test_enterprise_environment.py \
    tests/test_enterprise_environment_config.py \
    tests/test_enterprise_reward_config.py \
    tests/test_hybrid_environment.py \
    tests/test_simulation_agentknowledge_boundary.py \
    tests/test_simulation_conversion_policy.py \
    tests/test_simulation_conversion_validation.py \
    tests/test_simulation_conversion_isolation.py \
    tests/test_attacker_belief.py \
    tests/test_agentknowledge_belief_bridge.py \
    tests/test_attacker_graph.py \
    tests/test_belief_observation.py \
    tests/test_information_value.py \
    tests/test_attack_path_reasoner.py \
    tests/test_attacker_decision.py \
    tests/test_decision_action_mapper.py \
    tests/test_v2_execution.py \
    tests/test_v2_reasoner.py \
    tests/test_v2_episode.py \
    tests/test_v2_semantic_scenarios.py
