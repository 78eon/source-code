#!/usr/bin/env bash
# Phase9 fixed allowlist. Never accepts pytest arguments or executes training.
set -euo pipefail
if (( $# )); then
    echo 'This runner accepts no arguments.' >&2
    exit 2
fi
phase9_root='/home/god/Desktop/sem 4/source-code-merge'
cd "$phase9_root"
exec podman run --rm --pull never --network none --cap-drop ALL \
    --security-opt no-new-privileges \
    -e PYTHONPATH=/app/src:/app -e PYTHONDONTWRITEBYTECODE=1 \
    -e OPENBLAS_NUM_THREADS=1 -e OMP_NUM_THREADS=1 -e MKL_NUM_THREADS=1 \
    -v "$phase9_root:/app:ro" -w /app localhost/security-rl-desktop-api:dev \
    python -B -m pytest -q -p no:cacheprovider \
    -p rlredteam.application.analytical_test_guard \
    tests/test_phase9_actions.py tests/test_attacker_decision.py \
    tests/test_decision_action_mapper.py tests/test_v2_execution.py \
    tests/test_v2_reasoner.py tests/test_v2_semantic_scenarios.py
