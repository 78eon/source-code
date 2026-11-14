#!/usr/bin/env bash
# Bounded reward-only checks; the protected reference is a single read-only file.
set -euo pipefail
if (( $# )); then
    echo 'This runner accepts no arguments.' >&2
    exit 2
fi
phase8_root='/home/god/Desktop/sem 4/source-code-merge'
phase8_reference='/home/god/Desktop/sem 4/source code/src/rlredteam/enterprise/environment.py'
cd "$phase8_root"
exec podman run --rm --pull never --network none --cap-drop ALL \
    --security-opt no-new-privileges \
    -e PYTHONPATH=/app/src:/app -e PYTHONDONTWRITEBYTECODE=1 \
    -e OPENBLAS_NUM_THREADS=1 -e OMP_NUM_THREADS=1 -e MKL_NUM_THREADS=1 \
    -v "$phase8_root:/app:ro" -v "$phase8_reference:/reference/environment.py:ro" \
    -w /app localhost/security-rl-desktop-api:dev \
    python -B -m pytest -q -p no:cacheprovider \
    -p rlredteam.application.analytical_test_guard \
    tests/test_phase8_rewards.py tests/test_enterprise_reward_config.py tests/test_reward.py \
    tests/test_component_ablation.py::test_legacy_reward_hash_is_unchanged \
    tests/test_component_ablation.py::test_explicit_zero_model_is_distinct_from_legacy_model \
    tests/test_component_ablation.py::test_each_component_can_be_enabled_in_isolation \
    tests/test_component_ablation.py::test_component_design_is_matched_and_changes_only_reward_switches \
    tests/test_component_ablation.py::test_component_scoring_is_deterministic
