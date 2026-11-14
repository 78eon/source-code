#!/usr/bin/env bash
# Phase10 interface/config tests only. No learner, registration or launch command.
set -euo pipefail
if (( $# )); then
    echo 'This runner accepts no arguments.' >&2
    exit 2
fi
phase10_root='/home/god/Desktop/sem 4/source-code-merge'
cd "$phase10_root"
exec podman run --rm --pull never --network none --cap-drop ALL \
    --security-opt no-new-privileges \
    -e PYTHONPATH=/app/src:/app -e PYTHONDONTWRITEBYTECODE=1 \
    -e OPENBLAS_NUM_THREADS=1 -e OMP_NUM_THREADS=1 -e MKL_NUM_THREADS=1 \
    -v "$phase10_root:/app:ro" -w /app localhost/security-rl-desktop-api:dev \
    python -B -m pytest -q -p no:cacheprovider \
    -p rlredteam.application.analytical_test_guard tests/test_comparison_contract.py
