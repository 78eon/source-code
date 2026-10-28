#!/usr/bin/env python3
"""Verify or execute one separately authorized registered seed; no automatic next seed."""

import argparse
import json

from rlredteam.enterprise.campaign_execution import ROOT, train_authorized_seed, verify_campaign


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("verify", "train"))
    parser.add_argument("--authorization-sha", required=True)
    parser.add_argument("--seed", type=int, required=True)
    args = parser.parse_args()
    result = (verify_campaign if args.operation == "verify" else train_authorized_seed)(
        ROOT, args.authorization_sha, args.seed
    )
    print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
    if args.operation == "verify" and not result["allowed_to_train"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
