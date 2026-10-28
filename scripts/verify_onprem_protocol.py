#!/usr/bin/env python3
"""Read-only registered on-prem pre-flight; never starts training or evaluation."""

import argparse
import json

from rlredteam.enterprise.onprem_protocol import CONFIG, ROOT, load_protocol, verify_protocol


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=str(CONFIG))
    parser.add_argument(
        "--pre-registration",
        action="store_true",
        help="Check technical readiness; never authorizes training",
    )
    args = parser.parse_args(argv)
    try:
        result = verify_protocol(
            load_protocol(args.config), ROOT, pre_registration=args.pre_registration
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        passed = (
            result["ready_for_registration"]
            if args.pre_registration
            else result["allowed_to_train"]
        )
        return 0 if passed else 1
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"allowed_to_train": False, "error": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
