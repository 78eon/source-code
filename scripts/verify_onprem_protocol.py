#!/usr/bin/env python3
"""Read-only registered on-prem pre-flight; never starts training or evaluation."""

import argparse
import json

from rlredteam.enterprise.onprem_protocol import CONFIG, ROOT, load_protocol, verify_protocol


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=str(CONFIG))
    args = parser.parse_args(argv)
    try:
        result = verify_protocol(load_protocol(args.config), ROOT)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["allowed_to_train"] else 1
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"allowed_to_train": False, "error": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
