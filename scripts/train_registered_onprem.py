#!/usr/bin/env python3
"""Run only seed 42 after the registered on-prem pre-flight passes."""

import argparse
import json

from rlredteam.enterprise.onprem_protocol import CONFIG, load_protocol
from rlredteam.enterprise.registered_onprem import train_registered_seed42


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=str(CONFIG))
    args = parser.parse_args()
    print(json.dumps(train_registered_seed42(load_protocol(args.config)), indent=2))


if __name__ == "__main__":
    main()
