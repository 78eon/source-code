"""Offline engineering conversion. Default is readiness only; never runs a simulation."""

import argparse
import json
from pathlib import Path

from rlredteam.digital_twin.conversion import SimulationConversionPolicy
from rlredteam.digital_twin.conversion_models import (
    SelectionSource,
    SimulationAssumption,
    SimulationCrownJewel,
    SimulationEntryPoint,
)
from rlredteam.digital_twin.conversion_result import convert_draft_to_true_topology
from rlredteam.digital_twin.conversion_serialization import dumps, loads
from rlredteam.digital_twin.models import DigitalTwin
from rlredteam.digital_twin.serialization import loads as load_twin
from rlredteam.digital_twin.simulation_draft import build_simulation_draft, provenance
from rlredteam.knowledge.vulnerabilities.importers import _read


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--twin", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--convert", action="store_true")
    parser.add_argument("--entry-asset", action="append", default=[])
    parser.add_argument("--crown-asset", action="append", default=[])
    parser.add_argument("--analyst")
    parser.add_argument("--assumption", type=Path, action="append", default=[])
    args = parser.parse_args(argv)
    if (args.entry_asset or args.crown_asset) and not args.analyst:
        parser.error("explicit selections require --analyst attribution")
    try:
        twin = load_twin(_read(args.twin).decode())
        policy = loads(_read(args.policy).decode())
        if not isinstance(twin, DigitalTwin) or not isinstance(policy, SimulationConversionPolicy):
            raise ValueError("typed twin and conversion policy required")
        assets = {a.stable_id: a for a in twin.assets}

        def select(identifier, kind):
            if identifier not in assets:
                raise ValueError("unknown explicit asset selection")
            return kind(
                asset_id=identifier,
                source=SelectionSource.ANALYST,
                evidence_ids=assets[identifier].evidence_ids,
                selection_rule="analyst:" + args.analyst,
                provenance=provenance(assets[identifier]),
            )

        assumptions = tuple(loads(_read(path).decode()) for path in args.assumption)
        if not all(isinstance(a, SimulationAssumption) for a in assumptions):
            raise ValueError("typed simulation assumptions required")
        draft = build_simulation_draft(
            twin,
            policy,
            entry_points=tuple(select(x, SimulationEntryPoint) for x in args.entry_asset),
            crown_jewels=tuple(select(x, SimulationCrownJewel) for x in args.crown_asset),
            assumptions=assumptions,
        )
        if args.convert:
            print(dumps(convert_draft_to_true_topology(draft, policy)))
        else:
            print(
                json.dumps(
                    {
                        "status": draft.assessment.status.value,
                        "reasons": draft.assessment.reasons,
                        "draft_digest": draft.draft_digest,
                        "converted": False,
                    },
                    sort_keys=True,
                )
            )
        return 0
    except (ValueError, OSError) as exc:
        parser.exit(2, f"Conversion refused: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
