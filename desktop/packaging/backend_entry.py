"""Frozen runtime entry point; only the public MITRE catalogue is bundled."""
import os
import sys
from pathlib import Path

import rlredteam.catalogues

rlredteam.catalogues.DEFAULT_MITRE_CATALOGUE = Path(sys._MEIPASS) / "assets" / "mitre.yaml"
os.environ["SECURITY_RL_USE_LOCAL_CONFIG"] = "1"

from rlredteam.api.owned_backend import entry  # noqa: E402 -- catalogue path precedes API import

raise SystemExit(entry())
