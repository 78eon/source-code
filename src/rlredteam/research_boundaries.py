"""Research provenance labels only; no training or ingestion behaviour.

Live-lab evidence must never silently enter a registered simulation experiment.
Any import requires explicit scope, provenance, versioning and a new study
registration. These labels are not access controls or registration validators.
Historical evidence must not be relabelled or rewritten by importing this module.
"""

from enum import StrEnum


class ResearchBoundary(StrEnum):
    FROZEN_CORE = "FROZEN_CORE"
    CONFIRMATORY = "CONFIRMATORY"
    GENERALISATION_RESEARCH = "GENERALISATION_RESEARCH"
    ENGINEERING_EXTENSION = "ENGINEERING_EXTENSION"
    LIVE_LAB_EXTENSION = "LIVE_LAB_EXTENSION"
