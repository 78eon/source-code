"""Transparent engineering scores, NOT probabilities or statistical confidence."""

from rlredteam.evidence.models import EvidenceStatus

from .models import FactStatus, TwinProvenance


def metadata(records, rule, created_at, *, inferred=False, cap=1.0, conflict=False):
    records = tuple(records)
    # No bonus for merely renaming a source. Minimum support score, capped for
    # inference, penalised for contradiction. All source quality defaults equal.
    minimum = min((record.confidence for record in records), default=0.0)
    cap = min(cap, 0.8 if inferred else 1.0)
    score = round(min(minimum, cap) * (0.5 if conflict else 1.0), 6)
    if records and all(record.status == EvidenceStatus.SYNTHETIC for record in records):
        status = FactStatus.SYNTHETIC
    elif (
        inferred
        or not records
        or any(record.status != EvidenceStatus.OBSERVED for record in records)
    ):
        status = FactStatus.INFERRED
    else:
        status = FactStatus.OBSERVED
    return dict(
        evidence_ids=tuple(sorted({record.evidence_id for record in records})),
        status=status,
        confidence=score,
        created_at=created_at,
        provenance=TwinProvenance(
            source_ids=tuple(
                sorted({source for record in records for source in record.provenance.source_ids})
            ),
            rules=(rule,),
            confidence_calculation={
                "method": "minimum-support-capped-v1",
                "minimum_support": minimum,
                "cap": cap,
                "conflict_multiplier": 0.5 if conflict else 1.0,
                "source_quality_weight": 1.0,
                "score": score,
            },
        ),
    )
