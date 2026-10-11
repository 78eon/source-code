"""In-memory append-only registry: duplicate IDs fail; conflicting facts coexist."""

from rlredteam.knowledge.validation import ModelError

from .models import EvidenceBundle, EvidenceRecord, EvidenceStatus, Finding, ObservedRelationship


class EvidenceRegistry:
    def __init__(self, *, bundle_id, created_at, sources, records=(), findings=()):
        self._bundle = EvidenceBundle(
            bundle_id=bundle_id,
            created_at=created_at,
            sources=tuple(sources),
            records=tuple(records),
            findings=tuple(findings),
        )

    @property
    def bundle(self):
        return self._bundle

    def add(self, record):
        if not isinstance(record, EvidenceRecord | Finding):
            raise ModelError("expected an evidence record or finding")
        records, findings = self._bundle.records, self._bundle.findings
        if isinstance(record, Finding):
            findings += (record,)
        else:
            records += (record,)
        # Validate the whole candidate before replacing state: failed adds are atomic.
        candidate = EvidenceBundle(
            bundle_id=self._bundle.bundle_id,
            created_at=self._bundle.created_at,
            sources=self._bundle.sources,
            records=records,
            findings=findings,
        )
        self._bundle = candidate

    def _items(self):
        return tuple(
            sorted(
                (*self._bundle.records, *self._bundle.findings),
                key=lambda item: item.finding_id if isinstance(item, Finding) else item.evidence_id,
            )
        )

    def get(self, identifier):
        for item in self._items():
            key = item.finding_id if isinstance(item, Finding) else item.evidence_id
            if key == identifier:
                return item
        raise KeyError(identifier)

    def for_subject(self, identifier):
        return tuple(
            item
            for item in self._items()
            if (item.asset_id if isinstance(item, Finding) else item.subject_id) == identifier
        )

    def by_status(self, status):
        status = EvidenceStatus(status)
        return tuple(item for item in self._items() if item.status == status)

    def by_source(self, source_id):
        return tuple(item for item in self._items() if source_id in item.provenance.source_ids)

    def findings_for_asset(self, asset_id):
        return tuple(item for item in self._bundle.findings if item.asset_id == asset_id)

    def relationships_for_asset(self, asset_id):
        return tuple(
            item
            for item in self._bundle.records
            if isinstance(item, ObservedRelationship)
            and asset_id in (item.source_asset_id, item.target_asset_id)
        )
