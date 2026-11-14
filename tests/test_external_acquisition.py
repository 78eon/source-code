import json
from uuid import uuid4

import pytest

from rlredteam.knowledge.external.acquisition import AcquisitionPlan, acquire, diff_snapshots
from rlredteam.knowledge.external.ingestion import ingest
from rlredteam.knowledge.validation import ModelError
from tests.test_external_reference_knowledge import bundle, capture, cve, page, stix


def plan_for(source, **kwargs):
    return AcquisitionPlan(
        dataset=source.dataset,
        domain=source.domain,
        release=source.release,
        revision=source.revision,
        uri=source.uri,
        captured_at=source.captured_at,
        parameters={},
        synthetic=True,
        **kwargs,
    )


def test_acquires_complete_nvd_query_and_preserves_raw():
    first = page("nvd-cve", [{"cve": cve()}], total=2)
    second = page("nvd-cve", [{"cve": cve()}], start=1, total=2)
    source, _ = capture("nvd-cve", first)
    requests, retained = [], []

    class Transport:
        def fetch(self, uri, parameters, dataset):
            requests.append(dict(parameters))
            return json.dumps(second if parameters.get("startIndex") else first).encode()

    result = acquire(plan_for(source), Transport(), retain_raw=lambda s, b: retained.append((s, b)))
    assert result == tuple(retained)
    assert len(ingest(result).records) == 2
    assert requests == [{}, {"startIndex": 1}]


def test_taxii_pagination_and_replay():
    cursor = uuid4().hex
    docs = [
        {"objects": [stix("tool")], "more": True, "next": cursor},
        {"objects": [stix("campaign")], "more": False},
    ]
    source, _ = capture("attack-taxii", docs[0])

    class Transport:
        def fetch(self, uri, parameters, dataset):
            return json.dumps(docs[bool(parameters.get("next"))]).encode()

    result = acquire(plan_for(source), Transport())
    assert len(ingest(result).records) == 2
    assert result[1][0].cursor == cursor


def test_no_partial_publication_when_page_budget_exhausted():
    body = page("nvd-cve", [{"cve": cve()}], total=2)
    source, content = capture("nvd-cve", body)

    class Transport:
        def fetch(self, *args):
            return content

    with pytest.raises(ModelError, match="budget"):
        acquire(plan_for(source, max_pages=1), Transport())


def test_credentials_and_nonofficial_origin_rejected_before_transport():
    source, _ = capture("attack-stix", bundle(stix("tool")))
    values = dict(
        dataset=source.dataset,
        domain=source.domain,
        release=source.release,
        revision=source.revision,
        uri=source.uri,
        captured_at=source.captured_at,
    )
    with pytest.raises(ModelError, match="credentials"):
        AcquisitionPlan(**values, parameters={"apiKey": uuid4().hex})
    with pytest.raises(ModelError, match="official"):
        AcquisitionPlan(**{**values, "uri": "https://" + uuid4().hex + ".invalid/"}, parameters={})


def test_diff_does_not_claim_deletion_or_modify_snapshots():
    before = ingest((capture("attack-stix", bundle(stix("tool"))),))
    after = ingest((capture("attack-stix", bundle(stix("campaign"))),))
    result = diff_snapshots(before, after)
    assert result["added"] and result["not_in_capture"]
    assert "absence is not" in result["limitation"]
