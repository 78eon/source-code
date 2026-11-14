"""Generated official-envelope fixtures; all captures explicitly marked synthetic."""

import hashlib
import json
import secrets
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from rlredteam.knowledge.external.ingestion import ingest
from rlredteam.knowledge.external.models import SourceArtifact, dumps, loads
from rlredteam.knowledge.external.repository import ExternalKnowledgeRepository, _plain
from rlredteam.knowledge.validation import ModelError

ATTACK_TYPES = (
    "x-mitre-tactic",
    "attack-pattern",
    "course-of-action",
    "intrusion-set",
    "campaign",
    "malware",
    "tool",
    "relationship",
    "x-mitre-detection-strategy",
    "x-mitre-analytic",
    "x-mitre-data-component",
    "x-mitre-data-source",
    "x-mitre-asset",
    "x-mitre-collection",
    "x-mitre-matrix",
    "identity",
    "marking-definition",
)


def now():
    return datetime.now(UTC).isoformat()


def capture(dataset, body, *, base=None, **changes):
    raw = json.dumps(body, sort_keys=True).encode()
    if base is None:
        source = SourceArtifact(
            dataset=dataset,
            domain=uuid4().hex,
            release=uuid4().hex,
            revision=uuid4().hex,
            uri=(
                "https://attack.mitre.org/"
                if dataset.startswith("attack-")
                else "https://services.nvd.nist.gov/"
            )
            + uuid4().hex,
            captured_at=now(),
            sha256=hashlib.sha256(raw).hexdigest(),
            scope={"kind": "generated-test-query", "query_id": uuid4().hex},
            synthetic=True,
        )
    else:
        source = replace(base, sha256=hashlib.sha256(raw).hexdigest())
    return replace(source, **changes), raw


def stix(kind):
    obj = dict(
        type=kind,
        id=kind + "--" + str(uuid4()),
        spec_version="2.1",
        created=now(),
        modified=now(),
        name=uuid4().hex,
        revoked=True,
        x_mitre_deprecated=True,
        x_mitre_version=uuid4().hex,
        x_mitre_domains=[uuid4().hex],
        external_references=[
            {
                "source_name": uuid4().hex,
                "url": "https://attack.mitre.org/" + uuid4().hex,
                "description": uuid4().hex,
            }
        ],
        x_future_field={"retain": uuid4().hex},
    )
    if kind == "relationship":
        obj.update(
            source_ref="intrusion-set--" + str(uuid4()),
            target_ref="attack-pattern--" + str(uuid4()),
            relationship_type="uses",
            description=uuid4().hex,
        )
    return obj


def bundle(*objects):
    return dict(type="bundle", id="bundle--" + str(uuid4()), objects=list(objects))


def page(dataset, records, *, start=0, total=None):
    key = {
        "nvd-cve": "vulnerabilities",
        "nvd-cpe": "products",
        "nvd-match": "matchStrings",
        "nvd-history": "cveChanges",
    }[dataset]
    return dict(
        format=uuid4().hex,
        version="2.0",
        timestamp=now(),
        startIndex=start,
        resultsPerPage=len(records),
        totalResults=len(records) if total is None else total,
        **{key: records},
    )


def cve():
    identifier = f"CVE-{secrets.randbelow(100) + 2000}-{secrets.randbelow(900000) + 1000}"
    vendor, product, version = (
        uuid4().hex,
        uuid4().hex,
        ".".join(str(secrets.randbelow(100)) for _ in range(3)),
    )
    criteria = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    return dict(
        id=identifier,
        sourceIdentifier=uuid4().hex,
        published=now(),
        lastModified=now(),
        vulnStatus="Rejected",
        descriptions=[{"lang": "en", "value": uuid4().hex}],
        metrics={
            key: [
                {
                    "source": uuid4().hex,
                    "type": "Primary",
                    "cvssData": {
                        "version": version,
                        "vectorString": uuid4().hex,
                        "baseScore": secrets.randbelow(101) / 10,
                    },
                }
            ]
            for key, version in (
                ("cvssMetricV2", "2.0"),
                ("cvssMetricV30", "3.0"),
                ("cvssMetricV31", "3.1"),
                ("cvssMetricV40", "4.0"),
            )
        },
        weaknesses=[
            {
                "source": uuid4().hex,
                "type": "Primary",
                "description": [
                    {"lang": "en", "value": "CWE-" + str(secrets.randbelow(10000) + 1)}
                ],
            }
        ],
        configurations=[
            {
                "operator": "AND",
                "negate": True,
                "nodes": [
                    {
                        "operator": "OR",
                        "negate": False,
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": criteria,
                                "matchCriteriaId": str(uuid4()),
                                "versionStartIncluding": version,
                                "versionEndExcluding": version + ".1",
                            }
                        ],
                    }
                ],
            }
        ],
        references=[
            {
                "url": "https://nvd.nist.gov/" + uuid4().hex,
                "source": uuid4().hex,
                "tags": ["Patch", "Vendor Advisory"],
            }
        ],
        vendorComments=[
            {"organization": uuid4().hex, "comment": uuid4().hex, "lastModified": now()}
        ],
        cveTags=[{"sourceIdentifier": uuid4().hex, "tags": [uuid4().hex]}],
        future_extension={"value": uuid4().hex},
    )


@pytest.fixture
def repo(tmp_path):
    with sqlite3.connect(tmp_path / (uuid4().hex + ".sqlite")) as conn:
        store = ExternalKnowledgeRepository(conn)
        store.initialize()
        yield store


@pytest.mark.parametrize("kind", ATTACK_TYPES)
def test_stix_types_preserved_without_field_loss(kind):
    obj = stix(kind)
    source = capture("attack-stix", bundle(obj))
    result = ingest((source,))
    assert len(result.records) == 1
    assert _plain(result.records[0].payload) == obj
    assert result.records[0].origins[0]["sha256"] == source[0].sha256
    assert loads(dumps(result)) == result


@pytest.mark.parametrize("domain", ["enterprise-attack", "mobile-attack", "ics-attack"])
def test_domains_are_separate_and_versioned(domain):
    record = stix("attack-pattern")
    record["x_mitre_is_subtechnique"] = True
    result = ingest((capture("attack-stix", bundle(record), domain=domain),))
    assert result.artifacts[0].domain == domain
    assert result.records[0].payload["x_mitre_is_subtechnique"] is True


def test_explicit_and_embedded_references_are_separate_source_claims():
    obj = stix("relationship")
    obj["x_mitre_nested"] = {"x_mitre_analytic_refs": ["x-mitre-analytic--" + str(uuid4())]}
    obj["x_mitre_contents"] = [{"object_ref": obj["target_ref"], "object_modified": now()}]
    result = ingest((capture("attack-stix", bundle(obj)),))
    assert {r.target_id for r in result.references} >= {obj["source_ref"], obj["target_ref"]}
    assert any(r.pointer == "/x_mitre_nested/x_mitre_analytic_refs/0" for r in result.references)
    assert any(
        r.target_version == obj["x_mitre_contents"][0]["object_modified"] for r in result.references
    )
    assert _plain(result.records[0].payload) == obj


def test_nvd_cve_complete_payload_and_reference_tags_preserved():
    record = cve()
    result = ingest((capture("nvd-cve", page("nvd-cve", [{"cve": record}])),))
    assert _plain(result.records[0].payload) == record
    assert {r.predicate for r in result.references} >= {"criteria", "matchCriteriaId", "value"}
    assert not any(r.predicate in ("verified_remediation", "mitigates") for r in result.references)


@pytest.mark.parametrize(
    "dataset,wrapper,id_field,modified",
    [
        ("nvd-cpe", "cpe", "cpeNameId", "lastModified"),
        ("nvd-match", "matchString", "matchCriteriaId", "lastModified"),
        ("nvd-history", "change", "cveChangeId", "created"),
    ],
)
def test_other_nvd_sources_remain_independent(dataset, wrapper, id_field, modified):
    record = {
        id_field: str(uuid4()),
        modified: now(),
        "deprecated": True,
        "status": uuid4().hex,
        "deprecatedBy": [{"cpeNameId": str(uuid4())}],
        "details": [{"value": uuid4().hex}],
        "matches": [{"cpeName": uuid4().hex}],
        "versionStartIncluding": uuid4().hex,
    }
    result = ingest((capture(dataset, page(dataset, [{wrapper: record}])),))
    assert _plain(result.records[0].payload) == record
    assert result.records[0].object_type == dataset


def test_nvd_pagination_replay_order_independent(repo):
    first = capture("nvd-cve", page("nvd-cve", [{"cve": cve()}], total=2))
    second = capture("nvd-cve", page("nvd-cve", [{"cve": cve()}], start=1, total=2), base=first[0])
    assert ingest((first, second)) == ingest((second, first))
    result = repo.publish((second, first))
    assert repo.publish((first, second)) == repo.load(result.snapshot_id) == result


def test_taxii_cursor_chain_and_incomplete_capture_rejection():
    token = uuid4().hex
    first = capture(
        "attack-taxii", {"objects": [stix("attack-pattern")], "more": True, "next": token}
    )
    second = capture(
        "attack-taxii", {"objects": [stix("tool")], "more": False}, base=first[0], cursor=token
    )
    assert ingest((first, second)) == ingest((second, first))
    with pytest.raises(ModelError, match="partial TAXII"):
        ingest((first,))


def test_multiple_object_versions_and_conflicts():
    old = stix("attack-pattern")
    new = {**old, "modified": now(), "name": uuid4().hex}
    assert len(ingest((capture("attack-stix", bundle(old, new)),)).records) == 2
    with pytest.raises(ModelError, match="conflicting native"):
        ingest((capture("attack-stix", bundle(old, {**old, "name": uuid4().hex})),))


def test_metadata_and_old_release_remain_replayable(repo):
    first = capture("attack-stix", bundle(stix("attack-pattern")))
    metadata = capture(
        "attack-stix",
        {"release": uuid4().hex, "changelog": uuid4().hex},
        base=first[0],
        role="metadata",
    )
    before = repo.publish((first, metadata))
    newer = capture(
        "attack-stix", bundle(stix("attack-pattern")), base=first[0], release=uuid4().hex
    )
    repo.publish((newer,))
    assert repo.load(before.snapshot_id) == before
    assert len(before.artifacts) == 2
    with pytest.raises(ModelError, match="immutable release"):
        repo.publish((capture("attack-stix", bundle(stix("tool")), base=first[0]),))


@pytest.mark.parametrize(
    "failure", ["digest", "gap", "partial", "mixed", "duplicate_json", "nonfinite"]
)
def test_failed_import_leaves_no_partial_update(repo, failure):
    original = capture("nvd-cve", page("nvd-cve", [{"cve": cve()}]))
    if failure == "digest":
        captures = ((replace(original[0], sha256=secrets.token_hex(32)), original[1]),)
    elif failure in ("gap", "partial"):
        captures = (
            capture(
                "nvd-cve",
                page("nvd-cve", [{"cve": cve()}], start=1 if failure == "gap" else 0, total=2),
                base=original[0],
            ),
        )
    elif failure == "mixed":
        captures = (original, capture("attack-stix", bundle(stix("tool"))))
    else:
        content = (
            b'{"objects":[],"objects":[]}' if failure == "duplicate_json" else b'{"objects":NaN}'
        )
        captures = ((replace(original[0], sha256=hashlib.sha256(content).hexdigest()), content),)
    with pytest.raises(ModelError):
        repo.publish(captures)
    assert (
        repo.connection.execute("SELECT count(*) FROM external_knowledge_artifact").fetchone()[0]
        == 0
    )
    assert (
        repo.connection.execute("SELECT count(*) FROM external_knowledge_snapshot").fetchone()[0]
        == 0
    )


def test_transaction_rolls_back_mid_publication(repo):
    repo.connection.execute("""CREATE TRIGGER reject_record
        BEFORE INSERT ON external_knowledge_record
        BEGIN SELECT RAISE(ABORT, 'injected publication failure'); END""")
    with pytest.raises(sqlite3.Error, match="injected"):
        repo.publish((capture("attack-stix", bundle(stix("tool"))),))
    assert (
        repo.connection.execute("SELECT count(*) FROM external_knowledge_artifact").fetchone()[0]
        == 0
    )


def test_tampering_detected_by_raw_replay(repo):
    result = repo.publish((capture("attack-stix", bundle(stix("tool"))),))
    repo.connection.execute(
        "UPDATE external_knowledge_artifact SET content=?", (secrets.token_bytes(16),)
    )
    with pytest.raises(ModelError, match="digest"):
        repo.load(result.snapshot_id)


def test_refuses_research_database_and_has_no_automatic_initialization():
    with sqlite3.connect(":memory:") as conn:
        conn.execute("CREATE TABLE historical_record(value TEXT)")
        repository = ExternalKnowledgeRepository(conn)
        assert (
            conn.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0] == 1
        )
        with pytest.raises(ModelError, match="isolated"):
            repository.initialize()
        assert (
            conn.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0] == 1
        )


def test_offline_ingestion_and_publication_never_acquire_network(repo, monkeypatch):
    import socket
    import subprocess

    source = capture("attack-stix", bundle(stix("tool")))

    def denied(*args, **kwargs):
        raise AssertionError("external source replay must remain offline")

    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    result = repo.publish((source,))
    assert repo.load(result.snapshot_id) == result


def test_repeated_nvd_records_cannot_hide_pagination_drift():
    record = {"cve": cve()}
    first = capture("nvd-cve", page("nvd-cve", [record], total=2))
    second = capture("nvd-cve", page("nvd-cve", [record], start=1, total=2), base=first[0])
    with pytest.raises(ModelError, match="duplicate NVD record"):
        ingest((first, second))


def test_autocommit_publication_rolls_back_atomically(tmp_path):
    with sqlite3.connect(tmp_path / (uuid4().hex + ".sqlite"), isolation_level=None) as connection:
        store = ExternalKnowledgeRepository(connection)
        store.initialize()
        connection.execute("""CREATE TRIGGER reject_snapshot
            BEFORE INSERT ON external_knowledge_snapshot
            BEGIN SELECT RAISE(ABORT, 'injected autocommit failure'); END""")
        with pytest.raises(sqlite3.Error, match="injected"):
            store.publish((capture("attack-stix", bundle(stix("tool"))),))
        assert (
            connection.execute("SELECT count(*) FROM external_knowledge_artifact").fetchone()[0]
            == 0
        )


def test_wrong_publisher_origin_cannot_masquerade_as_nvd():
    descriptor, _ = capture("attack-stix", bundle(stix("tool")))
    with pytest.raises(ModelError, match="official publisher"):
        replace(descriptor, dataset="nvd-cve")


def test_unknown_stix_extensions_are_retained():
    obj = stix("x-" + uuid4().hex)
    snapshot = ingest((capture("attack-stix", bundle(obj)),))
    assert _plain(snapshot.records[0].payload) == obj


def test_record_projection_tampering_is_detected(repo):
    snapshot = repo.publish((capture("attack-stix", bundle(stix("tool"))),))
    repo.connection.execute("UPDATE external_knowledge_record SET payload='{}'")
    with pytest.raises(ModelError, match="projection mismatch"):
        repo.load(snapshot.snapshot_id)


def test_oversized_snapshot_fails_before_any_persistence(repo, monkeypatch):
    from rlredteam.knowledge.external import models

    source = capture("attack-stix", bundle(stix("tool")))
    monkeypatch.setattr(models, "MAX_SNAPSHOT_BYTES", len(source[1]))
    with pytest.raises(ModelError, match="document limit"):
        repo.publish((source,))
    assert (
        repo.connection.execute("SELECT count(*) FROM external_knowledge_artifact").fetchone()[0]
        == 0
    )
