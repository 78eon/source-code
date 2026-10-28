from rlredteam.digital_twin.models import VersionStatus
from rlredteam.evidence.models import ObservedService, ObservedSoftware
from tests.digital_twin_fixtures import build, host
from tests.knowledge_evidence_fixtures import record


def test_conflicting_os_and_hostname_are_retained_without_winner():
    extra = host("alternate", 1, subject_id="asset:web", value={"os": "windows"})
    twin = build(extras=(extra,))
    web = next(asset for asset in twin.assets if "asset:web" in asset.subject_ids)
    assert web.os is None and web.hostname is None
    conflicts = twin.explain_entity(web.stable_id)["conflicts"]
    assert {item.field_name for item in conflicts} >= {"hostname", "os"}
    os_conflict = next(item for item in conflicts if item.field_name == "os")
    assert set(os_conflict.alternatives.values()) == {"linux", "windows"}
    assert os_conflict.resolution_state == "UNRESOLVED"
    assert {item.evidence_id for item in twin.evidence.records} >= {
        "evidence:web",
        "evidence:alternate",
    }


def test_software_and_service_conflicts_are_not_silently_chosen():
    extra = (
        record(
            "evidence:software-conflict",
            ObservedSoftware,
            subject_id="software:web",
            asset_id="asset:web",
            product_id="product:b",
            version="9.9",
            attributes={"version_kind": "exact"},
        ),
        record(
            "evidence:service-conflict",
            ObservedService,
            subject_id="service:https",
            asset_id="asset:web",
            port=80,
            protocol="udp",
        ),
    )
    twin = build(extras=extra)
    assert twin.software[0].version_status == VersionStatus.CONFLICTING
    assert twin.software[0].versions == ("2.4.50", "9.9")
    assert twin.software[0].product_id is None
    assert twin.services[0].port is None and twin.services[0].protocol is None
    assert {item.field_name for item in twin.conflicts} >= {
        "version",
        "product",
        "port",
        "protocol",
    }
