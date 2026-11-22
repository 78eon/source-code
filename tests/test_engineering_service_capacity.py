from copy import deepcopy

import pytest

from rlredteam.application.engineering_simulation.models import MAX_SERVICE_TEMPLATES, SimulationSpec
from rlredteam.application.engineering_simulation.service import SimulationService
from rlredteam.application.engineering_simulation.report import assessment
from rlredteam.api.engineering_simulations import DEFAULT_SPEC


@pytest.mark.parametrize("count", [1, 4, 8, 12])
def test_service_capacity_roundtrip_and_inventory(tmp_path, count):
    values = deepcopy(DEFAULT_SPEC)
    values["services"] = [dict(name="custom service", port=1024+i, version=f"instance-{i}")
                          for i in range(count)]
    values["vulnerabilities"] = {"per_host": 0}
    spec = SimulationSpec.model_validate(values)
    service = SimulationService(tmp_path / "engineering-simulations")
    saved = service.create(spec)
    loaded = service.get(saved["simulation_id"])
    assert len(loaded["specification"]["services"]) == count
    assert sum(n["type"] == "service" for n in loaded["topology"]["nodes"]) == count * spec.hosts
    result = service.run(saved["simulation_id"])
    assert len(assessment(loaded, result)["scope"]["services"]) == count


def test_capacity_and_scope_rejected():
    values = deepcopy(DEFAULT_SPEC)
    values["services"] = [dict(name="custom service", port=1024+i)
                          for i in range(MAX_SERVICE_TEMPLATES+1)]
    with pytest.raises(ValueError):
        SimulationSpec.model_validate(values)
    values["services"] = [dict(name="custom service", port=1024, device_group=19)]
    with pytest.raises(ValueError):
        SimulationSpec.model_validate(values)


def healthcare_services():
    pairs = [("HTTPS",443,"subnet",""),("custom service",8443,"subnet","Synthetic clinical application service"),
             ("directory/identity service",636,"enterprise",""),("file sharing",445,"subnet",""),
             ("database service",5432,"host",""),("database service",5432,"subnet",""),
             ("custom service",9443,"subnet","Synthetic monitoring console"),("RDP",3389,"subnet","")]
    return [dict(name=n,port=p,accessibility=a,version=v,importance="high",
                 device_group=i,authentication_required=True) for i,(n,p,a,v) in enumerate(pairs)]


def test_healthcare_eight_templates_and_observed_projection(tmp_path):
    from rlredteam.causal_graph import graph_from_dict
    from rlredteam.storage.neo4j_projection import build_projection_plan

    values = deepcopy(DEFAULT_SPEC)
    values.update(hosts=24,organisation_type="healthcare",
                  subnets=[dict(label="Healthcare",size=24)],
                  devices=[dict(category=c,count=3,subnet=0) for c in
                           ["web server","application server","identity server","file server",
                            "database server","database server","security appliance","workstation"]],
                  services=healthcare_services(),max_steps=200)
    service = SimulationService(tmp_path / "engineering-simulations")
    spec = SimulationSpec.model_validate(values)
    saved = service.create(spec)
    loaded = SimulationService(service.repository.root).get(saved["simulation_id"])
    assert loaded["specification"]["services"] == spec.model_dump()["services"]
    configured = {n["id"] for n in loaded["topology"]["nodes"] if n["type"]=="service"}
    assert len(configured)==24
    result = service.run(saved["simulation_id"])
    assert assessment(loaded,result)["scope"]["services"] == spec.model_dump()["services"]
    graph=graph_from_dict(result["graph"])
    plan=build_projection_plan(graph)
    assert {n.node_id for n in graph.nodes} == {n["node_id"] for n in plan.node_rows}
    assert result["graph_id"] == plan.graph_id
    assert result["report_id"] == graph.report_id
    # Projection includes recorded discoveries; undiscovered configured inventory is excluded.
    assert configured.intersection({n.node_id for n in graph.nodes})


def test_duplicate_templates_follow_existing_domain_contract():
    values=deepcopy(DEFAULT_SPEC)
    base=dict(name="database service",port=5432,device_group=0)
    values["services"]=[base,dict(base,device_group=1)]
    assert len(SimulationSpec.model_validate(values).services)==2
    values["services"]=[base,dict(base)]
    assert len(SimulationSpec.model_validate(values).services)==2
