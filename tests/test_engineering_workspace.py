from copy import deepcopy

import pytest

from rlredteam.api.engineering_simulations import DEFAULT_SPEC
from rlredteam.application.engineering_simulation.models import SimulationSpec
from rlredteam.application.engineering_simulation.service import SimulationService
from rlredteam.application.engineering_simulation.workspace import summary


def test_workspace_requires_database_report_and_exact_graph(tmp_path):
    service = SimulationService(tmp_path / "engineering-simulations")
    spec = SimulationSpec.model_validate(deepcopy(DEFAULT_SPEC))
    record = service.create(spec)
    result = service.run(record["simulation_id"])

    class Repository:
        def attack_path_reports(self, **kwargs):
            assert kwargs["report_ids"] == [result["report_id"]]
            return [deepcopy(result["report"])]

        def causal_attack_graphs(self, **kwargs):
            assert kwargs["report_ids"] == [result["report_id"]]
            return [deepcopy(result["graph"])]

    response = summary(service, record["simulation_id"], Repository())
    assert response["identity"]["graph_id"] == result["graph_id"]
    assert response["configured"]["systems"] == spec.hosts
    assert response["episode"]["actions"] == len(result["episodes"][0]["events"])

    class Missing(Repository):
        def causal_attack_graphs(self, **kwargs):
            return []

    assert (
        summary(service, record["simulation_id"], Missing())["state"] == "assessment_not_published"
    )

    class Wrong(Repository):
        def attack_path_reports(self, **kwargs):
            report = super().attack_path_reports(**kwargs)[0]
            report["facts"] = []
            return [report]

    with pytest.raises(ValueError):
        summary(service, record["simulation_id"], Wrong())
