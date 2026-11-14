import secrets
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from rlredteam.observation.lab_scope_bridge import project_lab_scope
from rlredteam.observation.protocols import Capability
from tests import test_lab_input

generated = test_lab_input.generated


def test_bridge_retains_exact_authority_and_cannot_enable_execution(generated):
    service, values, _, _ = generated
    scope, auth = service.approvals[values["scope_id"]]
    projected = project_lab_scope(
        scope,
        auth,
        (values["target"],),
        Capability.ADDRESS_OBSERVATION,
        at=datetime.now(UTC).isoformat(),
    )
    assert not projected.execution_enabled
    assert projected.authorization_id == auth.authorization_id
    assert projected.allowed_networks[0].num_addresses == 1


def test_bridge_rejects_excluded_target_and_invalid_authority(generated):
    service, values, _, _ = generated
    scope, auth = service.approvals[values["scope_id"]]
    for candidate, authorization in (
        (replace(scope, excluded_assets=(values["target"],)), auth),
        (scope, replace(auth, scope_id=secrets.token_hex(), digest="")),
    ):
        with pytest.raises(ValueError):
            project_lab_scope(
                candidate,
                authorization,
                (values["target"],),
                Capability.ADDRESS_OBSERVATION,
                at=datetime.now(UTC).isoformat(),
            )
