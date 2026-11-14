"""Planning-only exact-host projection of canonical scope; never execution permission."""

import ipaddress

from rlredteam.enterprise.live import LabScope
from rlredteam.knowledge.validation import ModelError


def project_lab_scope(scope, authorization, targets, capability, *, at):
    """Preserves exclusions/capabilities by validating each explicit target first.

    Legacy Nmap profiles do not yet enforce canonical per-port request budgets;
    therefore this projection ALWAYS disables execution, even for live-enabled
    canonical scopes. No CIDR widening, DNS resolution or implicit discovery.
    """
    authorization.validate(scope, at=at)
    targets = tuple(targets)
    if not targets or len(set(targets)) != len(targets) or len(targets) > scope.max_hosts:
        raise ModelError("explicit unique targets within canonical host budget required")
    networks = []
    for target in targets:
        address = ipaddress.ip_address(target)
        scope.validate_target(str(address), capability, at=at)
        networks.append(str(ipaddress.ip_network((address, address.max_prefixlen))))
    return LabScope.from_strings(
        authorization_id=authorization.authorization_id,
        allowed_networks=tuple(networks),
        max_addresses=len(targets),
        execution_enabled=False,
    )
