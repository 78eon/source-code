"""Bounded synthetic inputs: no addresses, credentials, tools or checkpoint paths."""

import re
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator

MAX_SERVICE_TEMPLATES = 12

DISCLAIMER = "SIMULATED SECURITY ASSESSMENT — NOT A LIVE PENETRATION TEST"
POLICY = "engineering-observation-heuristic-v1"
DECISION_ENGINE = "Engineering V2 Reasoner / masked heuristic"
DEVICE_CATEGORIES = [
    "workstation",
    "laptop",
    "server",
    "web server",
    "application server",
    "database server",
    "file server",
    "identity server",
    "DNS server",
    "mail server",
    "firewall",
    "router",
    "switch",
    "VPN gateway",
    "proxy",
    "load balancer",
    "storage/NAS",
    "printer",
    "IoT-like device",
    "security appliance",
    "custom synthetic device",
]
SERVICE_CATEGORIES = [
    "HTTP",
    "HTTPS",
    "SSH",
    "SMB",
    "RDP",
    "DNS",
    "SMTP",
    "database service",
    "directory/identity service",
    "file sharing",
    "custom service",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)

    @model_validator(mode="after")
    def no_secret_material(self):
        text = self.model_dump_json()
        if re.search(
            r"(?:password|api[_ -]?key|api[_ -]?token|secret|authorization)\s*[:=]|BEGIN[^\n]*PRIVATE KEY|Bearer\s+[A-Za-z0-9_-]{12}",
            text,
            re.I,
        ):
            raise ValueError("Do not supply credentials or secrets in synthetic simulation fields")
        return self


class Subnet(StrictModel):
    label: str = Field(min_length=1, max_length=60)
    size: int = Field(ge=1, le=40)
    role: Literal[
        "DMZ", "internal", "management", "servers", "workstations", "database", "isolated critical"
    ] = "internal"


class DeviceGroup(StrictModel):
    category: str = Field(min_length=1, max_length=60)
    count: int = Field(ge=1, le=40)
    os_family: Literal["Linux", "Windows", "network appliance", "other synthetic"] = "Linux"
    os_version: str = Field(default="synthetic-1", max_length=60)
    role: str = Field(default="synthetic host", max_length=60)
    criticality: Literal["low", "medium", "high", "critical"] = "medium"
    subnet: int = Field(ge=0, le=7)
    internet_exposed: bool = False
    crown_jewel: bool = False


class Service(StrictModel):
    name: str = Field(min_length=1, max_length=60)
    version: str = Field(default="synthetic-1", max_length=60)
    port: int = Field(ge=1, le=65535)
    device_group: int | None = Field(default=None, ge=0, le=19)
    accessibility: Literal["host", "subnet", "enterprise", "synthetic exposed"] = "subnet"
    authentication_required: bool = True
    importance: Literal["low", "medium", "high"] = "medium"


class VulnerabilitySettings(StrictModel):
    mode: Literal["automatic_synthetic", "catalogue_metadata"] = "automatic_synthetic"
    risk_profile: Literal["hardened", "low", "medium", "high", "intentionally vulnerable lab"] = (
        "medium"
    )
    cvss_min: float = Field(default=0, ge=0, le=10)
    cvss_max: float = Field(default=10, ge=0, le=10)
    per_host: int = Field(default=1, ge=0, le=2)
    access: Literal["remote", "local"] = "remote"
    privilege: Literal["user", "root"] = "user"
    service_index: int = Field(default=0, ge=0, le=MAX_SERVICE_TEMPLATES - 1)
    catalogue_ids: list[str] = Field(default_factory=list, max_length=20)


class Controls(StrictModel):
    firewall_segmentation: bool = True
    endpoint_protection: bool = False
    mfa: bool = False
    restricted_administration: bool = False
    service_hardening: bool = False
    patch_coverage: float = Field(default=0, ge=0, le=1)
    monitoring: bool = True


class ExampleOrigin(StrictModel):
    preset_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,60}$")
    version: int = Field(ge=1)
    specification_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    topology_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class SimulationSpec(StrictModel):
    name: str = Field(min_length=1, max_length=100)
    critical_asset_label: str | None = Field(default=None, min_length=1, max_length=100)
    example_origin: ExampleOrigin | None = None
    description: str = Field(default="", max_length=1000)
    organisation_type: str = Field(default="generic enterprise", min_length=1, max_length=80)
    scenario_label: str = Field(default="engineering demonstration", max_length=100)
    analyst_notes: str = Field(default="", max_length=1000)
    seed: int = Field(default=7, ge=0, le=1000000)
    hosts: int = Field(default=6, ge=2, le=40)
    subnets: list[Subnet] = Field(min_length=1, max_length=8)
    segmentation: Literal["low", "balanced", "strict"] = "balanced"
    dmz: bool = False
    devices: list[DeviceGroup] = Field(min_length=1, max_length=20)
    services: list[Service] = Field(min_length=1, max_length=MAX_SERVICE_TEMPLATES)
    vulnerabilities: VulnerabilitySettings = Field(default_factory=VulnerabilitySettings)
    identity_roles: list[
        Literal[
            "standard user",
            "privileged user",
            "administrator",
            "service account",
            "domain administrator-like",
        ]
    ] = Field(default_factory=lambda: ["standard user"], max_length=5)
    controls: Controls = Field(default_factory=Controls)
    target_group: int = Field(default=0, ge=0, le=19)
    objective: Literal[
        "reach target",
        "establish simulated access",
        "demonstrate attack path",
        "privilege objective",
        "lateral-movement objective",
    ] = "establish simulated access"
    max_steps: int = Field(default=100, ge=1, le=200)
    episodes: int = Field(default=1, ge=1, le=3)
    policy_id: Literal["engineering-observation-heuristic-v1"] = POLICY
    action_masking: Literal[True] = True
    partial_observability: Literal[True] = True
    reward_profile: Literal["engineering-exclusive-v1"] = "engineering-exclusive-v1"

    @model_validator(mode="after")
    def consistent(self):
        if self.objective in {"privilege objective", "lateral-movement objective"}:
            raise ValueError(
                "This adapter supports asset-access objectives only; privilege/lateral objectives are unavailable"
            )
        if 16001 <= self.seed <= 16020:
            raise ValueError("Reserved held-out seeds cannot be used by engineering simulations")
        if (
            sum(s.size for s in self.subnets) != self.hosts
            or sum(g.count for g in self.devices) != self.hosts
        ):
            raise ValueError("Subnet sizes and device counts must each equal host count")
        for i, subnet in enumerate(self.subnets):
            if sum(g.count for g in self.devices if g.subnet == i) != subnet.size:
                raise ValueError(f"Device assignment does not match size of subnet {i+1}")
        if any(g.subnet >= len(self.subnets) for g in self.devices):
            raise ValueError("Unknown subnet assignment")
        if self.target_group >= len(self.devices) or any(
            s.device_group is not None and s.device_group >= len(self.devices)
            for s in self.services
        ):
            raise ValueError("Unknown device group")
        if (
            self.vulnerabilities.service_index >= len(self.services)
            or self.vulnerabilities.cvss_min > self.vulnerabilities.cvss_max
        ):
            raise ValueError("Invalid vulnerability service or CVSS bounds")
        if (
            self.vulnerabilities.mode == "catalogue_metadata"
            and not self.vulnerabilities.catalogue_ids
        ):
            raise ValueError("Select at least one catalogue record")
        if self.dmz and self.subnets[0].role != "DMZ":
            raise ValueError("DMZ mode requires first subnet to have DMZ role")
        return self


def episode_seed(seed: int, episode: int) -> int:
    """Deterministic engineering RNG seeds with the reserved interval removed."""
    import hashlib
    value = int(hashlib.sha256(f"engineering:{seed}:{episode}".encode()).hexdigest()[:12], 16) % 999981
    return value + 20 if value >= 16001 else value
