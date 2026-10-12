"""Declarative, bounded rule predicates; extractors name audited local parsers."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum

from rlredteam.evidence.models import Provenance
from rlredteam.knowledge import validation as v

from .fingerprint_features import FEATURE_FIELDS


class ServiceFamily(StrEnum):
    SSH = "SSH"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    SMTP = "SMTP"
    IMAP = "IMAP"
    POP3 = "POP3"
    FTP = "FTP"
    DATABASE = "DATABASE"
    LDAP = "LDAP"
    DNS = "DNS"
    FILE_SERVICE = "FILE_SERVICE"
    REMOTE_DESKTOP = "REMOTE_DESKTOP"
    GENERIC_TLS = "GENERIC_TLS"
    GENERIC_TCP = "GENERIC_TCP"
    UNKNOWN = "UNKNOWN"


class RulePrecedence(IntEnum):
    DISCLOSURE = 1
    SIGNATURE = 2
    CORROBORATED = 3
    GENERIC = 4
    PORT_HINT = 5


@dataclass(frozen=True, slots=True, kw_only=True)
class FingerprintRule:
    rule_id: str
    rule_version: str
    name: str
    description: str
    protocol_family: ServiceFamily
    required_features: tuple[str, ...]
    candidate_service: ServiceFamily
    base_engineering_confidence: float
    provenance: Provenance
    precedence: RulePrecedence
    conditions: Mapping[str, object] = field(default_factory=dict)
    optional_features: tuple[str, ...] = ()
    forbidden_features: tuple[str, ...] = ()
    candidate_product: str | None = None
    candidate_vendor: str | None = None
    version_extractor: str | None = None
    evidence_weighting: Mapping[str, float] = field(
        default_factory=lambda: {
            "independent_bonus": 0.03,
            "max_bonus": 0.06,
            "conflict_penalty": 0.2,
            "ambiguous_penalty": 0.1,
        }
    )
    enabled: bool = True
    notes: str = ""

    def __post_init__(self):
        v.validate_fields(self)
        v.stable_id(self.rule_id)
        for name in ("rule_version", "name", "description"):
            v.text(getattr(self, name), name)
        for name in ("required_features", "optional_features", "forbidden_features"):
            v.ids(self, name, required=name == "required_features")
            if not set(getattr(self, name)) <= set(FEATURE_FIELDS):
                raise v.ModelError("unknown rule feature")
        if set(self.required_features) & set(self.forbidden_features):
            raise v.ModelError("required and forbidden features overlap")
        if not set(self.conditions) <= set(self.required_features):
            raise v.ModelError("conditions must constrain required features")
        if self.version_extractor not in (None, "ssh", "http-server", "smtp", "ftp"):
            raise v.ModelError("unsupported local extractor")
        if self.candidate_product != ("disclosed" if self.version_extractor else None):
            raise v.ModelError("product candidates must originate from a disclosed local field")
        if self.candidate_vendor is not None:
            raise v.ModelError("vendor enrichment belongs to the separate knowledge lookup")
        object.__setattr__(
            self, "base_engineering_confidence", v.bounded(self.base_engineering_confidence)
        )
        if set(self.evidence_weighting) != {
            "independent_bonus",
            "max_bonus",
            "conflict_penalty",
            "ambiguous_penalty",
        }:
            raise v.ModelError("unsupported confidence factors")
        for weight in self.evidence_weighting.values():
            v.bounded(weight)
        v.attributes(self, "conditions")
        v.attributes(self, "evidence_weighting")


def builtin_rules():
    provenance = Provenance(
        source_ids=("native-fingerprint-rules",), activity="rule-definition", version="1"
    )
    specs = [
        (
            "ssh-banner",
            ServiceFamily.SSH,
            {"ssh_signature": True},
            0.85,
            RulePrecedence.SIGNATURE,
            None,
        ),
        (
            "ssh-product",
            ServiceFamily.SSH,
            {"ssh_signature": True, "banner": None},
            0.85,
            RulePrecedence.DISCLOSURE,
            "ssh",
        ),
        (
            "http-response",
            ServiceFamily.HTTP,
            {"http": True, "http_status": None},
            0.8,
            RulePrecedence.SIGNATURE,
            None,
        ),
        (
            "https-response",
            ServiceFamily.HTTPS,
            {"tls": True, "http": True, "http_status": None},
            0.9,
            RulePrecedence.CORROBORATED,
            None,
        ),
        (
            "http-product",
            ServiceFamily.HTTP,
            {"http": True, "http_server": None},
            0.85,
            RulePrecedence.DISCLOSURE,
            "http-server",
        ),
        (
            "smtp-banner",
            ServiceFamily.SMTP,
            {"smtp_signature": True},
            0.8,
            RulePrecedence.SIGNATURE,
            None,
        ),
        (
            "smtp-product",
            ServiceFamily.SMTP,
            {"smtp_signature": True, "banner": None},
            0.8,
            RulePrecedence.DISCLOSURE,
            "smtp",
        ),
        (
            "ftp-banner",
            ServiceFamily.FTP,
            {"ftp_signature": True},
            0.8,
            RulePrecedence.SIGNATURE,
            None,
        ),
        (
            "ftp-product",
            ServiceFamily.FTP,
            {"ftp_signature": True, "banner": None},
            0.8,
            RulePrecedence.DISCLOSURE,
            "ftp",
        ),
        (
            "imap-banner",
            ServiceFamily.IMAP,
            {"imap_signature": True},
            0.8,
            RulePrecedence.SIGNATURE,
            None,
        ),
        (
            "pop3-banner",
            ServiceFamily.POP3,
            {"pop3_signature": True},
            0.8,
            RulePrecedence.SIGNATURE,
            None,
        ),
        (
            "database-greeting",
            ServiceFamily.DATABASE,
            {"database_signature": True},
            0.75,
            RulePrecedence.SIGNATURE,
            None,
        ),
        (
            "generic-tls",
            ServiceFamily.GENERIC_TLS,
            {"tls": True},
            0.65,
            RulePrecedence.GENERIC,
            None,
        ),
        (
            "generic-tcp",
            ServiceFamily.GENERIC_TCP,
            {"reachable": True},
            0.4,
            RulePrecedence.GENERIC,
            None,
        ),
        ("weak-ssh-port", ServiceFamily.SSH, {"port": 22}, 0.2, RulePrecedence.PORT_HINT, None),
        (
            "weak-https-port",
            ServiceFamily.HTTPS,
            {"port": 443},
            0.2,
            RulePrecedence.PORT_HINT,
            None,
        ),
    ]
    for port, family in (
        (21, ServiceFamily.FTP),
        (25, ServiceFamily.SMTP),
        (53, ServiceFamily.DNS),
        (80, ServiceFamily.HTTP),
        (110, ServiceFamily.POP3),
        (143, ServiceFamily.IMAP),
        (389, ServiceFamily.LDAP),
        (445, ServiceFamily.FILE_SERVICE),
        (3306, ServiceFamily.DATABASE),
        (3389, ServiceFamily.REMOTE_DESKTOP),
    ):
        specs.append(
            ("weak-port-" + str(port), family, {"port": port}, 0.2, RulePrecedence.PORT_HINT, None)
        )
    specs.append(
        ("unknown-port", ServiceFamily.UNKNOWN, {"port": None}, 0.1, RulePrecedence.GENERIC, None)
    )
    return tuple(
        FingerprintRule(
            rule_id="native:" + key,
            rule_version="1",
            name=key,
            description="Match all named features and literal conditions",
            protocol_family=family,
            required_features=tuple(features),
            conditions={k: val for k, val in features.items() if val is not None},
            candidate_service=family,
            candidate_product="disclosed" if extractor else None,
            version_extractor=extractor,
            base_engineering_confidence=score,
            precedence=precedence,
            provenance=provenance,
        )
        for key, family, features, score, precedence, extractor in specs
    )
