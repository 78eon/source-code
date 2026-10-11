"""Full deterministic SHA-256 over supplied metadata, never host discovery."""

from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from datetime import datetime

from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import digest


@dataclass(frozen=True, slots=True, kw_only=True)
class ObservationProvenance:
    source_id: str
    collector: str
    software_version: str
    schema_version: str
    timestamp: str
    input_digest: str
    metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self):
        v.validate_fields(self)
        v.stable_id(self.source_id)
        for name in ("collector", "software_version", "schema_version"):
            v.text(getattr(self, name), name)
        v.time_field(self, "timestamp")
        v.digest_string(self.input_digest)
        v.attributes(self, "metadata")

    @property
    def digest(self):
        return digest(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class AuthorizationRecord:
    authorization_id: str
    scope_id: str
    owner: str
    authorized_by: str
    valid_from: str
    valid_until: str
    permitted_purpose: str
    authorization_reference: str
    notes: str = ""
    digest: str = ""

    def __post_init__(self):
        v.validate_fields(self)
        v.stable_id(self.authorization_id)
        v.stable_id(self.scope_id)
        for name in ("owner", "authorized_by", "permitted_purpose", "authorization_reference"):
            v.text(getattr(self, name), name)
        v.time_field(self, "valid_from")
        v.time_field(self, "valid_until")
        if datetime.fromisoformat(self.valid_from) >= datetime.fromisoformat(self.valid_until):
            raise v.ModelError("authorization validity interval is empty")
        actual = digest(
            {item.name: getattr(self, item.name) for item in fields(self) if item.name != "digest"}
        )
        if self.digest and self.digest != actual:
            raise v.ModelError("authorization digest mismatch")
        object.__setattr__(self, "digest", actual)

    def validate(self, scope, *, at):
        now = datetime.fromisoformat(v.timestamp(at))
        if (
            not datetime.fromisoformat(self.valid_from)
            <= now
            < datetime.fromisoformat(self.valid_until)
        ):
            raise v.ModelError("authorization is expired or not yet valid")
        if (
            self.scope_id != scope.scope_id
            or self.authorization_reference != scope.authorization_reference
        ):
            raise v.ModelError("authorization does not bind this scope/reference")
