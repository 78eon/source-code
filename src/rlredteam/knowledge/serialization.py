"""Deterministic, explicitly tagged JSON; no pickle or dynamic imports from input."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from enum import Enum

from .validation import ModelError


def encode(value):
    if isinstance(value, Enum):
        return {"enum": type(value).__name__, "value": value.value}
    if is_dataclass(value) and not isinstance(value, type):
        return {
            "type": type(value).__name__,
            "fields": {field.name: encode(getattr(value, field.name)) for field in fields(value)},
        }
    if isinstance(value, Mapping):
        return {"map": {key: encode(item) for key, item in sorted(value.items())}}
    if isinstance(value, tuple | list):
        return {"items": [encode(item) for item in value]}
    if value is None or type(value) in (str, int, bool, float):
        return value
    raise ModelError(f"unsupported serialization type: {type(value).__name__}")


def canonical_json(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def digest(value):
    return hashlib.sha256(canonical_json(encode(value)).encode()).hexdigest()


def model_types():
    from .models import (
        EntityType,
        KnowledgeEntity,
        KnowledgeReference,
        KnowledgeSource,
        KnowledgeStatus,
        SourceType,
    )
    from .relations import KnowledgeRelation, RelationType
    from .snapshot import KnowledgeSnapshot

    return {
        item.__name__: item
        for item in (
            EntityType,
            KnowledgeEntity,
            KnowledgeReference,
            KnowledgeSource,
            KnowledgeStatus,
            SourceType,
            KnowledgeRelation,
            RelationType,
            KnowledgeSnapshot,
        )
    }


def _decode(value, allowed, depth=0):
    if depth > 64:
        raise ModelError("document nesting exceeds 64")
    if not isinstance(value, dict):
        if value is None or type(value) in (str, int, bool, float):
            return value
        raise ModelError("untagged container in document")
    keys = set(value)
    if keys == {"items"} and isinstance(value["items"], list):
        return tuple(_decode(item, allowed, depth + 1) for item in value["items"])
    if keys == {"map"} and isinstance(value["map"], dict):
        return {key: _decode(item, allowed, depth + 1) for key, item in value["map"].items()}
    if keys == {"enum", "value"}:
        kind = allowed.get(value["enum"]) if isinstance(value["enum"], str) else None
        if kind is None or not issubclass(kind, Enum):
            raise ModelError("unknown enum")
        return kind(value["value"])
    if keys == {"type", "fields"}:
        kind = allowed.get(value["type"]) if isinstance(value["type"], str) else None
        if kind is None or not is_dataclass(kind) or not isinstance(value["fields"], dict):
            raise ModelError("unknown model type")
        expected = {field.name for field in fields(kind)}
        if set(value["fields"]) != expected:
            raise ModelError("missing or unexpected model fields")
        return kind(
            **{key: _decode(item, allowed, depth + 1) for key, item in value["fields"].items()}
        )
    raise ModelError("malformed tagged document")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ModelError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _constant(value):
    raise ModelError(f"non-finite JSON number: {value}")


def dumps(value):
    if type(value) not in model_types().values() or not is_dataclass(value):
        raise ModelError("not a knowledge model")
    return canonical_json({"schema": "security-rl-knowledge-json-v1", "model": encode(value)})


def load_document(text, *, schema, allowed):
    if not isinstance(text, str) or len(text.encode()) > 8 * 1024 * 1024:
        raise ModelError("expected JSON text up to 8 MiB")
    try:
        raw = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
        if not isinstance(raw, dict) or set(raw) != {"schema", "model"}:
            raise ModelError("invalid document envelope")
        if raw["schema"] != schema:
            raise ModelError("unsupported schema")
        result = _decode(raw["model"], allowed)
        if not is_dataclass(result):
            raise ModelError("expected a model at document root")
        return result
    except (TypeError, ValueError, RecursionError) as exc:
        raise ModelError(f"invalid model document: {exc}") from exc


def loads(text):
    return load_document(text, schema="security-rl-knowledge-json-v1", allowed=model_types())
