"""Strict, side-effect-free validation shared by knowledge and evidence models."""

from __future__ import annotations

import math
import re
import types
from collections.abc import Mapping
from dataclasses import fields
from datetime import UTC, datetime
from types import MappingProxyType
from typing import get_args, get_origin, get_type_hints


class ModelError(ValueError):
    """A domain model or serialized document violates its contract."""


def text(value, field, *, empty=False):
    if not isinstance(value, str) or (not empty and not value.strip()):
        raise ModelError(f"{field} must be {'a string' if empty else 'non-empty text'}")


def stable_id(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}", value
    ):
        raise ModelError(f"invalid stable ID: {value!r}")
    if ".." in value:
        raise ModelError("stable IDs must not contain traversal segments")
    return value


def timestamp(value):
    text(value, "timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ModelError("timestamp must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ModelError("timestamp must include a timezone")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def time_field(instance, name, *, optional=False):
    value = getattr(instance, name)
    if value is None and optional:
        return
    object.__setattr__(instance, name, timestamp(value))


def time_order(first, last):
    if first is not None and last is not None:
        if datetime.fromisoformat(first.replace("Z", "+00:00")) > datetime.fromisoformat(
            last.replace("Z", "+00:00")
        ):
            raise ModelError("timestamps are in reverse order")


def bounded(value, minimum=0.0, maximum=1.0):
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ModelError("score must be a finite number, not a boolean")
    if not minimum <= value <= maximum:
        raise ModelError(f"score must be within {minimum}..{maximum}")
    return float(value)


def frozen_json(value, depth=0):
    """Defensive deep copy; arbitrary Python objects and non-finite values fail."""
    if depth > 64:
        raise ModelError("JSON nesting exceeds 64")
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    if isinstance(value, Mapping):
        if not all(type(key) is str for key in value):
            raise ModelError("JSON object keys must be strings")
        return MappingProxyType({key: frozen_json(value[key], depth + 1) for key in sorted(value)})
    if isinstance(value, tuple | list):
        return tuple(frozen_json(item, depth + 1) for item in value)
    raise ModelError(f"unsupported JSON value: {type(value).__name__}")


def check_type(value, annotation):
    origin, args = get_origin(annotation), get_args(annotation)
    if annotation is object:
        frozen_json(value)
        return True
    if origin is types.UnionType:
        return any(check_type(value, arg) for arg in args)
    if origin is tuple:
        return isinstance(value, tuple) and all(check_type(item, args[0]) for item in value)
    if origin is Mapping:
        return isinstance(value, Mapping) and all(
            check_type(key, args[0]) and check_type(item, args[1]) for key, item in value.items()
        )
    if annotation is float:
        return type(value) in (int, float) and math.isfinite(value)
    if annotation in (int, bool, str, type(None)):
        return type(value) is annotation
    return isinstance(value, annotation)


def validate_fields(instance):
    hints = get_type_hints(type(instance))
    for field in fields(instance):
        if not check_type(getattr(instance, field.name), hints[field.name]):
            raise ModelError(f"invalid type for {type(instance).__name__}.{field.name}")


def ids(instance, name, *, required=False):
    values = getattr(instance, name)
    if required and not values:
        raise ModelError(f"{name} must not be empty")
    for value in values:
        stable_id(value)
    if len(values) != len(set(values)):
        raise ModelError(f"duplicate {name}")
    object.__setattr__(instance, name, tuple(sorted(values)))


def attributes(instance, name="attributes"):
    object.__setattr__(instance, name, frozen_json(getattr(instance, name)))


def digest_string(value):
    if not isinstance(value, str) or not re.fullmatch("[0-9a-f]{64}", value):
        raise ModelError("expected lowercase SHA-256 digest")


def unique(items, key):
    result = {}
    for item in items:
        identifier = getattr(item, key)
        if identifier in result:
            raise ModelError(f"duplicate {key}: {identifier}")
        result[identifier] = item
    return result


def require_refs(values, available, label):
    missing = set(values) - set(available)
    if missing:
        raise ModelError(f"dangling {label}: {sorted(missing)}")
