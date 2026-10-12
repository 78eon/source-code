"""Bounded read-only local JSON loading. URIs in source metadata are never retrieved."""

import hashlib
import json
import os
import stat
import types
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import get_args, get_origin, get_type_hints

from rlredteam.knowledge.models import KnowledgeSource
from rlredteam.knowledge.serialization import _constant, _pairs
from rlredteam.knowledge.validation import ModelError

from .models import VulnerabilityKnowledgeEntry
from .registry import VulnerabilityKnowledgeRegistry
from .serialization import JSON_SCHEMA, loads
from .snapshot import VulnerabilityKnowledgeSnapshot, freeze

INPUT_SCHEMA = "security-rl-curated-vulnerability-input-v1"
MAX_BYTES = 8 * 1024 * 1024


def _construct(kind, value, depth=0):
    if depth > 40:
        raise ModelError("curated input nesting exceeds 40")
    origin, args = get_origin(kind), get_args(kind)
    if origin is types.UnionType:
        if value is None and type(None) in args:
            return None
        options = [t for t in args if t is not type(None)]
        if len(options) != 1:
            raise ModelError("unsupported input union")
        return _construct(options[0], value, depth + 1)
    if origin is tuple:
        if not isinstance(value, list):
            raise ModelError("expected JSON array")
        return tuple(_construct(args[0], item, depth + 1) for item in value)
    if origin is Mapping or kind is object:
        return value
    if isinstance(kind, type) and issubclass(kind, Enum):
        return kind(value)
    if is_dataclass(kind):
        if not isinstance(value, dict) or set(value) - {f.name for f in fields(kind)}:
            raise ModelError("unexpected curated model fields")
        hints = get_type_hints(kind)
        return kind(**{key: _construct(hints[key], item, depth + 1) for key, item in value.items()})
    return value  # Domain constructors validate strict primitive types.


def _read(path):
    # Reject symlinks, devices/FIFOs, URL strings, and replacement during read.
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ModelError("knowledge input must not traverse symlinks")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_BYTES:
            raise ModelError("knowledge input must be a bounded regular file")
        content = stream.read(MAX_BYTES + 1)
        after = os.fstat(stream.fileno())
        if len(content) > MAX_BYTES or (before.st_size, before.st_mtime_ns) != (
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ModelError("knowledge input changed or exceeded size limit")
    return content


def load_local(path, *, created_at):
    path = Path(path)
    if path.is_symlink():
        raise ModelError("knowledge path must not be a symlink")
    paths = tuple(sorted(path.glob("*.json"))) if path.is_dir() else (path,)
    if not paths or len(paths) > 64:
        raise ModelError("select 1..64 local knowledge JSON files")
    entries, sources, byte_count = [], {}, 0
    input_digests = {}
    try:
        for filename in paths:
            content = _read(filename)
            byte_count += len(content)
            if byte_count > MAX_BYTES:
                raise ModelError("combined knowledge input exceeds 8 MiB")
            input_digests[filename.name] = hashlib.sha256(content).hexdigest()
            document = json.loads(content, object_pairs_hook=_pairs, parse_constant=_constant)
            if not isinstance(document, dict):
                raise ModelError("knowledge root must be an object")
            if document.get("schema") == JSON_SCHEMA:
                snapshot = loads(content.decode("utf-8"))
                if not isinstance(snapshot, VulnerabilityKnowledgeSnapshot) or len(paths) != 1:
                    raise ModelError("a snapshot must be supplied alone")
                return snapshot
            if (
                set(document) != {"schema", "entries", "sources"}
                or document["schema"] != INPUT_SCHEMA
            ):
                raise ModelError("invalid curated input envelope")
            entries.extend(_construct(tuple[VulnerabilityKnowledgeEntry, ...], document["entries"]))
            for source in _construct(tuple[KnowledgeSource, ...], document["sources"]):
                if source.source_id in sources and sources[source.source_id] != source:
                    raise ModelError("conflicting source metadata")
                sources[source.source_id] = source
        registry = VulnerabilityKnowledgeRegistry(
            entries=entries, sources=sources.values(), input_digests=input_digests
        )
        return freeze(registry, created_at=created_at)
    except (TypeError, ValueError, KeyError, RecursionError, UnicodeError) as exc:
        raise ModelError(f"invalid local vulnerability knowledge: {exc}") from exc
