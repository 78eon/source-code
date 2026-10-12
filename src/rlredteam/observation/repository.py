"""Local immutable repositories, with bounded, no-follow, atomic JSON publication."""

import os
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from rlredteam.knowledge.serialization import digest
from rlredteam.knowledge.validation import ModelError

from .audit import AuditTrail
from .models import ObservationBundle, ObservationSession
from .serialization import dumps, loads

MAX_BYTES = 8 * 1024 * 1024
KINDS = {"session": ObservationSession, "bundle": ObservationBundle, "audit": AuditTrail}


class ObservationRepository(Protocol):
    def save_session(self, session: ObservationSession) -> None: ...
    def load_session(self, session_id: str) -> ObservationSession: ...
    def save_bundle(self, bundle: ObservationBundle) -> None: ...
    def load_bundle(self, bundle_id: str) -> ObservationBundle: ...
    def list_sessions(self) -> tuple[str, ...]: ...
    def exists(self, identifier: str) -> bool: ...
    def save_audit(self, audit: AuditTrail) -> None: ...
    def load_audit(self, session_id: str) -> AuditTrail: ...


class InMemoryObservationRepository:
    def __init__(self):
        self._values = {}

    def _save(self, kind, key, value):
        expected = KINDS[kind]
        if not isinstance(value, expected):
            raise ModelError("wrong repository object type")
        text = dumps(value)
        loads(text)
        previous = self._values.get((kind, key))
        if previous is not None and previous != text:
            raise ModelError("repository ID already exists with different content")
        self._values[(kind, key)] = text

    def save_session(self, session):
        self._save("session", session.session_id, session)

    def load_session(self, session_id):
        return self._load("session", session_id)

    def save_bundle(self, bundle):
        self._save("bundle", bundle.bundle_id, bundle)

    def load_bundle(self, bundle_id):
        return self._load("bundle", bundle_id)

    def save_audit(self, audit):
        self._save("audit", audit.session_id, audit)

    def load_audit(self, session_id):
        return self._load("audit", session_id)

    def _load(self, kind, key):
        return loads(self._values[(kind, key)])

    def list_sessions(self):
        return tuple(sorted(key for kind, key in self._values if kind == "session"))

    def exists(self, identifier):
        return any(key == identifier for _, key in self._values)


class JsonObservationRepository(InMemoryObservationRepository):
    """One explicit engineering directory, never a research evidence directory."""

    def __init__(self, root):
        self.root = Path(root).absolute()
        if any(path.is_symlink() for path in (self.root, *self.root.parents)):
            raise ModelError("repository directory must not traverse symlinks")
        project = Path(__file__).resolve().parents[3]
        resolved = self.root.resolve()
        if (
            any(
                resolved.is_relative_to(project / name)
                for name in ("configs", "results", "runs", "data")
            )
            or resolved == project
        ):
            raise ModelError("observation repository cannot write research/workspace roots")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    @contextmanager
    def _directory(self):
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield fd
        finally:
            os.close(fd)

    def _name(self, kind, key):
        return kind + "-" + digest(key) + ".json"

    def _read(self, fd, name):
        try:
            handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        except FileNotFoundError as exc:
            raise KeyError(name) from exc
        with os.fdopen(handle, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
                raise ModelError("repository requires bounded regular JSON files")
            raw = stream.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ModelError("repository document too large")
            return raw.decode("utf-8")

    def _save(self, kind, key, value):
        expected = KINDS[kind]
        if not isinstance(value, expected):
            raise ModelError("wrong repository object type")
        text = dumps(value)
        loads(text)
        name, temporary = self._name(kind, key), ".pending-" + uuid4().hex
        with self._directory() as fd:
            handle = os.open(
                temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd
            )
            try:
                with os.fdopen(handle, "w", encoding="utf-8") as stream:
                    stream.write(text)
                    stream.flush()
                    os.fsync(stream.fileno())
                try:
                    os.link(temporary, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
                except FileExistsError:
                    if self._read(fd, name) != text:
                        raise ModelError(
                            "repository ID already exists with different content"
                        ) from None
                os.fsync(fd)
            finally:
                os.unlink(temporary, dir_fd=fd)

    def _load(self, kind, key):
        with self._directory() as fd:
            result = loads(self._read(fd, self._name(kind, key)))
        expected = KINDS[kind]
        if (
            not isinstance(result, expected)
            or getattr(result, "bundle_id" if kind == "bundle" else "session_id") != key
        ):
            raise ModelError("repository identity mismatch")
        return result

    def list_sessions(self):
        result = []
        with self._directory() as fd:
            for name in sorted(os.listdir(fd)):
                if name.startswith("session-") and name.endswith(".json"):
                    session = loads(self._read(fd, name))
                    if not isinstance(session, ObservationSession) or name != self._name(
                        "session", session.session_id
                    ):
                        raise ModelError("repository session identity mismatch")
                    result.append(session.session_id)
        return tuple(sorted(result))

    def exists(self, identifier):
        for kind in KINDS:
            try:
                self._load(kind, identifier)
            except KeyError:
                continue
            return True
        return False
