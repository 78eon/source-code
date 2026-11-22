"""Bounded, owner-only engineering state; immutable hash-sealed records, no research crawling."""

import fcntl
import json
import os
import re
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path
from rlredteam.storage.analytical_identity import digest


class SimulationRepository:
    def __init__(self, root):
        self.root = Path(root)
        if (
            not self.root.is_absolute()
            or self.root.name != "engineering-simulations"
            or ".." in self.root.parts
            or any(p.is_symlink() for p in (self.root, *self.root.parents))
            or set(self.root.parts)
            & {"runs", "results", "research_evidence", "checkpoints", "source code"}
        ):
            raise ValueError(
                "Use a dedicated engineering-simulations state directory outside protected evidence"
            )

    def prepare(self):
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.root.stat()
        if info.st_uid == os.getuid() and not any(self.root.iterdir()):
            self.root.chmod(0o700)  # Only a new empty engineering volume, never repository trees.
            info = self.root.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("Engineering state must be owner-only")

    @contextmanager
    def locked(self):
        self.prepare()
        fd = os.open(self.root / "operation.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)

    def path(self, identifier, kind):
        if not re.fullmatch(r"engineering-[a-f0-9]{32}", identifier) or kind not in {
            "specification",
            "result",
            "publication",
        }:
            raise ValueError("Invalid engineering simulation identifier")
        folder = self.root / identifier
        if folder.is_symlink():
            raise ValueError("State symlinks prohibited")
        return folder / (kind + ".json")

    def save(self, identifier, kind, record):
        path = self.path(identifier, kind)
        if path.exists():
            old = self.load(identifier, kind)
            if old != record:
                raise ValueError("Immutable engineering record already exists")
            return
        path.parent.mkdir(mode=0o700, exist_ok=True)
        body = json.dumps(
            {"payload": record, "sha256": digest(record)}, sort_keys=True, allow_nan=False
        )
        if len(body.encode()) > 32 * 1024 * 1024:
            raise ValueError("Simulation artifact limit exceeded")
        fd, name = tempfile.mkstemp(dir=path.parent)
        try:
            with os.fdopen(fd, "w") as f:
                f.write(body)
                f.flush()
                os.fsync(f.fileno())
            os.link(name, path)  # Never overwrite a racing or historical result.
        finally:
            os.unlink(name)

    def load(self, identifier, kind):
        path = self.path(identifier, kind)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd) as f:
            info = os.fstat(f.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 32 * 1024 * 1024:
                raise ValueError("Invalid artifact")
            sealed = json.load(f)
        if sealed["sha256"] != digest(sealed["payload"]):
            raise ValueError("Engineering artifact integrity mismatch")
        return sealed["payload"]

    def list(self):
        return [
            self.load(p.name, "specification")
            for p in sorted(self.root.glob("engineering-*"))
            if p.is_dir()
        ][:100]
